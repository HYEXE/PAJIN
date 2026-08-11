"""Durable append-only audit authority for complete Graph Decisions."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from re import fullmatch
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.consistency import GraphDecision
from pajin.graph.models import canonical_graph_json, graph_digest
from pajin.graph.projection import GraphSnapshot, graph_snapshot_ref
from pajin.graph.sqlite_store import (
    SQLiteGraphStoreError,
    load_verified_current_graph_snapshot,
    load_verified_graph_snapshot_history,
)
from pajin.runtime.safe_files import parse_strict_json_bytes

GRAPH_DECISION_AUDIT_RECORD_API_VERSION: Literal[
    "pajin.dev/graph-decision-audit-record/v1alpha1"
] = "pajin.dev/graph-decision-audit-record/v1alpha1"

_SCHEMA_VERSION: Literal[1] = 1
_APPLICATION_ID = 0x50414441  # ASCII "PADA"
_BUSY_TIMEOUT_MS = 30_000
_MAX_RECORD_BYTES = 64 * 1024
_MAX_RECORD_NODES = 2_000
_CAMPAIGN_PATTERN = r"^[a-z0-9][a-z0-9-]{2,79}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_RECORD_ID_PATTERN = r"^graph-decision-audit-record_[a-f0-9]{64}$"
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class GraphDecisionAuditError(RuntimeError):
    """Raised when the Decision audit authority cannot be verified."""


class GraphDecisionAuditRecord(StrictModel):
    """One complete canonical Decision in an immutable audit chain."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/graph-decision-audit-record/v1alpha1"] = Field(
        default=GRAPH_DECISION_AUDIT_RECORD_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GraphDecisionAuditRecord"] = "GraphDecisionAuditRecord"
    sequence: int = Field(ge=1)
    record_id: str = Field(default="", alias="recordId", max_length=96)
    record_digest: str = Field(default="", alias="recordDigest", max_length=64)
    previous_record_digest: _Sha256 | None = Field(alias="previousRecordDigest")
    campaign_id: str = Field(alias="campaignId", pattern=_CAMPAIGN_PATTERN)
    decision: GraphDecision
    recorder_id: str = Field(alias="recorderId", pattern=_IDENTIFIER_PATTERN)
    recorder_digest: _Sha256 = Field(alias="recorderDigest")
    recorded_at: datetime = Field(alias="recordedAt")

    @field_validator("recorded_at")
    @classmethod
    def require_utc_recorded_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Graph Decision audit record time must be UTC")
        return value

    @model_validator(mode="after")
    def bind_record_identity(self) -> Self:
        if self.decision.campaign_id != self.campaign_id:
            raise ValueError("Graph Decision audit record belongs to another Campaign")
        if self.recorded_at < self.decision.created_at:
            raise ValueError("Graph Decision audit record predates its Decision")
        if (self.sequence == 1) is not (self.previous_record_digest is None):
            raise ValueError("Graph Decision audit record predecessor is inconsistent")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"record_id", "record_digest"},
        )
        digest = graph_digest(
            "pajin.graph.decision-audit-record/v1",
            material,
            max_bytes=_MAX_RECORD_BYTES,
        )
        record_id = f"graph-decision-audit-record_{digest}"
        if self.record_digest and self.record_digest != digest:
            raise ValueError("Graph Decision audit record digest differs from canonical material")
        if self.record_id and self.record_id != record_id:
            raise ValueError("Graph Decision audit record ID differs from canonical material")
        object.__setattr__(self, "record_digest", digest)
        object.__setattr__(self, "record_id", record_id)
        if fullmatch(_RECORD_ID_PATTERN, self.record_id) is None:
            raise ValueError("Graph Decision audit record ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="GraphDecisionAuditRecord",
            max_bytes=_MAX_RECORD_BYTES,
        )
        return self


@dataclass(frozen=True)
class VerifiedGraphDecisionAudit:
    """Complete locally verified audit state and its current Graph head."""

    campaign_id: str
    schema_version: Literal[1]
    schema_digest: str
    recorder_id: str
    recorder_digest: str
    records: tuple[GraphDecisionAuditRecord, ...]
    current_snapshot: GraphSnapshot

    @property
    def head_digest(self) -> str | None:
        return self.records[-1].record_digest if self.records else None


_METADATA_TABLE_SQL = """
    CREATE TABLE graph_decision_audit_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT
    """
_RECORDER_TABLE_SQL = """
    CREATE TABLE graph_decision_audit_recorder (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
        recorder_id TEXT NOT NULL,
        recorder_digest TEXT NOT NULL CHECK (length(recorder_digest) = 64)
    ) STRICT
    """
_RECORDS_TABLE_SQL = """
    CREATE TABLE graph_decision_audit_records (
        sequence INTEGER PRIMARY KEY NOT NULL CHECK (sequence >= 1),
        record_id TEXT NOT NULL UNIQUE,
        record_digest TEXT NOT NULL UNIQUE CHECK (length(record_digest) = 64),
        previous_record_digest TEXT CHECK (
            previous_record_digest IS NULL OR length(previous_record_digest) = 64
        ),
        campaign_id TEXT NOT NULL,
        decision_id TEXT NOT NULL UNIQUE,
        decision_digest TEXT NOT NULL UNIQUE CHECK (length(decision_digest) = 64),
        snapshot_id TEXT NOT NULL,
        snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
        decision_kind TEXT NOT NULL CHECK (
            decision_kind IN ('plan', 'task-assignment', 'replan', 'action-proposal', 'stop')
        ),
        actor_digest TEXT NOT NULL CHECK (length(actor_digest) = 64),
        recorder_digest TEXT NOT NULL CHECK (length(recorder_digest) = 64),
        created_at TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        record_json BLOB NOT NULL,
        CHECK (
            (sequence = 1 AND previous_record_digest IS NULL)
            OR (sequence > 1 AND previous_record_digest IS NOT NULL)
        )
    ) STRICT
    """
_RECORDS_SNAPSHOT_INDEX_SQL = (
    "CREATE INDEX graph_decision_audit_records_snapshot_idx "
    "ON graph_decision_audit_records(snapshot_id, sequence)"
)


def _immutable_triggers(table: str, identity_column: str) -> dict[tuple[str, str], str]:
    return {
        (
            "trigger",
            f"{table}_no_update",
        ): f"""
            CREATE TRIGGER {table}_no_update
            BEFORE UPDATE ON {table}
            BEGIN
                SELECT RAISE(ABORT, '{table} is append-only');
            END
        """,
        (
            "trigger",
            f"{table}_no_delete",
        ): f"""
            CREATE TRIGGER {table}_no_delete
            BEFORE DELETE ON {table}
            BEGIN
                SELECT RAISE(ABORT, '{table} is append-only');
            END
        """,
        (
            "trigger",
            f"{table}_no_replace",
        ): f"""
            CREATE TRIGGER {table}_no_replace
            BEFORE INSERT ON {table}
            WHEN EXISTS (
                SELECT 1 FROM {table}
                WHERE {identity_column} = NEW.{identity_column}
            )
            BEGIN
                SELECT RAISE(ABORT, '{table} cannot be replaced');
            END
        """,
    }


_SCHEMA_OBJECT_SQL: dict[tuple[str, str], str] = {
    ("table", "graph_decision_audit_metadata"): _METADATA_TABLE_SQL,
    ("table", "graph_decision_audit_recorder"): _RECORDER_TABLE_SQL,
    ("table", "graph_decision_audit_records"): _RECORDS_TABLE_SQL,
    (
        "index",
        "graph_decision_audit_records_snapshot_idx",
    ): _RECORDS_SNAPSHOT_INDEX_SQL,
}
for _table, _identity in (
    ("graph_decision_audit_metadata", "key"),
    ("graph_decision_audit_recorder", "singleton"),
    ("graph_decision_audit_records", "sequence"),
):
    _SCHEMA_OBJECT_SQL.update(_immutable_triggers(_table, _identity))

_TABLES = frozenset(
    {
        "graph_decision_audit_metadata",
        "graph_decision_audit_recorder",
        "graph_decision_audit_records",
    }
)


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split())


def _schema_digest(objects: dict[tuple[str, str], str]) -> str:
    return sha256(
        json.dumps(
            {
                f"{object_type}:{name}": _normalize_schema_sql(statement)
                for (object_type, name), statement in sorted(objects.items())
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


_SCHEMA_DIGEST = _schema_digest(_SCHEMA_OBJECT_SQL)


class SQLiteGraphDecisionAuditStore:
    """Own one Campaign's complete, append-only Graph Decision audit history."""

    def __init__(
        self,
        path: Path,
        *,
        graph_database: Path,
        campaign_id: str,
        recorder_id: str,
        recorder_digest: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        _require_campaign(campaign_id)
        _require_recorder(recorder_id, recorder_digest)
        self.path = _absolute_path(path)
        self.graph_database = _absolute_path(graph_database)
        _require_distinct_sqlite_paths(self.path, self.graph_database)
        self.campaign_id = campaign_id
        self.recorder_id = recorder_id
        self.recorder_digest = recorder_digest
        self._clock = clock or _utc_now
        self._lock = threading.RLock()
        _initialize(
            self.path,
            campaign_id=campaign_id,
            recorder_id=recorder_id,
            recorder_digest=recorder_digest,
        )

    def append(
        self,
        decision: GraphDecision,
        *,
        recorded_at: datetime | None = None,
    ) -> GraphDecisionAuditRecord:
        """Append one current Snapshot-bound Decision, or return its exact prior record."""

        canonical_decision = _canonical_decision(decision)
        if canonical_decision.campaign_id != self.campaign_id:
            raise GraphDecisionAuditError("Graph Decision belongs to another Campaign")
        with self._lock:
            try:
                with _write_transaction(self.path) as connection:
                    _validate_schema(
                        connection,
                        campaign_id=self.campaign_id,
                        recorder_id=self.recorder_id,
                        recorder_digest=self.recorder_digest,
                    )
                    records = _verified_records(
                        connection,
                        campaign_id=self.campaign_id,
                        recorder_id=self.recorder_id,
                        recorder_digest=self.recorder_digest,
                    )
                    existing = next(
                        (
                            record
                            for record in records
                            if record.decision.decision_id == canonical_decision.decision_id
                        ),
                        None,
                    )
                    if existing is not None:
                        if existing.decision != canonical_decision:
                            raise GraphDecisionAuditError(
                                "Graph Decision audit identity is equivocated"
                            )
                        return existing
                    snapshot = load_verified_current_graph_snapshot(
                        self.graph_database,
                        campaign_id=self.campaign_id,
                        snapshot_id=canonical_decision.snapshot.snapshot_id,
                    )
                    if (
                        snapshot is None
                        or graph_snapshot_ref(snapshot) != canonical_decision.snapshot
                    ):
                        raise GraphDecisionAuditError(
                            "Graph Decision is not bound to the current canonical Snapshot"
                        )
                    if canonical_decision.created_at < snapshot.created_at:
                        raise GraphDecisionAuditError("Graph Decision predates its bound Snapshot")
                    observed_at = recorded_at if recorded_at is not None else self._clock()
                    record = GraphDecisionAuditRecord(
                        sequence=len(records) + 1,
                        previousRecordDigest=(records[-1].record_digest if records else None),
                        campaignId=self.campaign_id,
                        decision=canonical_decision,
                        recorderId=self.recorder_id,
                        recorderDigest=self.recorder_digest,
                        recordedAt=observed_at,
                    )
                    _insert_record(connection, record)
                    return _record_from_row(
                        connection.execute(
                            "SELECT * FROM graph_decision_audit_records WHERE sequence = ?",
                            (record.sequence,),
                        ).fetchone(),
                        campaign_id=self.campaign_id,
                    )
            except GraphDecisionAuditError:
                raise
            except (
                OSError,
                SQLiteGraphStoreError,
                ValidationError,
                ValueError,
                sqlite3.Error,
            ) as exc:
                raise GraphDecisionAuditError("Graph Decision audit append failed") from exc

    def records(self) -> tuple[GraphDecisionAuditRecord, ...]:
        """Return the fully verified local audit chain without Graph freshness claims."""

        try:
            identity = _file_identity(self.path)
            with _readonly_connection(self.path) as connection:
                _validate_schema(
                    connection,
                    campaign_id=self.campaign_id,
                    recorder_id=self.recorder_id,
                    recorder_digest=self.recorder_digest,
                )
                records = _verified_records(
                    connection,
                    campaign_id=self.campaign_id,
                    recorder_id=self.recorder_id,
                    recorder_digest=self.recorder_digest,
                )
            if _file_identity(self.path) != identity:
                raise GraphDecisionAuditError(
                    "Graph Decision audit store changed during verification"
                )
            return records
        except GraphDecisionAuditError:
            raise
        except (OSError, ValidationError, ValueError, sqlite3.Error) as exc:
            raise GraphDecisionAuditError("Graph Decision audit read failed") from exc


def load_verified_graph_decision_audit(
    audit_database: Path,
    *,
    graph_database: Path,
    campaign_id: str,
    snapshot_id: str,
) -> VerifiedGraphDecisionAudit | None:
    """Verify both stores, every historical binding, and one exact current Snapshot."""

    _require_campaign(campaign_id)
    if fullmatch(r"^graph-snapshot_[a-f0-9]{64}$", snapshot_id) is None:
        raise ValueError("Graph Snapshot ID is invalid")
    audit_path = _absolute_path(audit_database)
    graph_path = _absolute_path(graph_database)
    _require_distinct_sqlite_paths(audit_path, graph_path)
    current = load_verified_current_graph_snapshot(
        graph_path,
        campaign_id=campaign_id,
        snapshot_id=snapshot_id,
    )
    if current is None:
        return None
    snapshots = load_verified_graph_snapshot_history(graph_path, campaign_id=campaign_id)
    snapshot_index = {snapshot.snapshot_id: snapshot for snapshot in snapshots}
    if len(snapshot_index) != len(snapshots) or snapshot_index.get(snapshot_id) != current:
        raise GraphDecisionAuditError("Canonical Graph Snapshot history is inconsistent")
    identity = _file_identity(audit_path)
    with _readonly_connection(audit_path) as connection:
        campaign, recorder_id, recorder_digest = _authority_metadata(connection)
        if campaign != campaign_id:
            raise GraphDecisionAuditError("Graph Decision audit Campaign identity differs")
        _validate_schema(
            connection,
            campaign_id=campaign_id,
            recorder_id=recorder_id,
            recorder_digest=recorder_digest,
        )
        records = _verified_records(
            connection,
            campaign_id=campaign_id,
            recorder_id=recorder_id,
            recorder_digest=recorder_digest,
        )
        for record in records:
            snapshot = snapshot_index.get(record.decision.snapshot.snapshot_id)
            if snapshot is None or record.decision.snapshot != graph_snapshot_ref(snapshot):
                raise GraphDecisionAuditError(
                    "Graph Decision audit record differs from its historical Snapshot"
                )
    if _file_identity(audit_path) != identity:
        raise GraphDecisionAuditError("Graph Decision audit store changed during verification")
    rechecked = load_verified_current_graph_snapshot(
        graph_path,
        campaign_id=campaign_id,
        snapshot_id=snapshot_id,
    )
    if rechecked != current:
        raise GraphDecisionAuditError("Canonical Graph head changed during audit verification")
    return VerifiedGraphDecisionAudit(
        campaign_id=campaign_id,
        schema_version=_SCHEMA_VERSION,
        schema_digest=_SCHEMA_DIGEST,
        recorder_id=recorder_id,
        recorder_digest=recorder_digest,
        records=records,
        current_snapshot=current,
    )


def require_distinct_graph_decision_audit_paths(
    audit_database: Path,
    graph_database: Path,
) -> None:
    """Expose the database-family separation check to read-only compositions."""

    _require_distinct_sqlite_paths(
        _absolute_path(audit_database),
        _absolute_path(graph_database),
    )


def _insert_record(connection: sqlite3.Connection, record: GraphDecisionAuditRecord) -> None:
    connection.execute(
        """
        INSERT INTO graph_decision_audit_records (
            sequence, record_id, record_digest, previous_record_digest,
            campaign_id, decision_id, decision_digest, snapshot_id,
            snapshot_digest, decision_kind, actor_digest, recorder_digest,
            created_at, recorded_at, record_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.sequence,
            record.record_id,
            record.record_digest,
            record.previous_record_digest,
            record.campaign_id,
            record.decision.decision_id,
            record.decision.decision_digest,
            record.decision.snapshot.snapshot_id,
            record.decision.snapshot.snapshot_digest,
            record.decision.decision_kind.value,
            record.decision.actor_digest,
            record.recorder_digest,
            _utc_text(record.decision.created_at),
            _utc_text(record.recorded_at),
            sqlite3.Binary(_record_bytes(record)),
        ),
    )


def _verified_records(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    recorder_id: str,
    recorder_digest: str,
) -> tuple[GraphDecisionAuditRecord, ...]:
    rows = connection.execute(
        "SELECT * FROM graph_decision_audit_records ORDER BY sequence"
    ).fetchall()
    records: list[GraphDecisionAuditRecord] = []
    previous_digest: str | None = None
    seen_decisions: set[tuple[str, str]] = set()
    for expected_sequence, row in enumerate(rows, start=1):
        record = _record_from_row(row, campaign_id=campaign_id)
        if record.sequence != expected_sequence:
            raise GraphDecisionAuditError("Graph Decision audit sequence is not contiguous")
        if record.previous_record_digest != previous_digest:
            raise GraphDecisionAuditError("Graph Decision audit chain is not contiguous")
        if (record.recorder_id, record.recorder_digest) != (
            recorder_id,
            recorder_digest,
        ):
            raise GraphDecisionAuditError("Graph Decision audit recorder identity differs")
        decision_identity = (
            record.decision.decision_id,
            record.decision.decision_digest,
        )
        if decision_identity in seen_decisions:
            raise GraphDecisionAuditError("Graph Decision audit contains a duplicate Decision")
        seen_decisions.add(decision_identity)
        records.append(record)
        previous_digest = record.record_digest
    return tuple(records)


def _record_from_row(
    row: sqlite3.Row | None,
    *,
    campaign_id: str,
) -> GraphDecisionAuditRecord:
    if row is None:
        raise GraphDecisionAuditError("Graph Decision audit record was not persisted")
    value = parse_strict_json_bytes(
        _required_bytes(row, "record_json"),
        label="GraphDecisionAuditRecord",
        max_bytes=_MAX_RECORD_BYTES,
        max_depth=32,
        max_nodes=_MAX_RECORD_NODES,
    )
    try:
        record = GraphDecisionAuditRecord.model_validate(value)
    except ValidationError as exc:
        raise GraphDecisionAuditError("Graph Decision audit record is not canonical") from exc
    expected = (
        record.sequence,
        record.record_id,
        record.record_digest,
        record.previous_record_digest,
        record.campaign_id,
        record.decision.decision_id,
        record.decision.decision_digest,
        record.decision.snapshot.snapshot_id,
        record.decision.snapshot.snapshot_digest,
        record.decision.decision_kind.value,
        record.decision.actor_digest,
        record.recorder_digest,
        _utc_text(record.decision.created_at),
        _utc_text(record.recorded_at),
        _record_bytes(record),
    )
    observed = (
        row["sequence"],
        row["record_id"],
        row["record_digest"],
        row["previous_record_digest"],
        row["campaign_id"],
        row["decision_id"],
        row["decision_digest"],
        row["snapshot_id"],
        row["snapshot_digest"],
        row["decision_kind"],
        row["actor_digest"],
        row["recorder_digest"],
        row["created_at"],
        row["recorded_at"],
        _required_bytes(row, "record_json"),
    )
    if observed != expected or record.campaign_id != campaign_id:
        raise GraphDecisionAuditError("Graph Decision audit row differs from its record")
    return record


def _record_bytes(record: GraphDecisionAuditRecord) -> bytes:
    return canonical_graph_json(
        record.model_dump(mode="json", by_alias=True),
        label="GraphDecisionAuditRecord",
        max_bytes=_MAX_RECORD_BYTES,
    )


def _canonical_decision(decision: GraphDecision) -> GraphDecision:
    try:
        return GraphDecision.model_validate(decision.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise GraphDecisionAuditError("Graph Decision is not canonical") from exc


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if not isinstance(value, bytes):
        raise GraphDecisionAuditError(f"Graph Decision audit {field} is not binary")
    return value


def _initialize(
    path: Path,
    *,
    campaign_id: str,
    recorder_id: str,
    recorder_digest: str,
) -> None:
    created, file_size = _prepare_store_file(path)
    initialize_empty = created or file_size == 0
    try:
        connection = _open_write_connection(path)
        try:
            if initialize_empty:
                journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
                if journal_mode is None or str(journal_mode[0]).lower() != "delete":
                    raise GraphDecisionAuditError(
                        "Graph Decision audit store requires DELETE journal mode"
                    )
            connection.execute("BEGIN IMMEDIATE")
            tables = _application_tables(connection)
            if not tables:
                if not initialize_empty:
                    raise GraphDecisionAuditError(
                        "existing Graph Decision audit store has no trusted schema"
                    )
                for statement in _SCHEMA_OBJECT_SQL.values():
                    connection.execute(statement)
                connection.executemany(
                    "INSERT INTO graph_decision_audit_metadata (key, value) VALUES (?, ?)",
                    (
                        ("schema_version", str(_SCHEMA_VERSION)),
                        ("schema_digest", _SCHEMA_DIGEST),
                        ("campaign_id", campaign_id),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO graph_decision_audit_recorder (
                        singleton, recorder_id, recorder_digest
                    ) VALUES (1, ?, ?)
                    """,
                    (recorder_id, recorder_digest),
                )
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            _validate_schema(
                connection,
                campaign_id=campaign_id,
                recorder_id=recorder_id,
                recorder_digest=recorder_digest,
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
    except GraphDecisionAuditError:
        raise
    except sqlite3.Error as exc:
        raise GraphDecisionAuditError("Graph Decision audit initialization failed") from exc


def _validate_schema(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    recorder_id: str,
    recorder_digest: str,
) -> None:
    if _application_tables(connection) != _TABLES:
        raise GraphDecisionAuditError("Graph Decision audit schema is invalid")
    campaign, stored_recorder_id, stored_recorder_digest = _authority_metadata(connection)
    if (
        campaign != campaign_id
        or stored_recorder_id != recorder_id
        or stored_recorder_digest != recorder_digest
    ):
        raise GraphDecisionAuditError("Graph Decision audit Campaign or recorder identity differs")
    user_version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
    application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
    if (
        user_version != _SCHEMA_VERSION
        or application_id != _APPLICATION_ID
        or journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
        or foreign_keys is None
        or foreign_keys[0] != 1
        or trusted_schema is None
        or trusted_schema[0] != 0
    ):
        raise GraphDecisionAuditError(
            "Graph Decision audit version or connection policy is invalid"
        )
    placeholders = ", ".join("?" for _ in _TABLES)
    rows = connection.execute(
        f"""
        SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL
          AND type IN ('table', 'index', 'trigger')
          AND (name IN ({placeholders}) OR tbl_name IN ({placeholders}))
        """,
        (*sorted(_TABLES), *sorted(_TABLES)),
    ).fetchall()
    actual = {
        (cast(str, row["type"]), cast(str, row["name"])): _normalize_schema_sql(
            cast(str, row["sql"])
        )
        for row in rows
    }
    expected = {
        key: _normalize_schema_sql(statement) for key, statement in _SCHEMA_OBJECT_SQL.items()
    }
    if actual != expected:
        raise GraphDecisionAuditError("Graph Decision audit schema fingerprint is invalid")
    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if len(quick_check) != 1 or quick_check[0][0] != "ok":
        raise GraphDecisionAuditError("Graph Decision audit integrity check failed")


def _authority_metadata(connection: sqlite3.Connection) -> tuple[str, str, str]:
    metadata_rows = connection.execute(
        "SELECT key, value FROM graph_decision_audit_metadata ORDER BY key"
    ).fetchall()
    metadata = {cast(str, row["key"]): cast(str, row["value"]) for row in metadata_rows}
    if set(metadata) != {"campaign_id", "schema_digest", "schema_version"} or (
        metadata.get("schema_digest") != _SCHEMA_DIGEST
        or metadata.get("schema_version") != str(_SCHEMA_VERSION)
    ):
        raise GraphDecisionAuditError("Graph Decision audit metadata differs")
    recorder_rows = connection.execute(
        "SELECT singleton, recorder_id, recorder_digest FROM graph_decision_audit_recorder"
    ).fetchall()
    if len(recorder_rows) != 1 or recorder_rows[0]["singleton"] != 1:
        raise GraphDecisionAuditError("Graph Decision audit recorder is not pinned")
    return (
        metadata["campaign_id"],
        cast(str, recorder_rows[0]["recorder_id"]),
        cast(str, recorder_rows[0]["recorder_digest"]),
    )


def _application_tables(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    return {cast(str, row["name"]) for row in rows}


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    connection = _open_write_connection(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    identity = _file_identity(path)
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    if _file_identity(path) != identity:
        connection.close()
        raise GraphDecisionAuditError("Graph Decision audit store changed while opening")
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    try:
        connection.execute("BEGIN")
        yield connection
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _open_write_connection(path: Path) -> sqlite3.Connection:
    identity = _file_identity(path)
    connection = sqlite3.connect(
        path,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    if _file_identity(path) != identity:
        connection.close()
        raise GraphDecisionAuditError("Graph Decision audit store changed while opening")
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    return connection


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _prepare_store_file(path: Path) -> tuple[bool, int]:
    _prepare_private_parent(path.parent)
    _reject_sidecar_links(path)
    created = False
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise GraphDecisionAuditError(
                "Graph Decision audit path is not a regular file"
            ) from exc
    try:
        file_stat = os.fstat(descriptor)
        path_stat = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(file_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or file_stat.st_nlink != 1
            or (file_stat.st_dev, file_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino)
        ):
            raise GraphDecisionAuditError("Graph Decision audit path is not a private regular file")
        if os.name == "posix":
            if file_stat.st_uid != os.geteuid():
                raise GraphDecisionAuditError(
                    "Graph Decision audit store is not owned by this user"
                )
            os.fchmod(descriptor, 0o600)
        return created, file_stat.st_size
    finally:
        os.close(descriptor)


def _prepare_private_parent(directory: Path) -> None:
    current = Path(directory.anchor)
    for component in directory.parts[1:]:
        current /= component
        try:
            component_stat = current.lstat()
        except FileNotFoundError:
            with suppress(FileExistsError):
                current.mkdir(mode=0o700)
            component_stat = current.lstat()
        if (
            current.is_symlink()
            or current.is_junction()
            or not stat.S_ISDIR(component_stat.st_mode)
        ):
            raise GraphDecisionAuditError(
                "Graph Decision audit parent contains a non-directory component"
            )
    directory_stat = directory.lstat()
    if (
        directory.is_symlink()
        or directory.is_junction()
        or not stat.S_ISDIR(directory_stat.st_mode)
    ):
        raise GraphDecisionAuditError("Graph Decision audit parent is not a regular directory")
    if os.name == "posix":
        if directory_stat.st_uid != os.geteuid():
            raise GraphDecisionAuditError("Graph Decision audit parent is not owned by this user")
        if stat.S_IMODE(directory_stat.st_mode) & 0o077:
            raise GraphDecisionAuditError("Graph Decision audit parent must be owner-only")


def _reject_sidecar_links(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists() and not sidecar.is_symlink() and not sidecar.is_junction():
            continue
        sidecar_stat = sidecar.lstat()
        if (
            sidecar.is_symlink()
            or sidecar.is_junction()
            or not stat.S_ISREG(sidecar_stat.st_mode)
            or sidecar_stat.st_nlink != 1
        ):
            raise GraphDecisionAuditError(
                "Graph Decision audit sidecar is not a private regular file"
            )
        if os.name == "posix" and sidecar_stat.st_uid != os.geteuid():
            raise GraphDecisionAuditError("Graph Decision audit sidecar is not owned by this user")


def _file_identity(path: Path) -> tuple[tuple[int, int], tuple[int, int]]:
    parent_stat = path.parent.lstat()
    file_stat = path.lstat()
    if (
        path.parent.is_symlink()
        or path.parent.is_junction()
        or path.is_symlink()
        or path.is_junction()
        or not stat.S_ISDIR(parent_stat.st_mode)
        or not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_nlink != 1
    ):
        raise GraphDecisionAuditError("Graph Decision audit path identity is invalid")
    return (
        (parent_stat.st_dev, parent_stat.st_ino),
        (file_stat.st_dev, file_stat.st_ino),
    )


def _require_distinct_sqlite_paths(audit_path: Path, graph_path: Path) -> None:
    suffixes = ("-journal", "-wal", "-shm")
    audit_family = {audit_path, *(Path(f"{audit_path}{suffix}") for suffix in suffixes)}
    graph_family = {graph_path, *(Path(f"{graph_path}{suffix}") for suffix in suffixes)}
    if audit_family & graph_family:
        raise GraphDecisionAuditError(
            "Graph and Decision audit databases must use distinct SQLite path families"
        )
    if audit_path.exists() and graph_path.exists():
        try:
            if os.path.samefile(audit_path, graph_path):
                raise GraphDecisionAuditError(
                    "Graph and Decision audit databases must be distinct files"
                )
        except OSError as exc:
            raise GraphDecisionAuditError(
                "Graph and Decision audit database identity cannot be verified"
            ) from exc


def _require_campaign(campaign_id: str) -> None:
    if fullmatch(_CAMPAIGN_PATTERN, campaign_id) is None:
        raise ValueError("Graph Decision audit Campaign ID is invalid")


def _require_recorder(recorder_id: str, recorder_digest: str) -> None:
    if (
        fullmatch(_IDENTIFIER_PATTERN, recorder_id) is None
        or fullmatch(r"^[a-f0-9]{64}$", recorder_digest) is None
    ):
        raise ValueError("Graph Decision audit recorder identity is invalid")


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("Graph Decision audit timestamps must be UTC")
    return value.isoformat().replace("+00:00", "Z")


def _utc_now() -> datetime:
    return datetime.now(UTC)
