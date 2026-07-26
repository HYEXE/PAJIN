"""Durable single-Campaign SQLite adapters for the Canonical Graph stores."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from re import fullmatch
from typing import cast

from pydantic import ValidationError

from pajin.graph.admission import (
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphEventLogError,
)
from pajin.graph.authority import (
    ActionPermit,
    ActionPermitAuthorization,
    ActionPermitBudgetExceeded,
    ActionPermitConflict,
    ActionPermitError,
    ActionPermitStaleDecision,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
    action_permit_attempt_id,
    build_action_permit,
    validate_action_authority,
)
from pajin.graph.consistency import GraphDecision
from pajin.graph.models import (
    GraphNode,
    GraphNodeKind,
    canonical_graph_json,
    parse_graph_node,
)
from pajin.graph.projection import (
    GraphProjection,
    GraphProjectionAdvanceResult,
    GraphProjectionConflict,
    GraphProjectionError,
    GraphProjector,
    GraphSnapshot,
    GraphSnapshotError,
    GraphSnapshotRef,
)

_SCHEMA_VERSION = 2
_LEGACY_SCHEMA_VERSION = 1
_APPLICATION_ID = 0x50414752  # ASCII "PAGR"
_BUSY_TIMEOUT_MS = 30_000
_MAX_GRAPH_BYTES = 64 * 1024 * 1024
_LEGACY_TABLES = frozenset(
    {
        "graph_store_metadata",
        "graph_store_writers",
        "graph_events",
        "graph_nodes",
        "graph_projections",
        "graph_snapshots",
    }
)

_METADATA_TABLE_SQL = """
    CREATE TABLE graph_store_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT
    """
_WRITERS_TABLE_SQL = """
    CREATE TABLE graph_store_writers (
        writer_kind TEXT PRIMARY KEY NOT NULL
            CHECK (writer_kind IN ('event', 'snapshot')),
        writer_id TEXT NOT NULL,
        writer_digest TEXT NOT NULL CHECK (length(writer_digest) = 64)
    ) STRICT
    """
_EVENTS_TABLE_SQL = """
    CREATE TABLE graph_events (
        sequence INTEGER PRIMARY KEY NOT NULL CHECK (sequence >= 1),
        event_id TEXT NOT NULL UNIQUE,
        event_digest TEXT NOT NULL UNIQUE CHECK (length(event_digest) = 64),
        previous_event_digest TEXT CHECK (
            previous_event_digest IS NULL OR length(previous_event_digest) = 64
        ),
        proposal_id TEXT NOT NULL,
        proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
        decision TEXT NOT NULL CHECK (decision IN ('admitted', 'rejected')),
        event_json BLOB NOT NULL,
        UNIQUE (proposal_id, proposal_digest)
    ) STRICT
    """
_EVENTS_PROPOSAL_INDEX_SQL = (
    "CREATE INDEX graph_events_proposal_idx ON graph_events(proposal_id, sequence)"
)
_NODES_TABLE_SQL = """
    CREATE TABLE graph_nodes (
        node_id TEXT PRIMARY KEY NOT NULL,
        node_kind TEXT NOT NULL,
        admitted_sequence INTEGER NOT NULL REFERENCES graph_events(sequence),
        node_json BLOB NOT NULL
    ) STRICT
    """
_PROJECTIONS_TABLE_SQL = """
    CREATE TABLE graph_projections (
        revision INTEGER PRIMARY KEY NOT NULL CHECK (revision >= 0),
        event_log_head_digest TEXT CHECK (
            event_log_head_digest IS NULL OR length(event_log_head_digest) = 64
        ),
        projection_id TEXT NOT NULL UNIQUE,
        projection_digest TEXT NOT NULL UNIQUE CHECK (length(projection_digest) = 64),
        projection_json BLOB NOT NULL,
        CHECK (
            (revision = 0 AND event_log_head_digest IS NULL)
            OR (revision > 0 AND event_log_head_digest IS NOT NULL)
        )
    ) STRICT
    """
_SNAPSHOTS_TABLE_SQL = """
    CREATE TABLE graph_snapshots (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        snapshot_id TEXT NOT NULL UNIQUE,
        snapshot_digest TEXT NOT NULL UNIQUE CHECK (length(snapshot_digest) = 64),
        previous_snapshot_digest TEXT CHECK (
            previous_snapshot_digest IS NULL OR length(previous_snapshot_digest) = 64
        ),
        revision INTEGER NOT NULL REFERENCES graph_projections(revision),
        projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64),
        snapshot_json BLOB NOT NULL
    ) STRICT
    """
_ACTION_PERMIT_WRITERS_TABLE_SQL = """
    CREATE TABLE graph_action_permit_writers (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
        compiler_id TEXT NOT NULL,
        compiler_version TEXT NOT NULL,
        compiler_digest TEXT NOT NULL CHECK (length(compiler_digest) = 64)
    ) STRICT
    """
_ACTION_PERMITS_TABLE_SQL = """
    CREATE TABLE graph_action_permits (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        permit_id TEXT NOT NULL UNIQUE,
        permit_digest TEXT NOT NULL UNIQUE CHECK (length(permit_digest) = 64),
        dispatch_id TEXT NOT NULL UNIQUE,
        envelope_id TEXT NOT NULL,
        envelope_digest TEXT NOT NULL CHECK (length(envelope_digest) = 64),
        proposal_id TEXT NOT NULL UNIQUE,
        proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
        decision_id TEXT NOT NULL,
        decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 64),
        snapshot_id TEXT NOT NULL REFERENCES graph_snapshots(snapshot_id),
        snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
        revision INTEGER NOT NULL REFERENCES graph_projections(revision),
        event_log_head_digest TEXT CHECK (
            event_log_head_digest IS NULL OR length(event_log_head_digest) = 64
        ),
        projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64),
        request_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
        request_units INTEGER NOT NULL CHECK (request_units >= 1),
        cost_microusd INTEGER NOT NULL CHECK (cost_microusd >= 0),
        issued_at TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        permit_json BLOB NOT NULL,
        CHECK (
            (revision = 0 AND event_log_head_digest IS NULL)
            OR (revision > 0 AND event_log_head_digest IS NOT NULL)
        )
    ) STRICT
    """
_ACTION_PERMITS_ENVELOPE_INDEX_SQL = (
    "CREATE INDEX graph_action_permits_envelope_idx ON graph_action_permits(envelope_id, ordinal)"
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


_LEGACY_SCHEMA_OBJECT_SQL: dict[tuple[str, str], str] = {
    ("table", "graph_store_metadata"): _METADATA_TABLE_SQL,
    ("table", "graph_store_writers"): _WRITERS_TABLE_SQL,
    ("table", "graph_events"): _EVENTS_TABLE_SQL,
    ("index", "graph_events_proposal_idx"): _EVENTS_PROPOSAL_INDEX_SQL,
    ("table", "graph_nodes"): _NODES_TABLE_SQL,
    ("table", "graph_projections"): _PROJECTIONS_TABLE_SQL,
    ("table", "graph_snapshots"): _SNAPSHOTS_TABLE_SQL,
}
for _table, _identity in (
    ("graph_store_metadata", "key"),
    ("graph_store_writers", "writer_kind"),
    ("graph_events", "sequence"),
    ("graph_nodes", "node_id"),
    ("graph_projections", "revision"),
    ("graph_snapshots", "ordinal"),
):
    _LEGACY_SCHEMA_OBJECT_SQL.update(_immutable_triggers(_table, _identity))

_SCHEMA_OBJECT_SQL = dict(_LEGACY_SCHEMA_OBJECT_SQL)
_SCHEMA_OBJECT_SQL.update(
    {
        ("table", "graph_action_permit_writers"): _ACTION_PERMIT_WRITERS_TABLE_SQL,
        ("table", "graph_action_permits"): _ACTION_PERMITS_TABLE_SQL,
        (
            "index",
            "graph_action_permits_envelope_idx",
        ): _ACTION_PERMITS_ENVELOPE_INDEX_SQL,
    }
)
for _table, _identity in (
    ("graph_action_permit_writers", "singleton"),
    ("graph_action_permits", "ordinal"),
):
    _SCHEMA_OBJECT_SQL.update(_immutable_triggers(_table, _identity))

_TABLES = _LEGACY_TABLES | {
    "graph_action_permit_writers",
    "graph_action_permits",
}


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


_LEGACY_SCHEMA_DIGEST = _schema_digest(_LEGACY_SCHEMA_OBJECT_SQL)
_SCHEMA_DIGEST = _schema_digest(_SCHEMA_OBJECT_SQL)


class SQLiteGraphStoreError(RuntimeError):
    """Raised when the durable Graph Store cannot establish a trusted boundary."""


class SQLiteGraphStore:
    """Own one Campaign's durable Graph and final ActionPermit authority."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("SQLite Graph Store campaign ID is invalid")
        self.path = _absolute_path(path)
        self.campaign_id = campaign_id
        _initialize(self.path, campaign_id)
        self.event_log = SQLiteGraphEventLog(self.path, campaign_id=campaign_id)
        self.projection_store = SQLiteGraphProjectionStore(
            self.path,
            campaign_id=campaign_id,
        )
        self.snapshot_store = SQLiteGraphSnapshotStore(
            self.path,
            campaign_id=campaign_id,
        )
        self.permit_store = SQLiteGraphActionPermitStore(
            self.path,
            campaign_id=campaign_id,
        )


class SQLiteGraphEventLog:
    """SQLite-backed append-only Graph Event Log with a pinned writer identity."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id
        self._writer: object | None = None
        self._writer_identity: tuple[str, str] | None = None
        self._lock = threading.RLock()

    def claim_writer(self, authority_id: str, authority_digest: str) -> object:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", authority_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", authority_digest) is None
        ):
            raise GraphEventLogError("Canonical Event Log writer identity is invalid")
        with self._lock:
            if self._writer is not None:
                raise GraphEventLogError("Canonical Event Log writer is already claimed")
            try:
                with _write_transaction(self.path) as connection:
                    _pin_writer(
                        connection,
                        writer_kind="event",
                        writer_id=authority_id,
                        writer_digest=authority_digest,
                    )
            except sqlite3.Error as exc:
                raise GraphEventLogError("Graph Event Log writer claim failed") from exc
            writer = object()
            self._writer = writer
            self._writer_identity = (authority_id, authority_digest)
            return writer

    def event_for_attempt(
        self,
        proposal_id: str,
        proposal_digest: str,
    ) -> GraphAdmissionEvent | None:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM graph_events
                    WHERE proposal_id = ? AND proposal_digest = ?
                    """,
                    (proposal_id, proposal_digest),
                ).fetchone()
                return _event_from_row(row, campaign_id=self._campaign_id) if row else None
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log attempt lookup failed") from exc

    def first_proposal_digest(self, proposal_id: str) -> str | None:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT proposal_digest FROM graph_events
                    WHERE proposal_id = ?
                    ORDER BY sequence
                    LIMIT 1
                    """,
                    (proposal_id,),
                ).fetchone()
                return cast(str, row["proposal_digest"]) if row else None
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log proposal lookup failed") from exc

    def next_position(self) -> tuple[int, str | None]:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT sequence, event_digest FROM graph_events
                    ORDER BY sequence DESC
                    LIMIT 1
                    """
                ).fetchone()
                if row is None:
                    return 1, None
                return cast(int, row["sequence"]) + 1, cast(str, row["event_digest"])
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log head lookup failed") from exc

    def admitted_node(self, node_id: str) -> GraphNode | None:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    "SELECT * FROM graph_nodes WHERE node_id = ?",
                    (node_id,),
                ).fetchone()
                return _node_from_row(row, campaign_id=self._campaign_id) if row else None
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log node lookup failed") from exc

    def append(
        self,
        event: GraphAdmissionEvent,
        *,
        writer: object,
    ) -> GraphAdmissionEvent:
        with self._lock:
            if writer is not self._writer or self._writer_identity is None:
                raise GraphEventLogError("Canonical Event Log write authority is invalid")
            stored = _canonical_event(event)
            if stored.campaign_id != self._campaign_id:
                raise GraphEventLogError("Graph event belongs to another Campaign")
            if self._writer_identity != (stored.authority_id, stored.authority_digest):
                raise GraphEventLogError("Graph event authority differs from the claimed writer")
            try:
                with _write_transaction(self.path) as connection:
                    if _writer_identity(connection, "event") != self._writer_identity:
                        raise GraphEventLogError(
                            "Graph event authority differs from durable writer identity"
                        )
                    self._require_next_event(connection, stored)
                    connection.execute(
                        """
                        INSERT INTO graph_events (
                            sequence, event_id, event_digest, previous_event_digest,
                            proposal_id, proposal_digest, decision, event_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            stored.sequence,
                            stored.event_id,
                            stored.event_digest,
                            stored.previous_event_digest,
                            stored.proposal_id,
                            stored.proposal_digest,
                            stored.decision.value,
                            sqlite3.Binary(_event_bytes(stored)),
                        ),
                    )
                    if stored.decision is GraphAdmissionDecision.ADMITTED:
                        self._record_nodes(connection, stored)
            except sqlite3.IntegrityError as exc:
                raise GraphEventLogError("Graph event append conflicted") from exc
            except sqlite3.Error as exc:
                raise GraphEventLogError("Graph event append failed") from exc
            return _canonical_event(stored)

    def events(self) -> tuple[GraphAdmissionEvent, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute("SELECT * FROM graph_events ORDER BY sequence").fetchall()
                events = tuple(_event_from_row(row, campaign_id=self._campaign_id) for row in rows)
                _require_event_chain(events, campaign_id=self._campaign_id)
                return events
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log read failed") from exc

    def _require_next_event(
        self,
        connection: sqlite3.Connection,
        event: GraphAdmissionEvent,
    ) -> None:
        row = connection.execute(
            """
            SELECT sequence, event_digest FROM graph_events
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()
        expected_sequence = cast(int, row["sequence"]) + 1 if row else 1
        expected_previous = cast(str, row["event_digest"]) if row else None
        if event.sequence != expected_sequence or event.previous_event_digest != expected_previous:
            raise GraphEventLogError("Graph event sequence or predecessor is stale")
        duplicate = connection.execute(
            """
            SELECT 1 FROM graph_events
            WHERE event_id = ? OR (proposal_id = ? AND proposal_digest = ?)
            LIMIT 1
            """,
            (event.event_id, event.proposal_id, event.proposal_digest),
        ).fetchone()
        if duplicate is not None:
            raise GraphEventLogError("Graph semantic attempt is already recorded")

        proposed = {
            node.node_id: (node.campaign_id, GraphNodeKind(node.kind))
            for node in event.admitted_nodes
        }
        for edge in event.admitted_edges:
            for reference in (edge.source, edge.target):
                identity = proposed.get(reference.node_id)
                if identity is None:
                    row = connection.execute(
                        "SELECT * FROM graph_nodes WHERE node_id = ?",
                        (reference.node_id,),
                    ).fetchone()
                    if row is None:
                        raise GraphEventLogError("Graph event contains a dangling edge")
                    existing = _node_from_row(row, campaign_id=self._campaign_id)
                    identity = (existing.campaign_id, GraphNodeKind(existing.kind))
                if identity != (reference.campaign_id, reference.kind):
                    raise GraphEventLogError("Graph event edge identity is inconsistent")

    def _record_nodes(
        self,
        connection: sqlite3.Connection,
        event: GraphAdmissionEvent,
    ) -> None:
        for node in event.admitted_nodes:
            existing_row = connection.execute(
                "SELECT * FROM graph_nodes WHERE node_id = ?",
                (node.node_id,),
            ).fetchone()
            if existing_row is not None:
                if _node_from_row(existing_row, campaign_id=self._campaign_id) != node:
                    raise GraphEventLogError("canonical Graph node identity has equivocated")
                continue
            connection.execute(
                """
                INSERT INTO graph_nodes (
                    node_id, node_kind, admitted_sequence, node_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    node.node_id,
                    GraphNodeKind(node.kind).value,
                    event.sequence,
                    sqlite3.Binary(_node_bytes(node)),
                ),
            )


class SQLiteGraphProjectionStore:
    """Append-only projection history with cross-process revision/head CAS."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id

    def current(self) -> GraphProjection:
        try:
            with _readonly_connection(self.path) as connection:
                return _current_projection(connection, campaign_id=self._campaign_id)
        except sqlite3.Error as exc:
            raise GraphProjectionError("Graph projection read failed") from exc

    def compare_and_advance(
        self,
        events: Iterable[GraphAdmissionEvent],
        *,
        expected_revision: int,
        expected_head_digest: str | None,
    ) -> GraphProjectionAdvanceResult:
        canonical_events = tuple(_canonical_event(event) for event in events)
        candidate = GraphProjector.project(
            campaign_id=self._campaign_id,
            events=canonical_events,
        )
        try:
            with _write_transaction(self.path) as connection:
                authoritative_events = _events_from_connection(
                    connection,
                    campaign_id=self._campaign_id,
                )
                if (
                    len(canonical_events) > len(authoritative_events)
                    or canonical_events != authoritative_events[: len(canonical_events)]
                ):
                    raise GraphProjectionConflict(
                        "Graph projection input differs from the durable Event Log prefix"
                    )
                current = _current_projection(
                    connection,
                    campaign_id=self._campaign_id,
                )
                if (
                    expected_revision != current.revision
                    or expected_head_digest != current.event_log_head_digest
                ):
                    raise GraphProjectionConflict(
                        "Graph projection revision compare-and-set failed"
                    )
                if candidate.revision < current.revision:
                    raise GraphProjectionConflict("Graph projection rollback was rejected")
                prefix = GraphProjector.project(
                    campaign_id=self._campaign_id,
                    events=canonical_events[: current.revision],
                )
                if prefix.projection_digest != current.projection_digest:
                    raise GraphProjectionConflict(
                        "Graph Event Log prefix differs from current projection"
                    )
                applied = candidate.revision - current.revision
                if applied:
                    connection.execute(
                        """
                        INSERT INTO graph_projections (
                            revision, event_log_head_digest, projection_id,
                            projection_digest, projection_json
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            candidate.revision,
                            candidate.event_log_head_digest,
                            candidate.projection_id,
                            candidate.projection_digest,
                            sqlite3.Binary(_projection_bytes(candidate)),
                        ),
                    )
                observed = (
                    _current_projection(connection, campaign_id=self._campaign_id)
                    if applied
                    else current
                )
                return GraphProjectionAdvanceResult(
                    projection=observed,
                    previousRevision=current.revision,
                    appliedEventCount=applied,
                    idempotent=not applied,
                )
        except sqlite3.IntegrityError as exc:
            raise GraphProjectionConflict("Graph projection publication conflicted") from exc
        except sqlite3.Error as exc:
            raise GraphProjectionError("Graph projection publication failed") from exc


class SQLiteGraphSnapshotStore:
    """SQLite-backed immutable Snapshot chain with exact-reference resolution."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id
        self._writer: object | None = None
        self._writer_identity: tuple[str, str] | None = None
        self._lock = threading.RLock()

    def claim_writer(self, creator_id: str, creator_digest: str) -> object:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", creator_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", creator_digest) is None
        ):
            raise GraphSnapshotError("Graph Snapshot writer identity is invalid")
        with self._lock:
            if self._writer is not None:
                raise GraphSnapshotError("Graph Snapshot writer is already claimed")
            try:
                with _write_transaction(self.path) as connection:
                    _pin_writer(
                        connection,
                        writer_kind="snapshot",
                        writer_id=creator_id,
                        writer_digest=creator_digest,
                    )
            except sqlite3.Error as exc:
                raise GraphSnapshotError("Graph Snapshot writer claim failed") from exc
            writer = object()
            self._writer = writer
            self._writer_identity = (creator_id, creator_digest)
            return writer

    def head_digest(self) -> str | None:
        try:
            with _readonly_connection(self.path) as connection:
                return _snapshot_head_digest(connection)
        except sqlite3.Error as exc:
            raise GraphSnapshotError("Graph Snapshot head lookup failed") from exc

    def append(self, snapshot: GraphSnapshot, *, writer: object) -> GraphSnapshot:
        with self._lock:
            if writer is not self._writer or self._writer_identity is None:
                raise GraphSnapshotError("Graph Snapshot write authority is invalid")
            stored = _canonical_snapshot(snapshot)
            if stored.campaign_id != self._campaign_id:
                raise GraphSnapshotError("Graph Snapshot belongs to another Campaign")
            if self._writer_identity != (stored.creator_id, stored.creator_digest):
                raise GraphSnapshotError("Graph Snapshot creator differs from claimed writer")
            try:
                with _write_transaction(self.path) as connection:
                    if _writer_identity(connection, "snapshot") != self._writer_identity:
                        raise GraphSnapshotError(
                            "Graph Snapshot creator differs from durable writer identity"
                        )
                    existing = connection.execute(
                        "SELECT * FROM graph_snapshots WHERE snapshot_id = ?",
                        (stored.snapshot_id,),
                    ).fetchone()
                    if existing is not None:
                        resolved = _snapshot_from_row(
                            existing,
                            campaign_id=self._campaign_id,
                        )
                        if resolved != stored:
                            raise GraphSnapshotError("Graph Snapshot identity has equivocated")
                        return resolved
                    if stored.previous_snapshot_digest != _snapshot_head_digest(connection):
                        raise GraphSnapshotError("Graph Snapshot predecessor is stale")
                    projection = connection.execute(
                        """
                        SELECT * FROM graph_projections
                        WHERE revision = ? AND projection_digest = ?
                        """,
                        (stored.revision, stored.projection_digest),
                    ).fetchone()
                    if (
                        projection is None
                        or _projection_from_row(
                            projection,
                            campaign_id=self._campaign_id,
                        )
                        != stored.projection
                    ):
                        raise GraphSnapshotError(
                            "Graph Snapshot projection is not durably published"
                        )
                    ordinal_row = connection.execute(
                        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal FROM graph_snapshots"
                    ).fetchone()
                    assert ordinal_row is not None
                    connection.execute(
                        """
                        INSERT INTO graph_snapshots (
                            ordinal, snapshot_id, snapshot_digest,
                            previous_snapshot_digest, revision,
                            projection_digest, snapshot_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cast(int, ordinal_row["next_ordinal"]),
                            stored.snapshot_id,
                            stored.snapshot_digest,
                            stored.previous_snapshot_digest,
                            stored.revision,
                            stored.projection_digest,
                            sqlite3.Binary(_snapshot_bytes(stored)),
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise GraphSnapshotError("Graph Snapshot append conflicted") from exc
            except sqlite3.Error as exc:
                raise GraphSnapshotError("Graph Snapshot append failed") from exc
            return _canonical_snapshot(stored)

    def resolve(self, reference: GraphSnapshotRef) -> GraphSnapshot:
        try:
            reference = GraphSnapshotRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except ValidationError as exc:
            raise GraphSnapshotError("Graph Snapshot reference is invalid") from exc
        if reference.campaign_id != self._campaign_id:
            raise GraphSnapshotError("Graph Snapshot reference belongs to another Campaign")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    "SELECT * FROM graph_snapshots WHERE snapshot_id = ?",
                    (reference.snapshot_id,),
                ).fetchone()
                if row is None:
                    raise GraphSnapshotError("Graph Snapshot was not found")
                resolved = _snapshot_from_row(row, campaign_id=self._campaign_id)
        except sqlite3.Error as exc:
            raise GraphSnapshotError("Graph Snapshot resolution failed") from exc
        if (
            resolved.snapshot_digest,
            resolved.campaign_id,
            resolved.graph_schema_version,
            resolved.revision,
            resolved.event_log_head_digest,
            resolved.projection_digest,
        ) != (
            reference.snapshot_digest,
            reference.campaign_id,
            reference.graph_schema_version,
            reference.revision,
            reference.event_log_head_digest,
            reference.projection_digest,
        ):
            raise GraphSnapshotError("Graph Snapshot reference differs from stored authority")
        return resolved

    def snapshots(self) -> tuple[GraphSnapshot, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_snapshots ORDER BY ordinal"
                ).fetchall()
                snapshots = tuple(
                    _snapshot_from_row(row, campaign_id=self._campaign_id) for row in rows
                )
        except sqlite3.Error as exc:
            raise GraphSnapshotError("Graph Snapshot chain read failed") from exc
        previous: str | None = None
        for snapshot in snapshots:
            if snapshot.previous_snapshot_digest != previous:
                raise GraphSnapshotError("Graph Snapshot chain is not contiguous")
            previous = snapshot.snapshot_digest
        return snapshots


class SQLiteGraphActionPermitStore:
    """Final revision check plus consumed-on-issuance Permit transaction."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id
        self._writer: object | None = None
        self._writer_identity: tuple[str, str, str] | None = None
        self._lock = threading.RLock()

    def claim_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
    ) -> object:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_id) is None
            or fullmatch(
                r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
                compiler_version,
            )
            is None
            or fullmatch(r"^[a-f0-9]{64}$", compiler_digest) is None
        ):
            raise ActionPermitError("ActionPermit compiler identity is invalid")
        with self._lock:
            if self._writer is not None:
                raise ActionPermitError("ActionPermit compiler writer is already claimed")
            identity = (compiler_id, compiler_version, compiler_digest)
            try:
                with _write_transaction(self.path) as connection:
                    _pin_action_permit_writer(connection, identity)
            except sqlite3.Error as exc:
                raise ActionPermitError("ActionPermit compiler claim failed") from exc
            writer = object()
            self._writer = writer
            self._writer_identity = identity
            return writer

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ActionPermitAuthorization:
        with self._lock:
            if writer is not self._writer or self._writer_identity is None:
                raise ActionPermitError("ActionPermit compiler write authority is invalid")
            envelope = _canonical_mission_envelope(envelope)
            proposal = _canonical_action_proposal(proposal)
            decision = _canonical_graph_decision(decision)
            capability = _canonical_registered_capability(capability)
            if (
                envelope.campaign_id != self._campaign_id
                or proposal.campaign_id != self._campaign_id
                or decision.campaign_id != self._campaign_id
            ):
                raise ActionPermitError("ActionPermit input belongs to another Campaign")
            if self._writer_identity != (
                envelope.compiler_id,
                envelope.compiler_version,
                envelope.compiler_digest,
            ):
                raise ActionPermitError("ActionPermit compiler differs from durable writer")
            attempt_id = action_permit_attempt_id(envelope, proposal, decision)
            try:
                with _write_transaction(self.path) as connection:
                    if _action_permit_writer_identity(connection) != self._writer_identity:
                        raise ActionPermitError("ActionPermit compiler differs from durable writer")
                    existing_row = connection.execute(
                        "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    if existing_row is not None:
                        existing = _action_permit_from_row(
                            existing_row,
                            campaign_id=self._campaign_id,
                        )
                        _require_exact_action_permit_retry(
                            existing,
                            envelope=envelope,
                            proposal=proposal,
                            decision=decision,
                            capability=capability,
                        )
                        return ActionPermitAuthorization(
                            permit=existing,
                            newlyConsumed=False,
                        )
                    collision = connection.execute(
                        """
                        SELECT permit_id FROM graph_action_permits
                        WHERE proposal_id = ? OR request_id = ?
                        LIMIT 1
                        """,
                        (proposal.proposal_id, proposal.request_id),
                    ).fetchone()
                    if collision is not None:
                        raise ActionPermitConflict(
                            "ActionProposal or request identity is already consumed"
                        )
                    validate_action_authority(
                        envelope,
                        proposal,
                        decision,
                        capability,
                        evaluated_at=evaluated_at,
                    )
                    _require_latest_action_snapshot(
                        connection,
                        campaign_id=self._campaign_id,
                        proposal=proposal,
                        decision=decision,
                    )
                    _require_action_budget(
                        connection,
                        envelope=envelope,
                        proposal=proposal,
                        evaluated_at=evaluated_at,
                    )
                    permit = build_action_permit(
                        envelope,
                        proposal,
                        decision,
                        evaluated_at=evaluated_at,
                        permit_ttl=permit_ttl,
                    )
                    if permit.permit_id != attempt_id:
                        raise ActionPermitError(
                            "ActionPermit deterministic attempt identity differs"
                        )
                    ordinal_row = connection.execute(
                        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal "
                        "FROM graph_action_permits"
                    ).fetchone()
                    assert ordinal_row is not None
                    connection.execute(
                        """
                        INSERT INTO graph_action_permits (
                            ordinal, permit_id, permit_digest, dispatch_id,
                            envelope_id, envelope_digest, proposal_id,
                            proposal_digest, decision_id, decision_digest,
                            snapshot_id, snapshot_digest, revision,
                            event_log_head_digest, projection_digest,
                            request_id, request_digest, request_units,
                            cost_microusd, issued_at, consumed_at, expires_at,
                            permit_json
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            cast(int, ordinal_row["next_ordinal"]),
                            permit.permit_id,
                            permit.permit_digest,
                            permit.dispatch_id,
                            permit.envelope_id,
                            permit.envelope_digest,
                            permit.proposal_id,
                            permit.proposal_digest,
                            permit.decision_id,
                            permit.decision_digest,
                            permit.snapshot.snapshot_id,
                            permit.snapshot.snapshot_digest,
                            permit.snapshot.revision,
                            permit.snapshot.event_log_head_digest,
                            permit.snapshot.projection_digest,
                            permit.request_id,
                            permit.request_digest,
                            permit.reservation.request_units,
                            permit.reservation.cost_microusd,
                            permit.issued_at.isoformat(),
                            permit.consumed_at.isoformat(),
                            permit.expires_at.isoformat(),
                            sqlite3.Binary(_action_permit_bytes(permit)),
                        ),
                    )
                    return ActionPermitAuthorization(
                        permit=permit,
                        newlyConsumed=True,
                    )
            except sqlite3.IntegrityError as exc:
                raise ActionPermitConflict(
                    "ActionPermit durable compare-and-set conflicted"
                ) from exc
            except sqlite3.Error as exc:
                raise ActionPermitError("ActionPermit authority transaction failed") from exc

    def permit(self, permit_id: str) -> ActionPermit | None:
        if fullmatch(r"^action-permit_[a-f0-9]{64}$", permit_id) is None:
            raise ActionPermitError("ActionPermit ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                return (
                    _action_permit_from_row(row, campaign_id=self._campaign_id)
                    if row is not None
                    else None
                )
        except sqlite3.Error as exc:
            raise ActionPermitError("ActionPermit lookup failed") from exc

    def permits(self) -> tuple[ActionPermit, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_action_permits ORDER BY ordinal"
                ).fetchall()
                return tuple(
                    _action_permit_from_row(row, campaign_id=self._campaign_id) for row in rows
                )
        except sqlite3.Error as exc:
            raise ActionPermitError("ActionPermit ledger read failed") from exc


def _absolute_path(path: Path) -> Path:
    """Normalize lexical components without following a symlink leaf."""

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
            raise SQLiteGraphStoreError("SQLite Graph Store path is not a regular file") from exc
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
            raise SQLiteGraphStoreError("SQLite Graph Store path is not a private regular file")
        if os.name == "posix":
            if file_stat.st_uid != os.geteuid():
                raise SQLiteGraphStoreError("SQLite Graph Store is not owned by this user")
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
            raise SQLiteGraphStoreError(
                "SQLite Graph Store parent path contains a non-directory component"
            )
    try:
        directory_stat = directory.lstat()
    except OSError as exc:
        raise SQLiteGraphStoreError("SQLite Graph Store parent changed during validation") from exc
    if (
        directory.is_symlink()
        or directory.is_junction()
        or not stat.S_ISDIR(directory_stat.st_mode)
    ):
        raise SQLiteGraphStoreError("SQLite Graph Store parent is not a regular directory")
    if os.name == "posix":
        if directory_stat.st_uid != os.geteuid():
            raise SQLiteGraphStoreError("SQLite Graph Store parent is not owned by this user")
        if stat.S_IMODE(directory_stat.st_mode) & 0o077:
            raise SQLiteGraphStoreError("SQLite Graph Store parent must be owner-only")


def _reject_sidecar_links(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists() and not sidecar.is_symlink() and not sidecar.is_junction():
            continue
        try:
            sidecar_stat = sidecar.lstat()
        except OSError as exc:
            raise SQLiteGraphStoreError(
                "SQLite Graph Store sidecar changed during validation"
            ) from exc
        if (
            sidecar.is_symlink()
            or sidecar.is_junction()
            or not stat.S_ISREG(sidecar_stat.st_mode)
            or sidecar_stat.st_nlink != 1
        ):
            raise SQLiteGraphStoreError("SQLite Graph Store sidecar is not a private regular file")
        if os.name == "posix" and sidecar_stat.st_uid != os.geteuid():
            raise SQLiteGraphStoreError("SQLite Graph Store sidecar is not owned by this user")


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
        raise SQLiteGraphStoreError("SQLite Graph Store path identity is invalid")
    return (
        (parent_stat.st_dev, parent_stat.st_ino),
        (file_stat.st_dev, file_stat.st_ino),
    )


def _initialize(path: Path, campaign_id: str) -> None:
    created, file_size = _prepare_store_file(path)
    initialize_empty_file = created or file_size == 0
    try:
        connection = _open_write_connection(path)
        try:
            if initialize_empty_file:
                journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
                if journal_mode is None or str(journal_mode[0]).lower() != "delete":
                    raise SQLiteGraphStoreError("SQLite Graph Store requires DELETE journal mode")
            connection.execute("BEGIN IMMEDIATE")
            tables = _application_tables(connection)
            if not tables:
                if not initialize_empty_file:
                    raise SQLiteGraphStoreError("existing SQLite Graph Store has no trusted schema")
                for statement in _SCHEMA_OBJECT_SQL.values():
                    connection.execute(statement)
                connection.executemany(
                    "INSERT INTO graph_store_metadata (key, value) VALUES (?, ?)",
                    (
                        ("schema_version", str(_SCHEMA_VERSION)),
                        ("schema_digest", _SCHEMA_DIGEST),
                        ("campaign_id", campaign_id),
                    ),
                )
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                genesis = GraphProjector.project(campaign_id=campaign_id, events=())
                connection.execute(
                    """
                    INSERT INTO graph_projections (
                        revision, event_log_head_digest, projection_id,
                        projection_digest, projection_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        genesis.revision,
                        genesis.event_log_head_digest,
                        genesis.projection_id,
                        genesis.projection_digest,
                        sqlite3.Binary(_projection_bytes(genesis)),
                    ),
                )
            elif tables == _LEGACY_TABLES:
                _validate_schema_contract(
                    connection,
                    campaign_id=campaign_id,
                    tables=_LEGACY_TABLES,
                    objects=_LEGACY_SCHEMA_OBJECT_SQL,
                    version=_LEGACY_SCHEMA_VERSION,
                    digest=_LEGACY_SCHEMA_DIGEST,
                )
                _migrate_legacy_schema(connection)
            _validate_schema(connection, campaign_id=campaign_id)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SQLiteGraphStoreError("SQLite Graph Store initialization failed") from exc


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
        raise SQLiteGraphStoreError("SQLite Graph Store changed while it was opened")
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
        raise SQLiteGraphStoreError("SQLite Graph Store changed while it was opened")
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA trusted_schema = OFF")
    return connection


def _application_tables(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    return {cast(str, row["name"]) for row in rows}


def _validate_schema(connection: sqlite3.Connection, *, campaign_id: str) -> None:
    _validate_schema_contract(
        connection,
        campaign_id=campaign_id,
        tables=_TABLES,
        objects=_SCHEMA_OBJECT_SQL,
        version=_SCHEMA_VERSION,
        digest=_SCHEMA_DIGEST,
    )


def _validate_schema_contract(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    tables: frozenset[str],
    objects: dict[tuple[str, str], str],
    version: int,
    digest: str,
) -> None:
    if _application_tables(connection) != tables:
        raise SQLiteGraphStoreError("SQLite Graph Store schema is invalid")
    metadata_rows = connection.execute(
        "SELECT key, value FROM graph_store_metadata ORDER BY key"
    ).fetchall()
    metadata = {cast(str, row["key"]): cast(str, row["value"]) for row in metadata_rows}
    if metadata != {
        "campaign_id": campaign_id,
        "schema_digest": digest,
        "schema_version": str(version),
    }:
        raise SQLiteGraphStoreError("SQLite Graph Store metadata or Campaign identity differs")
    user_version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
    application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
    if (
        user_version != version
        or application_id != _APPLICATION_ID
        or journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
        or foreign_keys is None
        or foreign_keys[0] != 1
        or trusted_schema is None
        or trusted_schema[0] != 0
    ):
        raise SQLiteGraphStoreError("SQLite Graph Store version or connection policy is invalid")
    placeholders = ", ".join("?" for _ in tables)
    rows = connection.execute(
        f"""
        SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL
          AND type IN ('table', 'index', 'trigger')
          AND (name IN ({placeholders}) OR tbl_name IN ({placeholders}))
        """,
        (*sorted(tables), *sorted(tables)),
    ).fetchall()
    actual = {
        (cast(str, row["type"]), cast(str, row["name"])): _normalize_schema_sql(
            cast(str, row["sql"])
        )
        for row in rows
    }
    expected = {key: _normalize_schema_sql(statement) for key, statement in objects.items()}
    if actual != expected:
        raise SQLiteGraphStoreError("SQLite Graph Store schema fingerprint is invalid")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SQLiteGraphStoreError("SQLite Graph Store contains orphaned records")
    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if len(quick_check) != 1 or quick_check[0][0] != "ok":
        raise SQLiteGraphStoreError("SQLite Graph Store integrity check failed")


def _migrate_legacy_schema(connection: sqlite3.Connection) -> None:
    """Upgrade the exact append-only v1 store to the v2 Permit authority schema."""

    new_keys = _SCHEMA_OBJECT_SQL.keys() - _LEGACY_SCHEMA_OBJECT_SQL.keys()
    for key, statement in _SCHEMA_OBJECT_SQL.items():
        if key in new_keys:
            connection.execute(statement)
    metadata_triggers = _immutable_triggers("graph_store_metadata", "key")
    for _, trigger_name in metadata_triggers:
        connection.execute(f"DROP TRIGGER {trigger_name}")
    connection.execute(
        "UPDATE graph_store_metadata SET value = ? WHERE key = 'schema_version'",
        (str(_SCHEMA_VERSION),),
    )
    connection.execute(
        "UPDATE graph_store_metadata SET value = ? WHERE key = 'schema_digest'",
        (_SCHEMA_DIGEST,),
    )
    for statement in metadata_triggers.values():
        connection.execute(statement)
    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")


def _pin_writer(
    connection: sqlite3.Connection,
    *,
    writer_kind: str,
    writer_id: str,
    writer_digest: str,
) -> None:
    existing = _writer_identity(connection, writer_kind)
    if existing is None:
        connection.execute(
            """
            INSERT INTO graph_store_writers (
                writer_kind, writer_id, writer_digest
            ) VALUES (?, ?, ?)
            """,
            (writer_kind, writer_id, writer_digest),
        )
        return
    if existing != (writer_id, writer_digest):
        raise SQLiteGraphStoreError(
            f"SQLite Graph Store {writer_kind} writer identity is already pinned"
        )


def _writer_identity(
    connection: sqlite3.Connection,
    writer_kind: str,
) -> tuple[str, str] | None:
    row = connection.execute(
        """
        SELECT writer_id, writer_digest FROM graph_store_writers
        WHERE writer_kind = ?
        """,
        (writer_kind,),
    ).fetchone()
    if row is None:
        return None
    return cast(str, row["writer_id"]), cast(str, row["writer_digest"])


def _pin_action_permit_writer(
    connection: sqlite3.Connection,
    identity: tuple[str, str, str],
) -> None:
    existing = _action_permit_writer_identity(connection)
    if existing is None:
        connection.execute(
            """
            INSERT INTO graph_action_permit_writers (
                singleton, compiler_id, compiler_version, compiler_digest
            ) VALUES (1, ?, ?, ?)
            """,
            identity,
        )
        return
    if existing != identity:
        raise SQLiteGraphStoreError(
            "SQLite Graph Store ActionPermit compiler identity is already pinned"
        )


def _action_permit_writer_identity(
    connection: sqlite3.Connection,
) -> tuple[str, str, str] | None:
    row = connection.execute(
        """
        SELECT compiler_id, compiler_version, compiler_digest
        FROM graph_action_permit_writers
        WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        return None
    return (
        cast(str, row["compiler_id"]),
        cast(str, row["compiler_version"]),
        cast(str, row["compiler_digest"]),
    )


def _current_projection(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
) -> GraphProjection:
    row = connection.execute(
        "SELECT * FROM graph_projections ORDER BY revision DESC LIMIT 1"
    ).fetchone()
    if row is None:
        raise GraphProjectionError("SQLite Graph Store has no genesis projection")
    return _projection_from_row(row, campaign_id=campaign_id)


def _events_from_connection(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
) -> tuple[GraphAdmissionEvent, ...]:
    rows = connection.execute("SELECT * FROM graph_events ORDER BY sequence").fetchall()
    events = tuple(_event_from_row(row, campaign_id=campaign_id) for row in rows)
    _require_event_chain(events, campaign_id=campaign_id)
    return events


def _snapshot_head_digest(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT snapshot_digest FROM graph_snapshots ORDER BY ordinal DESC LIMIT 1"
    ).fetchone()
    return cast(str, row["snapshot_digest"]) if row else None


def _require_latest_action_snapshot(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    proposal: ActionProposal,
    decision: GraphDecision,
) -> None:
    row = connection.execute(
        "SELECT * FROM graph_snapshots WHERE snapshot_id = ?",
        (decision.snapshot.snapshot_id,),
    ).fetchone()
    if row is None:
        raise ActionPermitError("ActionPermit Graph Snapshot was not found")
    snapshot = _snapshot_from_row(row, campaign_id=campaign_id)
    if (
        snapshot.snapshot_id != decision.snapshot.snapshot_id
        or snapshot.snapshot_digest != decision.snapshot.snapshot_digest
        or snapshot.campaign_id != decision.snapshot.campaign_id
        or snapshot.graph_schema_version != decision.snapshot.graph_schema_version
        or snapshot.revision != decision.snapshot.revision
        or snapshot.event_log_head_digest != decision.snapshot.event_log_head_digest
        or snapshot.projection_digest != decision.snapshot.projection_digest
        or proposal.snapshot != decision.snapshot
    ):
        raise ActionPermitError("ActionPermit Graph Snapshot binding differs")
    if decision.created_at < snapshot.created_at or proposal.created_at < decision.created_at:
        raise ActionPermitError("Action authority timeline predates its Graph Snapshot")
    current = _current_projection(connection, campaign_id=campaign_id)
    events = _events_from_connection(connection, campaign_id=campaign_id)
    latest = GraphProjector.project(campaign_id=campaign_id, events=events)
    if current.projection_digest != latest.projection_digest:
        raise ActionPermitStaleDecision(
            "Graph projection recovery is required before ActionPermit dispatch"
        )
    observed = (
        snapshot.revision,
        snapshot.event_log_head_digest,
        snapshot.projection_id,
        snapshot.projection_digest,
    )
    expected = (
        latest.revision,
        latest.event_log_head_digest,
        latest.projection_id,
        latest.projection_digest,
    )
    if observed != expected:
        raise ActionPermitStaleDecision("Graph changed before the ActionPermit dispatch claim")


def _require_action_budget(
    connection: sqlite3.Connection,
    *,
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    evaluated_at: datetime,
) -> None:
    rows = connection.execute(
        """
        SELECT * FROM graph_action_permits
        WHERE envelope_id = ?
        ORDER BY ordinal
        """,
        (envelope.envelope_id,),
    ).fetchall()
    permits = tuple(_action_permit_from_row(row, campaign_id=envelope.campaign_id) for row in rows)
    if any(permit.envelope_digest != envelope.envelope_digest for permit in permits):
        raise ActionPermitConflict("MissionEnvelope identity has equivocated")
    used_calls = len(permits)
    used_units = sum(permit.reservation.request_units for permit in permits)
    used_cost = sum(permit.reservation.cost_microusd for permit in permits)
    reservation = proposal.reservation
    if (
        used_calls + reservation.tool_calls > envelope.budget.tool_call_limit
        or used_units + reservation.request_units > envelope.budget.request_unit_limit
        or used_cost + reservation.cost_microusd > envelope.budget.cost_limit_microusd
    ):
        raise ActionPermitBudgetExceeded("MissionEnvelope durable ActionPermit budget is exhausted")
    window_seconds = envelope.budget.rolling_window_seconds
    window_limit = envelope.budget.rolling_request_unit_limit
    if window_seconds is None or window_limit is None:
        return
    window_start = evaluated_at - timedelta(seconds=window_seconds)
    window_units = sum(
        permit.reservation.request_units for permit in permits if permit.consumed_at > window_start
    )
    if window_units + reservation.request_units > window_limit:
        raise ActionPermitBudgetExceeded("MissionEnvelope rolling ActionPermit rate is exhausted")


def _require_exact_action_permit_retry(
    permit: ActionPermit,
    *,
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    capability: RegisteredActionCapability,
) -> None:
    if (
        permit.campaign_id != envelope.campaign_id
        or permit.run_id != envelope.run_id
        or permit.compiler_id != envelope.compiler_id
        or permit.compiler_version != envelope.compiler_version
        or permit.compiler_digest != envelope.compiler_digest
        or permit.envelope_id != envelope.envelope_id
        or permit.envelope_digest != envelope.envelope_digest
        or permit.proposal_id != proposal.proposal_id
        or permit.proposal_digest != proposal.proposal_digest
        or permit.decision_id != decision.decision_id
        or permit.decision_digest != decision.decision_digest
        or permit.snapshot != decision.snapshot
        or permit.capability != capability.reference()
        or permit.target_digest != proposal.target_digest
        or permit.request_id != proposal.request_id
        or permit.request_digest != proposal.request_digest
        or permit.normalized_parameters_digest != proposal.normalized_parameters_digest
        or permit.reservation != proposal.reservation
    ):
        raise ActionPermitConflict("ActionPermit exact retry differs from stored authority")


def _event_bytes(event: GraphAdmissionEvent) -> bytes:
    return canonical_graph_json(
        event.model_dump(mode="json", by_alias=True),
        label="GraphAdmissionEvent",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _node_bytes(node: GraphNode) -> bytes:
    return canonical_graph_json(
        node.model_dump(mode="json", by_alias=True),
        label="GraphNode",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _projection_bytes(projection: GraphProjection) -> bytes:
    return canonical_graph_json(
        projection.model_dump(mode="json", by_alias=True),
        label="GraphProjection",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _snapshot_bytes(snapshot: GraphSnapshot) -> bytes:
    return canonical_graph_json(
        snapshot.model_dump(mode="json", by_alias=True),
        label="GraphSnapshot",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _action_permit_bytes(permit: ActionPermit) -> bytes:
    return canonical_graph_json(
        permit.model_dump(mode="json", by_alias=True),
        label="ActionPermit",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if not isinstance(value, bytes):
        raise SQLiteGraphStoreError(f"SQLite Graph Store {field} is not canonical bytes")
    return value


def _decode_json(raw: bytes, *, label: str) -> object:
    if len(raw) > _MAX_GRAPH_BYTES:
        raise SQLiteGraphStoreError(f"SQLite Graph Store {label} exceeds byte limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SQLiteGraphStoreError(f"SQLite Graph Store {label} is not canonical JSON") from exc


def _canonical_event(event: GraphAdmissionEvent) -> GraphAdmissionEvent:
    try:
        return GraphAdmissionEvent.model_validate(event.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise GraphEventLogError("Graph admission event is not canonical") from exc


def _event_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> GraphAdmissionEvent:
    raw = _required_bytes(row, "event_json")
    try:
        event = GraphAdmissionEvent.model_validate(_decode_json(raw, label="GraphAdmissionEvent"))
    except ValidationError as exc:
        raise GraphEventLogError("stored Graph admission event is invalid") from exc
    if raw != _event_bytes(event):
        raise GraphEventLogError("stored Graph admission event is not canonical bytes")
    if (
        event.campaign_id != campaign_id
        or event.sequence != row["sequence"]
        or event.event_id != row["event_id"]
        or event.event_digest != row["event_digest"]
        or event.previous_event_digest != row["previous_event_digest"]
        or event.proposal_id != row["proposal_id"]
        or event.proposal_digest != row["proposal_digest"]
        or event.decision.value != row["decision"]
    ):
        raise GraphEventLogError("stored Graph admission event index differs from payload")
    return event


def _node_from_row(row: sqlite3.Row, *, campaign_id: str) -> GraphNode:
    raw = _required_bytes(row, "node_json")
    try:
        node = parse_graph_node(_decode_json(raw, label="GraphNode"))
    except ValidationError as exc:
        raise GraphEventLogError("stored Graph node is invalid") from exc
    if raw != _node_bytes(node):
        raise GraphEventLogError("stored Graph node is not canonical bytes")
    if (
        node.campaign_id != campaign_id
        or node.node_id != row["node_id"]
        or GraphNodeKind(node.kind).value != row["node_kind"]
    ):
        raise GraphEventLogError("stored Graph node index differs from payload")
    return node


def _projection_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> GraphProjection:
    raw = _required_bytes(row, "projection_json")
    try:
        projection = GraphProjection.model_validate(_decode_json(raw, label="GraphProjection"))
    except ValidationError as exc:
        raise GraphProjectionError("stored Graph projection is invalid") from exc
    if raw != _projection_bytes(projection):
        raise GraphProjectionError("stored Graph projection is not canonical bytes")
    if (
        projection.campaign_id != campaign_id
        or projection.revision != row["revision"]
        or projection.event_log_head_digest != row["event_log_head_digest"]
        or projection.projection_id != row["projection_id"]
        or projection.projection_digest != row["projection_digest"]
    ):
        raise GraphProjectionError("stored Graph projection index differs from payload")
    return projection


def _canonical_snapshot(snapshot: GraphSnapshot) -> GraphSnapshot:
    try:
        return GraphSnapshot.model_validate(snapshot.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise GraphSnapshotError("Graph Snapshot is not canonical") from exc


def _snapshot_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> GraphSnapshot:
    raw = _required_bytes(row, "snapshot_json")
    try:
        snapshot = GraphSnapshot.model_validate(_decode_json(raw, label="GraphSnapshot"))
    except ValidationError as exc:
        raise GraphSnapshotError("stored Graph Snapshot is invalid") from exc
    if raw != _snapshot_bytes(snapshot):
        raise GraphSnapshotError("stored Graph Snapshot is not canonical bytes")
    if (
        snapshot.campaign_id != campaign_id
        or snapshot.snapshot_id != row["snapshot_id"]
        or snapshot.snapshot_digest != row["snapshot_digest"]
        or snapshot.previous_snapshot_digest != row["previous_snapshot_digest"]
        or snapshot.revision != row["revision"]
        or snapshot.projection_digest != row["projection_digest"]
    ):
        raise GraphSnapshotError("stored Graph Snapshot index differs from payload")
    return snapshot


def _canonical_mission_envelope(envelope: MissionEnvelope) -> MissionEnvelope:
    try:
        return MissionEnvelope.model_validate(envelope.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("MissionEnvelope is not canonical") from exc


def _canonical_action_proposal(proposal: ActionProposal) -> ActionProposal:
    try:
        return ActionProposal.model_validate(proposal.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("ActionProposal is not canonical") from exc


def _canonical_graph_decision(decision: GraphDecision) -> GraphDecision:
    try:
        return GraphDecision.model_validate(decision.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("GraphDecision is not canonical") from exc


def _canonical_registered_capability(
    capability: RegisteredActionCapability,
) -> RegisteredActionCapability:
    try:
        return RegisteredActionCapability.model_validate(
            capability.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise ActionPermitError("Registered Action Capability is not canonical") from exc


def _action_permit_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> ActionPermit:
    raw = _required_bytes(row, "permit_json")
    try:
        permit = ActionPermit.model_validate(_decode_json(raw, label="ActionPermit"))
    except ValidationError as exc:
        raise ActionPermitError("stored ActionPermit is invalid") from exc
    if raw != _action_permit_bytes(permit):
        raise ActionPermitError("stored ActionPermit is not canonical bytes")
    if (
        permit.campaign_id != campaign_id
        or permit.permit_id != row["permit_id"]
        or permit.permit_digest != row["permit_digest"]
        or permit.dispatch_id != row["dispatch_id"]
        or permit.envelope_id != row["envelope_id"]
        or permit.envelope_digest != row["envelope_digest"]
        or permit.proposal_id != row["proposal_id"]
        or permit.proposal_digest != row["proposal_digest"]
        or permit.decision_id != row["decision_id"]
        or permit.decision_digest != row["decision_digest"]
        or permit.snapshot.snapshot_id != row["snapshot_id"]
        or permit.snapshot.snapshot_digest != row["snapshot_digest"]
        or permit.snapshot.revision != row["revision"]
        or permit.snapshot.event_log_head_digest != row["event_log_head_digest"]
        or permit.snapshot.projection_digest != row["projection_digest"]
        or permit.request_id != row["request_id"]
        or permit.request_digest != row["request_digest"]
        or permit.reservation.request_units != row["request_units"]
        or permit.reservation.cost_microusd != row["cost_microusd"]
        or permit.issued_at.isoformat() != row["issued_at"]
        or permit.consumed_at.isoformat() != row["consumed_at"]
        or permit.expires_at.isoformat() != row["expires_at"]
    ):
        raise ActionPermitError("stored ActionPermit index differs from payload")
    return permit


def _require_event_chain(
    events: tuple[GraphAdmissionEvent, ...],
    *,
    campaign_id: str,
) -> None:
    previous: str | None = None
    for sequence, event in enumerate(events, start=1):
        if (
            event.campaign_id != campaign_id
            or event.sequence != sequence
            or event.previous_event_digest != previous
        ):
            raise GraphEventLogError("stored Graph Event Log chain is not contiguous")
        previous = event.event_digest
