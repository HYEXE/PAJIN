"""Crash-safe SQLite authority for single-use restricted-replay tickets."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

from pajin.domain.replay import ReplayCompilation
from pajin.replay.tickets import (
    ClaimedReplayExecution,
    ReplayExecutionTicket,
    ReplayTicketClaimer,
    ReplayTicketContext,
    ReplayTicketFinalizationVerifier,
    ReplayTicketIssuer,
    ReplayTicketState,
    canonical_replay_compilation_bytes,
)

_SCHEMA_VERSION = 1
_APPLICATION_ID = 0x50414A49  # ASCII "PAJI"
_BUSY_TIMEOUT_MS = 30_000
_DIGEST_LENGTH = 64
_TABLES = frozenset({"replay_ticket_metadata", "replay_tickets", "replay_ticket_events"})

_METADATA_TABLE_SQL = """
    CREATE TABLE replay_ticket_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT
    """
_TICKETS_TABLE_SQL = """
    CREATE TABLE replay_tickets (
        ticket_id TEXT PRIMARY KEY NOT NULL,
        canonical_compilation BLOB NOT NULL,
        compilation_digest TEXT NOT NULL,
        candidate_source_root_digest TEXT NOT NULL,
        campaign_digest TEXT NOT NULL,
        tool_spec_digest TEXT NOT NULL,
        scenario_digest TEXT NOT NULL,
        replay_run_id TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('issued', 'claimed', 'finalized')),
        issued_at TEXT NOT NULL,
        claimed_at TEXT,
        finalized_at TEXT,
        final_seal_root_digest TEXT,
        artifact_set_digest TEXT,
        issuance_digest TEXT NOT NULL,
        state_digest TEXT NOT NULL
    ) STRICT
    """
_EVENTS_TABLE_SQL = """
    CREATE TABLE replay_ticket_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id TEXT NOT NULL REFERENCES replay_tickets(ticket_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
        from_state TEXT CHECK (from_state IN ('issued', 'claimed', 'finalized')),
        to_state TEXT NOT NULL CHECK (to_state IN ('issued', 'claimed', 'finalized')),
        occurred_at TEXT NOT NULL,
        final_seal_root_digest TEXT,
        artifact_set_digest TEXT,
        previous_event_digest TEXT,
        event_digest TEXT NOT NULL,
        UNIQUE (ticket_id, ordinal)
    ) STRICT
    """
_EVENTS_INDEX_SQL = (
    "CREATE INDEX replay_ticket_events_ticket_idx ON replay_ticket_events(ticket_id, ordinal)"
)
_EVENTS_NO_UPDATE_TRIGGER_SQL = """
    CREATE TRIGGER replay_ticket_events_no_update
    BEFORE UPDATE ON replay_ticket_events
    BEGIN
        SELECT RAISE(ABORT, 'replay ticket events are append-only');
    END
    """
_EVENTS_NO_DELETE_TRIGGER_SQL = """
    CREATE TRIGGER replay_ticket_events_no_delete
    BEFORE DELETE ON replay_ticket_events
    BEGIN
        SELECT RAISE(ABORT, 'replay ticket events are append-only');
    END
    """
_EVENTS_NO_REPLACE_TRIGGER_SQL = """
    CREATE TRIGGER replay_ticket_events_no_replace
    BEFORE INSERT ON replay_ticket_events
    WHEN EXISTS (
        SELECT 1 FROM replay_ticket_events
        WHERE event_id = NEW.event_id
           OR (ticket_id = NEW.ticket_id AND ordinal = NEW.ordinal)
    )
    BEGIN
        SELECT RAISE(ABORT, 'replay ticket events cannot be replaced');
    END
    """
_TICKETS_ISSUANCE_IMMUTABLE_TRIGGER_SQL = """
    CREATE TRIGGER replay_tickets_issuance_immutable
    BEFORE UPDATE OF
        ticket_id, canonical_compilation, compilation_digest,
        candidate_source_root_digest, campaign_digest, tool_spec_digest,
        scenario_digest, replay_run_id, expires_at, issued_at, issuance_digest
    ON replay_tickets
    BEGIN
        SELECT RAISE(ABORT, 'replay ticket issuance is immutable');
    END
    """
_TICKETS_ROWID_IMMUTABLE_TRIGGER_SQL = """
    CREATE TRIGGER replay_tickets_rowid_immutable
    BEFORE UPDATE ON replay_tickets
    WHEN OLD.rowid != NEW.rowid
    BEGIN
        SELECT RAISE(ABORT, 'replay ticket rowid is immutable');
    END
    """
_TICKETS_NO_DELETE_TRIGGER_SQL = """
    CREATE TRIGGER replay_tickets_no_delete
    BEFORE DELETE ON replay_tickets
    BEGIN
        SELECT RAISE(ABORT, 'replay tickets are append-only');
    END
    """
_TICKETS_NO_REPLACE_TRIGGER_SQL = """
    CREATE TRIGGER replay_tickets_no_replace
    BEFORE INSERT ON replay_tickets
    WHEN EXISTS (
        SELECT 1 FROM replay_tickets
        WHERE rowid = NEW.rowid
           OR ticket_id = NEW.ticket_id
           OR replay_run_id = NEW.replay_run_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'replay tickets cannot be replaced');
    END
    """
_TICKETS_STATE_TRANSITION_TRIGGER_SQL = """
    CREATE TRIGGER replay_tickets_state_transition
    BEFORE UPDATE OF state ON replay_tickets
    WHEN NOT (
        (OLD.state = 'issued' AND NEW.state = 'claimed')
        OR (OLD.state = 'claimed' AND NEW.state = 'finalized')
    )
    BEGIN
        SELECT RAISE(ABORT, 'invalid replay ticket state transition');
    END
    """
_SCHEMA_OBJECT_SQL = {
    ("table", "replay_ticket_metadata"): _METADATA_TABLE_SQL,
    ("table", "replay_tickets"): _TICKETS_TABLE_SQL,
    ("table", "replay_ticket_events"): _EVENTS_TABLE_SQL,
    ("index", "replay_ticket_events_ticket_idx"): _EVENTS_INDEX_SQL,
    ("trigger", "replay_ticket_events_no_update"): _EVENTS_NO_UPDATE_TRIGGER_SQL,
    ("trigger", "replay_ticket_events_no_delete"): _EVENTS_NO_DELETE_TRIGGER_SQL,
    ("trigger", "replay_ticket_events_no_replace"): _EVENTS_NO_REPLACE_TRIGGER_SQL,
    (
        "trigger",
        "replay_tickets_issuance_immutable",
    ): _TICKETS_ISSUANCE_IMMUTABLE_TRIGGER_SQL,
    ("trigger", "replay_tickets_rowid_immutable"): _TICKETS_ROWID_IMMUTABLE_TRIGGER_SQL,
    ("trigger", "replay_tickets_no_delete"): _TICKETS_NO_DELETE_TRIGGER_SQL,
    ("trigger", "replay_tickets_no_replace"): _TICKETS_NO_REPLACE_TRIGGER_SQL,
    ("trigger", "replay_tickets_state_transition"): _TICKETS_STATE_TRANSITION_TRIGGER_SQL,
}
_CREATE_STATEMENTS = tuple(_SCHEMA_OBJECT_SQL.values())


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split())


_SCHEMA_DIGEST = sha256(
    json.dumps(
        {
            f"{object_type}:{name}": _normalize_schema_sql(statement)
            for (object_type, name), statement in sorted(_SCHEMA_OBJECT_SQL.items())
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
).hexdigest()


class SQLiteReplayExecutionAuthority:
    """Durable ticket issuer/runtime authority backed by one local SQLite ledger."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = _absolute_path(path)
        self._clock = clock or _utc_now
        self.__issuer_token = object()
        self.__claimer_token = object()
        self._initialize()

    def issuer(self) -> ReplayTicketIssuer:
        return ReplayTicketIssuer(self, self.__issuer_token)

    def claimer(self) -> ReplayTicketClaimer:
        return ReplayTicketClaimer(self, self.__claimer_token)

    def verifier(self) -> ReplayTicketFinalizationVerifier:
        return SQLiteReplayTicketFinalizationVerifier(self.path)

    def _issue(
        self,
        token: object,
        compilation: ReplayCompilation,
        *,
        context: ReplayTicketContext,
    ) -> ReplayExecutionTicket:
        if token is not self.__issuer_token:
            raise PermissionError("invalid replay ticket issuer authority")
        canonical = canonical_replay_compilation_bytes(compilation)
        trusted = ReplayCompilation.model_validate_json(canonical)
        if canonical_replay_compilation_bytes(trusted) != canonical:
            raise ValueError("replay compilation is not in canonical form")
        compilation_digest = sha256(canonical).hexdigest()
        ticket = ReplayExecutionTicket(ticket_id=f"replay-ticket_{uuid4().hex}")
        replay_run_id = trusted.spec.binding.replay_run_id
        expires_at = _format_timestamp(_aware_utc(trusted.spec.expires_at, "expires_at"))
        issued_at = _format_timestamp(self._trusted_now())
        issuance_digest = _issuance_digest(
            ticket_id=ticket.ticket_id,
            compilation_digest=compilation_digest,
            context=context,
            replay_run_id=replay_run_id,
            expires_at=expires_at,
            issued_at=issued_at,
        )
        state_digest = _state_digest(
            issuance_digest=issuance_digest,
            state=ReplayTicketState.ISSUED,
            claimed_at=None,
            finalized_at=None,
            final_seal_root_digest=None,
            artifact_set_digest=None,
        )
        event_digest = _event_digest(
            ticket_id=ticket.ticket_id,
            ordinal=1,
            from_state=None,
            to_state=ReplayTicketState.ISSUED,
            occurred_at=issued_at,
            final_seal_root_digest=None,
            artifact_set_digest=None,
            previous_event_digest=None,
        )
        _secure_ledger_files(self.path)
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                connection.execute(
                    """
                    INSERT INTO replay_tickets (
                        ticket_id, canonical_compilation, compilation_digest,
                        candidate_source_root_digest, campaign_digest, tool_spec_digest,
                        scenario_digest, replay_run_id, expires_at, state, issued_at,
                        claimed_at, finalized_at, final_seal_root_digest, artifact_set_digest,
                        issuance_digest, state_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
                    """,
                    (
                        ticket.ticket_id,
                        canonical,
                        compilation_digest,
                        context.candidate_source_root_digest,
                        context.campaign_digest,
                        context.tool_spec_digest,
                        context.scenario_digest,
                        replay_run_id,
                        expires_at,
                        ReplayTicketState.ISSUED.value,
                        issued_at,
                        issuance_digest,
                        state_digest,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO replay_ticket_events (
                        ticket_id, ordinal, from_state, to_state, occurred_at,
                        final_seal_root_digest, artifact_set_digest,
                        previous_event_digest, event_digest
                    ) VALUES (?, 1, NULL, ?, ?, NULL, NULL, NULL, ?)
                    """,
                    (
                        ticket.ticket_id,
                        ReplayTicketState.ISSUED.value,
                        issued_at,
                        event_digest,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            if "replay_run_id" in str(exc) or "replay tickets cannot be replaced" in str(exc):
                raise PermissionError(
                    "a replay execution ticket already exists for this Run"
                ) from exc
            raise RuntimeError("replay ticket ledger rejected a duplicate record") from exc
        except sqlite3.Error as exc:
            raise RuntimeError("replay ticket ledger write failed") from exc
        return ticket

    def _claim(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        expected_replay_run_id: str,
        expected_candidate_source_root_digest: str,
        expected_campaign_digest: str,
        claimed_at: datetime,
    ) -> ClaimedReplayExecution:
        if token is not self.__claimer_token:
            raise PermissionError("invalid replay ticket claimer authority")
        del claimed_at  # The durable authority trusts only its own injected clock.
        now = self._trusted_now()
        now_wire = _format_timestamp(now)
        _secure_ledger_files(self.path)
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                row = _load_ticket(connection, ticket.ticket_id, unknown_as_permission=False)
                trusted, context, state = _validate_ticket_record(connection, row)
                if state is not ReplayTicketState.ISSUED:
                    raise PermissionError(f"replay execution ticket is already {state.value}")
                if _required_text(row, "replay_run_id") != expected_replay_run_id:
                    raise PermissionError("replay execution ticket belongs to another Run")
                if (
                    context.candidate_source_root_digest != expected_candidate_source_root_digest
                    or context.campaign_digest != expected_campaign_digest
                ):
                    raise PermissionError(
                        "trusted replay execution context changed after compilation"
                    )
                issued_at = _parse_timestamp(_required_text(row, "issued_at"), "issued_at")
                expires_at = _parse_timestamp(_required_text(row, "expires_at"), "expires_at")
                if now < issued_at:
                    raise PermissionError("trusted replay ticket clock moved before issuance")
                if now >= expires_at:
                    raise PermissionError("replay execution ticket authority expired")
                issuance_digest = _required_digest(row, "issuance_digest")
                state_digest = _state_digest(
                    issuance_digest=issuance_digest,
                    state=ReplayTicketState.CLAIMED,
                    claimed_at=now_wire,
                    finalized_at=None,
                    final_seal_root_digest=None,
                    artifact_set_digest=None,
                )
                cursor = connection.execute(
                    """
                    UPDATE replay_tickets
                    SET state = ?, claimed_at = ?, state_digest = ?
                    WHERE ticket_id = ? AND state = ?
                    """,
                    (
                        ReplayTicketState.CLAIMED.value,
                        now_wire,
                        state_digest,
                        ticket.ticket_id,
                        ReplayTicketState.ISSUED.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise PermissionError("replay execution ticket claim lost its atomic race")
                previous_event_digest = _last_event_digest(connection, ticket.ticket_id)
                event_digest = _event_digest(
                    ticket_id=ticket.ticket_id,
                    ordinal=2,
                    from_state=ReplayTicketState.ISSUED,
                    to_state=ReplayTicketState.CLAIMED,
                    occurred_at=now_wire,
                    final_seal_root_digest=None,
                    artifact_set_digest=None,
                    previous_event_digest=previous_event_digest,
                )
                connection.execute(
                    """
                    INSERT INTO replay_ticket_events (
                        ticket_id, ordinal, from_state, to_state, occurred_at,
                        final_seal_root_digest, artifact_set_digest,
                        previous_event_digest, event_digest
                    ) VALUES (?, 2, ?, ?, ?, NULL, NULL, ?, ?)
                    """,
                    (
                        ticket.ticket_id,
                        ReplayTicketState.ISSUED.value,
                        ReplayTicketState.CLAIMED.value,
                        now_wire,
                        previous_event_digest,
                        event_digest,
                    ),
                )
                compilation_digest = _required_digest(row, "compilation_digest")
        except sqlite3.Error as exc:
            raise RuntimeError("replay ticket ledger claim failed") from exc
        return ClaimedReplayExecution(
            ticket=ticket,
            compilation=trusted,
            compilation_digest=compilation_digest,
            context=context,
        )

    def _finalize(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        finalized_at: datetime,
    ) -> None:
        if token is not self.__claimer_token:
            raise PermissionError("invalid replay ticket finalizer authority")
        del finalized_at  # The durable authority trusts only its own injected clock.
        self._finalize_record(
            ticket,
            final_seal_root_digest=final_seal_root_digest,
            artifact_set_digest=artifact_set_digest,
        )

    def _recover_finalization(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        context: ReplayTicketContext,
        replay_run_id: str,
        finalized_at: datetime,
    ) -> None:
        if token is not self.__claimer_token:
            raise PermissionError("invalid replay ticket recovery authority")
        del finalized_at  # The durable authority trusts only its own injected clock.
        _validate_digest(compilation_digest, "compilation_digest")
        if not replay_run_id:
            raise ValueError("replay_run_id must be non-empty")
        self._finalize_record(
            ticket,
            final_seal_root_digest=final_seal_root_digest,
            artifact_set_digest=artifact_set_digest,
            expected_compilation_digest=compilation_digest,
            expected_context=context,
            expected_replay_run_id=replay_run_id,
        )

    def _finalize_record(
        self,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        expected_compilation_digest: str | None = None,
        expected_context: ReplayTicketContext | None = None,
        expected_replay_run_id: str | None = None,
    ) -> None:
        _validate_digest(final_seal_root_digest, "final_seal_root_digest")
        _validate_digest(artifact_set_digest, "artifact_set_digest")
        now = self._trusted_now()
        now_wire = _format_timestamp(now)
        _secure_ledger_files(self.path)
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                row = _load_ticket(connection, ticket.ticket_id, unknown_as_permission=False)
                _, context, state = _validate_ticket_record(connection, row)
                if expected_compilation_digest is not None and (
                    _required_digest(row, "compilation_digest") != expected_compilation_digest
                    or context != expected_context
                    or _required_text(row, "replay_run_id") != expected_replay_run_id
                ):
                    raise PermissionError("replay ticket recovery context does not match issuance")
                if state is ReplayTicketState.FINALIZED:
                    if (
                        _optional_text(row, "final_seal_root_digest") == final_seal_root_digest
                        and _optional_text(row, "artifact_set_digest") == artifact_set_digest
                    ):
                        return
                    raise PermissionError(
                        "replay ticket was already finalized with different sealed artifacts"
                    )
                if state is not ReplayTicketState.CLAIMED:
                    raise PermissionError("only a claimed replay ticket can be finalized")
                claimed_wire = _required_text(row, "claimed_at")
                claimed = _parse_timestamp(claimed_wire, "claimed_at")
                if now < claimed:
                    raise PermissionError("trusted replay ticket clock moved before claim")
                issuance_digest = _required_digest(row, "issuance_digest")
                state_digest = _state_digest(
                    issuance_digest=issuance_digest,
                    state=ReplayTicketState.FINALIZED,
                    claimed_at=claimed_wire,
                    finalized_at=now_wire,
                    final_seal_root_digest=final_seal_root_digest,
                    artifact_set_digest=artifact_set_digest,
                )
                cursor = connection.execute(
                    """
                    UPDATE replay_tickets
                    SET state = ?, finalized_at = ?, final_seal_root_digest = ?,
                        artifact_set_digest = ?, state_digest = ?
                    WHERE ticket_id = ? AND state = ?
                    """,
                    (
                        ReplayTicketState.FINALIZED.value,
                        now_wire,
                        final_seal_root_digest,
                        artifact_set_digest,
                        state_digest,
                        ticket.ticket_id,
                        ReplayTicketState.CLAIMED.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise PermissionError("replay ticket finalization lost its atomic race")
                previous_event_digest = _last_event_digest(connection, ticket.ticket_id)
                event_digest = _event_digest(
                    ticket_id=ticket.ticket_id,
                    ordinal=3,
                    from_state=ReplayTicketState.CLAIMED,
                    to_state=ReplayTicketState.FINALIZED,
                    occurred_at=now_wire,
                    final_seal_root_digest=final_seal_root_digest,
                    artifact_set_digest=artifact_set_digest,
                    previous_event_digest=previous_event_digest,
                )
                connection.execute(
                    """
                    INSERT INTO replay_ticket_events (
                        ticket_id, ordinal, from_state, to_state, occurred_at,
                        final_seal_root_digest, artifact_set_digest,
                        previous_event_digest, event_digest
                    ) VALUES (?, 3, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ticket.ticket_id,
                        ReplayTicketState.CLAIMED.value,
                        ReplayTicketState.FINALIZED.value,
                        now_wire,
                        final_seal_root_digest,
                        artifact_set_digest,
                        previous_event_digest,
                        event_digest,
                    ),
                )
        except sqlite3.Error as exc:
            raise RuntimeError("replay ticket ledger finalization failed") from exc

    def _verify_finalized(
        self,
        token: object,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        if token is not self.__claimer_token:
            raise PermissionError("invalid replay ticket verification authority")
        SQLiteReplayTicketFinalizationVerifier(self.path).verify_finalized(
            ticket_id,
            final_seal_root_digest=final_seal_root_digest,
            artifact_set_digest=artifact_set_digest,
            compilation_digest=compilation_digest,
            candidate_source_root_digest=candidate_source_root_digest,
            replay_run_id=replay_run_id,
        )

    def _trusted_now(self) -> datetime:
        return _aware_utc(self._clock(), "trusted clock")

    def _initialize(self) -> None:
        created_file, file_size = _prepare_ledger_file(self.path)
        initialize_empty_file = created_file or file_size == 0
        _secure_ledger_files(self.path)
        try:
            connection = _open_write_connection(self.path)
            try:
                if initialize_empty_file:
                    journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
                    if journal_mode is None or str(journal_mode[0]).lower() != "delete":
                        raise RuntimeError("replay ticket ledger requires DELETE journal mode")
                connection.execute("BEGIN IMMEDIATE")
                tables = _application_tables(connection)
                if not tables:
                    if not initialize_empty_file:
                        raise RuntimeError("existing replay ticket ledger has no trusted schema")
                    for statement in _CREATE_STATEMENTS:
                        connection.execute(statement)
                    connection.executemany(
                        "INSERT INTO replay_ticket_metadata (key, value) VALUES (?, ?)",
                        (
                            ("schema_version", str(_SCHEMA_VERSION)),
                            ("schema_digest", _SCHEMA_DIGEST),
                        ),
                    )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                    connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                    _validate_schema(connection)
                else:
                    _validate_schema(connection)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise RuntimeError("replay ticket ledger initialization failed") from exc


class SQLiteReplayTicketFinalizationVerifier:
    """Read-only verifier that can be reopened after the issuing process exits."""

    def __init__(self, path: Path) -> None:
        self.path = _absolute_path(path)

    def verify_finalized(
        self,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        for name, value in (
            ("final_seal_root_digest", final_seal_root_digest),
            ("artifact_set_digest", artifact_set_digest),
            ("compilation_digest", compilation_digest),
            ("candidate_source_root_digest", candidate_source_root_digest),
        ):
            _validate_digest(value, name)
        if not ticket_id or not replay_run_id:
            raise ValueError("ticket_id and replay_run_id must be non-empty")
        _validate_existing_ledger(self.path)
        try:
            with _readonly_connection(self.path) as connection:
                _validate_schema(connection)
                row = _load_ticket(connection, ticket_id, unknown_as_permission=True)
                _, context, state = _validate_ticket_record(connection, row)
                if state is not ReplayTicketState.FINALIZED:
                    raise PermissionError("replay execution ticket is not finalized")
                if (
                    _required_digest(row, "final_seal_root_digest") != final_seal_root_digest
                    or _required_digest(row, "artifact_set_digest") != artifact_set_digest
                    or _required_digest(row, "compilation_digest") != compilation_digest
                    or context.candidate_source_root_digest != candidate_source_root_digest
                    or _required_text(row, "replay_run_id") != replay_run_id
                ):
                    raise PermissionError(
                        "replay ticket finalization does not match the sealed receipt"
                    )
        except sqlite3.Error as exc:
            raise RuntimeError("replay ticket ledger verification failed") from exc


def _absolute_path(path: Path) -> Path:
    """Normalize lexical components without following attacker-controlled symlinks."""

    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


type _FileIdentity = tuple[int, int]


@dataclass(frozen=True, slots=True)
class _PrivateParent:
    path: Path
    identity: _FileIdentity
    descriptor: int | None

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)


def _file_identity(file_stat: os.stat_result) -> _FileIdentity:
    return file_stat.st_dev, file_stat.st_ino


def _open_private_parent(directory: Path, *, create: bool) -> _PrivateParent:
    directory = _absolute_path(directory)
    if os.name == "posix":
        return _open_posix_private_parent(directory, create=create)
    return _open_windows_private_parent(directory, create=create)


def _open_posix_private_parent(directory: Path, *, create: bool) -> _PrivateParent:
    current = os.open(
        directory.anchor,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in directory.parts[1:]:
            child = _open_posix_directory_component(current, component, create=create)
            os.close(current)
            current = child
        identity = _validate_posix_parent_descriptor(directory, current)
        return _PrivateParent(path=directory, identity=identity, descriptor=current)
    except BaseException:
        os.close(current)
        raise


def _open_posix_directory_component(parent: int, component: str, *, create: bool) -> int:
    flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    if create:
        with suppress(FileExistsError):
            os.mkdir(component, 0o700, dir_fd=parent)
    try:
        return os.open(component, flags, dir_fd=parent)
    except FileNotFoundError:
        raise RuntimeError("replay ticket ledger parent does not exist") from None
    except OSError as exc:
        raise RuntimeError("replay ticket ledger parent is not a regular directory") from exc


def _validate_posix_parent_descriptor(directory: Path, descriptor: int) -> _FileIdentity:
    parent_stat = os.fstat(descriptor)
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise RuntimeError("replay ticket ledger parent is not a regular directory")
    if parent_stat.st_uid != os.geteuid():
        raise RuntimeError("replay ticket ledger parent is not owned by this user")
    if stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise RuntimeError("replay ticket ledger parent must be owner-only")
    try:
        path_stat = os.stat(directory, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("replay ticket ledger parent changed during validation") from exc
    identity = _file_identity(parent_stat)
    if not stat.S_ISDIR(path_stat.st_mode) or _file_identity(path_stat) != identity:
        raise RuntimeError("replay ticket ledger parent changed during validation")
    return identity


def _open_windows_private_parent(
    directory: Path,
    *,
    create: bool,
) -> _PrivateParent:  # pragma: no cover - exercised by Windows CI
    current = Path(directory.anchor)
    for component in directory.parts[1:]:
        current /= component
        _validate_windows_directory_component(current, create=create)
    parent_stat = _windows_path_stat(directory, kind="parent")
    return _PrivateParent(
        path=directory,
        identity=_file_identity(parent_stat),
        descriptor=None,
    )


def _validate_windows_directory_component(
    directory: Path,
    *,
    create: bool,
) -> None:  # pragma: no cover - exercised by Windows CI
    if create:
        with suppress(FileExistsError):
            directory.mkdir(mode=0o700)
    try:
        directory_stat = directory.lstat()
    except FileNotFoundError:
        raise RuntimeError("replay ticket ledger parent does not exist") from None
    if (
        directory.is_symlink()
        or directory.is_junction()
        or not stat.S_ISDIR(directory_stat.st_mode)
    ):
        raise RuntimeError("replay ticket ledger parent is not a regular directory")


def _windows_path_stat(
    path: Path,
    *,
    kind: str,
) -> os.stat_result:  # pragma: no cover - exercised by Windows CI
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"replay ticket ledger {kind} changed during validation") from exc
    if path.is_symlink() or path.is_junction():
        raise RuntimeError(f"replay ticket ledger {kind} is not a regular file")
    return path_stat


def _open_ledger_descriptor(
    path: Path,
    *,
    create: bool,
) -> tuple[int, _PrivateParent, bool]:
    parent = _open_private_parent(path.parent, create=create)
    try:
        if parent.descriptor is not None:
            descriptor, created = _open_posix_ledger_descriptor(
                path,
                parent,
                create=create,
            )
        else:
            descriptor, created = _open_windows_ledger_descriptor(
                path,
                parent,
                create=create,
            )
        return descriptor, parent, created
    except BaseException:
        parent.close()
        raise


def _open_posix_ledger_descriptor(
    path: Path,
    parent: _PrivateParent,
    *,
    create: bool,
) -> tuple[int, bool]:
    assert parent.descriptor is not None
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor, created = _open_descriptor(
        path.name,
        flags=flags,
        create=create,
        dir_fd=parent.descriptor,
        error="replay ticket ledger path is not a regular file",
    )
    try:
        file_stat = _validate_private_regular_descriptor(descriptor, owner_required=True)
        os.fchmod(descriptor, 0o600)
        path_stat = os.stat(path.name, dir_fd=parent.descriptor, follow_symlinks=False)
        _validate_unchanged_regular_file(file_stat, path_stat)
        return descriptor, created
    except BaseException:
        os.close(descriptor)
        raise


def _open_windows_ledger_descriptor(
    path: Path,
    parent: _PrivateParent,
    *,
    create: bool,
) -> tuple[int, bool]:  # pragma: no cover - exercised by Windows CI
    _validate_windows_parent_identity(parent)
    if path.exists() or path.is_symlink() or path.is_junction():
        _validate_windows_regular_path(path)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor, created = _open_descriptor(
        path,
        flags=flags,
        create=create,
        dir_fd=None,
        error="replay ticket ledger path is not a regular file",
    )
    try:
        file_stat = _validate_private_regular_descriptor(descriptor, owner_required=False)
        path_stat = _validate_windows_regular_path(path)
        _validate_unchanged_regular_file(file_stat, path_stat)
        _validate_windows_parent_identity(parent)
        return descriptor, created
    except BaseException:
        os.close(descriptor)
        raise


def _open_descriptor(
    path: str | Path,
    *,
    flags: int,
    create: bool,
    dir_fd: int | None,
    error: str,
) -> tuple[int, bool]:
    if create:
        try:
            return os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd), True
        except FileExistsError:
            pass
    try:
        return os.open(path, flags, dir_fd=dir_fd), False
    except OSError as exc:
        raise RuntimeError(error) from exc


def _validate_private_regular_descriptor(
    descriptor: int,
    *,
    owner_required: bool,
) -> os.stat_result:
    file_stat = os.fstat(descriptor)
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
        raise RuntimeError("replay ticket ledger path is not a private regular file")
    if owner_required and file_stat.st_uid != os.geteuid():
        raise RuntimeError("replay ticket ledger is not owned by this user")
    return file_stat


def _validate_unchanged_regular_file(
    descriptor_stat: os.stat_result,
    path_stat: os.stat_result,
) -> None:
    if not stat.S_ISREG(path_stat.st_mode) or _file_identity(path_stat) != _file_identity(
        descriptor_stat
    ):
        raise RuntimeError("replay ticket ledger changed during validation")


def _validate_windows_regular_path(
    path: Path,
) -> os.stat_result:  # pragma: no cover - exercised by Windows CI
    path_stat = _windows_path_stat(path, kind="path")
    if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
        raise RuntimeError("replay ticket ledger path is not a private regular file")
    return path_stat


def _validate_windows_parent_identity(
    parent: _PrivateParent,
) -> None:  # pragma: no cover - exercised by Windows CI
    parent_stat = _windows_path_stat(parent.path, kind="parent")
    if not stat.S_ISDIR(parent_stat.st_mode) or _file_identity(parent_stat) != parent.identity:
        raise RuntimeError("replay ticket ledger parent changed during validation")


def _prepare_ledger_file(path: Path) -> tuple[bool, int]:
    descriptor, parent, created = _open_ledger_descriptor(path, create=True)
    try:
        return created, os.fstat(descriptor).st_size
    finally:
        os.close(descriptor)
        parent.close()


def _validate_existing_ledger(path: Path) -> None:
    descriptor, parent, _created = _open_ledger_descriptor(path, create=False)
    os.close(descriptor)
    parent.close()


def _ledger_identity(path: Path) -> tuple[tuple[int, int], tuple[int, int]]:
    descriptor, parent, _created = _open_ledger_descriptor(path, create=False)
    try:
        file_stat = os.fstat(descriptor)
        return parent.identity, _file_identity(file_stat)
    finally:
        os.close(descriptor)
        parent.close()


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
    identity = _ledger_identity(path)
    uri = f"{path.as_uri()}?mode=ro"
    connection = sqlite3.connect(
        uri,
        uri=True,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    if _ledger_identity(path) != identity:
        connection.close()
        raise RuntimeError("replay ticket ledger changed while it was opened")
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
    identity = _ledger_identity(path)
    connection = sqlite3.connect(
        path,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    if _ledger_identity(path) != identity:
        connection.close()
        raise RuntimeError("replay ticket ledger changed while it was opened")
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


def _validate_schema(connection: sqlite3.Connection) -> None:
    tables = _application_tables(connection)
    if tables != _TABLES:
        raise RuntimeError("replay ticket ledger schema is invalid")
    metadata_rows = connection.execute(
        "SELECT key, value FROM replay_ticket_metadata ORDER BY key"
    ).fetchall()
    metadata = {cast(str, row["key"]): cast(str, row["value"]) for row in metadata_rows}
    user_version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
    application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
    if (
        metadata
        != {
            "schema_digest": _SCHEMA_DIGEST,
            "schema_version": str(_SCHEMA_VERSION),
        }
        or user_version != _SCHEMA_VERSION
        or application_id != _APPLICATION_ID
    ):
        raise RuntimeError("replay ticket ledger schema version is unsupported")
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
    if (
        journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
        or foreign_keys is None
        or foreign_keys[0] != 1
        or trusted_schema is None
        or trusted_schema[0] != 0
    ):
        raise RuntimeError("replay ticket ledger connection policy is invalid")

    placeholders = ", ".join("?" for _ in _TABLES)
    schema_rows = connection.execute(
        f"""
        SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL
          AND type IN ('table', 'index', 'trigger')
          AND (name IN ({placeholders}) OR tbl_name IN ({placeholders}))
        """,
        (*sorted(_TABLES), *sorted(_TABLES)),
    ).fetchall()
    actual_schema = {
        (cast(str, row["type"]), cast(str, row["name"])): _normalize_schema_sql(
            cast(str, row["sql"])
        )
        for row in schema_rows
    }
    expected_schema = {
        key: _normalize_schema_sql(statement) for key, statement in _SCHEMA_OBJECT_SQL.items()
    }
    if actual_schema != expected_schema:
        raise RuntimeError("replay ticket ledger schema fingerprint is invalid")

    expected_indexes = {
        "replay_ticket_metadata": {(True, "pk", False, ("key",))},
        "replay_tickets": {
            (True, "pk", False, ("ticket_id",)),
            (True, "u", False, ("replay_run_id",)),
        },
        "replay_ticket_events": {
            (True, "u", False, ("ticket_id", "ordinal")),
            (False, "c", False, ("ticket_id", "ordinal")),
        },
    }
    for table, expected in expected_indexes.items():
        if _index_signatures(connection, table) != expected:
            raise RuntimeError("replay ticket ledger index constraints are invalid")

    foreign_key_rows = connection.execute(
        "PRAGMA foreign_key_list(replay_ticket_events)"
    ).fetchall()
    foreign_key_signatures = {
        (
            cast(str, row["table"]),
            cast(str, row["from"]),
            cast(str, row["to"]),
            cast(str, row["on_update"]),
            cast(str, row["on_delete"]),
            cast(str, row["match"]),
        )
        for row in foreign_key_rows
    }
    if foreign_key_signatures != {
        ("replay_tickets", "ticket_id", "ticket_id", "NO ACTION", "NO ACTION", "NONE")
    }:
        raise RuntimeError("replay ticket ledger foreign-key constraint is invalid")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise RuntimeError("replay ticket ledger contains orphaned event records")

    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if len(quick_check) != 1 or quick_check[0][0] != "ok":
        raise RuntimeError("replay ticket ledger integrity check failed")


def _index_signatures(
    connection: sqlite3.Connection,
    table: str,
) -> set[tuple[bool, str, bool, tuple[str, ...]]]:
    signatures: set[tuple[bool, str, bool, tuple[str, ...]]] = set()
    for row in connection.execute(f"PRAGMA index_list({table})").fetchall():
        index_name = cast(str, row["name"])
        columns = tuple(
            cast(str, column["name"])
            for column in connection.execute(f"PRAGMA index_info({index_name})").fetchall()
        )
        signatures.add(
            (
                bool(row["unique"]),
                cast(str, row["origin"]),
                bool(row["partial"]),
                columns,
            )
        )
    return signatures


def _load_ticket(
    connection: sqlite3.Connection,
    ticket_id: str,
    *,
    unknown_as_permission: bool,
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM replay_tickets WHERE ticket_id = ?",
        (ticket_id,),
    ).fetchone()
    if row is None:
        if unknown_as_permission:
            raise PermissionError("unknown replay ticket")
        raise KeyError("unknown replay execution ticket")
    return cast(sqlite3.Row, row)


def _validate_ticket_record(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> tuple[ReplayCompilation, ReplayTicketContext, ReplayTicketState]:
    try:
        ticket_id = _required_text(row, "ticket_id")
        canonical = _required_bytes(row, "canonical_compilation")
        compilation_digest = _required_digest(row, "compilation_digest")
        if sha256(canonical).hexdigest() != compilation_digest:
            raise PermissionError("replay ticket canonical compilation digest changed")
        compilation = ReplayCompilation.model_validate_json(canonical)
        if canonical_replay_compilation_bytes(compilation) != canonical:
            raise PermissionError("replay ticket canonical compilation bytes changed")
        context = ReplayTicketContext(
            candidate_source_root_digest=_required_digest(row, "candidate_source_root_digest"),
            campaign_digest=_required_digest(row, "campaign_digest"),
            tool_spec_digest=_required_digest(row, "tool_spec_digest"),
            scenario_digest=_required_digest(row, "scenario_digest"),
        )
        replay_run_id = _required_text(row, "replay_run_id")
        if compilation.spec.binding.replay_run_id != replay_run_id:
            raise PermissionError("replay ticket compilation belongs to another Run")
        expires_at = _required_text(row, "expires_at")
        if _format_timestamp(_aware_utc(compilation.spec.expires_at, "expires_at")) != expires_at:
            raise PermissionError("replay ticket compilation expiry changed")
        issued_at = _required_text(row, "issued_at")
        _parse_timestamp(issued_at, "issued_at")
        issuance_digest = _required_digest(row, "issuance_digest")
        expected_issuance = _issuance_digest(
            ticket_id=ticket_id,
            compilation_digest=compilation_digest,
            context=context,
            replay_run_id=replay_run_id,
            expires_at=expires_at,
            issued_at=issued_at,
        )
        if issuance_digest != expected_issuance:
            raise PermissionError("replay ticket issuance context integrity check failed")
        try:
            state = ReplayTicketState(_required_text(row, "state"))
        except ValueError as exc:
            raise PermissionError("replay ticket state is invalid") from exc
        claimed_at = _optional_text(row, "claimed_at")
        finalized_at = _optional_text(row, "finalized_at")
        final_seal = _optional_text(row, "final_seal_root_digest")
        artifact_set = _optional_text(row, "artifact_set_digest")
        _validate_state_fields(
            state=state,
            issued_at=issued_at,
            claimed_at=claimed_at,
            finalized_at=finalized_at,
            final_seal_root_digest=final_seal,
            artifact_set_digest=artifact_set,
        )
        expected_state_digest = _state_digest(
            issuance_digest=issuance_digest,
            state=state,
            claimed_at=claimed_at,
            finalized_at=finalized_at,
            final_seal_root_digest=final_seal,
            artifact_set_digest=artifact_set,
        )
        if _required_digest(row, "state_digest") != expected_state_digest:
            raise PermissionError("replay ticket state integrity check failed")
        _validate_event_chain(connection, row, state)
        return compilation, context, state
    except PermissionError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PermissionError("replay ticket ledger record integrity check failed") from exc


def _validate_state_fields(
    *,
    state: ReplayTicketState,
    issued_at: str,
    claimed_at: str | None,
    finalized_at: str | None,
    final_seal_root_digest: str | None,
    artifact_set_digest: str | None,
) -> None:
    issued = _parse_timestamp(issued_at, "issued_at")
    if state is ReplayTicketState.ISSUED:
        if any(
            value is not None
            for value in (claimed_at, finalized_at, final_seal_root_digest, artifact_set_digest)
        ):
            raise PermissionError("issued replay ticket contains later state fields")
        return
    if claimed_at is None:
        raise PermissionError("claimed replay ticket is missing claimed_at")
    claimed = _parse_timestamp(claimed_at, "claimed_at")
    if claimed < issued:
        raise PermissionError("replay ticket claim predates issuance")
    if state is ReplayTicketState.CLAIMED:
        if any(
            value is not None
            for value in (finalized_at, final_seal_root_digest, artifact_set_digest)
        ):
            raise PermissionError("claimed replay ticket contains finalization fields")
        return
    if finalized_at is None or final_seal_root_digest is None or artifact_set_digest is None:
        raise PermissionError("finalized replay ticket is missing finalization fields")
    finalized = _parse_timestamp(finalized_at, "finalized_at")
    if finalized < claimed:
        raise PermissionError("replay ticket finalization predates claim")
    _validate_digest(final_seal_root_digest, "final_seal_root_digest")
    _validate_digest(artifact_set_digest, "artifact_set_digest")


def _validate_event_chain(
    connection: sqlite3.Connection,
    ticket: sqlite3.Row,
    state: ReplayTicketState,
) -> None:
    ticket_id = _required_text(ticket, "ticket_id")
    events = connection.execute(
        "SELECT * FROM replay_ticket_events WHERE ticket_id = ? ORDER BY ordinal",
        (ticket_id,),
    ).fetchall()
    expected_states = {
        ReplayTicketState.ISSUED: [ReplayTicketState.ISSUED],
        ReplayTicketState.CLAIMED: [ReplayTicketState.ISSUED, ReplayTicketState.CLAIMED],
        ReplayTicketState.FINALIZED: [
            ReplayTicketState.ISSUED,
            ReplayTicketState.CLAIMED,
            ReplayTicketState.FINALIZED,
        ],
    }[state]
    if len(events) != len(expected_states):
        raise PermissionError("replay ticket event chain length is invalid")
    previous_digest: str | None = None
    for index, (event, to_state) in enumerate(zip(events, expected_states, strict=True), start=1):
        from_state = None if index == 1 else expected_states[index - 2]
        previous_digest = _validate_event_record(
            event=event,
            ticket_id=ticket_id,
            ordinal=index,
            from_state=from_state,
            to_state=to_state,
            previous_event_digest=previous_digest,
        )
    _validate_event_ticket_bindings(events, ticket=ticket, state=state)


def _validate_event_record(
    *,
    event: sqlite3.Row,
    ticket_id: str,
    ordinal: int,
    from_state: ReplayTicketState | None,
    to_state: ReplayTicketState,
    previous_event_digest: str | None,
) -> str:
    stored_ordinal = event["ordinal"]
    if type(stored_ordinal) is not int or stored_ordinal != ordinal:
        raise PermissionError("replay ticket event ordinal is invalid")
    expected_from_state = from_state.value if from_state is not None else None
    if (
        _optional_text(event, "from_state") != expected_from_state
        or _required_text(event, "to_state") != to_state.value
    ):
        raise PermissionError("replay ticket event transition is invalid")
    occurred_at = _required_text(event, "occurred_at")
    _parse_timestamp(occurred_at, "occurred_at")
    final_seal = _optional_text(event, "final_seal_root_digest")
    artifact_set = _optional_text(event, "artifact_set_digest")
    if _optional_text(event, "previous_event_digest") != previous_event_digest:
        raise PermissionError("replay ticket event chain was broken")
    digest = _required_digest(event, "event_digest")
    expected_digest = _event_digest(
        ticket_id=ticket_id,
        ordinal=ordinal,
        from_state=from_state,
        to_state=to_state,
        occurred_at=occurred_at,
        final_seal_root_digest=final_seal,
        artifact_set_digest=artifact_set,
        previous_event_digest=previous_event_digest,
    )
    if digest != expected_digest:
        raise PermissionError("replay ticket event integrity check failed")
    if to_state is not ReplayTicketState.FINALIZED and (
        final_seal is not None or artifact_set is not None
    ):
        raise PermissionError("non-final replay ticket event contains sealed artifacts")
    return digest


def _validate_event_ticket_bindings(
    events: list[sqlite3.Row],
    *,
    ticket: sqlite3.Row,
    state: ReplayTicketState,
) -> None:
    if _required_text(events[0], "occurred_at") != _required_text(ticket, "issued_at"):
        raise PermissionError("replay ticket issuance event timestamp changed")
    if state is not ReplayTicketState.ISSUED and _required_text(
        events[1], "occurred_at"
    ) != _required_text(ticket, "claimed_at"):
        raise PermissionError("replay ticket claim event timestamp changed")
    if state is ReplayTicketState.FINALIZED:
        final_event = events[2]
        if (
            _required_text(final_event, "occurred_at") != _required_text(ticket, "finalized_at")
            or _required_digest(final_event, "final_seal_root_digest")
            != _required_digest(ticket, "final_seal_root_digest")
            or _required_digest(final_event, "artifact_set_digest")
            != _required_digest(ticket, "artifact_set_digest")
        ):
            raise PermissionError("replay ticket finalization event changed")


def _last_event_digest(connection: sqlite3.Connection, ticket_id: str) -> str:
    row = connection.execute(
        """
        SELECT event_digest FROM replay_ticket_events
        WHERE ticket_id = ? ORDER BY ordinal DESC LIMIT 1
        """,
        (ticket_id,),
    ).fetchone()
    if row is None:
        raise PermissionError("replay ticket event chain is missing")
    return _required_digest(cast(sqlite3.Row, row), "event_digest")


def _issuance_digest(
    *,
    ticket_id: str,
    compilation_digest: str,
    context: ReplayTicketContext,
    replay_run_id: str,
    expires_at: str,
    issued_at: str,
) -> str:
    return _digest_payload(
        {
            "schemaVersion": _SCHEMA_VERSION,
            "ticketId": ticket_id,
            "compilationDigest": compilation_digest,
            "candidateSourceRootDigest": context.candidate_source_root_digest,
            "campaignDigest": context.campaign_digest,
            "toolSpecDigest": context.tool_spec_digest,
            "scenarioDigest": context.scenario_digest,
            "replayRunId": replay_run_id,
            "expiresAt": expires_at,
            "issuedAt": issued_at,
        }
    )


def _state_digest(
    *,
    issuance_digest: str,
    state: ReplayTicketState,
    claimed_at: str | None,
    finalized_at: str | None,
    final_seal_root_digest: str | None,
    artifact_set_digest: str | None,
) -> str:
    return _digest_payload(
        {
            "issuanceDigest": issuance_digest,
            "state": state.value,
            "claimedAt": claimed_at,
            "finalizedAt": finalized_at,
            "finalSealRootDigest": final_seal_root_digest,
            "artifactSetDigest": artifact_set_digest,
        }
    )


def _event_digest(
    *,
    ticket_id: str,
    ordinal: int,
    from_state: ReplayTicketState | None,
    to_state: ReplayTicketState,
    occurred_at: str,
    final_seal_root_digest: str | None,
    artifact_set_digest: str | None,
    previous_event_digest: str | None,
) -> str:
    return _digest_payload(
        {
            "ticketId": ticket_id,
            "ordinal": ordinal,
            "fromState": from_state.value if from_state is not None else None,
            "toState": to_state.value,
            "occurredAt": occurred_at,
            "finalSealRootDigest": final_seal_root_digest,
            "artifactSetDigest": artifact_set_digest,
            "previousEventDigest": previous_event_digest,
        }
    )


def _digest_payload(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()
    return sha256(canonical).hexdigest()


def _required_text(row: sqlite3.Row, field: str) -> str:
    value = row[field]
    if type(value) is not str or not value:
        raise TypeError(f"{field} must be non-empty text")
    return value


def _optional_text(row: sqlite3.Row, field: str) -> str | None:
    value = row[field]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise TypeError(f"{field} must be non-empty text or null")
    return value


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if not isinstance(value, bytes):
        raise TypeError(f"{field} must be bytes")
    return value


def _required_digest(row: sqlite3.Row, field: str) -> str:
    value = _required_text(row, field)
    _validate_digest(value, field)
    return value


def _validate_digest(value: str, field: str) -> None:
    if (
        type(value) is not str
        or len(value) != _DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    normalized = _aware_utc(parsed, field)
    if _format_timestamp(normalized) != value:
        raise ValueError(f"{field} must be a canonical UTC timestamp")
    return normalized


def _format_timestamp(value: datetime) -> str:
    return _aware_utc(value, "timestamp").isoformat()


def _aware_utc(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must return a timezone-aware datetime")
    return value.astimezone(UTC)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _secure_ledger_files(path: Path) -> None:
    _validate_existing_ledger(path)
    parent = _open_private_parent(path.parent, create=False)
    try:
        if parent.descriptor is not None:
            _secure_posix_journal(path, parent)
        else:
            _validate_windows_journal(path, parent)
    finally:
        parent.close()


def _secure_posix_journal(path: Path, parent: _PrivateParent) -> None:
    assert parent.descriptor is not None
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(f"{path.name}-journal", flags, dir_fd=parent.descriptor)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError("replay ticket journal is not a regular file") from exc
    try:
        journal_stat = os.fstat(descriptor)
        if not stat.S_ISREG(journal_stat.st_mode) or journal_stat.st_nlink != 1:
            raise RuntimeError("replay ticket journal is not a private regular file")
        if journal_stat.st_uid != os.geteuid():
            raise RuntimeError("replay ticket journal is not owned by this user")
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _validate_windows_journal(
    path: Path,
    parent: _PrivateParent,
) -> None:  # pragma: no cover - exercised by Windows CI
    journal_path = Path(f"{path}-journal")
    _validate_windows_parent_identity(parent)
    if (
        not journal_path.exists()
        and not journal_path.is_symlink()
        and not journal_path.is_junction()
    ):
        return
    _validate_windows_regular_path(journal_path)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor, _created = _open_descriptor(
        journal_path,
        flags=flags,
        create=False,
        dir_fd=None,
        error="replay ticket journal is not a regular file",
    )
    try:
        descriptor_stat = os.fstat(descriptor)
        if not stat.S_ISREG(descriptor_stat.st_mode) or descriptor_stat.st_nlink != 1:
            raise RuntimeError("replay ticket journal is not a private regular file")
        path_stat = _validate_windows_regular_path(journal_path)
        _validate_unchanged_regular_file(descriptor_stat, path_stat)
        _validate_windows_parent_identity(parent)
    finally:
        os.close(descriptor)
