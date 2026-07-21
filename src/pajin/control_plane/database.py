"""Durable Control Plane repository and transaction boundary.

Declarative records and frozen version metadata live in ``database_schema``.
Forward-only migrations and dialect validation live in ``database_migrations``.
Both remain re-exported here so existing callers keep a stable import surface.
"""

from __future__ import annotations

import time as time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import RLock

from sqlalchemy import create_engine, event, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pajin.control_plane.database_migrations import (
    _V2_MIGRATION_WRITE_LOCK_TABLES,
    _V3_MIGRATION_WRITE_LOCK_TABLES,
    _V4_MIGRATION_WRITE_LOCK_TABLES,
    _V5_MIGRATION_WRITE_LOCK_TABLES,
    _V6_MIGRATION_WRITE_LOCK_TABLES,
    _V7_MIGRATION_WRITE_LOCK_TABLES,
    _V9_MIGRATION_WRITE_LOCK_TABLES,
    _enable_sqlite_safety_pragmas,
    _initialize_schema,
    _install_append_only_trigger,
    _install_complete_append_only_guard,
    _json_object_is_valid_sql,
    _lock_v2_migration_writes,
    _lock_v3_migration_writes,
    _lock_v4_migration_writes,
    _lock_v5_migration_writes,
    _lock_v6_migration_writes,
    _lock_v7_migration_writes,
    _lock_v9_migration_writes,
    _migrate_v7_schema,
    _postgres_append_only_trigger_is_valid,
    _postgres_check_signature,
    _postgres_truncate_trigger_is_valid,
    _validate_append_only_trigger,
    _validate_current_schema,
    _validate_v9_schema,
    utc_now,
)
from pajin.control_plane.database_schema import (
    _SQLITE_BUSY_TIMEOUT_MILLISECONDS,
    _V2_METADATA,
    _V3_METADATA,
    _V4_METADATA,
    _V5_METADATA,
    _V6_METADATA,
    _V7_METADATA,
    _V9_METADATA,
    ARTIFACT_AUTHORITY_SCHEMA_VERSION,
    ARTIFACT_AUTHORITY_TABLES,
    COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
    CURRENT_CONTROL_PLANE_TABLES,
    CURRENT_SCHEMA_VERSION,
    DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
    LEGACY_SCHEMA_VERSION,
    MAX_JOB_LEASE_LIFETIME_SECONDS,
    REPLAY_AUTHORITY_SCHEMA_VERSION,
    REPLAY_AUTHORITY_TABLES,
    REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
    REPLAY_COMPILATION_AUTHORITY_TABLES,
    REPLAY_EXECUTION_CONTEXT_AUTHORITY_TABLES,
    REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION,
    REPLAY_FINALIZATION_AUTHORITY_TABLES,
    REPLAY_FINALIZATION_SCHEMA_VERSION,
    REPLAY_RESERVATION_AUTHORITY_TABLES,
    REPLAY_TOOL_PERMIT_AUTHORITY_TABLES,
    REPLAY_TOOL_PERMIT_SCHEMA_VERSION,
    SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION,
    V2_CONTROL_PLANE_TABLES,
    V3_CONTROL_PLANE_TABLES,
    V4_CONTROL_PLANE_TABLES,
    V5_CONTROL_PLANE_TABLES,
    V6_CONTROL_PLANE_TABLES,
    V7_CONTROL_PLANE_TABLES,
    V8_CONTROL_PLANE_TABLES,
    ApprovalRecord,
    ArtifactRecord,
    Base,
    CheckpointRecord,
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayBudgetAccountRecord,
    ReplayBudgetReservationRecord,
    ReplayCompilationRecord,
    ReplayEventRecord,
    ReplayExecutionContextRecord,
    ReplayFinalizationRecord,
    ReplayItemRecord,
    ReplayRateAccountRecord,
    ReplayRateReservationRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
    RunRecord,
    SchemaInitializationError,
    SchemaVersionRecord,
)

__all__ = [
    "ARTIFACT_AUTHORITY_SCHEMA_VERSION",
    "ARTIFACT_AUTHORITY_TABLES",
    "COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION",
    "CURRENT_CONTROL_PLANE_TABLES",
    "CURRENT_SCHEMA_VERSION",
    "DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION",
    "LEGACY_CONTROL_PLANE_TABLES",
    "LEGACY_SCHEMA_VERSION",
    "MAX_JOB_LEASE_LIFETIME_SECONDS",
    "REPLAY_AUTHORITY_SCHEMA_VERSION",
    "REPLAY_AUTHORITY_TABLES",
    "REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION",
    "REPLAY_COMPILATION_AUTHORITY_TABLES",
    "REPLAY_EXECUTION_CONTEXT_AUTHORITY_TABLES",
    "REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION",
    "REPLAY_FINALIZATION_AUTHORITY_TABLES",
    "REPLAY_FINALIZATION_SCHEMA_VERSION",
    "REPLAY_RESERVATION_AUTHORITY_TABLES",
    "REPLAY_TOOL_PERMIT_AUTHORITY_TABLES",
    "REPLAY_TOOL_PERMIT_SCHEMA_VERSION",
    "SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION",
    "V2_CONTROL_PLANE_TABLES",
    "V3_CONTROL_PLANE_TABLES",
    "V4_CONTROL_PLANE_TABLES",
    "V5_CONTROL_PLANE_TABLES",
    "V6_CONTROL_PLANE_TABLES",
    "V7_CONTROL_PLANE_TABLES",
    "V8_CONTROL_PLANE_TABLES",
    "_V2_METADATA",
    "_V2_MIGRATION_WRITE_LOCK_TABLES",
    "_V3_METADATA",
    "_V3_MIGRATION_WRITE_LOCK_TABLES",
    "_V4_METADATA",
    "_V4_MIGRATION_WRITE_LOCK_TABLES",
    "_V5_METADATA",
    "_V5_MIGRATION_WRITE_LOCK_TABLES",
    "_V6_METADATA",
    "_V6_MIGRATION_WRITE_LOCK_TABLES",
    "_V7_METADATA",
    "_V7_MIGRATION_WRITE_LOCK_TABLES",
    "_V9_METADATA",
    "_V9_MIGRATION_WRITE_LOCK_TABLES",
    "ApprovalRecord",
    "ArtifactRecord",
    "Base",
    "CheckpointRecord",
    "ControlPlaneRepository",
    "EventRecord",
    "JobRecord",
    "ReplayBatchRecord",
    "ReplayBudgetAccountRecord",
    "ReplayBudgetReservationRecord",
    "ReplayCompilationRecord",
    "ReplayEventRecord",
    "ReplayExecutionContextRecord",
    "ReplayFinalizationRecord",
    "ReplayItemRecord",
    "ReplayRateAccountRecord",
    "ReplayRateReservationRecord",
    "ReplayTicketRecord",
    "ReplayToolPermitRecord",
    "RunRecord",
    "SchemaInitializationError",
    "SchemaVersionRecord",
    "_enable_sqlite_safety_pragmas",
    "_initialize_schema",
    "_install_append_only_trigger",
    "_install_complete_append_only_guard",
    "_json_object_is_valid_sql",
    "_lock_v2_migration_writes",
    "_lock_v3_migration_writes",
    "_lock_v4_migration_writes",
    "_lock_v5_migration_writes",
    "_lock_v6_migration_writes",
    "_lock_v7_migration_writes",
    "_lock_v9_migration_writes",
    "_migrate_v7_schema",
    "_postgres_append_only_trigger_is_valid",
    "_postgres_check_signature",
    "_postgres_truncate_trigger_is_valid",
    "_validate_append_only_trigger",
    "_validate_current_schema",
    "_validate_v9_schema",
    "utc_now",
]


class ControlPlaneRepository:
    """Own the database engine and expose short, explicit transaction scopes."""

    def __init__(self, database_url: str, *, echo: bool = False) -> None:
        parsed_url = make_url(database_url)
        is_sqlite = parsed_url.get_backend_name() == "sqlite"
        is_memory_sqlite = is_sqlite and parsed_url.database in {None, "", ":memory:"}
        if database_url.startswith("sqlite:///"):
            raw_path = database_url.removeprefix("sqlite:///")
            if raw_path != ":memory:":
                Path(raw_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        connect_args: dict[str, object] = {}
        if is_sqlite:
            connect_args["check_same_thread"] = False
            connect_args["timeout"] = _SQLITE_BUSY_TIMEOUT_MILLISECONDS / 1_000
        engine_options: dict[str, object] = {}
        if is_memory_sqlite:
            engine_options["poolclass"] = StaticPool
        self.engine = create_engine(
            database_url,
            echo=echo,
            pool_pre_ping=True,
            connect_args=connect_args,
            **engine_options,
        )
        if is_sqlite:
            event.listen(self.engine, "connect", _enable_sqlite_safety_pragmas)
            event.listen(self.engine, "checkout", _enable_sqlite_safety_pragmas)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)
        # StaticPool deliberately shares one DBAPI connection for an in-memory
        # SQLite repository.  SQLAlchemy Sessions are thread-local objects, but
        # the underlying connection is not able to host overlapping transactions.
        self._sqlite_memory_lock = RLock() if is_memory_sqlite else None

    @property
    def dialect_name(self) -> str:
        return self.engine.dialect.name

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        """Open a mutation transaction with SQLite writer serialization."""

        with self._memory_sqlite_connection_scope():
            if self.dialect_name != "sqlite":
                with self._sessions.begin() as session:
                    yield session
                return
            # SQLite ignores SELECT ... FOR UPDATE. Acquire its single-writer
            # reservation before any service read so read-modify-write state
            # machines remain serializable across threads, repositories, and
            # processes instead of surfacing trigger/flush races to the loser.
            session = self._sessions()
            try:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise
            finally:
                session.close()

    @contextmanager
    def read_transaction(self) -> Iterator[Session]:
        """Open a rollback-only read scope without taking SQLite's writer reservation."""

        with self._memory_sqlite_connection_scope():
            session = self._sessions(autoflush=False)
            try:
                if self.dialect_name == "sqlite":
                    # Python's sqlite3 legacy transaction mode does not begin a DB
                    # transaction for SELECT. Start DEFERRED explicitly so multi-query
                    # responses (for example count + page) observe one snapshot.
                    session.connection().exec_driver_sql("BEGIN")
                yield session
                if session.new or session.dirty or session.deleted:
                    raise RuntimeError("read transaction cannot persist mutations")
            finally:
                # A read scope never commits. Disabling autoflush plus rollback keeps an
                # accidental ORM mutation from silently converting this into a writer.
                session.rollback()
                session.close()

    @contextmanager
    def _memory_sqlite_connection_scope(self) -> Iterator[None]:
        lock = self._sqlite_memory_lock
        if lock is None:
            yield
            return
        with lock:
            yield

    def initialize(self) -> None:
        """Initialize or migrate a recognized schema, failing closed on any drift."""

        with self._memory_sqlite_connection_scope():
            if self.dialect_name == "sqlite":
                with self.engine.connect() as connection:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                    try:
                        _initialize_schema(connection)
                    except BaseException:
                        connection.rollback()
                        raise
                    connection.commit()
                return
            with self.engine.begin() as connection:
                if self.dialect_name == "postgresql":
                    connection.exec_driver_sql("SELECT pg_advisory_xact_lock(742018311564702185)")
                _initialize_schema(connection)

    def close(self) -> None:
        with self._memory_sqlite_connection_scope():
            self.engine.dispose()

    def schema_version(self) -> int:
        """Return the validated current schema version."""

        with self._memory_sqlite_connection_scope(), self.engine.connect() as connection:
            _validate_current_schema(connection)
            version = connection.scalar(select(func.max(SchemaVersionRecord.version)))
            if version is None:
                raise SchemaInitializationError("cp_schema_version contains no migrations")
            return int(version)

    @staticmethod
    def next_event_sequence(session: Session, run_id: str) -> int:
        current = session.scalar(
            select(func.max(EventRecord.sequence)).where(EventRecord.run_id == run_id)
        )
        return int(current or 0) + 1

    @staticmethod
    def next_replay_event_sequence(session: Session, batch_id: str) -> int:
        current = session.scalar(
            select(func.max(ReplayEventRecord.sequence)).where(
                ReplayEventRecord.batch_id == batch_id
            )
        )
        return int(current or 0) + 1
