from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Thread
from threading import Event as ThreadEvent
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import MetaData, inspect, select, text, update
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.exc import DatabaseError, DBAPIError, IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from pajin.control_plane import database as database_module
from pajin.control_plane import database_dialect, database_migrations, database_schema
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import (
    _V2_METADATA,
    _V2_MIGRATION_WRITE_LOCK_TABLES,
    _V3_METADATA,
    _V3_MIGRATION_WRITE_LOCK_TABLES,
    _V4_METADATA,
    _V4_MIGRATION_WRITE_LOCK_TABLES,
    _V5_METADATA,
    _V5_MIGRATION_WRITE_LOCK_TABLES,
    _V6_METADATA,
    _V6_MIGRATION_WRITE_LOCK_TABLES,
    _V7_MIGRATION_WRITE_LOCK_TABLES,
    _V9_METADATA,
    _V9_MIGRATION_WRITE_LOCK_TABLES,
    ARTIFACT_AUTHORITY_SCHEMA_VERSION,
    COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
    CURRENT_CONTROL_PLANE_TABLES,
    CURRENT_SCHEMA_VERSION,
    DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
    REPLAY_AUTHORITY_SCHEMA_VERSION,
    REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
    REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION,
    REPLAY_FINALIZATION_SCHEMA_VERSION,
    REPLAY_TOOL_PERMIT_SCHEMA_VERSION,
    SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION,
    V2_CONTROL_PLANE_TABLES,
    V3_CONTROL_PLANE_TABLES,
    V4_CONTROL_PLANE_TABLES,
    V5_CONTROL_PLANE_TABLES,
    V6_CONTROL_PLANE_TABLES,
    V7_CONTROL_PLANE_TABLES,
    V8_CONTROL_PLANE_TABLES,
    ArtifactRecord,
    Base,
    ControlPlaneRepository,
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
    _validate_v9_schema,
)
from pajin.control_plane.models import (
    Principal,
    PrincipalRole,
    job_submission_authority_digest,
    non_replayable_submission_authority_digest,
    submission_authority_digest,
)


def _repository(path: Path) -> ControlPlaneRepository:
    return ControlPlaneRepository(f"sqlite:///{path.as_posix()}")


def test_database_compatibility_surface_reexports_owned_objects_by_identity() -> None:
    """Module extraction must not fork authority objects or break legacy imports."""

    exported_names = (
        "Base",
        "RunRecord",
        "JobRecord",
        "ReplayTicketRecord",
        "ReplayFinalizationRecord",
        "_V2_METADATA",
        "_V9_METADATA",
    )
    for name in exported_names:
        assert getattr(database_module, name) is getattr(database_schema, name)
    migration_exports = (
        "_V2_MIGRATION_WRITE_LOCK_TABLES",
        "_install_append_only_trigger",
        "_lock_v4_migration_writes",
        "_postgres_check_signature",
        "_validate_current_schema",
        "utc_now",
    )
    for name in migration_exports:
        assert getattr(database_module, name) is getattr(database_migrations, name)
    dialect_exports = (
        "_json_object_is_valid_sql",
        "_postgres_append_only_trigger_is_valid",
        "_postgres_check_signature",
        "_postgres_truncate_trigger_is_valid",
        "_validate_append_only_trigger",
    )
    for name in dialect_exports:
        assert getattr(database_migrations, name) is getattr(database_dialect, name)
    assert database_schema.Base.__module__ == "pajin.control_plane.database_schema"


def _create_legacy_schema(repository: ControlPlaneRepository) -> None:
    pending = set(LEGACY_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V9_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        connection.exec_driver_sql("DROP INDEX ux_cp_jobs_job_run")
        for operation in ("UPDATE", "DELETE"):
            connection.exec_driver_sql(
                f"""
                CREATE TRIGGER cp_events_no_{operation.lower()}
                BEFORE {operation} ON cp_events
                BEGIN SELECT RAISE(ABORT, 'cp_events is append-only'); END
                """
            )


def _create_v2_schema(repository: ControlPlaneRepository) -> None:
    pending = set(V2_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V2_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        for table_name in ("cp_events", "cp_replay_events"):
            for operation in ("UPDATE", "DELETE"):
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER {table_name}_no_{operation.lower()}
                    BEFORE {operation} ON {table_name}
                    BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
                    """
                )
        schema_version = _V2_METADATA.tables["cp_schema_version"]
        now = datetime.now(UTC)
        connection.execute(
            schema_version.insert(),
            [
                {
                    "version": 1,
                    "description": "legacy-control-plane-core",
                    "applied_at": now,
                },
                {
                    "version": 2,
                    "description": "replay-authority",
                    "applied_at": now,
                },
            ],
        )


def _create_v3_schema(repository: ControlPlaneRepository) -> None:
    pending = set(V3_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V3_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        for table_name in ("cp_events", "cp_artifacts", "cp_replay_events"):
            for operation in ("UPDATE", "DELETE"):
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER {table_name}_no_{operation.lower()}
                    BEFORE {operation} ON {table_name}
                    BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
                    """
                )
        schema_version = _V3_METADATA.tables["cp_schema_version"]
        now = datetime.now(UTC)
        connection.execute(
            schema_version.insert(),
            [
                {
                    "version": 1,
                    "description": "legacy-control-plane-core",
                    "applied_at": now,
                },
                {
                    "version": 2,
                    "description": "replay-authority",
                    "applied_at": now,
                },
                {
                    "version": 3,
                    "description": "artifact-authority",
                    "applied_at": now,
                },
            ],
        )


def _create_v4_schema(repository: ControlPlaneRepository) -> None:
    pending = set(V4_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V4_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        for table_name in (
            "cp_events",
            "cp_artifacts",
            "cp_replay_events",
            "cp_replay_compilations",
        ):
            for operation in ("UPDATE", "DELETE"):
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER {table_name}_no_{operation.lower()}
                    BEFORE {operation} ON {table_name}
                    BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
                    """
                )
        schema_version = _V4_METADATA.tables["cp_schema_version"]
        now = datetime.now(UTC)
        connection.execute(
            schema_version.insert(),
            [
                {
                    "version": 1,
                    "description": "legacy-control-plane-core",
                    "applied_at": now,
                },
                {
                    "version": 2,
                    "description": "replay-authority",
                    "applied_at": now,
                },
                {
                    "version": 3,
                    "description": "artifact-authority",
                    "applied_at": now,
                },
                {
                    "version": 4,
                    "description": "trusted-replay-compilation-authority",
                    "applied_at": now,
                },
            ],
        )


def _create_v5_schema(repository: ControlPlaneRepository) -> None:
    pending = set(V5_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V5_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        for table_name in (
            "cp_events",
            "cp_artifacts",
            "cp_replay_events",
            "cp_replay_compilations",
        ):
            for operation in ("UPDATE", "DELETE"):
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER {table_name}_no_{operation.lower()}
                    BEFORE {operation} ON {table_name}
                    BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
                    """
                )
        schema_version = _V5_METADATA.tables["cp_schema_version"]
        now = datetime.now(UTC)
        connection.execute(
            schema_version.insert(),
            [
                {
                    "version": version,
                    "description": description,
                    "applied_at": now,
                }
                for version, description in (
                    (1, "legacy-control-plane-core"),
                    (2, "replay-authority"),
                    (3, "artifact-authority"),
                    (4, "trusted-replay-compilation-authority"),
                    (5, "durable-replay-permit-authority"),
                )
            ],
        )


def _create_v6_schema(repository: ControlPlaneRepository) -> None:
    pending = set(V6_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V6_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        for table_name in (
            "cp_events",
            "cp_artifacts",
            "cp_replay_events",
            "cp_replay_compilations",
            "cp_replay_tool_permits",
        ):
            for operation in ("UPDATE", "DELETE"):
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER {table_name}_no_{operation.lower()}
                    BEFORE {operation} ON {table_name}
                    BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
                    """
                )
        schema_version = _V6_METADATA.tables["cp_schema_version"]
        now = datetime.now(UTC)
        connection.execute(
            schema_version.insert(),
            [
                {
                    "version": version,
                    "description": description,
                    "applied_at": now,
                }
                for version, description in (
                    (1, "legacy-control-plane-core"),
                    (2, "replay-authority"),
                    (3, "artifact-authority"),
                    (4, "trusted-replay-compilation-authority"),
                    (5, "durable-replay-permit-authority"),
                    (6, "replay-tool-call-permit-authority"),
                )
            ],
        )


def _create_v7_schema(repository: ControlPlaneRepository) -> None:
    pending = set(V7_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V9_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        for table_name in (
            "cp_events",
            "cp_artifacts",
            "cp_replay_events",
            "cp_replay_compilations",
            "cp_replay_tool_permits",
            "cp_replay_execution_contexts",
        ):
            for operation in ("UPDATE", "DELETE"):
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER {table_name}_no_{operation.lower()}
                    BEFORE {operation} ON {table_name}
                    BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
                    """
                )
        schema_version = _V9_METADATA.tables["cp_schema_version"]
        now = datetime.now(UTC)
        connection.execute(
            schema_version.insert(),
            [
                {
                    "version": version,
                    "description": description,
                    "applied_at": now,
                }
                for version, description in (
                    (1, "legacy-control-plane-core"),
                    (2, "replay-authority"),
                    (3, "artifact-authority"),
                    (4, "trusted-replay-compilation-authority"),
                    (5, "durable-replay-permit-authority"),
                    (6, "replay-tool-call-permit-authority"),
                    (7, "replay-execution-context-authority"),
                )
            ],
        )


def _create_v8_schema(repository: ControlPlaneRepository) -> None:
    _create_v7_schema(repository)
    with repository.engine.begin() as connection:
        _migrate_v7_schema(connection)


def _create_v9_schema(repository: ControlPlaneRepository) -> None:
    """Create an exact parser-safe v9 fixture without invoking the v10 chain."""

    _create_v8_schema(repository)
    with repository.engine.begin() as connection:
        finalization_table = _V9_METADATA.tables[ReplayFinalizationRecord.__tablename__]
        finalization_table.create(connection, checkfirst=False)
        _install_append_only_trigger(connection, finalization_table.name)
        _install_complete_append_only_guard(connection, finalization_table.name)
        schema_version = _V9_METADATA.tables[SchemaVersionRecord.__tablename__]
        connection.execute(
            schema_version.insert().values(
                version=REPLAY_FINALIZATION_SCHEMA_VERSION,
                description="server-derived-replay-finalization",
                applied_at=datetime.now(UTC),
            )
        )
        _validate_v9_schema(connection)


def test_postgres_v2_migration_locks_all_legacy_write_surfaces_in_fixed_order() -> None:
    statements: list[str] = []
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=statements.append,
    )

    _lock_v2_migration_writes(connection)  # type: ignore[arg-type]

    assert statements == [
        "LOCK TABLE " + ", ".join(_V2_MIGRATION_WRITE_LOCK_TABLES) + " IN ACCESS EXCLUSIVE MODE"
    ]
    assert _V2_MIGRATION_WRITE_LOCK_TABLES == (
        "cp_jobs",
        "cp_replay_batches",
        "cp_replay_items",
        "cp_replay_tickets",
        "cp_replay_events",
    )


def test_postgres_v3_migration_locks_all_legacy_write_surfaces_in_fixed_order() -> None:
    statements: list[str] = []
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=statements.append,
    )

    _lock_v3_migration_writes(connection)  # type: ignore[arg-type]

    assert statements == [
        "LOCK TABLE " + ", ".join(_V3_MIGRATION_WRITE_LOCK_TABLES) + " IN ACCESS EXCLUSIVE MODE"
    ]
    assert _V3_MIGRATION_WRITE_LOCK_TABLES == _V2_MIGRATION_WRITE_LOCK_TABLES


def test_postgres_v4_migration_locks_all_authority_surfaces_in_fixed_order() -> None:
    statements: list[str] = []
    savepoint_actions: list[str] = []
    savepoint = SimpleNamespace(
        commit=lambda: savepoint_actions.append("commit"),
        rollback=lambda: savepoint_actions.append("rollback"),
    )
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=statements.append,
        begin_nested=lambda: savepoint,
    )

    _lock_v4_migration_writes(connection)  # type: ignore[arg-type]

    assert statements == [
        "LOCK TABLE "
        + ", ".join(_V4_MIGRATION_WRITE_LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE NOWAIT"
    ]
    assert savepoint_actions == ["commit"]
    assert _V4_MIGRATION_WRITE_LOCK_TABLES == (
        "cp_artifacts",
        "cp_runs",
        "cp_jobs",
        "cp_replay_tickets",
        "cp_replay_items",
        "cp_replay_batches",
        "cp_replay_compilations",
        "cp_replay_events",
        "cp_approvals",
        "cp_checkpoints",
        "cp_events",
        "cp_schema_version",
    )


def test_postgres_v5_migration_locks_every_reservation_writer_atomically() -> None:
    statements: list[str] = []
    savepoint_actions: list[str] = []
    savepoint = SimpleNamespace(
        commit=lambda: savepoint_actions.append("commit"),
        rollback=lambda: savepoint_actions.append("rollback"),
    )
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=statements.append,
        begin_nested=lambda: savepoint,
    )

    _lock_v5_migration_writes(connection)  # type: ignore[arg-type]

    assert statements == [
        "LOCK TABLE "
        + ", ".join(_V5_MIGRATION_WRITE_LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE NOWAIT"
    ]
    assert savepoint_actions == ["commit"]
    assert _V5_MIGRATION_WRITE_LOCK_TABLES == (
        "cp_jobs",
        "cp_replay_tickets",
        "cp_replay_items",
        "cp_replay_batches",
        "cp_replay_budget_accounts",
        "cp_replay_rate_accounts",
        "cp_replay_budget_reservations",
        "cp_replay_rate_reservations",
        "cp_replay_compilations",
        "cp_replay_events",
        "cp_approvals",
        "cp_checkpoints",
        "cp_artifacts",
        "cp_events",
        "cp_schema_version",
        "cp_runs",
    )


def test_postgres_v6_migration_locks_every_context_writer_atomically() -> None:
    statements: list[str] = []
    savepoint_actions: list[str] = []
    savepoint = SimpleNamespace(
        commit=lambda: savepoint_actions.append("commit"),
        rollback=lambda: savepoint_actions.append("rollback"),
    )
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=statements.append,
        begin_nested=lambda: savepoint,
    )

    _lock_v6_migration_writes(connection)  # type: ignore[arg-type]

    assert statements == [
        "LOCK TABLE "
        + ", ".join(_V6_MIGRATION_WRITE_LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE NOWAIT"
    ]
    assert savepoint_actions == ["commit"]
    assert _V6_MIGRATION_WRITE_LOCK_TABLES == (
        "cp_jobs",
        "cp_replay_tickets",
        "cp_replay_items",
        "cp_replay_batches",
        "cp_replay_budget_accounts",
        "cp_replay_rate_accounts",
        "cp_replay_budget_reservations",
        "cp_replay_rate_reservations",
        "cp_replay_compilations",
        "cp_replay_tool_permits",
        "cp_replay_events",
        "cp_approvals",
        "cp_checkpoints",
        "cp_artifacts",
        "cp_events",
        "cp_schema_version",
        "cp_runs",
    )


def test_postgres_v7_migration_locks_the_complete_table_set_atomically() -> None:
    statements: list[str] = []
    savepoint_actions: list[str] = []
    savepoint = SimpleNamespace(
        commit=lambda: savepoint_actions.append("commit"),
        rollback=lambda: savepoint_actions.append("rollback"),
    )
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=statements.append,
        begin_nested=lambda: savepoint,
    )

    _lock_v7_migration_writes(connection)  # type: ignore[arg-type]

    assert statements == [
        "LOCK TABLE "
        + ", ".join(_V7_MIGRATION_WRITE_LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE NOWAIT"
    ]
    assert savepoint_actions == ["commit"]
    assert set(_V7_MIGRATION_WRITE_LOCK_TABLES) == V8_CONTROL_PLANE_TABLES
    assert len(_V7_MIGRATION_WRITE_LOCK_TABLES) == len(V8_CONTROL_PLANE_TABLES)


def test_postgres_v9_migration_locks_submission_and_lease_writers_atomically() -> None:
    statements: list[str] = []
    savepoint_actions: list[str] = []
    savepoint = SimpleNamespace(
        commit=lambda: savepoint_actions.append("commit"),
        rollback=lambda: savepoint_actions.append("rollback"),
    )
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=statements.append,
        begin_nested=lambda: savepoint,
    )

    _lock_v9_migration_writes(connection)  # type: ignore[arg-type]

    assert statements == [
        "LOCK TABLE "
        + ", ".join(_V9_MIGRATION_WRITE_LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE NOWAIT"
    ]
    assert savepoint_actions == ["commit"]
    assert _V9_MIGRATION_WRITE_LOCK_TABLES == (
        "cp_runs",
        "cp_jobs",
        "cp_events",
        "cp_schema_version",
    )


def test_atomic_migration_lock_releases_partial_set_before_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LockNotAvailable(RuntimeError):
        sqlstate = "55P03"

    lock_error = DBAPIError("LOCK TABLE", None, LockNotAvailable())
    statements: list[str] = []
    savepoint_actions: list[str] = []
    sleeps: list[float] = []

    def execute(statement: str) -> None:
        statements.append(statement)
        if len(statements) == 1:
            raise lock_error

    def begin_nested() -> SimpleNamespace:
        attempt = len(statements) + 1
        return SimpleNamespace(
            commit=lambda: savepoint_actions.append(f"commit:{attempt}"),
            rollback=lambda: savepoint_actions.append(f"rollback:{attempt}"),
        )

    monkeypatch.setattr("pajin.control_plane.database.time.sleep", sleeps.append)
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=execute,
        begin_nested=begin_nested,
    )

    _lock_v4_migration_writes(connection)  # type: ignore[arg-type]

    assert len(statements) == 2
    assert statements[0] == statements[1]
    assert savepoint_actions == ["rollback:1", "commit:2"]
    assert sleeps == [0.05]


def test_atomic_migration_lock_timeout_keeps_versioned_typed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LockNotAvailable(RuntimeError):
        sqlstate = "55P03"

    lock_error = DBAPIError("LOCK TABLE", None, LockNotAvailable())
    savepoint_actions: list[str] = []
    monotonic_values = iter([100.0, 105.0])
    monkeypatch.setattr(
        "pajin.control_plane.database.time.monotonic",
        lambda: next(monotonic_values),
    )
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        exec_driver_sql=lambda _statement: (_ for _ in ()).throw(lock_error),
        begin_nested=lambda: SimpleNamespace(
            commit=lambda: savepoint_actions.append("commit"),
            rollback=lambda: savepoint_actions.append("rollback"),
        ),
    )

    with pytest.raises(
        SchemaInitializationError,
        match="schema v9 migration could not exclude active writers",
    ) as raised:
        _lock_v9_migration_writes(connection)  # type: ignore[arg-type]

    assert raised.value.__cause__ is lock_error
    assert savepoint_actions == ["rollback"]


def test_sqlite_initialization_begins_with_immediate_write_reservation(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "sqlite-immediate.db")
    statements: list[str] = []

    def capture_statement(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(" ".join(statement.split()))

    sqlalchemy_event.listen(repository.engine, "before_cursor_execute", capture_statement)
    try:
        repository.initialize()
        assert statements[0] == "BEGIN IMMEDIATE"
    finally:
        repository.close()


def test_sqlite_safety_pragmas_are_reapplied_on_pool_checkout(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "sqlite-pragmas.db")
    try:
        repository.initialize()
        with repository.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA recursive_triggers").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA ignore_check_constraints").scalar_one() == 0
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 30_000
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.exec_driver_sql("PRAGMA recursive_triggers=OFF")
            connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
            connection.exec_driver_sql("PRAGMA busy_timeout=1")
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 0
            assert connection.exec_driver_sql("PRAGMA recursive_triggers").scalar_one() == 0
            assert connection.exec_driver_sql("PRAGMA ignore_check_constraints").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 1

        with repository.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA recursive_triggers").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA ignore_check_constraints").scalar_one() == 0
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 30_000
    finally:
        repository.close()


def test_in_memory_sqlite_uses_one_database_across_threads() -> None:
    repository = ControlPlaneRepository("sqlite:///:memory:")
    run_id = "run_in_memory_thread"
    observed: list[str | None] = []
    failures: list[BaseException] = []
    try:
        repository.initialize()
        assert isinstance(repository.engine.pool, StaticPool)
        with repository.transaction() as session:
            session.add(_run(run_id))

        def read_from_worker_thread() -> None:
            try:
                with repository.transaction() as session:
                    record = session.get(RunRecord, run_id)
                    observed.append(None if record is None else record.run_id)
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        worker = Thread(target=read_from_worker_thread)
        worker.start()
        worker.join(timeout=5)

        assert not worker.is_alive()
        assert failures == []
        assert observed == [run_id]
    finally:
        repository.close()


def test_in_memory_sqlite_serializes_concurrent_initializers() -> None:
    repository = ControlPlaneRepository("sqlite:///:memory:")
    barrier = Barrier(9)
    versions: list[int] = []
    failures: list[BaseException] = []

    def initialize() -> None:
        try:
            barrier.wait(timeout=5)
            repository.initialize()
            versions.append(repository.schema_version())
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    workers = [Thread(target=initialize) for _ in range(8)]
    try:
        for worker in workers:
            worker.start()
        barrier.wait(timeout=5)
        for worker in workers:
            worker.join(timeout=10)

        assert all(not worker.is_alive() for worker in workers)
        assert failures == []
        assert versions == [CURRENT_SCHEMA_VERSION] * len(workers)
        with repository.transaction() as session:
            assert session.scalars(
                select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
            ).all() == list(range(1, CURRENT_SCHEMA_VERSION + 1))
    finally:
        repository.close()


def _run(run_id: str) -> RunRecord:
    now = datetime.now(UTC)
    return RunRecord(
        run_id=run_id,
        campaign_name="migration-test",
        state="queued",
        input={"preserve": True},
        submission_key=f"submission-{run_id}",
        submission_authority_digest=non_replayable_submission_authority_digest(
            run_id=run_id,
            authority_kind="migration-test-fixture",
        ),
        current_checkpoint_id=None,
        created_at=now,
        updated_at=now,
    )


def _job(run_id: str, job_id: str) -> JobRecord:
    now = datetime.now(UTC)
    payload = {"preserve": True}
    idempotency_key = f"idempotency-{job_id}"
    return JobRecord(
        job_id=job_id,
        run_id=run_id,
        kind="campaign",
        state="succeeded",
        payload=payload,
        priority=0,
        attempts=1,
        max_attempts=1,
        idempotency_key=idempotency_key,
        submission_authority_digest=job_submission_authority_digest(
            job_id=job_id,
            run_id=run_id,
            job_kind="campaign",
            payload=payload,
            max_attempts=1,
            idempotency_key=idempotency_key,
        ),
        available_at=now,
        lease_owner=None,
        lease_token_hash=None,
        lease_expires_at=None,
        heartbeat_at=None,
        result={"status": "completed"},
        error=None,
        created_at=now,
        updated_at=now,
    )


def _insert_frozen_record(
    session: Session,
    record: RunRecord | JobRecord,
    *,
    metadata: MetaData,
) -> None:
    """Insert a core row without making the current ORM reference future columns."""

    table = metadata.tables[record.__tablename__]
    session.execute(
        table.insert().values(
            {column.name: getattr(record, column.name) for column in table.columns}
        )
    )


def _add_versioned_record(
    session: Session,
    record: RunRecord | JobRecord,
) -> None:
    """Use current ORM only when the fixture database has its future columns."""

    table_name = record.__tablename__
    actual_columns = {
        str(column["name"]) for column in inspect(session.connection()).get_columns(table_name)
    }
    frozen_columns = set(_V9_METADATA.tables[table_name].c.keys())
    if actual_columns == frozen_columns:
        _insert_frozen_record(session, record, metadata=_V9_METADATA)
        return
    session.add(record)


def _artifact(run_id: str, job_id: str) -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=f"artifact_{'1' * 32}",
        repository_version=1,
        producer_run_id=run_id,
        producer_job_id=job_id,
        producer_attempt=1,
        sealed_run_id="sealed-migration-run",
        media_type="application/vnd.pajin.run+json",
        schema_kind="pajin.run.v1",
        byte_length=512,
        content_digest="a" * 64,
        root_digest="b" * 64,
        created_by="migration-test-operator",
        storage_key="objects/artifact-migration-v1",
        idempotency_key="artifact-admission-migration-v1",
        admission_digest="c" * 64,
        created_at=datetime.now(UTC),
    )


def _batch(run_id: str, batch_id: str = "batch_migration") -> ReplayBatchRecord:
    now = datetime.now(UTC)
    return ReplayBatchRecord(
        batch_id=batch_id,
        source_run_id=run_id,
        idempotency_key=f"idempotency-{batch_id}",
        campaign_name="migration-test",
        created_by="migration-test-operator",
        source_artifact_id=f"artifact_{'1' * 32}",
        source_repository_version=1,
        source_content_digest="a" * 64,
        source_root_digest="b" * 64,
        source_artifact_run_id="sealed-migration-run",
        source_media_type="application/vnd.pajin.run+json",
        source_schema_kind="pajin.run.v1",
        source_byte_length=512,
        source_created_by="migration-test-operator",
        mode="ai-redteam",
        purpose="confirmation",
        policy_version="policy-v1",
        state="planned",
        cas_version=1,
        cancellation_reason=None,
        created_at=now,
        updated_at=now,
        cancelled_at=None,
    )


def _item(
    source_run_id: str,
    replay_run_id: str,
    *,
    item_id: str = "item_migration",
    batch_id: str = "batch_migration",
) -> ReplayItemRecord:
    now = datetime.now(UTC)
    return ReplayItemRecord(
        item_id=item_id,
        batch_id=batch_id,
        source_run_id=source_run_id,
        replay_run_id=replay_run_id,
        ordinal=0,
        candidate_id="candidate-migration",
        candidate_digest="d" * 64,
        contract_digest="e" * 64,
        compilation_digest="f" * 64,
        grant_digest="1" * 64,
        state="pending",
        required_attempts=1,
        max_attempts=1,
        attempts=0,
        created_at=now,
        updated_at=now,
    )


def _compilation(
    *,
    compilation_id: str = f"replay-compilation_{'6' * 32}",
    item_id: str = "item_migration",
    batch_id: str = "batch_migration",
    candidate_id: str = "candidate-migration",
    replay_run_id: str,
    canonical_compilation: bytes = b'{"schemaVersion":1}',
    byte_length: int | None = None,
    candidate_digest: str = "d" * 64,
    contract_digest: str = "e" * 64,
    compilation_digest: str = "f" * 64,
    grant_digest: str = "1" * 64,
) -> ReplayCompilationRecord:
    return ReplayCompilationRecord(
        compilation_id=compilation_id,
        item_id=item_id,
        batch_id=batch_id,
        candidate_id=candidate_id,
        replay_run_id=replay_run_id,
        candidate_digest=candidate_digest,
        contract_digest=contract_digest,
        compilation_digest=compilation_digest,
        grant_digest=grant_digest,
        canonical_compilation=canonical_compilation,
        byte_length=(len(canonical_compilation) if byte_length is None else byte_length),
        created_at=datetime.now(UTC),
    )


def _seed_replay_item_authority(
    repository: ControlPlaneRepository,
) -> tuple[str, str, str]:
    source_run_id = f"run_{'2' * 32}"
    source_job_id = f"job_{'3' * 32}"
    replay_run_id = f"run_{'4' * 32}"
    with repository.transaction() as session:
        _add_versioned_record(session, _run(source_run_id))
        _add_versioned_record(session, _run(replay_run_id))
        session.flush()
        _add_versioned_record(session, _job(source_run_id, source_job_id))
        session.flush()
        session.add(_artifact(source_run_id, source_job_id))
        session.flush()
        session.add(_batch(source_run_id))
        session.flush()
        session.add(_item(source_run_id, replay_run_id))
    return source_run_id, source_job_id, replay_run_id


def _seed_v5_issuance_prerequisites(
    repository: ControlPlaneRepository,
) -> dict[str, object]:
    source_run_id, _, planned_replay_run_id = _seed_replay_item_authority(repository)
    fresh_replay_run_id = f"run_{'5' * 32}"
    compilation_id = f"replay-compilation_{'7' * 32}"
    budget_account_id = f"replay-budget-account_{'8' * 32}"
    rate_account_id = f"replay-rate-account_{'9' * 32}"
    budget_reservation_id = f"budget-reservation_{'a' * 32}"
    rate_reservation_id = f"rate-reservation_{'b' * 32}"
    replay_job_id = f"job_{'c' * 32}"
    now = datetime.now(UTC)
    with repository.transaction() as session:
        session.add(_compilation(replay_run_id=planned_replay_run_id))
        _add_versioned_record(session, _run(fresh_replay_run_id))
        session.flush()
        session.add(
            _compilation(
                compilation_id=compilation_id,
                replay_run_id=fresh_replay_run_id,
                compilation_digest="2" * 64,
                grant_digest="3" * 64,
                canonical_compilation=b'{"kind":"ReplayCompilation","fresh":true}',
            )
        )
        session.add(
            ReplayBudgetAccountRecord(
                budget_account_id=budget_account_id,
                source_run_id=source_run_id,
                source_root_digest="b" * 64,
                campaign_name="migration-test",
                budget_digest="4" * 64,
                max_tool_calls=10,
                baseline_used_calls=2,
                reserved_calls=2,
                consumed_calls=0,
                released_calls=0,
                cas_version=1,
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            ReplayRateAccountRecord(
                rate_account_id=rate_account_id,
                source_run_id=source_run_id,
                source_root_digest="b" * 64,
                campaign_name="migration-test",
                rate_limits_digest="5" * 64,
                ledger_id=f"rate-ledger_{'6' * 32}",
                max_requests_per_minute=10,
                observed_request_units=2,
                observed_at=now - timedelta(minutes=1),
                window_seconds=60,
                cas_version=1,
                created_at=now,
                updated_at=now,
            )
        )
        session.flush()
        session.add(
            ReplayBudgetReservationRecord(
                budget_reservation_id=budget_reservation_id,
                budget_account_id=budget_account_id,
                item_id="item_migration",
                batch_id="batch_migration",
                compilation_id=compilation_id,
                attempt_number=1,
                total_calls=2,
                consumed_calls=0,
                released_calls=0,
                state="active",
                created_at=now,
                updated_at=now,
                released_at=None,
            )
        )
        session.add(
            ReplayRateReservationRecord(
                rate_reservation_id=rate_reservation_id,
                rate_account_id=rate_account_id,
                item_id="item_migration",
                batch_id="batch_migration",
                compilation_id=compilation_id,
                attempt_number=1,
                total_request_units=2,
                consumed_request_units=0,
                released_request_units=0,
                state="active",
                reserved_at=now,
                expires_at=now + timedelta(minutes=1),
                updated_at=now,
                released_at=None,
            )
        )
        _add_versioned_record(
            session,
            JobRecord(
                job_id=replay_job_id,
                run_id=fresh_replay_run_id,
                kind="internal-replay",
                state="queued",
                payload={"authority": "v5"},
                priority=0,
                attempts=0,
                max_attempts=1,
                idempotency_key="v5-replay-ticket-authority",
                submission_authority_digest=job_submission_authority_digest(
                    job_id=replay_job_id,
                    run_id=fresh_replay_run_id,
                    job_kind="internal-replay",
                    payload={"authority": "v5"},
                    max_attempts=1,
                    idempotency_key="v5-replay-ticket-authority",
                ),
                available_at=now,
                lease_owner=None,
                lease_token_hash=None,
                lease_expires_at=None,
                heartbeat_at=None,
                result=None,
                error=None,
                created_at=now,
                updated_at=now,
            ),
        )

    return {
        "ticket_id": f"replay-ticket_{'d' * 32}",
        "batch_id": "batch_migration",
        "item_id": "item_migration",
        "job_id": replay_job_id,
        "replay_run_id": fresh_replay_run_id,
        "attempt_number": 1,
        "fencing_value": 1,
        "state": "issued",
        "grant_digest": "3" * 64,
        "source_root_digest": "b" * 64,
        "compilation_digest": "2" * 64,
        "compilation_id": compilation_id,
        "budget_reservation_id": budget_reservation_id,
        "rate_reservation_id": rate_reservation_id,
        "executor_profile": None,
        "claim_principal": None,
        "lease_token_hash": None,
        "result_digest": None,
        "abandon_reason": None,
        "issued_at": now,
        "expires_at": now + timedelta(minutes=1),
        "claimed_at": None,
        "lease_expires_at": None,
        "finalized_at": None,
        "abandoned_at": None,
        "updated_at": now,
    }


def _activate_v5_ticket_graph(
    repository: ControlPlaneRepository,
    ticket_values: dict[str, object],
) -> None:
    with repository.transaction() as session:
        batch = session.get(ReplayBatchRecord, ticket_values["batch_id"])
        item = session.get(ReplayItemRecord, ticket_values["item_id"])
        assert batch is not None and item is not None
        batch.state = "running"
        item.replay_run_id = str(ticket_values["replay_run_id"])
        item.compilation_digest = str(ticket_values["compilation_digest"])
        item.grant_digest = str(ticket_values["grant_digest"])
        item.state = "queued"
        item.attempts = int(ticket_values["attempt_number"])
        run_table = _V9_METADATA.tables[RunRecord.__tablename__]
        session.execute(
            run_table.update()
            .where(run_table.c.run_id == ticket_values["replay_run_id"])
            .values(state="queued")
        )
        session.add(ReplayTicketRecord(**ticket_values))


def _claim_v6_ticket_graph(
    repository: ControlPlaneRepository,
    ticket_values: dict[str, object],
) -> None:
    now = datetime.now(UTC)
    with repository.transaction() as session:
        ticket = session.get(ReplayTicketRecord, ticket_values["ticket_id"])
        assert ticket is not None
        ticket.state = "claimed"
        ticket.claim_principal = "migration-test-worker"
        ticket.executor_profile = "restricted-reproducer"
        ticket.lease_token_hash = "4" * 64
        ticket.claimed_at = now
        ticket.lease_expires_at = now + timedelta(seconds=30)
        ticket.updated_at = now


def _permit_values(ticket_values: dict[str, object]) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "permit_id": f"replay-permit_{'1' * 32}",
        "permit_digest": "2" * 64,
        "replay_request_id": f"tool_replay_{'3' * 32}",
        "job_id": ticket_values["job_id"],
        "batch_id": ticket_values["batch_id"],
        "item_id": ticket_values["item_id"],
        "ticket_id": ticket_values["ticket_id"],
        "compilation_id": ticket_values["compilation_id"],
        "budget_reservation_id": ticket_values["budget_reservation_id"],
        "rate_reservation_id": ticket_values["rate_reservation_id"],
        "replay_run_id": ticket_values["replay_run_id"],
        "attempt_number": ticket_values["attempt_number"],
        "fencing_value": ticket_values["fencing_value"],
        "call_ordinal": 1,
        "issued_to": "migration-test-worker",
        "executor_profile": "restricted-reproducer",
        "lease_token_hash": "4" * 64,
        "source_root_digest": ticket_values["source_root_digest"],
        "compilation_digest": ticket_values["compilation_digest"],
        "grant_digest": ticket_values["grant_digest"],
        "original_request_id": "tool_original_migration",
        "tool_id": "ai-chat-probe",
        "tool_version": "1.0.0",
        "target_id": "target-migration",
        "target": "https://example.invalid/chat",
        "method": "POST",
        "compiled_argument_digest": "5" * 64,
        "tool_call_units": 1,
        "request_units": 1,
        "issued_at": now,
        "expires_at": now + timedelta(seconds=30),
        "rate_window_expires_at": now + timedelta(seconds=60),
    }


def _execution_context_values(ticket_values: dict[str, object]) -> dict[str, object]:
    canonical_context = (
        b'{"kind":"ReplayExecutionContext","schemaVersion":"pajin.dev/replay/v1alpha1"}'
    )
    return {
        "context_id": f"replay-context_{'5' * 32}",
        "compilation_id": ticket_values["compilation_id"],
        "item_id": ticket_values["item_id"],
        "batch_id": ticket_values["batch_id"],
        "replay_run_id": ticket_values["replay_run_id"],
        "compilation_digest": ticket_values["compilation_digest"],
        "grant_digest": ticket_values["grant_digest"],
        "context_digest": "6" * 64,
        "canonical_context": canonical_context,
        "byte_length": len(canonical_context),
        "required_executor_profile": "kisa-exact-v1",
        "output_staging_id": f"stage_{'7' * 32}",
        "created_at": datetime.now(UTC),
    }


def _v2_batch_values(run_id: str, batch_id: str) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "batch_id": batch_id,
        "source_run_id": run_id,
        "idempotency_key": f"idempotency-{batch_id}",
        "campaign_name": "migration-test",
        "created_by": "migration-test-operator",
        "source_artifact_id": "unverified-artifact",
        "source_repository_version": 1,
        "source_content_digest": "a" * 64,
        "source_root_digest": "b" * 64,
        "source_media_type": "application/vnd.pajin.run+json",
        "source_schema_kind": "pajin.run.v1",
        "source_byte_length": 512,
        "source_created_by": "migration-test-operator",
        "mode": "ai-redteam",
        "purpose": "confirmation",
        "policy_version": "policy-v1",
        "state": "planned",
        "cas_version": 1,
        "cancellation_reason": None,
        "created_at": now,
        "updated_at": now,
        "cancelled_at": None,
    }


def test_empty_database_migrates_to_current_schema_and_restart_validates(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "empty.db")
    try:
        repository.initialize()
        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        assert {
            name for name in inspect(repository.engine).get_table_names() if name.startswith("cp_")
        } == CURRENT_CONTROL_PLANE_TABLES
        with repository.transaction() as session:
            versions = session.scalars(
                select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
            ).all()
        assert versions == [
            1,
            REPLAY_AUTHORITY_SCHEMA_VERSION,
            ARTIFACT_AUTHORITY_SCHEMA_VERSION,
            REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
            DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION,
            REPLAY_TOOL_PERMIT_SCHEMA_VERSION,
            REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION,
            COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
            REPLAY_FINALIZATION_SCHEMA_VERSION,
            CURRENT_SCHEMA_VERSION,
        ]

        repository.initialize()
        with repository.transaction() as session:
            assert (
                session.scalar(select(text("count(*)")).select_from(SchemaVersionRecord))
                == CURRENT_SCHEMA_VERSION
            )
    finally:
        repository.close()


def test_exact_v9_migration_backfills_submission_and_lease_authority_idempotently(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v9-submission-lease-authority.db")
    run_id = "run_v9_public_submission"
    ambiguous_run_id = "run_v9_ambiguous_submission"
    job_id = "job_v9_public_submission"
    submission_key = "v9-public-submission-key"
    actor = "v9-operator"
    input_value = {"objective": "preserve exact v9 authority"}
    heartbeat_at = datetime(2026, 1, 1, tzinfo=UTC)
    lease_expires_at = heartbeat_at + timedelta(seconds=30)
    try:
        _create_v9_schema(repository)
        with repository.transaction() as session:
            public_run = _run(run_id)
            public_run.campaign_name = "v9-campaign"
            public_run.input = input_value
            public_run.submission_key = submission_key
            _insert_frozen_record(session, public_run, metadata=_V9_METADATA)

            ambiguous_run = _run(ambiguous_run_id)
            ambiguous_run.submission_key = "v9-ambiguous-key"
            _insert_frozen_record(session, ambiguous_run, metadata=_V9_METADATA)

            job = _job(run_id, job_id)
            job.kind = "campaign"
            job.state = "leased"
            job.payload = {"input": input_value}
            job.attempts = 1
            job.max_attempts = 3
            job.idempotency_key = f"submission:{submission_key}"
            job.lease_owner = "v9-worker"
            job.lease_token_hash = "a" * 64
            job.lease_expires_at = lease_expires_at
            job.heartbeat_at = heartbeat_at
            job.result = None
            _insert_frozen_record(session, job, metadata=_V9_METADATA)

            event_table = _V9_METADATA.tables[EventRecord.__tablename__]
            session.execute(
                event_table.insert().values(
                    event_id="event_v9_public_submission",
                    run_id=run_id,
                    sequence=1,
                    event_type="run.submitted",
                    actor=actor,
                    payload={
                        "campaignName": "v9-campaign",
                        "jobId": job_id,
                        "jobKind": "campaign",
                    },
                    occurred_at=heartbeat_at,
                )
            )

        repository.initialize()

        with repository.transaction() as session:
            public_run = session.get(RunRecord, run_id)
            ambiguous_run = session.get(RunRecord, ambiguous_run_id)
            migrated_job = session.get(JobRecord, job_id)
            assert public_run is not None
            assert ambiguous_run is not None
            assert migrated_job is not None
            assert public_run.submission_authority_digest == submission_authority_digest(
                actor=actor,
                campaign_name="v9-campaign",
                input_value=input_value,
                idempotency_key=submission_key,
                job_kind="campaign",
                max_attempts=3,
            )
            assert ambiguous_run.submission_authority_digest == (
                non_replayable_submission_authority_digest(
                    run_id=ambiguous_run_id,
                    authority_kind="legacy-unproven-v9",
                )
            )
            assert migrated_job.submission_authority_digest == (
                job_submission_authority_digest(
                    job_id=job_id,
                    run_id=run_id,
                    job_kind="campaign",
                    payload={"input": input_value},
                    max_attempts=3,
                    idempotency_key=f"submission:{submission_key}",
                )
            )
            assert migrated_job.lease_deadline_at == migrated_job.lease_expires_at
            assert migrated_job.heartbeat_event_at == migrated_job.heartbeat_at

        assert repository.schema_version() == SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION
        repository.initialize()
        with repository.transaction() as session:
            versions = session.scalars(
                select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
            ).all()
            assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))
    finally:
        repository.close()


def test_partial_v10_authority_migration_is_rejected_without_history_repair(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "partial-v10-authority.db")
    try:
        _create_v9_schema(repository)
        with repository.engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE cp_runs ADD COLUMN submission_authority_digest VARCHAR(64)"
            )

        with pytest.raises(SchemaInitializationError, match="cp_runs"):
            repository.initialize()

        with repository.engine.connect() as connection:
            assert connection.scalar(text("SELECT max(version) FROM cp_schema_version")) == 9
            assert "lease_deadline_at" not in {
                column["name"] for column in inspect(connection).get_columns("cp_jobs")
            }
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("column_name", "invalid_json"),
    [("input", "{"), ("payload", "[]")],
)
def test_v9_migration_rejects_malformed_or_non_object_core_json_before_hydration(
    tmp_path: Path,
    column_name: str,
    invalid_json: str,
) -> None:
    path = tmp_path / f"v9-invalid-{column_name}.db"
    repository = _repository(path)
    _create_v9_schema(repository)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    with repository.engine.begin() as connection:
        if column_name == "input":
            connection.exec_driver_sql(
                """
                INSERT INTO cp_runs (
                    run_id, campaign_name, state, input, submission_key,
                    current_checkpoint_id, created_at, updated_at
                ) VALUES (?, 'invalid-json', 'queued', ?, ?, NULL, ?, ?)
                """,
                (
                    "run_v9_invalid_json",
                    invalid_json,
                    "v9-invalid-json-run",
                    now,
                    now,
                ),
            )
        else:
            run = _run("run_v9_invalid_job_json")
            run_table = _V9_METADATA.tables[RunRecord.__tablename__]
            connection.execute(
                run_table.insert().values(
                    {column.name: getattr(run, column.name) for column in run_table.columns}
                )
            )
            connection.exec_driver_sql(
                """
                INSERT INTO cp_jobs (
                    job_id, run_id, kind, state, payload, priority, attempts,
                    max_attempts, idempotency_key, available_at, lease_owner,
                    lease_token_hash, lease_expires_at, heartbeat_at, result,
                    error, created_at, updated_at
                ) VALUES (?, ?, 'campaign', 'queued', ?, 0, 0, 1, ?, ?,
                    NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    "job_v9_invalid_json",
                    run.run_id,
                    invalid_json,
                    "v9-invalid-json-job",
                    now,
                    now,
                    now,
                ),
            )

    with pytest.raises(SchemaInitializationError, match="JSON authority"):
        repository.initialize()
    with repository.engine.connect() as connection:
        assert connection.scalar(text("SELECT max(version) FROM cp_schema_version")) == 9
        assert "submission_authority_digest" not in {
            column["name"] for column in inspect(connection).get_columns("cp_runs")
        }
    repository.close()


def test_v9_migration_rejects_malformed_event_payload_before_hydration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v9-invalid-event-payload.db"
    repository = _repository(path)
    _create_v9_schema(repository)
    run = _run("run_v9_invalid_event_json")
    run_table = _V9_METADATA.tables[RunRecord.__tablename__]
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    with repository.engine.begin() as connection:
        connection.execute(
            run_table.insert().values(
                {column.name: getattr(run, column.name) for column in run_table.columns}
            )
        )
        connection.exec_driver_sql(
            """
            INSERT INTO cp_events (
                event_id, run_id, sequence, event_type, actor, payload, occurred_at
            ) VALUES (?, ?, 1, 'invalid-json', 'migration-test', ?, ?)
            """,
            ("event_v9_invalid_json", run.run_id, "{", now),
        )

    with pytest.raises(SchemaInitializationError, match=r"cp_events\.payload"):
        repository.initialize()
    with repository.engine.connect() as connection:
        assert connection.scalar(text("SELECT max(version) FROM cp_schema_version")) == 9
        assert "submission_authority_digest" not in {
            column["name"] for column in inspect(connection).get_columns("cp_runs")
        }
    repository.close()


def test_v9_migration_rejects_noncanonical_job_datetime_before_hydration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v9-invalid-job-datetime.db"
    repository = _repository(path)
    _create_v9_schema(repository)
    run = _run("run_v9_invalid_job_datetime")
    run_table = _V9_METADATA.tables[RunRecord.__tablename__]
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    with repository.engine.begin() as connection:
        connection.execute(
            run_table.insert().values(
                {column.name: getattr(run, column.name) for column in run_table.columns}
            )
        )
        connection.exec_driver_sql(
            """
            INSERT INTO cp_jobs (
                job_id, run_id, kind, state, payload, priority, attempts,
                max_attempts, idempotency_key, available_at, lease_owner,
                lease_token_hash, lease_expires_at, heartbeat_at, result,
                error, created_at, updated_at
            ) VALUES (?, ?, 'campaign', 'queued', '{}', 0, 0, 1, ?, ?,
                NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)
            """,
            (
                "job_v9_invalid_datetime",
                run.run_id,
                "v9-invalid-job-datetime",
                "2026-01-01T00:00:00+00:00",
                now,
                now,
            ),
        )

    with pytest.raises(
        SchemaInitializationError,
        match=r"available_at.*datetime authority",
    ):
        repository.initialize()
    with repository.engine.connect() as connection:
        assert connection.scalar(text("SELECT max(version) FROM cp_schema_version")) == 9
        assert "lease_deadline_at" not in {
            column["name"] for column in inspect(connection).get_columns("cp_jobs")
        }
    repository.close()


def test_concurrent_sqlite_v9_initializers_serialize_one_v10_migration(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "concurrent-v10-migration.db"
    fixture_repository = _repository(database_path)
    try:
        _create_v9_schema(fixture_repository)
    finally:
        fixture_repository.close()

    barrier = Barrier(3)
    versions: list[int] = []
    failures: list[BaseException] = []

    def initialize() -> None:
        repository = _repository(database_path)
        try:
            barrier.wait(timeout=5)
            repository.initialize()
            versions.append(repository.schema_version())
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            repository.close()

    workers = [Thread(target=initialize) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=5)
    for worker in workers:
        worker.join(timeout=10)

    assert all(not worker.is_alive() for worker in workers)
    assert failures == []
    assert sorted(versions) == [CURRENT_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION]
    repository = _repository(database_path)
    try:
        with repository.transaction() as session:
            assert session.scalars(
                select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
            ).all() == list(range(1, CURRENT_SCHEMA_VERSION + 1))
    finally:
        repository.close()


def test_v10_authority_migration_rolls_back_columns_guards_and_history_on_failure(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v10-authority-rollback.db")
    run_id = "run_v10_rollback_preserved"
    _create_v9_schema(repository)
    with repository.transaction() as session:
        _insert_frozen_record(session, _run(run_id), metadata=_V9_METADATA)

    def fail_during_guard_install(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if "CREATE TRIGGER cp_runs_submission_authority_guard_insert" in statement:
            raise RuntimeError("simulated v10 authority guard failure")

    sqlalchemy_event.listen(repository.engine, "before_cursor_execute", fail_during_guard_install)
    try:
        with pytest.raises(RuntimeError, match="simulated v10"):
            repository.initialize()
    finally:
        sqlalchemy_event.remove(
            repository.engine,
            "before_cursor_execute",
            fail_during_guard_install,
        )

    with repository.engine.connect() as connection:
        assert connection.scalar(text("SELECT max(version) FROM cp_schema_version")) == 9
        assert "submission_authority_digest" not in {
            column["name"] for column in inspect(connection).get_columns("cp_runs")
        }
        assert {
            "submission_authority_digest",
            "lease_deadline_at",
            "heartbeat_event_at",
        }.isdisjoint(column["name"] for column in inspect(connection).get_columns("cp_jobs"))
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' "
                    "AND name LIKE '%_authority_guard_%'"
                )
            )
            == 0
        )
        preserved = (
            connection.execute(
                select(_V9_METADATA.tables["cp_runs"]).where(
                    _V9_METADATA.tables["cp_runs"].c.run_id == run_id
                )
            )
            .mappings()
            .one()
        )
        assert preserved["input"] == {"preserve": True}

    repository.initialize()
    assert repository.schema_version() == CURRENT_SCHEMA_VERSION
    repository.close()


def test_sqlite_v10_guards_reject_late_v9_writes_and_identity_drift(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v10-late-v9-writer.db"
    repository = _repository(path)
    run_id = "run_v10_guard"
    job_id = "job_v10_guard"
    try:
        repository.initialize()
        with repository.transaction() as session:
            session.add(_run(run_id))
            session.flush()
            session.add(_job(run_id, job_id))
    finally:
        repository.close()

    direct = sqlite3.connect(path)
    now = datetime.now(UTC).isoformat()
    try:
        with pytest.raises(sqlite3.IntegrityError, match="submission authority"):
            direct.execute(
                """
                INSERT INTO cp_runs (
                    run_id, campaign_name, state, input, submission_key,
                    current_checkpoint_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "run_late_v9_writer",
                    "late-v9",
                    "queued",
                    '{"legacy":true}',
                    "late-v9-key",
                    None,
                    now,
                    now,
                ),
            )
        direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                """
                INSERT INTO cp_jobs (
                    job_id, run_id, kind, state, payload, priority, attempts,
                    max_attempts, idempotency_key, available_at, lease_owner,
                    lease_token_hash, lease_expires_at, heartbeat_at, result,
                    error, created_at, updated_at, lease_deadline_at,
                    heartbeat_event_at
                ) VALUES (?, ?, 'campaign', 'queued', '{}', 0, 0, 1, ?, ?,
                    NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL, NULL)
                """,
                (
                    "job_late_v9_writer",
                    run_id,
                    "late-v9-job-key",
                    now,
                    now,
                    now,
                ),
            )
        direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                """
                UPDATE cp_jobs SET state = 'leased', lease_owner = 'old-worker',
                    lease_token_hash = ?, lease_expires_at = ?, heartbeat_at = ?
                WHERE job_id = ?
                """,
                ("a" * 64, now, now, job_id),
            )
        direct.rollback()

        for statement in (
            "UPDATE cp_runs SET run_id = 'run_v10_guard_renamed' WHERE run_id = ?",
            "UPDATE cp_runs SET campaign_name = 'drifted' WHERE run_id = ?",
            "UPDATE cp_runs SET input = '{\"drifted\":true}' WHERE run_id = ?",
            "UPDATE cp_jobs SET job_id = 'job_v10_guard_renamed' WHERE job_id = ?",
            "UPDATE cp_jobs SET payload = '{\"drifted\":true}' WHERE job_id = ?",
            "UPDATE cp_jobs SET max_attempts = 2 WHERE job_id = ?",
            f"UPDATE cp_jobs SET submission_authority_digest = '{'f' * 64}' WHERE job_id = ?",
            "UPDATE cp_jobs SET result = '{\"tampered\":true}' WHERE job_id = ?",
            "UPDATE cp_jobs SET state = 'queued' WHERE job_id = ?",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="authority"):
                direct.execute(statement, (run_id if "cp_runs" in statement else job_id,))
            direct.rollback()

        for statement, identifier in (
            ("UPDATE cp_runs SET state = 'unknown' WHERE run_id = ?", run_id),
            ("DELETE FROM cp_jobs WHERE job_id = ?", job_id),
            ("DELETE FROM cp_runs WHERE run_id = ?", run_id),
        ):
            with pytest.raises(sqlite3.IntegrityError, match=r"authority|identity"):
                direct.execute(statement, (identifier,))
            direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="submission authority"):
            direct.execute(
                """
                INSERT INTO cp_runs (
                    run_id, campaign_name, state, input, submission_key,
                    current_checkpoint_id, created_at, updated_at,
                    submission_authority_digest
                ) VALUES (?, 'invalid-json', 'queued', '[]', ?, NULL, ?, ?, ?)
                """,
                ("run_invalid_json", "invalid-json-run", now, now, "a" * 64),
            )
        direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                """
                INSERT INTO cp_jobs (
                    job_id, run_id, kind, state, payload, priority, attempts,
                    max_attempts, idempotency_key, available_at, lease_owner,
                    lease_token_hash, lease_expires_at, heartbeat_at, result,
                    error, created_at, updated_at, lease_deadline_at,
                    heartbeat_event_at, submission_authority_digest
                ) VALUES (?, ?, 'campaign', 'queued', '[]', 0, 0, 1, ?, ?,
                    NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL, NULL, ?)
                """,
                (
                    "job_invalid_json",
                    run_id,
                    "invalid-json-job",
                    now,
                    now,
                    now,
                    "b" * 64,
                ),
            )
        direct.rollback()

        assert direct.execute(
            "SELECT campaign_name, input FROM cp_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone() == ("migration-test", '{"preserve": true}')
        assert direct.execute(
            "SELECT state, max_attempts FROM cp_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone() == ("succeeded", 1)
    finally:
        direct.close()


def test_sqlite_v10_run_guard_rejects_nested_escaped_duplicate_json_keys(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v10-duplicate-json-key.db"
    repository = _repository(path)
    repository.initialize()
    repository.close()

    direct = sqlite3.connect(path)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="submission authority"):
            direct.execute(
                """
                INSERT INTO cp_runs (
                    run_id, campaign_name, state, input, submission_key,
                    current_checkpoint_id, created_at, updated_at,
                    submission_authority_digest
                ) VALUES (?, 'duplicate-json-key', 'queued', ?, ?, NULL, ?, ?, ?)
                """,
                (
                    "run_v10_duplicate_json_key",
                    r'{"nested":{"name":1,"\u006eame":2}}',
                    "v10-duplicate-json-key",
                    now,
                    now,
                    "a" * 64,
                ),
            )
    finally:
        direct.close()


def test_v10_startup_rejects_run_input_beyond_public_resource_contract(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v10-oversized-run-input.db"
    repository = _repository(path)
    repository.initialize()
    repository.close()

    direct = sqlite3.connect(path)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    oversized_input = json.dumps(
        {"blob": "x" * 1_000_000},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    try:
        direct.execute(
            """
            INSERT INTO cp_runs (
                run_id, campaign_name, state, input, submission_key,
                current_checkpoint_id, created_at, updated_at,
                submission_authority_digest
            ) VALUES (?, 'oversized-input', 'queued', ?, ?, NULL, ?, ?, ?)
            """,
            (
                "run_v10_oversized_input",
                oversized_input,
                "v10-oversized-input",
                now,
                now,
                "a" * 64,
            ),
        )
        direct.commit()
    finally:
        direct.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match=r"input.*resource contract"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM cp_runs WHERE run_id = 'run_v10_oversized_input'")
                )
                == 1
            )
    finally:
        restarted.close()


def test_v10_startup_recomputes_job_submission_authority_binding(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v10-false-job-digest.db"
    repository = _repository(path)
    run_id = "run_false_job_digest"
    repository.initialize()
    with repository.transaction() as session:
        session.add(_run(run_id))
    repository.close()

    direct = sqlite3.connect(path)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    try:
        direct.execute(
            """
            INSERT INTO cp_jobs (
                job_id, run_id, kind, state, payload, priority, attempts,
                max_attempts, idempotency_key, available_at, lease_owner,
                lease_token_hash, lease_expires_at, heartbeat_at, result,
                error, created_at, updated_at, lease_deadline_at,
                heartbeat_event_at, submission_authority_digest
            ) VALUES (?, ?, 'campaign', 'queued', '{}', 0, 0, 1, ?, ?,
                NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL, NULL, ?)
            """,
            (
                "job_false_submission_digest",
                run_id,
                "false-job-digest",
                now,
                now,
                now,
                "a" * 64,
            ),
        )
        direct.commit()
    finally:
        direct.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="job bindings=1"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM cp_jobs WHERE job_id = 'job_false_submission_digest'"
                    )
                )
                == 1
            )
    finally:
        restarted.close()


def test_sqlite_v10_guards_reject_replace_and_lease_deadline_extension(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v10-replace-guard.db"
    repository = _repository(path)
    run_id = "run_v10_replace_guard"
    job_id = "job_v10_replace_guard"
    try:
        repository.initialize()
        with repository.transaction() as session:
            session.add(_run(run_id))
            session.flush()
            job = _job(run_id, job_id)
            job.state = "queued"
            job.attempts = 0
            job.result = None
            session.add(job)
    finally:
        repository.close()

    direct = sqlite3.connect(path)
    heartbeat = datetime(2026, 1, 1, tzinfo=UTC)
    expiry = heartbeat + timedelta(seconds=30)
    deadline = heartbeat + timedelta(hours=1)
    extended_deadline = deadline + timedelta(hours=1)
    extended_deadline_value = extended_deadline.strftime("%Y-%m-%d %H:%M:%S.%f")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="submission authority"):
            direct.execute(
                """
                INSERT OR REPLACE INTO cp_runs (
                    run_id, campaign_name, state, input, submission_key,
                    current_checkpoint_id, created_at, updated_at,
                    submission_authority_digest
                )
                SELECT run_id, 'replaced', state, input, submission_key,
                    current_checkpoint_id, created_at, updated_at,
                    submission_authority_digest
                FROM cp_runs WHERE run_id = ?
                """,
                (run_id,),
            )
        direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                """
                INSERT OR REPLACE INTO cp_jobs (
                    job_id, run_id, kind, state, payload, priority, attempts,
                    max_attempts, idempotency_key, available_at, lease_owner,
                    lease_token_hash, lease_expires_at, heartbeat_at, result,
                    error, created_at, updated_at, lease_deadline_at,
                    heartbeat_event_at, submission_authority_digest
                )
                SELECT job_id, run_id, kind, state, '{"replaced":true}', priority,
                    attempts, max_attempts, idempotency_key, available_at,
                    lease_owner, lease_token_hash, lease_expires_at, heartbeat_at,
                    result, error, created_at, updated_at, lease_deadline_at,
                    heartbeat_event_at, submission_authority_digest
                FROM cp_jobs WHERE job_id = ?
                """,
                (job_id,),
            )
        direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="authority"):
            direct.execute(
                "UPDATE cp_jobs SET state = 'succeeded', result = '{}' WHERE job_id = ?",
                (job_id,),
            )
        direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="authority"):
            direct.execute(
                "UPDATE cp_runs SET state = 'completed' WHERE run_id = ?",
                (run_id,),
            )
        direct.rollback()

        claim_sql = """
            UPDATE cp_jobs SET state = 'leased', result = NULL,
                attempts = attempts + 1,
                lease_owner = ?, lease_token_hash = ?, lease_expires_at = ?,
                heartbeat_at = ?, lease_deadline_at = ?, heartbeat_event_at = NULL
            WHERE job_id = ?
        """
        valid_token = "a" * 64
        valid_expiry = expiry.strftime("%Y-%m-%d %H:%M:%S.%f")
        valid_heartbeat = heartbeat.strftime("%Y-%m-%d %H:%M:%S.%f")
        valid_deadline = deadline.strftime("%Y-%m-%d %H:%M:%S.%f")
        invalid_lease_values = (
            (None, valid_token, valid_expiry, valid_heartbeat, valid_deadline),
            ("v10-worker", None, valid_expiry, valid_heartbeat, valid_deadline),
            (
                "v10-worker",
                sqlite3.Binary(valid_token.encode()),
                valid_expiry,
                valid_heartbeat,
                valid_deadline,
            ),
            ("v10-worker", valid_token, 2_460_000.5, valid_heartbeat, valid_deadline),
            ("v10-worker", valid_token, "12:00:00", valid_heartbeat, valid_deadline),
            (
                "v10-worker",
                valid_token,
                "2026-01-01 24:00:00.000000",
                valid_heartbeat,
                valid_deadline,
            ),
            (
                "v10-worker",
                valid_token,
                "2026-02-29 00:00:00.000000",
                valid_heartbeat,
                valid_deadline,
            ),
            (
                "v10-worker",
                valid_token,
                "2026-01-01 01:00:00.000400",
                valid_heartbeat,
                "2026-01-01 01:00:00.000100",
            ),
            (
                "v10-worker",
                valid_token,
                "2026-01-01 00:00:01.000000",
                "2026-01-01 00:00:00.000100",
                "2026-01-02 00:00:00.000400",
            ),
        )
        for invalid_values in invalid_lease_values:
            with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
                direct.execute(claim_sql, (*invalid_values, job_id))
            direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                claim_sql.replace("attempts = attempts + 1,", "attempts = attempts,"),
                (
                    "v10-worker",
                    valid_token,
                    valid_expiry,
                    valid_heartbeat,
                    valid_deadline,
                    job_id,
                ),
            )
        direct.rollback()

        direct.execute(
            """
            UPDATE cp_jobs SET state = 'leased', result = NULL,
                attempts = attempts + 1,
                lease_owner = 'v10-worker', lease_token_hash = ?,
                lease_expires_at = ?, heartbeat_at = ?, lease_deadline_at = ?,
                heartbeat_event_at = ?
            WHERE job_id = ?
            """,
            (
                "a" * 64,
                valid_expiry,
                valid_heartbeat,
                valid_deadline,
                valid_heartbeat,
                job_id,
            ),
        )
        direct.commit()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                """
                UPDATE cp_jobs SET state = 'queued', attempts = 0,
                    lease_owner = NULL, lease_token_hash = NULL,
                    lease_expires_at = NULL, heartbeat_at = NULL,
                    lease_deadline_at = NULL, heartbeat_event_at = NULL
                WHERE job_id = ?
                """,
                (job_id,),
            )
        direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                "UPDATE cp_jobs SET lease_owner = 'other-worker' WHERE job_id = ?",
                (job_id,),
            )
        direct.rollback()

        for invalid_deadline in (
            (deadline + timedelta(microseconds=1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
            extended_deadline_value,
        ):
            with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
                direct.execute(
                    "UPDATE cp_jobs SET lease_deadline_at = ? WHERE job_id = ?",
                    (invalid_deadline, job_id),
                )
            direct.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                """
                INSERT OR REPLACE INTO cp_jobs (
                    job_id, run_id, kind, state, payload, priority, attempts,
                    max_attempts, idempotency_key, available_at, lease_owner,
                    lease_token_hash, lease_expires_at, heartbeat_at, result,
                    error, created_at, updated_at, lease_deadline_at,
                    heartbeat_event_at, submission_authority_digest
                )
                SELECT job_id, run_id, kind, state, payload, priority, attempts,
                    max_attempts, idempotency_key, available_at, lease_owner,
                    lease_token_hash, lease_expires_at, heartbeat_at, result,
                    error, created_at, updated_at, ?, heartbeat_event_at,
                    submission_authority_digest
                FROM cp_jobs WHERE job_id = ?
                """,
                (extended_deadline_value, job_id),
            )
        direct.rollback()

        assert direct.execute(
            "SELECT state, payload, lease_deadline_at FROM cp_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone() == ("leased", '{"preserve": true}', valid_deadline)
    finally:
        direct.close()


def test_sqlite_v10_authority_rowids_cannot_create_replace_bypass_or_false_positive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v10-rowid-guard.db"
    repository = _repository(path)
    try:
        repository.initialize()
        with repository.transaction() as session:
            parent_run_id = "run_rowid_replace_parent"
            session.add(_run(parent_run_id))
            session.flush()
            session.add_all(
                [
                    _job(parent_run_id, "job_rowid_replace_attacker"),
                    _job(parent_run_id, "job_rowid_replace_victim"),
                ]
            )
    finally:
        repository.close()

    direct = sqlite3.connect(path)
    now = datetime.now(UTC).isoformat()
    try:
        assert direct.execute("PRAGMA recursive_triggers").fetchone() == (0,)
        victim_rowid = direct.execute(
            "SELECT rowid FROM cp_jobs WHERE job_id = 'job_rowid_replace_victim'"
        ).fetchone()
        assert victim_rowid is not None
        with pytest.raises(sqlite3.IntegrityError, match="lease authority"):
            direct.execute(
                "UPDATE OR REPLACE cp_jobs SET rowid = ? WHERE job_id = ?",
                (int(victim_rowid[0]), "job_rowid_replace_attacker"),
            )
        direct.rollback()
        assert direct.execute(
            "SELECT count(*) FROM cp_jobs WHERE job_id LIKE 'job_rowid_replace_%'"
        ).fetchone() == (2,)

        with pytest.raises(sqlite3.IntegrityError, match="authority rowid"):
            direct.execute(
                """
                INSERT INTO cp_runs (
                    rowid, run_id, campaign_name, state, input, submission_key,
                    current_checkpoint_id, created_at, updated_at,
                    submission_authority_digest
                ) VALUES (-1, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    "run_negative_rowid",
                    "rowid-guard",
                    "queued",
                    '{"rowid":-1}',
                    "negative-rowid-key",
                    now,
                    now,
                    "a" * 64,
                ),
            )
        direct.rollback()

        # SQLite exposes NEW.rowid as -1 for an ordinary auto-rowid BEFORE INSERT.
        # The AFTER guard must reject explicit non-positive rowids without turning
        # that sentinel into a false positive for normal managed inserts.
        direct.execute(
            """
            INSERT INTO cp_runs (
                run_id, campaign_name, state, input, submission_key,
                current_checkpoint_id, created_at, updated_at,
                submission_authority_digest
            ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
            """,
            (
                "run_automatic_rowid",
                "rowid-guard",
                "queued",
                '{"rowid":"automatic"}',
                "automatic-rowid-key",
                now,
                now,
                "b" * 64,
            ),
        )
        direct.commit()
        rowid = direct.execute(
            "SELECT rowid FROM cp_runs WHERE run_id = 'run_automatic_rowid'"
        ).fetchone()
        assert rowid is not None and int(rowid[0]) > 0
    finally:
        direct.close()


@pytest.mark.parametrize("table_name", ["cp_runs", "cp_jobs"])
def test_missing_v10_authority_guard_is_rejected_without_repair(
    tmp_path: Path,
    table_name: str,
) -> None:
    path = tmp_path / f"missing-v10-guard-{table_name}.db"
    repository = _repository(path)
    repository.initialize()
    trigger_name = (
        "cp_runs_submission_authority_guard_update"
        if table_name == "cp_runs"
        else "cp_jobs_lease_authority_guard_update"
    )
    with repository.engine.begin() as connection:
        connection.exec_driver_sql(f"DROP TRIGGER {trigger_name}")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match=r"authority.*trigger"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' "
                        "AND name = :trigger_name"
                    ),
                    {"trigger_name": trigger_name},
                )
                == 0
            )
    finally:
        restarted.close()


def test_exact_v7_migration_is_additive_preserves_data_and_is_idempotent(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "v7-append-only-guards.db")
    run_id = "run_v7_guard_preserved"
    event_id = "event_v7_guard_preserved"
    try:
        _create_v7_schema(repository)
        with repository.transaction() as session:
            _insert_frozen_record(session, _run(run_id), metadata=_V9_METADATA)
            session.flush()
            session.add(
                EventRecord(
                    event_id=event_id,
                    run_id=run_id,
                    sequence=1,
                    event_type="migration.preserved",
                    actor="migration-test",
                    payload={"preserve": True},
                    occurred_at=datetime.now(UTC),
                )
            )
        with repository.engine.connect() as connection:
            v7_definitions = dict(
                connection.execute(
                    text(
                        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                        "AND name IN ('cp_events_no_update', 'cp_events_no_delete')"
                    )
                ).all()
            )

        repository.initialize()

        with repository.transaction() as session:
            preserved = session.get(EventRecord, event_id)
            assert preserved is not None
            assert preserved.payload == {"preserve": True}
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))
        with repository.engine.connect() as connection:
            migrated_definitions = dict(
                connection.execute(
                    text(
                        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                        "AND name IN ('cp_events_no_update', 'cp_events_no_delete')"
                    )
                ).all()
            )
            trigger_names = set(
                connection.scalars(
                    text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
                ).all()
            )
        assert migrated_definitions == v7_definitions
        assert {
            f"{table_name}_no_replace"
            for table_name in (
                "cp_events",
                "cp_artifacts",
                "cp_replay_compilations",
                "cp_replay_execution_contexts",
                "cp_replay_events",
                "cp_replay_tool_permits",
            )
        }.issubset(trigger_names)

        repository.initialize()
        with repository.transaction() as session:
            assert (
                session.scalar(select(text("count(*)")).select_from(SchemaVersionRecord))
                == CURRENT_SCHEMA_VERSION
            )
            assert session.get(EventRecord, event_id) is not None
    finally:
        repository.close()


def test_exact_v8_migration_adds_replay_finalization_and_current_authority(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v8-replay-finalization.db")
    try:
        _create_v8_schema(repository)
        assert {
            name for name in inspect(repository.engine).get_table_names() if name.startswith("cp_")
        } == V8_CONTROL_PLANE_TABLES

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        assert {
            name for name in inspect(repository.engine).get_table_names() if name.startswith("cp_")
        } == CURRENT_CONTROL_PLANE_TABLES
        with repository.engine.connect() as connection:
            trigger_names = set(
                connection.scalars(
                    text(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                        "AND tbl_name = 'cp_replay_finalizations'"
                    )
                ).all()
            )
            versions = list(
                connection.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert trigger_names == {
            "cp_replay_finalizations_no_update",
            "cp_replay_finalizations_no_delete",
            "cp_replay_finalizations_no_replace",
        }
        assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))
        assert ReplayFinalizationRecord.__tablename__ == "cp_replay_finalizations"

        repository.initialize()
        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
    finally:
        repository.close()


def test_v8_finalization_migration_rolls_back_table_guards_and_history_on_failure(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v8-replay-finalization-rollback.db")
    _create_v8_schema(repository)

    def fail_mid_migration(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if "CREATE TRIGGER cp_replay_finalizations_no_delete" in statement:
            raise RuntimeError("simulated v9 finalization guard failure")

    sqlalchemy_event.listen(repository.engine, "before_cursor_execute", fail_mid_migration)
    try:
        with pytest.raises(RuntimeError, match="simulated v9"):
            repository.initialize()
    finally:
        sqlalchemy_event.remove(repository.engine, "before_cursor_execute", fail_mid_migration)

    try:
        assert {
            name for name in inspect(repository.engine).get_table_names() if name.startswith("cp_")
        } == V8_CONTROL_PLANE_TABLES
        with repository.engine.connect() as connection:
            versions = list(
                connection.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert versions == list(range(1, COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION + 1))

        repository.initialize()
        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
    finally:
        repository.close()


def test_v7_guard_migration_rolls_back_all_triggers_and_history_on_failure(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v7-guard-rollback.db")
    _create_v7_schema(repository)

    def fail_mid_migration(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if "CREATE TRIGGER cp_replay_compilations_no_replace" in statement:
            raise RuntimeError("simulated v8 trigger installation failure")

    sqlalchemy_event.listen(repository.engine, "before_cursor_execute", fail_mid_migration)
    try:
        with pytest.raises(RuntimeError, match="simulated v8"):
            repository.initialize()
    finally:
        sqlalchemy_event.remove(repository.engine, "before_cursor_execute", fail_mid_migration)

    try:
        with repository.engine.connect() as connection:
            assert list(
                connection.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            ) == list(range(1, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION + 1))
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' "
                        "AND name LIKE '%_no_replace'"
                    )
                )
                == 0
            )

        repository.initialize()
        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
    finally:
        repository.close()


def test_tampered_v7_trigger_is_rejected_without_v8_repair(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "tampered-v7-trigger.db")
    try:
        _create_v7_schema(repository)
        with repository.engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER cp_events_no_delete")

        with pytest.raises(SchemaInitializationError, match="append-only delete trigger"):
            repository.initialize()

        with repository.engine.connect() as connection:
            assert list(
                connection.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            ) == list(range(1, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION + 1))
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' "
                        "AND name LIKE '%_no_replace'"
                    )
                )
                == 0
            )
    finally:
        repository.close()


def test_api_with_deployment_managed_migrations_still_fails_closed(
    tmp_path: Path,
) -> None:
    settings = ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'unmanaged-empty.db').as_posix()}",
        credentials={
            "migration-test-token-that-is-at-least-32-characters": Principal(
                subject="migration-test-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            )
        },
        checkpoint_keys={"migration-v1": b"migration-test-signing-key-32-bytes"},
        active_checkpoint_key_id="migration-v1",
        initialize_schema=False,
    )

    with pytest.raises(SchemaInitializationError), TestClient(create_app(settings)):
        pass


def test_exact_legacy_database_migrates_forward_without_losing_rows(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "legacy.db")
    try:
        _create_legacy_schema(repository)
        with repository.transaction() as session:
            _insert_frozen_record(session, _run("run_legacy"), metadata=_V9_METADATA)

        repository.initialize()

        with repository.transaction() as session:
            preserved = session.get(RunRecord, "run_legacy")
            assert preserved is not None
            assert preserved.input == {"preserve": True}
        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
    finally:
        repository.close()


def test_legacy_internal_replay_job_is_rejected_before_schema_history_is_created(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "legacy-internal-replay.db")
    run_id = "run_legacy_internal_replay"
    job_id = "job_legacy_internal_replay"
    try:
        _create_legacy_schema(repository)
        with repository.transaction() as session:
            _insert_frozen_record(session, _run(run_id), metadata=_V9_METADATA)
            session.flush()
            job = _job(run_id, job_id)
            job.kind = "internal-replay"
            _insert_frozen_record(session, job, metadata=_V9_METADATA)

        with pytest.raises(SchemaInitializationError, match="internal-replay Jobs: 1"):
            repository.initialize()

        assert "cp_schema_version" not in inspect(repository.engine).get_table_names()
        with repository.transaction() as session:
            job_table = _V9_METADATA.tables[JobRecord.__tablename__]
            preserved = (
                session.execute(select(job_table).where(job_table.c.job_id == job_id))
                .mappings()
                .one()
            )
            assert preserved["kind"] == "internal-replay"
    finally:
        repository.close()


def test_empty_v2_database_migrates_forward_without_losing_core_rows(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v2-empty.db")
    try:
        _create_v2_schema(repository)
        with repository.transaction() as session:
            _add_versioned_record(session, _run("run_v2_preserved"))

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        with repository.transaction() as session:
            assert session.get(RunRecord, "run_v2_preserved") is not None
            versions = session.scalars(
                select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
            ).all()
        assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))
        columns = {
            column["name"] for column in inspect(repository.engine).get_columns("cp_replay_batches")
        }
        assert "source_artifact_run_id" in columns
        assert "cp_artifacts" in inspect(repository.engine).get_table_names()
    finally:
        repository.close()


def test_empty_v3_database_migrates_forward_without_losing_core_or_artifact_rows(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v3-empty.db")
    run_id = f"run_{'7' * 32}"
    job_id = f"job_{'8' * 32}"
    try:
        _create_v3_schema(repository)
        with repository.transaction() as session:
            _add_versioned_record(session, _run(run_id))
            session.flush()
            _add_versioned_record(session, _job(run_id, job_id))
            session.flush()
            session.add(_artifact(run_id, job_id))

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        with repository.transaction() as session:
            assert session.get(RunRecord, run_id) is not None
            assert session.get(ArtifactRecord, (f"artifact_{'1' * 32}", 1)) is not None
            versions = session.scalars(
                select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
            ).all()
        assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))
        assert "cp_replay_compilations" in inspect(repository.engine).get_table_names()
        item_unique_names = {
            constraint["name"]
            for constraint in inspect(repository.engine).get_unique_constraints("cp_replay_items")
        }
        assert "uq_cp_replay_items_compilation_plan" in item_unique_names
    finally:
        repository.close()


def test_v4_planned_replay_proof_migrates_forward_without_losing_authority_rows(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v4-planned-proof.db")
    try:
        _create_v4_schema(repository)
        source_run_id, _, replay_run_id = _seed_replay_item_authority(repository)
        canonical = b'{"kind":"ReplayCompilation","schemaVersion":"pajin.dev/replay/v1alpha1"}'
        now = datetime.now(UTC)
        with repository.transaction() as session:
            session.add(
                _compilation(
                    replay_run_id=replay_run_id,
                    canonical_compilation=canonical,
                )
            )
            session.add(
                ReplayEventRecord(
                    event_id="event_v4_planned_proof",
                    batch_id="batch_migration",
                    item_id="item_migration",
                    ticket_id=None,
                    job_id=None,
                    run_id=replay_run_id,
                    sequence=1,
                    event_type="replay.compilation.derived",
                    actor="migration-test-operator",
                    payload={"preserve": True},
                    occurred_at=now,
                )
            )

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        assert {
            name for name in inspect(repository.engine).get_table_names() if name.startswith("cp_")
        } == CURRENT_CONTROL_PLANE_TABLES
        with repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, "batch_migration")
            item = session.get(ReplayItemRecord, "item_migration")
            compilation = session.get(
                ReplayCompilationRecord,
                f"replay-compilation_{'6' * 32}",
            )
            replay_event = session.get(ReplayEventRecord, "event_v4_planned_proof")
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert batch is not None
        assert batch.source_run_id == source_run_id
        assert batch.state == "planned"
        assert item is not None
        assert item.state == "pending"
        assert item.attempts == 0
        assert compilation is not None
        assert compilation.replay_run_id == replay_run_id
        assert compilation.canonical_compilation == canonical
        assert replay_event is not None
        assert replay_event.payload == {"preserve": True}
        assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))

        repository.initialize()
    finally:
        repository.close()


def test_v5_active_ticket_refuses_execution_context_migration_without_data_loss(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v5-active-ticket.db")
    try:
        _create_v5_schema(repository)
        ticket_values = _seed_v5_issuance_prerequisites(repository)
        _activate_v5_ticket_graph(repository, ticket_values)

        with pytest.raises(
            SchemaInitializationError,
            match=(
                r"schema v6 contains dispatchable Replay authority without exact execution "
                r"context and cannot be trusted or backfilled .*tickets=1"
            ),
        ):
            repository.initialize()

        table_names = set(inspect(repository.engine).get_table_names())
        assert "cp_replay_tool_permits" not in table_names
        assert "cp_replay_execution_contexts" not in table_names
        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, ticket_values["ticket_id"])
            job_table = _V9_METADATA.tables[JobRecord.__tablename__]
            job = (
                session.execute(
                    select(job_table).where(job_table.c.job_id == ticket_values["job_id"])
                )
                .mappings()
                .one()
            )
            budget_reservation = session.get(
                ReplayBudgetReservationRecord,
                ticket_values["budget_reservation_id"],
            )
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                ticket_values["rate_reservation_id"],
            )
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert ticket is not None
        assert ticket.state == "issued"
        assert job["state"] == "queued"
        assert budget_reservation is not None and budget_reservation.state == "active"
        assert rate_reservation is not None and rate_reservation.state == "active"
        assert versions == [1, 2, 3, 4, 5]
    finally:
        repository.close()


def test_v6_planned_replay_proof_migrates_to_empty_execution_context_ledger(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v6-planned-proof.db")
    try:
        _create_v6_schema(repository)
        _, _, replay_run_id = _seed_replay_item_authority(repository)
        canonical = b'{"kind":"ReplayCompilation","preserve":"v6-proof"}'
        compilation_id = f"replay-compilation_{'6' * 32}"
        with repository.transaction() as session:
            session.add(
                _compilation(
                    compilation_id=compilation_id,
                    replay_run_id=replay_run_id,
                    canonical_compilation=canonical,
                )
            )

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        assert {
            name for name in inspect(repository.engine).get_table_names() if name.startswith("cp_")
        } == CURRENT_CONTROL_PLANE_TABLES
        with repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, "batch_migration")
            item = session.get(ReplayItemRecord, "item_migration")
            compilation = session.get(ReplayCompilationRecord, compilation_id)
            context_count = session.scalar(
                select(text("count(*)")).select_from(ReplayExecutionContextRecord)
            )
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert batch is not None and batch.state == "planned"
        assert item is not None and item.state == "pending" and item.attempts == 0
        assert compilation is not None
        assert compilation.replay_run_id == replay_run_id
        assert compilation.canonical_compilation == canonical
        assert context_count == 0
        assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))

        repository.initialize()
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("unsafe_authority", "expected_diagnostic"),
    [
        ("internal-replay-job", r"internal-replay Jobs=1"),
        ("public-replay-run-job", r"Replay Run Jobs=1"),
        ("non-planned-batch", r"non-planned batches=1"),
        ("advanced-item", r"advanced items=1"),
        ("active-ticket-graph", r"tickets=1"),
        ("claimed-permit-graph", r"permits=1"),
    ],
)
def test_v6_dispatch_authority_refuses_context_migration_without_data_loss(
    tmp_path: Path,
    unsafe_authority: str,
    expected_diagnostic: str,
) -> None:
    repository = _repository(tmp_path / f"v6-unsafe-{unsafe_authority}.db")
    try:
        _create_v6_schema(repository)
        if unsafe_authority in {"active-ticket-graph", "claimed-permit-graph"}:
            ticket_values = _seed_v5_issuance_prerequisites(repository)
            _activate_v5_ticket_graph(repository, ticket_values)
            if unsafe_authority == "claimed-permit-graph":
                _claim_v6_ticket_graph(repository, ticket_values)
                with repository.transaction() as session:
                    session.add(ReplayToolPermitRecord(**_permit_values(ticket_values)))
        else:
            _, _, replay_run_id = _seed_replay_item_authority(repository)
            with repository.transaction() as session:
                session.add(_compilation(replay_run_id=replay_run_id))
                if unsafe_authority in {
                    "internal-replay-job",
                    "public-replay-run-job",
                }:
                    job = _job(replay_run_id, f"job_{'e' * 32}")
                    if unsafe_authority == "internal-replay-job":
                        job.kind = "internal-replay"
                        job.state = "queued"
                        job.attempts = 0
                        job.result = None
                    _add_versioned_record(session, job)
                elif unsafe_authority == "non-planned-batch":
                    batch = session.get(ReplayBatchRecord, "batch_migration")
                    assert batch is not None
                    batch.state = "running"
                else:
                    item = session.get(ReplayItemRecord, "item_migration")
                    assert item is not None
                    item.state = "queued"
                    item.attempts = 1

        with repository.engine.connect() as connection:
            before_rows = {
                table_name: sorted(
                    [
                        dict(row)
                        for row in connection.execute(
                            _V6_METADATA.tables[table_name].select()
                        ).mappings()
                    ],
                    key=repr,
                )
                for table_name in V6_CONTROL_PLANE_TABLES
            }

        with pytest.raises(
            SchemaInitializationError,
            match=(
                r"schema v6 contains dispatchable Replay authority without exact execution "
                r"context and cannot be trusted or backfilled .*" + expected_diagnostic
            ),
        ):
            repository.initialize()

        assert "cp_replay_execution_contexts" not in inspect(repository.engine).get_table_names()
        with repository.engine.connect() as connection:
            after_rows = {
                table_name: sorted(
                    [
                        dict(row)
                        for row in connection.execute(
                            _V6_METADATA.tables[table_name].select()
                        ).mappings()
                    ],
                    key=repr,
                )
                for table_name in V6_CONTROL_PLANE_TABLES
            }
            versions = list(
                connection.scalars(
                    select(_V6_METADATA.tables["cp_schema_version"].c.version).order_by(
                        _V6_METADATA.tables["cp_schema_version"].c.version
                    )
                ).all()
            )
        assert after_rows == before_rows
        assert versions == [1, 2, 3, 4, 5, 6]
    finally:
        repository.close()


@pytest.mark.parametrize(
    "consumption",
    ["budget-account", "budget-reservation", "rate-reservation"],
)
def test_v5_unproven_consumption_refuses_permit_migration_without_data_loss(
    tmp_path: Path,
    consumption: str,
) -> None:
    repository = _repository(tmp_path / f"v5-unproven-{consumption}.db")
    try:
        _create_v5_schema(repository)
        ticket_values = _seed_v5_issuance_prerequisites(repository)
        _activate_v5_ticket_graph(repository, ticket_values)
        with repository.transaction() as session:
            budget_account = session.get(
                ReplayBudgetAccountRecord,
                f"replay-budget-account_{'8' * 32}",
            )
            budget_reservation = session.get(
                ReplayBudgetReservationRecord,
                ticket_values["budget_reservation_id"],
            )
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                ticket_values["rate_reservation_id"],
            )
            assert (
                budget_account is not None
                and budget_reservation is not None
                and rate_reservation is not None
            )
            if consumption == "budget-account":
                budget_account.reserved_calls -= 1
                budget_account.consumed_calls += 1
            elif consumption == "budget-reservation":
                budget_reservation.consumed_calls += 1
            else:
                rate_reservation.consumed_request_units += 1

        with pytest.raises(SchemaInitializationError, match="without per-call permit proof"):
            repository.initialize()

        assert "cp_replay_tool_permits" not in inspect(repository.engine).get_table_names()
        with repository.transaction() as session:
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
            assert session.get(ReplayTicketRecord, ticket_values["ticket_id"]) is not None
        assert versions == [1, 2, 3, 4, 5]
    finally:
        repository.close()


@pytest.mark.parametrize(
    "unsafe_authority",
    [
        "ticket",
        "internal-replay-job",
        "public-replay-run-job",
        "running-batch",
        "queued-item",
        "attempted-item",
    ],
)
def test_v4_dispatch_or_attempt_authority_refuses_migration_without_data_loss(
    tmp_path: Path,
    unsafe_authority: str,
) -> None:
    repository = _repository(tmp_path / f"v4-unsafe-{unsafe_authority}.db")
    replay_job_id = f"job_{'7' * 32}"
    replay_ticket_id = f"replay-ticket_{'8' * 32}"
    try:
        _create_v4_schema(repository)
        _, _, replay_run_id = _seed_replay_item_authority(repository)
        with repository.transaction() as session:
            session.add(_compilation(replay_run_id=replay_run_id))

        now = datetime.now(UTC)
        with repository.engine.begin() as connection:
            if unsafe_authority in {
                "ticket",
                "internal-replay-job",
                "public-replay-run-job",
            }:
                connection.execute(
                    _V4_METADATA.tables["cp_jobs"]
                    .insert()
                    .values(
                        job_id=replay_job_id,
                        run_id=replay_run_id,
                        kind=(
                            "campaign"
                            if unsafe_authority == "public-replay-run-job"
                            else "internal-replay"
                        ),
                        state="queued",
                        payload={"legacy": True},
                        priority=0,
                        attempts=0,
                        max_attempts=1,
                        idempotency_key=f"v4-unsafe-{unsafe_authority}",
                        available_at=now,
                        lease_owner=None,
                        lease_token_hash=None,
                        lease_expires_at=None,
                        heartbeat_at=None,
                        result=None,
                        error=None,
                        created_at=now,
                        updated_at=now,
                    )
                )
            if unsafe_authority == "ticket":
                connection.execute(
                    _V4_METADATA.tables["cp_replay_tickets"]
                    .insert()
                    .values(
                        ticket_id=replay_ticket_id,
                        batch_id="batch_migration",
                        item_id="item_migration",
                        job_id=replay_job_id,
                        replay_run_id=replay_run_id,
                        attempt_number=1,
                        fencing_value=1,
                        state="issued",
                        grant_digest="1" * 64,
                        source_root_digest="b" * 64,
                        compilation_digest="f" * 64,
                        executor_profile=None,
                        claim_principal=None,
                        lease_token_hash=None,
                        result_digest=None,
                        abandon_reason=None,
                        issued_at=now,
                        expires_at=now + timedelta(minutes=5),
                        claimed_at=None,
                        lease_expires_at=None,
                        finalized_at=None,
                        abandoned_at=None,
                        updated_at=now,
                    )
                )
            elif unsafe_authority == "running-batch":
                connection.execute(
                    _V4_METADATA.tables["cp_replay_batches"]
                    .update()
                    .where(_V4_METADATA.tables["cp_replay_batches"].c.batch_id == "batch_migration")
                    .values(state="running")
                )
            elif unsafe_authority == "queued-item":
                connection.execute(
                    _V4_METADATA.tables["cp_replay_items"]
                    .update()
                    .where(_V4_METADATA.tables["cp_replay_items"].c.item_id == "item_migration")
                    .values(state="queued")
                )
            elif unsafe_authority == "attempted-item":
                connection.execute(
                    _V4_METADATA.tables["cp_replay_items"]
                    .update()
                    .where(_V4_METADATA.tables["cp_replay_items"].c.item_id == "item_migration")
                    .values(attempts=1)
                )

        error_pattern = (
            r"Replay Run Jobs=1" if unsafe_authority == "public-replay-run-job" else r"schema v4"
        )
        with pytest.raises(SchemaInitializationError, match=error_pattern):
            repository.initialize()

        assert {
            name for name in inspect(repository.engine).get_table_names() if name.startswith("cp_")
        } == V4_CONTROL_PLANE_TABLES
        with repository.engine.connect() as connection:
            versions = list(
                connection.scalars(
                    select(_V4_METADATA.tables["cp_schema_version"].c.version).order_by(
                        _V4_METADATA.tables["cp_schema_version"].c.version
                    )
                ).all()
            )
            assert versions == [1, 2, 3, 4]
            assert (
                connection.scalar(
                    select(text("count(*)")).select_from(
                        _V4_METADATA.tables["cp_replay_compilations"]
                    )
                )
                == 1
            )
            if unsafe_authority == "ticket":
                assert (
                    connection.scalar(
                        select(text("count(*)")).select_from(
                            _V4_METADATA.tables["cp_replay_tickets"]
                        )
                    )
                    == 1
                )
            if unsafe_authority in {"ticket", "internal-replay-job"}:
                assert (
                    connection.scalar(
                        select(text("count(*)"))
                        .select_from(_V4_METADATA.tables["cp_jobs"])
                        .where(_V4_METADATA.tables["cp_jobs"].c.kind == "internal-replay")
                    )
                    == 1
                )
            if unsafe_authority == "public-replay-run-job":
                assert (
                    connection.scalar(
                        select(text("count(*)"))
                        .select_from(_V4_METADATA.tables["cp_jobs"])
                        .where(_V4_METADATA.tables["cp_jobs"].c.job_id == replay_job_id)
                    )
                    == 1
                )
    finally:
        repository.close()


def test_v3_replay_rows_are_rejected_without_inventing_canonical_compilations(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v3-replay-data.db")
    run_id = f"run_{'9' * 32}"
    job_id = f"job_{'a' * 32}"
    try:
        _create_v3_schema(repository)
        with repository.transaction() as session:
            _add_versioned_record(session, _run(run_id))
            session.flush()
            _add_versioned_record(session, _job(run_id, job_id))
            session.flush()
            session.add(_artifact(run_id, job_id))
            session.flush()
            session.add(_batch(run_id))

        with pytest.raises(
            SchemaInitializationError,
            match=r"schema v3.*cannot be trusted or backfilled",
        ):
            repository.initialize()

        assert "cp_replay_compilations" not in inspect(repository.engine).get_table_names()
        with repository.engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM cp_replay_batches")) == 1
    finally:
        repository.close()


def test_v3_internal_replay_job_is_rejected_without_aggregate_rows(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "v3-internal-job.db")
    run_id = f"run_{'b' * 32}"
    try:
        _create_v3_schema(repository)
        now = datetime.now(UTC)
        with repository.transaction() as session:
            _add_versioned_record(session, _run(run_id))
            session.flush()
            _add_versioned_record(
                session,
                JobRecord(
                    job_id=f"job_{'c' * 32}",
                    run_id=run_id,
                    kind="internal-replay",
                    state="queued",
                    payload={},
                    priority=0,
                    attempts=0,
                    max_attempts=1,
                    idempotency_key="idempotency-v3-internal-replay",
                    submission_authority_digest=job_submission_authority_digest(
                        job_id=f"job_{'c' * 32}",
                        run_id=run_id,
                        job_kind="internal-replay",
                        payload={},
                        max_attempts=1,
                        idempotency_key="idempotency-v3-internal-replay",
                    ),
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    heartbeat_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
                ),
            )

        with pytest.raises(SchemaInitializationError, match="internal-replay Jobs: 1"):
            repository.initialize()
        assert "cp_replay_compilations" not in inspect(repository.engine).get_table_names()
    finally:
        repository.close()


def test_sqlite_v2_migration_excludes_legacy_writer_from_count_through_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v2-writer-race.db"
    migration_repository = _repository(path)
    writer_repository = _repository(path)
    migration_reached_count = ThreadEvent()
    release_migration = ThreadEvent()
    writer_attempted = ThreadEvent()
    writer_finished = ThreadEvent()
    migration_errors: list[BaseException] = []
    writer_errors: list[BaseException] = []
    migration_thread: Thread | None = None
    writer_thread: Thread | None = None
    listener_installed = False

    def pause_at_authority_count(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalized = " ".join(statement.split())
        if normalized != "SELECT count(*) FROM cp_replay_batches":
            return
        migration_reached_count.set()
        if not release_migration.wait(timeout=5):
            raise RuntimeError("timed out waiting to release v2 migration")

    def migrate() -> None:
        try:
            migration_repository.initialize()
        except BaseException as error:
            migration_errors.append(error)

    def legacy_write() -> None:
        writer_attempted.set()
        try:
            with writer_repository.engine.begin() as connection:
                connection.execute(
                    _V2_METADATA.tables["cp_replay_batches"]
                    .insert()
                    .values(**_v2_batch_values("run_v2_race", "batch_v2_race"))
                )
        except BaseException as error:
            writer_errors.append(error)
        finally:
            writer_finished.set()

    try:
        _create_v2_schema(migration_repository)
        now = datetime.now(UTC)
        with migration_repository.engine.begin() as connection:
            connection.execute(
                _V2_METADATA.tables["cp_runs"]
                .insert()
                .values(
                    run_id="run_v2_race",
                    campaign_name="migration-test",
                    state="completed",
                    input={"legacy": True},
                    submission_key="submission-v2-race",
                    current_checkpoint_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )

        sqlalchemy_event.listen(
            migration_repository.engine,
            "before_cursor_execute",
            pause_at_authority_count,
        )
        listener_installed = True
        migration_thread = Thread(target=migrate, daemon=True)
        migration_thread.start()
        assert migration_reached_count.wait(timeout=5)

        writer_thread = Thread(target=legacy_write, daemon=True)
        writer_thread.start()
        assert writer_attempted.wait(timeout=5)
        assert not writer_finished.wait(timeout=0.2)

        release_migration.set()
        migration_thread.join(timeout=5)
        writer_thread.join(timeout=5)
        assert not migration_thread.is_alive()
        assert not writer_thread.is_alive()
        assert migration_errors == []
        assert len(writer_errors) == 1
        assert isinstance(writer_errors[0], DatabaseError)
        assert migration_repository.schema_version() == CURRENT_SCHEMA_VERSION
        with migration_repository.engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM cp_replay_batches")) == 0
    finally:
        release_migration.set()
        if migration_thread is not None:
            migration_thread.join(timeout=5)
        if writer_thread is not None:
            writer_thread.join(timeout=5)
        if listener_installed:
            sqlalchemy_event.remove(
                migration_repository.engine,
                "before_cursor_execute",
                pause_at_authority_count,
            )
        writer_repository.close()
        migration_repository.close()


def test_v2_replay_rows_are_rejected_without_trusting_or_backfilling(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v2-replay-data.db")
    try:
        _create_v2_schema(repository)
        now = datetime.now(UTC)
        with repository.engine.begin() as connection:
            connection.execute(
                _V2_METADATA.tables["cp_runs"]
                .insert()
                .values(
                    run_id="run_v2_replay",
                    campaign_name="migration-test",
                    state="completed",
                    input={"legacy": True},
                    submission_key="submission-v2-replay",
                    current_checkpoint_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                _V2_METADATA.tables["cp_replay_batches"]
                .insert()
                .values(
                    batch_id="batch_v2_unverified",
                    source_run_id="run_v2_replay",
                    idempotency_key="idempotency-v2-unverified",
                    campaign_name="migration-test",
                    created_by="migration-test-operator",
                    source_artifact_id="unverified-artifact",
                    source_repository_version=1,
                    source_content_digest="a" * 64,
                    source_root_digest="b" * 64,
                    source_media_type="application/vnd.pajin.run+json",
                    source_schema_kind="pajin.run.v1",
                    source_byte_length=512,
                    source_created_by="migration-test-operator",
                    mode="ai-redteam",
                    purpose="confirmation",
                    policy_version="policy-v1",
                    state="planned",
                    cas_version=1,
                    cancellation_reason=None,
                    created_at=now,
                    updated_at=now,
                    cancelled_at=None,
                )
            )

        with pytest.raises(SchemaInitializationError, match="cannot be trusted or backfilled"):
            repository.initialize()

        assert "cp_artifacts" not in inspect(repository.engine).get_table_names()
        with repository.engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM cp_replay_batches")) == 1
    finally:
        repository.close()


def test_v2_internal_replay_job_is_rejected_even_without_aggregate_rows(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v2-internal-job.db")
    try:
        _create_v2_schema(repository)
        now = datetime.now(UTC)
        with repository.engine.begin() as connection:
            connection.execute(
                _V2_METADATA.tables["cp_runs"]
                .insert()
                .values(
                    run_id="run_v2_internal",
                    campaign_name="migration-test",
                    state="queued",
                    input={},
                    submission_key="submission-v2-internal",
                    current_checkpoint_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                _V2_METADATA.tables["cp_jobs"]
                .insert()
                .values(
                    job_id="job_v2_internal",
                    run_id="run_v2_internal",
                    kind="internal-replay",
                    state="queued",
                    payload={},
                    priority=0,
                    attempts=0,
                    max_attempts=1,
                    idempotency_key="idempotency-v2-internal",
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    heartbeat_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
                )
            )

        with pytest.raises(SchemaInitializationError, match="internal-replay Jobs: 1"):
            repository.initialize()
        assert "cp_artifacts" not in inspect(repository.engine).get_table_names()
    finally:
        repository.close()


@pytest.mark.parametrize("partial", [True, False])
def test_partial_or_unknown_control_plane_schema_is_rejected(
    tmp_path: Path,
    partial: bool,
) -> None:
    repository = _repository(tmp_path / f"unknown-{partial}.db")
    try:
        with repository.engine.begin() as connection:
            if partial:
                RunRecord.__table__.create(connection)
            else:
                connection.exec_driver_sql("CREATE TABLE cp_unmanaged (id INTEGER PRIMARY KEY)")
        with pytest.raises(SchemaInitializationError, match="partial or unknown"):
            repository.initialize()
    finally:
        repository.close()


def test_unknown_migration_version_is_rejected_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "unknown-version.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.execute(
            update(SchemaVersionRecord)
            .where(SchemaVersionRecord.version == CURRENT_SCHEMA_VERSION)
            .values(version=99)
        )
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="migration history"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    select(SchemaVersionRecord.version).where(SchemaVersionRecord.version == 99)
                )
                == 99
            )
    finally:
        restarted.close()


def test_missing_required_column_is_rejected_without_automatic_repair(tmp_path: Path) -> None:
    path = tmp_path / "missing-column.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE cp_replay_batches DROP COLUMN campaign_name")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="columns do not match"):
            restarted.initialize()
        assert "campaign_name" not in {
            column["name"] for column in inspect(restarted.engine).get_columns("cp_replay_batches")
        }
    finally:
        restarted.close()


def test_unmanaged_authority_column_default_is_rejected_without_repair(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unmanaged-authority-default.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        definition = connection.scalar(text("SELECT sql FROM sqlite_master WHERE name = 'cp_runs'"))
        assert isinstance(definition, str)
        original = "submission_authority_digest VARCHAR(64)"
        replacement = f"{original} DEFAULT '{'a' * 64}'"
        assert original in definition
        connection.exec_driver_sql("PRAGMA writable_schema=ON")
        connection.execute(
            text("UPDATE sqlite_master SET sql = :sql WHERE name = 'cp_runs'"),
            {"sql": definition.replace(original, replacement, 1)},
        )
        connection.exec_driver_sql("PRAGMA writable_schema=OFF")
        schema_version = int(connection.scalar(text("PRAGMA schema_version")) or 0)
        connection.exec_driver_sql(f"PRAGMA schema_version={schema_version + 1}")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="unmanaged server default"):
            restarted.initialize()
        digest_column = next(
            column
            for column in inspect(restarted.engine).get_columns("cp_runs")
            if column["name"] == "submission_authority_digest"
        )
        assert digest_column["default"] == f"'{'a' * 64}'"
    finally:
        restarted.close()


def test_sqlite_existing_foreign_key_violation_is_rejected_without_repair(
    tmp_path: Path,
) -> None:
    path = tmp_path / "foreign-key-row-drift.db"
    repository = _repository(path)
    repository.initialize()
    repository.close()

    direct = sqlite3.connect(path)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    job_id = "job_orphaned_authority"
    run_id = "run_missing_authority"
    idempotency_key = "orphaned-authority"
    authority_digest = job_submission_authority_digest(
        job_id=job_id,
        run_id=run_id,
        job_kind="campaign",
        payload={},
        max_attempts=1,
        idempotency_key=idempotency_key,
    )
    try:
        assert direct.execute("PRAGMA foreign_keys").fetchone() == (0,)
        direct.execute(
            """
            INSERT INTO cp_jobs (
                job_id, run_id, kind, state, payload, priority, attempts,
                max_attempts, idempotency_key, available_at, lease_owner,
                lease_token_hash, lease_expires_at, heartbeat_at, result,
                error, created_at, updated_at, lease_deadline_at,
                heartbeat_event_at, submission_authority_digest
            ) VALUES (?, ?, 'campaign', 'queued', '{}', 0, 0, 1, ?, ?,
                NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL, NULL, ?)
            """,
            (
                job_id,
                run_id,
                idempotency_key,
                now,
                now,
                now,
                authority_digest,
            ),
        )
        direct.commit()
        assert direct.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        direct.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="foreign-key authority"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM cp_jobs WHERE job_id = 'job_orphaned_authority'")
                )
                == 1
            )
    finally:
        restarted.close()


def test_sqlite_existing_check_violation_is_rejected_without_repair(
    tmp_path: Path,
) -> None:
    path = tmp_path / "check-row-drift.db"
    repository = _repository(path)
    run_id = f"run_{'1' * 32}"
    job_id = f"job_{'2' * 32}"
    repository.initialize()
    with repository.transaction() as session:
        session.add(_run(run_id))
        session.flush()
        session.add(_job(run_id, job_id))
        session.flush()
        session.add(_artifact(run_id, job_id))
    repository.close()

    direct = sqlite3.connect(path)
    try:
        direct.execute("PRAGMA ignore_check_constraints=ON")
        direct.execute(
            """
            INSERT INTO cp_artifacts (
                artifact_id, repository_version, producer_run_id,
                producer_job_id, producer_attempt, sealed_run_id, media_type,
                schema_kind, byte_length, content_digest, root_digest,
                created_by, storage_key, idempotency_key, admission_digest,
                created_at
            )
            SELECT ?, repository_version, producer_run_id, producer_job_id,
                producer_attempt, sealed_run_id, media_type, schema_kind, 0,
                content_digest, root_digest, created_by, ?, ?, admission_digest,
                created_at
            FROM cp_artifacts WHERE artifact_id = ?
            """,
            (
                f"artifact_{'2' * 32}",
                "objects/artifact-invalid-check-v1",
                "artifact-invalid-check-admission-v1",
                f"artifact_{'1' * 32}",
            ),
        )
        direct.commit()
        direct.execute("PRAGMA ignore_check_constraints=OFF")
        assert direct.execute("PRAGMA quick_check('cp_artifacts')").fetchone() != ("ok",)
    finally:
        direct.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="integrity check"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM cp_artifacts "
                        f"WHERE artifact_id = 'artifact_{'2' * 32}'"
                    )
                )
                == 1
            )
    finally:
        restarted.close()


def test_sqlite_integrity_checks_ignore_unmanaged_coexisting_tables(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unmanaged-table-check-drift.db"
    repository = _repository(path)
    repository.initialize()
    repository.close()

    direct = sqlite3.connect(path)
    try:
        direct.execute("CREATE TABLE unrelated_rows (value INTEGER CHECK (value > 0))")
        direct.execute("PRAGMA ignore_check_constraints=ON")
        direct.execute("INSERT INTO unrelated_rows (value) VALUES (-1)")
        direct.commit()
    finally:
        direct.close()

    restarted = _repository(path)
    try:
        restarted.initialize()
        assert restarted.schema_version() == CURRENT_SCHEMA_VERSION
    finally:
        restarted.close()


@pytest.mark.parametrize(
    "table_name",
    [
        "cp_artifacts",
        "cp_replay_compilations",
        "cp_replay_execution_contexts",
        "cp_replay_events",
        "cp_replay_finalizations",
    ],
)
def test_missing_append_only_trigger_is_rejected_without_repair(
    tmp_path: Path,
    table_name: str,
) -> None:
    path = tmp_path / f"missing-trigger-{table_name}.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql(f"DROP TRIGGER {table_name}_no_delete")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="append-only delete trigger"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            trigger = connection.scalar(
                text(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = :trigger_name"
                ),
                {"trigger_name": f"{table_name}_no_delete"},
            )
        assert trigger is None
    finally:
        restarted.close()


def test_noop_append_only_trigger_with_managed_name_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "noop-trigger.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER cp_replay_events_no_delete")
        connection.exec_driver_sql(
            """
            CREATE TRIGGER cp_replay_events_no_delete
            BEFORE DELETE ON cp_replay_events WHEN 0
            BEGIN SELECT RAISE(ABORT, 'cp_replay_events is append-only'); END
            """
        )
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="append-only delete trigger"):
            restarted.initialize()
    finally:
        restarted.close()


@pytest.mark.parametrize(
    ("table_name", "operation"),
    [
        ("cp_replay_events", "INSERT"),
        ("cp_replay_batches", "UPDATE"),
    ],
)
def test_unmanaged_user_trigger_is_rejected_without_automatic_repair(
    tmp_path: Path,
    table_name: str,
    operation: str,
) -> None:
    path = tmp_path / f"unexpected-trigger-{table_name}.db"
    trigger_name = f"{table_name}_unmanaged"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql(
            f"CREATE TRIGGER {trigger_name} BEFORE {operation} ON {table_name} BEGIN SELECT 1; END"
        )
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="user trigger inventory"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    text(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'trigger' AND name = :trigger_name"
                    ),
                    {"trigger_name": trigger_name},
                )
                == trigger_name
            )
    finally:
        restarted.close()


def test_missing_named_check_constraint_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "missing-constraint.db"
    repository = _repository(path)
    repository.initialize()
    constraint = "CONSTRAINT ck_cp_replay_batches_cas_version CHECK (cas_version > 0), "
    with repository.engine.begin() as connection:
        definition = connection.scalar(
            text("SELECT sql FROM sqlite_master WHERE name = 'cp_replay_batches'")
        )
        assert isinstance(definition, str) and constraint in definition
        connection.exec_driver_sql("PRAGMA writable_schema=ON")
        connection.execute(
            text("UPDATE sqlite_master SET sql = :sql WHERE name = 'cp_replay_batches'"),
            {"sql": definition.replace(constraint, "")},
        )
        connection.exec_driver_sql("PRAGMA writable_schema=OFF")
        schema_version = int(connection.scalar(text("PRAGMA schema_version")) or 0)
        connection.exec_driver_sql(f"PRAGMA schema_version={schema_version + 1}")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="check constraint set"):
            restarted.initialize()
    finally:
        restarted.close()


def test_wrong_scalar_column_type_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "wrong-type.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        definition = connection.scalar(
            text("SELECT sql FROM sqlite_master WHERE name = 'cp_replay_batches'")
        )
        assert isinstance(definition, str)
        original = "cas_version INTEGER NOT NULL"
        assert original in definition
        connection.exec_driver_sql("PRAGMA writable_schema=ON")
        connection.execute(
            text("UPDATE sqlite_master SET sql = :sql WHERE name = 'cp_replay_batches'"),
            {"sql": definition.replace(original, "cas_version TEXT NOT NULL")},
        )
        connection.exec_driver_sql("PRAGMA writable_schema=OFF")
        schema_version = int(connection.scalar(text("PRAGMA schema_version")) or 0)
        connection.exec_driver_sql(f"PRAGMA schema_version={schema_version + 1}")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="type does not match"):
            restarted.initialize()
    finally:
        restarted.close()


def test_unexpected_index_is_rejected_without_automatic_repair(tmp_path: Path) -> None:
    path = tmp_path / "unexpected-index.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE INDEX ix_cp_replay_batches_unmanaged ON cp_replay_batches (state)"
        )
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="indexes do not match"):
            restarted.initialize()
    finally:
        restarted.close()


def test_same_named_sqlite_partial_index_is_rejected_without_automatic_repair(
    tmp_path: Path,
) -> None:
    path = tmp_path / "partial-claim-index.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ix_cp_jobs_claim")
        connection.exec_driver_sql(
            "CREATE INDEX ix_cp_jobs_claim "
            "ON cp_jobs (state, available_at, priority, created_at) "
            "WHERE state = 'leased'"
        )
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="unmanaged options"):
            restarted.initialize()
    finally:
        restarted.close()


def test_postgres_check_signature_accepts_repository_checks_and_pg_rendering() -> None:
    for table in Base.metadata.sorted_tables:
        for constraint in table.constraints:
            sqltext = getattr(constraint, "sqltext", None)
            if sqltext is not None:
                assert _postgres_check_signature(str(sqltext), str(sqltext), table), (
                    table.name,
                    constraint.name,
                )

    table = Base.metadata.tables["cp_replay_batches"]
    expected = "state IN ('planned', 'running', 'gating', 'completed', 'failed', 'cancelled')"
    actual = (
        "CHECK (((state)::text = ANY ((ARRAY["
        "'planned'::character varying, 'running'::character varying, "
        "'gating'::character varying, 'completed'::character varying, "
        "'failed'::character varying, 'cancelled'::character varying"
        "])::text[])))"
    )
    assert _postgres_check_signature(actual, expected, table)

    alternate_actual = (
        "state::text = ANY (ARRAY["
        "('planned'::character varying)::text, "
        "('running'::character varying)::text, "
        "('gating'::character varying)::text, "
        "('completed'::character varying)::text, "
        "('failed'::character varying)::text, "
        "('cancelled'::character varying)::text]::text[])"
    )
    assert _postgres_check_signature(alternate_actual, expected, table)

    expected_nulls = (
        "(cancelled_at IS NULL AND cancellation_reason IS NULL) OR "
        "(cancelled_at IS NOT NULL AND cancellation_reason IS NOT NULL)"
    )
    rendered_nulls = (
        "CHECK ((((cancelled_at IS NULL) AND (cancellation_reason IS NULL)) OR "
        "((cancelled_at IS NOT NULL) AND (cancellation_reason IS NOT NULL))))"
    )
    assert _postgres_check_signature(rendered_nulls, expected_nulls, table)


def test_postgres_json_authority_sql_preserves_duplicates_and_bounds_the_walk() -> None:
    rendered = _json_object_is_valid_sql(
        "NEW.input",
        dialect_name="postgresql",
        max_storage_bytes=4_096,
        max_depth=3,
        max_nodes=4,
        max_keys=2,
    )

    assert "WITH RECURSIVE pajin_json_walk" in rendered
    assert "json_each(" in rendered
    assert "json_array_elements(" in rendered
    assert "::jsonb" not in rendered
    assert "LIMIT 5" in rendered
    assert "LIMIT 3" in rendered
    assert "depth > 3" in rendered
    assert "count(*) <= 4 FROM pajin_json_nodes" in rendered
    assert "count(*) <= 2 FROM pajin_json_members" in rendered
    assert "GROUP BY path, key" in rendered
    assert "HAVING count(*) > 1" in rendered


@pytest.mark.parametrize(
    ("actual", "expected", "table_name"),
    [
        ("cas_version < 0", "cas_version > 0", "cp_replay_batches"),
        ("0 > cas_version", "cas_version > 0", "cp_replay_batches"),
        (
            "attempts <= max_attempts AND attempts >= 0",
            "attempts >= 0 AND attempts <= max_attempts",
            "cp_replay_items",
        ),
        (
            "max_attempts >= attempts AND 0 <= attempts",
            "attempts >= 0 AND attempts <= max_attempts",
            "cp_replay_items",
        ),
        (
            "state NOT IN ('planned', 'running', 'gating', 'completed', 'failed', 'cancelled')",
            "state IN ('planned', 'running', 'gating', 'completed', 'failed', 'cancelled')",
            "cp_replay_batches",
        ),
        (
            "state <> 'cancelled::text'",
            "state <> 'cancelled'",
            "cp_replay_batches",
        ),
        (
            "cas_version::integer > 0",
            "cas_version > 0",
            "cp_replay_batches",
        ),
        (
            "state::pajin_unmanaged_text <> 'cancelled'",
            "state <> 'cancelled'",
            "cp_replay_batches",
        ),
        (
            "length(media_type) = length(replace(media_type, '/', '')) + 2",
            "length(media_type) = length(replace(media_type, '/', '')) + 1",
            "cp_artifacts",
        ),
    ],
)
def test_postgres_check_signature_rejects_semantic_or_structural_drift(
    actual: str,
    expected: str,
    table_name: str,
) -> None:
    assert not _postgres_check_signature(actual, expected, Base.metadata.tables[table_name])


def _valid_postgres_trigger_row(table_name: str) -> SimpleNamespace:
    suffix = {
        "cp_artifacts": "artifact",
        "cp_events": "event",
        "cp_replay_compilations": "replay_compilation",
        "cp_replay_execution_contexts": "replay_execution_context",
        "cp_replay_events": "replay_event",
        "cp_replay_tool_permits": "replay_tool_permit",
    }[table_name]
    return SimpleNamespace(
        trigger_enabled="O",
        trigger_type=27,
        no_trigger_columns=True,
        has_when=False,
        trigger_arguments_length=0,
        function_name=f"pajin_cp_reject_{suffix}_mutation",
        function_schema="public",
        expected_schema="public",
        function_language="plpgsql",
        function_argument_count=0,
        returns_trigger=True,
        function_kind="f",
        security_definer=False,
        leakproof=False,
        volatility="v",
        parallel_mode="u",
        no_function_config=True,
        function_source=(f"BEGIN RAISE EXCEPTION '{table_name} is append-only'; END;"),
    )


def test_postgres_append_only_trigger_accepts_exact_managed_definition() -> None:
    for table_name in (
        "cp_artifacts",
        "cp_events",
        "cp_replay_compilations",
        "cp_replay_execution_contexts",
        "cp_replay_events",
        "cp_replay_tool_permits",
    ):
        assert _postgres_append_only_trigger_is_valid(
            _valid_postgres_trigger_row(table_name), table_name
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("trigger_enabled", "D"),
        ("trigger_type", 19),
        ("trigger_type", 25),
        ("no_trigger_columns", False),
        ("has_when", True),
        ("trigger_arguments_length", 1),
        ("function_name", "pajin_cp_unmanaged_mutation"),
        ("function_schema", "unmanaged"),
        ("function_language", "sql"),
        ("security_definer", True),
        ("function_source", "BEGIN RETURN OLD; END;"),
    ],
)
def test_postgres_append_only_trigger_rejects_disabled_scoped_or_mutated_definition(
    field: str,
    value: object,
) -> None:
    row = _valid_postgres_trigger_row("cp_replay_events")
    setattr(row, field, value)
    assert not _postgres_append_only_trigger_is_valid(row, "cp_replay_events")


def test_postgres_truncate_trigger_accepts_only_statement_level_truncate() -> None:
    row = _valid_postgres_trigger_row("cp_replay_events")
    row.trigger_type = 2 | 32
    assert _postgres_truncate_trigger_is_valid(row, "cp_replay_events")

    row.trigger_type = 1 | 2 | 32
    assert not _postgres_truncate_trigger_is_valid(row, "cp_replay_events")


@pytest.mark.parametrize("conflict_kind", ["rowid", "primary-key", "unique-key"])
def test_sqlite_direct_connection_cannot_replace_append_only_rows(
    tmp_path: Path,
    conflict_kind: str,
) -> None:
    path = tmp_path / f"direct-replace-{conflict_kind}.db"
    repository = _repository(path)
    run_id = f"run_direct_replace_{conflict_kind}"
    event_id = f"event_direct_replace_{conflict_kind}"
    try:
        repository.initialize()
        with repository.transaction() as session:
            session.add(_run(run_id))
            session.flush()
            session.add(
                EventRecord(
                    event_id=event_id,
                    run_id=run_id,
                    sequence=1,
                    event_type="original",
                    actor="migration-test",
                    payload={"original": True},
                    occurred_at=datetime.now(UTC),
                )
            )
    finally:
        repository.close()

    direct = sqlite3.connect(path)
    try:
        direct.execute("PRAGMA recursive_triggers=OFF")
        assert direct.execute("PRAGMA recursive_triggers").fetchone() == (0,)
        original_rowid = direct.execute(
            "SELECT rowid FROM cp_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        assert original_rowid is not None
        replacement_event_id = event_id if conflict_kind == "primary-key" else f"{event_id}_new"
        replacement_sequence = 1 if conflict_kind == "unique-key" else 2
        columns = "event_id, run_id, sequence, event_type, actor, payload, occurred_at"
        values: tuple[object, ...] = (
            replacement_event_id,
            run_id,
            replacement_sequence,
            "replaced",
            "migration-test",
            '{"original":false}',
            datetime.now(UTC).isoformat(),
        )
        if conflict_kind == "rowid":
            columns = "rowid, " + columns
            values = (int(original_rowid[0]), *values)
        placeholders = ", ".join("?" for _ in values)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            direct.execute(
                f"INSERT OR REPLACE INTO cp_events ({columns}) VALUES ({placeholders})",
                values,
            )
        direct.rollback()
        assert direct.execute(
            "SELECT event_type, payload FROM cp_events WHERE event_id = ?", (event_id,)
        ).fetchone() == ("original", '{"original": true}')
        assert direct.execute("SELECT count(*) FROM cp_events").fetchone() == (1,)
    finally:
        direct.close()


def test_missing_sqlite_no_replace_trigger_is_rejected_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "missing-no-replace-trigger.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER cp_events_no_replace")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="append-only insert trigger"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' "
                        "AND name = 'cp_events_no_replace'"
                    )
                )
                == 0
            )
    finally:
        restarted.close()


def test_replay_events_are_append_only_and_replay_checks_are_enforced(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "authority-constraints.db")
    repository.initialize()
    now = datetime.now(UTC)
    run_id = f"run_{'1' * 32}"
    job_id = f"job_{'2' * 32}"
    with repository.transaction() as session:
        session.add(_run(run_id))
        session.flush()
        session.add(_job(run_id, job_id))
        session.flush()
        session.add(_artifact(run_id, job_id))
        session.flush()
        session.add(_batch(run_id))
        session.flush()
        session.add(
            ReplayEventRecord(
                event_id="event_replay_constraints",
                batch_id="batch_migration",
                item_id=None,
                ticket_id=None,
                job_id=None,
                run_id=run_id,
                sequence=1,
                event_type="replay.batch.planned",
                actor="migration-test-operator",
                payload={"state": "planned"},
                occurred_at=now,
            )
        )

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        event = session.get(ReplayEventRecord, "event_replay_constraints")
        assert event is not None
        event.event_type = "replay.event.tampered"

    with pytest.raises(IntegrityError), repository.transaction() as session:
        invalid = _batch(run_id, "batch_invalid_state")
        invalid.state = "unknown"
        invalid.idempotency_key = "idempotency-invalid-state"
        invalid.created_at = now + timedelta(seconds=1)
        session.add(invalid)
    repository.close()


def test_artifacts_are_append_only_and_batch_requires_exact_authority_binding(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "artifact-authority.db")
    repository.initialize()
    run_id = f"run_{'3' * 32}"
    job_id = f"job_{'4' * 32}"
    with repository.transaction() as session:
        session.add(_run(run_id))
        session.flush()
        session.add(_job(run_id, job_id))
        session.flush()
        session.add(_artifact(run_id, job_id))

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        artifact = session.get(ArtifactRecord, (f"artifact_{'1' * 32}", 1))
        assert artifact is not None
        artifact.root_digest = "d" * 64

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        artifact = session.get(ArtifactRecord, (f"artifact_{'1' * 32}", 1))
        assert artifact is not None
        session.delete(artifact)

    with pytest.raises(IntegrityError), repository.transaction() as session:
        batch = _batch(run_id, "batch_wrong_artifact_binding")
        batch.idempotency_key = "idempotency-wrong-artifact-binding"
        batch.source_root_digest = "e" * 64
        session.add(batch)
    repository.close()


def test_replay_compilation_bytes_are_preserved_and_append_only(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "replay-compilation-append-only.db")
    repository.initialize()
    _, _, replay_run_id = _seed_replay_item_authority(repository)
    canonical = b'{"schemaVersion":1,"kind":"ReplayCompilation"}'
    with repository.transaction() as session:
        session.add(
            _compilation(
                replay_run_id=replay_run_id,
                canonical_compilation=canonical,
            )
        )

    with repository.transaction() as session:
        record = session.get(
            ReplayCompilationRecord,
            f"replay-compilation_{'6' * 32}",
        )
        assert record is not None
        assert record.canonical_compilation == canonical
        assert record.byte_length == len(canonical)

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        record = session.get(
            ReplayCompilationRecord,
            f"replay-compilation_{'6' * 32}",
        )
        assert record is not None
        record.canonical_compilation = b"tampered"
        record.byte_length = len(record.canonical_compilation)

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        record = session.get(
            ReplayCompilationRecord,
            f"replay-compilation_{'6' * 32}",
        )
        assert record is not None
        session.delete(record)
    repository.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("item_id", "item_other"),
        ("batch_id", "batch_other"),
        ("candidate_id", "candidate-other"),
        ("candidate_digest", "2" * 64),
        ("contract_digest", "3" * 64),
    ],
)
def test_replay_compilation_requires_exact_item_authority_binding(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    repository = _repository(tmp_path / f"replay-compilation-binding-{field}.db")
    repository.initialize()
    _, _, replay_run_id = _seed_replay_item_authority(repository)
    with pytest.raises(IntegrityError), repository.transaction() as session:
        compilation = _compilation(replay_run_id=replay_run_id)
        setattr(compilation, field, value)
        session.add(compilation)
    repository.close()


def test_replay_compilation_prevents_candidate_identity_mutation(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "replay-compilation-candidate-identity.db")
    repository.initialize()
    _, _, replay_run_id = _seed_replay_item_authority(repository)
    with repository.transaction() as session:
        session.add(_compilation(replay_run_id=replay_run_id))

    with pytest.raises(IntegrityError), repository.transaction() as session:
        item = session.get(ReplayItemRecord, "item_migration")
        assert item is not None
        item.candidate_id = "candidate-mutated-after-compilation"
    repository.close()


def test_replay_compilation_versions_own_fresh_run_grant_and_compilation_authority(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "replay-compilation-versions.db")
    repository.initialize()
    _, _, replay_run_id = _seed_replay_item_authority(repository)
    next_replay_run_id = f"run_{'5' * 32}"
    with repository.transaction() as session:
        session.add(_run(next_replay_run_id))
        session.flush()
        session.add(_compilation(replay_run_id=replay_run_id))
        session.add(
            _compilation(
                compilation_id=f"replay-compilation_{'7' * 32}",
                replay_run_id=next_replay_run_id,
                compilation_digest="2" * 64,
                grant_digest="3" * 64,
                canonical_compilation=b'{"schemaVersion":1,"version":2}',
            )
        )

    with repository.transaction() as session:
        records = list(
            session.scalars(
                select(ReplayCompilationRecord)
                .where(ReplayCompilationRecord.item_id == "item_migration")
                .order_by(ReplayCompilationRecord.compilation_id)
            ).all()
        )
    assert [record.compilation_id for record in records] == [
        f"replay-compilation_{'6' * 32}",
        f"replay-compilation_{'7' * 32}",
    ]
    assert records[1].replay_run_id == next_replay_run_id
    assert records[1].compilation_digest == "2" * 64
    assert records[1].grant_digest == "3" * 64

    with pytest.raises(IntegrityError), repository.transaction() as session:
        session.add(
            _compilation(
                compilation_id=f"replay-compilation_{'8' * 32}",
                replay_run_id=next_replay_run_id,
                compilation_digest="4" * 64,
            )
        )

    final_replay_run_id = f"run_{'9' * 32}"
    with repository.transaction() as session:
        session.add(_run(final_replay_run_id))
    with pytest.raises(IntegrityError), repository.transaction() as session:
        session.add(
            _compilation(
                compilation_id=f"replay-compilation_{'a' * 32}",
                replay_run_id=final_replay_run_id,
                compilation_digest="2" * 64,
            )
        )
    repository.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("compilation_id", f"replay-compilation_{'A' * 32}"),
        ("candidate_id", ""),
        ("candidate_id", "c" * 201),
        ("candidate_digest", "D" * 64),
        ("contract_digest", "g" * 64),
        ("compilation_digest", "f" * 63),
        ("grant_digest", "1" * 63 + "z"),
        ("byte_length", 1),
    ],
)
def test_replay_compilation_strict_checks_reject_invalid_canonical_authority(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    repository = _repository(tmp_path / f"replay-compilation-check-{field}.db")
    repository.initialize()
    _, _, replay_run_id = _seed_replay_item_authority(repository)
    with pytest.raises(IntegrityError), repository.transaction() as session:
        compilation = _compilation(replay_run_id=replay_run_id)
        setattr(compilation, field, value)
        session.add(compilation)
    repository.close()


def test_v5_ticket_has_exact_compilation_budget_and_rate_reservation_foreign_keys(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v5-ticket-authority.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    with repository.transaction() as session:
        session.add(ReplayTicketRecord(**ticket_values))

    with repository.transaction() as session:
        ticket = session.get(ReplayTicketRecord, ticket_values["ticket_id"])
        assert ticket is not None
        assert ticket.compilation_id == ticket_values["compilation_id"]
        assert ticket.budget_reservation_id == ticket_values["budget_reservation_id"]
        assert ticket.rate_reservation_id == ticket_values["rate_reservation_id"]

    foreign_keys = {
        constraint["name"]: (
            tuple(constraint.get("constrained_columns") or ()),
            constraint.get("referred_table"),
            tuple(constraint.get("referred_columns") or ()),
        )
        for constraint in inspect(repository.engine).get_foreign_keys("cp_replay_tickets")
    }
    assert foreign_keys["fk_cp_replay_tickets_compilation_authority"] == (
        (
            "compilation_id",
            "item_id",
            "batch_id",
            "replay_run_id",
            "compilation_digest",
            "grant_digest",
        ),
        "cp_replay_compilations",
        (
            "compilation_id",
            "item_id",
            "batch_id",
            "replay_run_id",
            "compilation_digest",
            "grant_digest",
        ),
    )
    assert foreign_keys["fk_cp_replay_tickets_budget_reservation"][0] == (
        "budget_reservation_id",
        "item_id",
        "batch_id",
        "attempt_number",
        "compilation_id",
    )
    assert foreign_keys["fk_cp_replay_tickets_budget_reservation"][1] == (
        "cp_replay_budget_reservations"
    )
    assert foreign_keys["fk_cp_replay_tickets_rate_reservation"][0] == (
        "rate_reservation_id",
        "item_id",
        "batch_id",
        "attempt_number",
        "compilation_id",
    )
    assert foreign_keys["fk_cp_replay_tickets_rate_reservation"][1] == (
        "cp_replay_rate_reservations"
    )
    ticket_uniques = {
        constraint["name"]: tuple(constraint.get("column_names") or ())
        for constraint in inspect(repository.engine).get_unique_constraints("cp_replay_tickets")
    }
    assert ticket_uniques["uq_cp_replay_tickets_compilation"] == ("compilation_id",)
    assert ticket_uniques["uq_cp_replay_tickets_budget_reservation"] == ("budget_reservation_id",)
    assert ticket_uniques["uq_cp_replay_tickets_rate_reservation"] == ("rate_reservation_id",)
    for table_name, expected_unique in (
        ("cp_replay_budget_reservations", "uq_cp_replay_budget_reservations_item_attempt"),
        ("cp_replay_rate_reservations", "uq_cp_replay_rate_reservations_item_attempt"),
    ):
        unique_names = {
            constraint["name"]
            for constraint in inspect(repository.engine).get_unique_constraints(table_name)
        }
        assert expected_unique in unique_names
    repository.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("compilation_id", f"replay-compilation_{'6' * 32}"),
        ("budget_reservation_id", f"budget-reservation_{'e' * 32}"),
        ("rate_reservation_id", f"rate-reservation_{'e' * 32}"),
        ("replay_run_id", f"run_{'4' * 32}"),
        ("attempt_number", 2),
        ("compilation_digest", "f" * 64),
        ("grant_digest", "1" * 64),
    ],
)
def test_v5_ticket_rejects_mismatched_compilation_or_reservation_authority(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    repository = _repository(tmp_path / f"v5-ticket-mismatch-{field}.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    ticket_values[field] = value
    with pytest.raises(IntegrityError), repository.transaction() as session:
        session.add(ReplayTicketRecord(**ticket_values))
    repository.close()


@pytest.mark.parametrize(
    ("record_name", "updates"),
    [
        ("budget-account", {"reserved_calls": 9}),
        ("budget-reservation", {"state": "consumed"}),
        ("budget-reservation", {"released_calls": 3}),
        ("rate-account", {"max_requests_per_minute": 0}),
        ("rate-reservation", {"state": "released"}),
        ("rate-reservation", {"expires_at": None}),
    ],
)
def test_v5_permit_checks_reject_impossible_usage_and_lifecycle(
    tmp_path: Path,
    record_name: str,
    updates: dict[str, object],
) -> None:
    repository = _repository(tmp_path / f"v5-permit-check-{record_name}-{'-'.join(updates)}.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    identities = {
        "budget-account": (
            ReplayBudgetAccountRecord,
            f"replay-budget-account_{'8' * 32}",
        ),
        "budget-reservation": (
            ReplayBudgetReservationRecord,
            ticket_values["budget_reservation_id"],
        ),
        "rate-account": (
            ReplayRateAccountRecord,
            f"replay-rate-account_{'9' * 32}",
        ),
        "rate-reservation": (
            ReplayRateReservationRecord,
            ticket_values["rate_reservation_id"],
        ),
    }
    record_type, record_id = identities[record_name]
    with pytest.raises(IntegrityError), repository.transaction() as session:
        record = session.get(record_type, record_id)
        assert record is not None
        if record_name == "rate-reservation" and "expires_at" in updates:
            updates = {"expires_at": record.reserved_at}
        for field, value in updates.items():
            setattr(record, field, value)
    repository.close()


def test_v7_execution_context_has_exact_compilation_authority_and_is_append_only(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v7-execution-context-authority.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    context_values = _execution_context_values(ticket_values)
    with repository.transaction() as session:
        session.add(ReplayExecutionContextRecord(**context_values))

    with repository.transaction() as session:
        context = session.get(ReplayExecutionContextRecord, context_values["context_id"])
        assert context is not None
        assert context.compilation_id == ticket_values["compilation_id"]
        assert context.item_id == ticket_values["item_id"]
        assert context.batch_id == ticket_values["batch_id"]
        assert context.replay_run_id == ticket_values["replay_run_id"]
        assert context.compilation_digest == ticket_values["compilation_digest"]
        assert context.grant_digest == ticket_values["grant_digest"]
        assert context.canonical_context == context_values["canonical_context"]
        assert context.byte_length == len(context.canonical_context)
        assert context.required_executor_profile == "kisa-exact-v1"

    foreign_keys = {
        constraint["name"]: (
            tuple(constraint.get("constrained_columns") or ()),
            constraint.get("referred_table"),
            tuple(constraint.get("referred_columns") or ()),
        )
        for constraint in inspect(repository.engine).get_foreign_keys(
            "cp_replay_execution_contexts"
        )
    }
    assert foreign_keys["fk_cp_replay_execution_contexts_compilation_authority"] == (
        (
            "compilation_id",
            "item_id",
            "batch_id",
            "replay_run_id",
            "compilation_digest",
            "grant_digest",
        ),
        "cp_replay_compilations",
        (
            "compilation_id",
            "item_id",
            "batch_id",
            "replay_run_id",
            "compilation_digest",
            "grant_digest",
        ),
    )
    unique_constraints = {
        constraint["name"]: tuple(constraint.get("column_names") or ())
        for constraint in inspect(repository.engine).get_unique_constraints(
            "cp_replay_execution_contexts"
        )
    }
    assert unique_constraints == {
        "uq_cp_replay_execution_contexts_compilation": ("compilation_id",),
        "uq_cp_replay_execution_contexts_digest": ("context_digest",),
        "uq_cp_replay_execution_contexts_output_staging_id": ("output_staging_id",),
    }

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        context = session.get(ReplayExecutionContextRecord, context_values["context_id"])
        assert context is not None
        context.required_executor_profile = "different-profile"

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        context = session.get(ReplayExecutionContextRecord, context_values["context_id"])
        assert context is not None
        session.delete(context)
    repository.close()


@pytest.mark.parametrize(
    "duplicate_authority",
    ["compilation_id", "context_digest", "output_staging_id"],
)
def test_v7_execution_context_rejects_duplicate_authority(
    tmp_path: Path,
    duplicate_authority: str,
) -> None:
    repository = _repository(tmp_path / f"v7-context-duplicate-{duplicate_authority}.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    context_values = _execution_context_values(ticket_values)
    with repository.transaction() as session:
        session.add(ReplayExecutionContextRecord(**context_values))

    duplicate = {
        **context_values,
        "context_id": f"replay-context_{'8' * 32}",
        "compilation_id": f"replay-compilation_{'6' * 32}",
        "replay_run_id": f"run_{'4' * 32}",
        "compilation_digest": "f" * 64,
        "grant_digest": "1" * 64,
        "context_digest": "9" * 64,
        "output_staging_id": f"stage_{'a' * 32}",
    }
    if duplicate_authority == "compilation_id":
        duplicate.update(
            compilation_id=context_values["compilation_id"],
            replay_run_id=context_values["replay_run_id"],
            compilation_digest=context_values["compilation_digest"],
            grant_digest=context_values["grant_digest"],
        )
    else:
        duplicate[duplicate_authority] = context_values[duplicate_authority]

    with pytest.raises(IntegrityError), repository.transaction() as session:
        session.add(ReplayExecutionContextRecord(**duplicate))
    repository.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("context_id", f"replay-context_{'A' * 32}"),
        ("context_digest", "A" * 64),
        ("canonical_context", b""),
        ("byte_length", 0),
        ("required_executor_profile", "kisa/exact/v1"),
        ("required_executor_profile", ".kisa-exact-v1"),
        ("output_staging_id", f"stage_{'A' * 32}"),
        ("compilation_id", f"replay-compilation_{'e' * 32}"),
        ("item_id", "item_other"),
        ("batch_id", "batch_other"),
        ("replay_run_id", f"run_{'4' * 32}"),
        ("compilation_digest", "f" * 64),
        ("grant_digest", "1" * 64),
    ],
)
def test_v7_execution_context_rejects_invalid_or_mismatched_authority(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    repository = _repository(tmp_path / f"v7-context-invalid-{field}.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    context_values = _execution_context_values(ticket_values)
    context_values[field] = value
    with pytest.raises(IntegrityError), repository.transaction() as session:
        session.add(ReplayExecutionContextRecord(**context_values))
    repository.close()


def test_v6_tool_permit_is_exactly_bound_unique_and_append_only(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "v6-tool-permit-authority.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    _activate_v5_ticket_graph(repository, ticket_values)
    _claim_v6_ticket_graph(repository, ticket_values)
    permit_values = _permit_values(ticket_values)
    with repository.transaction() as session:
        session.add(ReplayToolPermitRecord(**permit_values))

    with repository.transaction() as session:
        permit = session.get(ReplayToolPermitRecord, permit_values["permit_id"])
        assert permit is not None
        assert permit.ticket_id == ticket_values["ticket_id"]
        assert permit.call_ordinal == permit.tool_call_units == permit.request_units == 1

    duplicate = dict(permit_values)
    duplicate.update(
        permit_id=f"replay-permit_{'6' * 32}",
        permit_digest="7" * 64,
        replay_request_id=f"tool_replay_{'8' * 32}",
    )
    with pytest.raises(IntegrityError), repository.transaction() as session:
        session.add(ReplayToolPermitRecord(**duplicate))

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        permit = session.get(ReplayToolPermitRecord, permit_values["permit_id"])
        assert permit is not None
        permit.request_units = 2

    with (
        pytest.raises(DatabaseError, match="append-only"),
        repository.transaction() as session,
    ):
        permit = session.get(ReplayToolPermitRecord, permit_values["permit_id"])
        assert permit is not None
        session.delete(permit)
    repository.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("permit_id", f"replay-permit_{'A' * 32}"),
        ("permit_digest", "G" * 64),
        ("replay_request_id", f"tool_replay_{'A' * 32}"),
        ("compilation_id", f"replay-compilation_{'6' * 32}"),
        ("budget_reservation_id", f"budget-reservation_{'e' * 32}"),
        ("rate_reservation_id", f"rate-reservation_{'e' * 32}"),
        ("replay_run_id", f"run_{'4' * 32}"),
        ("attempt_number", 2),
        ("fencing_value", 2),
        ("issued_to", "different-worker"),
        ("executor_profile", "different-profile"),
        ("lease_token_hash", "0" * 64),
        ("source_root_digest", "0" * 64),
        ("compilation_digest", "f" * 64),
        ("grant_digest", "1" * 64),
        ("call_ordinal", 0),
        ("tool_call_units", 2),
        ("request_units", 0),
    ],
)
def test_v6_tool_permit_rejects_mismatched_authority_or_invalid_units(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    repository = _repository(tmp_path / f"v6-tool-permit-invalid-{field}.db")
    repository.initialize()
    ticket_values = _seed_v5_issuance_prerequisites(repository)
    _activate_v5_ticket_graph(repository, ticket_values)
    _claim_v6_ticket_graph(repository, ticket_values)
    permit_values = _permit_values(ticket_values)
    permit_values[field] = value
    with pytest.raises(IntegrityError), repository.transaction() as session:
        session.add(ReplayToolPermitRecord(**permit_values))
    repository.close()


def test_partial_v5_permit_schema_is_rejected_without_repair(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "partial-v5-permit.db")
    try:
        _create_v4_schema(repository)
        with repository.engine.begin() as connection:
            ReplayBudgetAccountRecord.__table__.create(connection)

        with pytest.raises(SchemaInitializationError, match="partial or unknown"):
            repository.initialize()

        table_names = set(inspect(repository.engine).get_table_names())
        assert "cp_replay_budget_accounts" in table_names
        assert "cp_replay_budget_reservations" not in table_names
        with repository.engine.connect() as connection:
            assert list(
                connection.scalars(
                    select(_V4_METADATA.tables["cp_schema_version"].c.version).order_by(
                        _V4_METADATA.tables["cp_schema_version"].c.version
                    )
                ).all()
            ) == [1, 2, 3, 4]
    finally:
        repository.close()


def test_corrupt_v5_permit_index_is_rejected_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "corrupt-v5-permit-index.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ix_cp_replay_budget_reservations_account_state")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="indexes do not match"):
            restarted.initialize()
        assert "ix_cp_replay_budget_reservations_account_state" not in {
            index["name"]
            for index in inspect(restarted.engine).get_indexes("cp_replay_budget_reservations")
        }
    finally:
        restarted.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_id", f"artifact_{'A' * 32}"),
        ("content_digest", "G" * 64),
        ("root_digest", "0" * 63 + "z"),
        ("admission_digest", "F" * 64),
        ("producer_attempt", 2_147_483_648),
        ("byte_length", 2_147_483_648),
        ("sealed_run_id", "_sealed-run"),
        ("sealed_run_id", "sealed/run"),
        ("schema_kind", ".pajin.run.v1"),
        ("schema_kind", "pajin/run/v1"),
        ("media_type", ".application/json"),
        ("media_type", "application/.json"),
        ("media_type", "application/json/extra"),
        ("media_type", "application_json"),
    ],
)
def test_artifact_strict_checks_reject_invalid_authority_metadata(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    repository = _repository(tmp_path / f"artifact-invalid-{field}.db")
    repository.initialize()
    run_id = f"run_{'5' * 32}"
    job_id = f"job_{'6' * 32}"
    with repository.transaction() as session:
        session.add(_run(run_id))
        session.flush()
        session.add(_job(run_id, job_id))
        session.flush()
    with pytest.raises(IntegrityError), repository.transaction() as session:
        artifact = _artifact(run_id, job_id)
        setattr(artifact, field, value)
        session.add(artifact)
    repository.close()
