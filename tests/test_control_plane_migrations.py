from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text, update
from sqlalchemy.exc import DatabaseError, IntegrityError

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import (
    CURRENT_CONTROL_PLANE_TABLES,
    CURRENT_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
    Base,
    ControlPlaneRepository,
    ReplayBatchRecord,
    ReplayEventRecord,
    RunRecord,
    SchemaInitializationError,
    SchemaVersionRecord,
    _postgres_append_only_trigger_is_valid,
    _postgres_check_signature,
)
from pajin.control_plane.models import Principal, PrincipalRole


def _repository(path: Path) -> ControlPlaneRepository:
    return ControlPlaneRepository(f"sqlite:///{path.as_posix()}")


def _create_legacy_schema(repository: ControlPlaneRepository) -> None:
    pending = set(LEGACY_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
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


def _run(run_id: str) -> RunRecord:
    now = datetime.now(UTC)
    return RunRecord(
        run_id=run_id,
        campaign_name="migration-test",
        state="queued",
        input={"preserve": True},
        submission_key=f"submission-{run_id}",
        current_checkpoint_id=None,
        created_at=now,
        updated_at=now,
    )


def _batch(run_id: str, batch_id: str = "batch_migration") -> ReplayBatchRecord:
    now = datetime.now(UTC)
    return ReplayBatchRecord(
        batch_id=batch_id,
        source_run_id=run_id,
        idempotency_key=f"idempotency-{batch_id}",
        campaign_name="migration-test",
        created_by="migration-test-operator",
        source_artifact_id="artifact_source",
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
        assert versions == [1, CURRENT_SCHEMA_VERSION]

        repository.initialize()
        with repository.transaction() as session:
            assert session.scalar(select(text("count(*)")).select_from(SchemaVersionRecord)) == 2
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
            session.add(_run("run_legacy"))

        repository.initialize()

        with repository.transaction() as session:
            preserved = session.get(RunRecord, "run_legacy")
            assert preserved is not None
            assert preserved.input == {"preserve": True}
        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
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
            assert connection.scalar(
                select(SchemaVersionRecord.version).where(SchemaVersionRecord.version == 99)
            ) == 99
    finally:
        restarted.close()


def test_missing_required_column_is_rejected_without_automatic_repair(tmp_path: Path) -> None:
    path = tmp_path / "missing-column.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE cp_replay_batches DROP COLUMN source_created_by"
        )
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="columns do not match"):
            restarted.initialize()
        assert "source_created_by" not in {
            column["name"]
            for column in inspect(restarted.engine).get_columns("cp_replay_batches")
        }
    finally:
        restarted.close()


def test_missing_append_only_trigger_is_rejected_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "missing-trigger.db"
    repository = _repository(path)
    repository.initialize()
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER cp_replay_events_no_delete")
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="append-only delete trigger"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            trigger = connection.scalar(
                text(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND name = 'cp_replay_events_no_delete'"
                )
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
            f"CREATE TRIGGER {trigger_name} BEFORE {operation} ON {table_name} "
            "BEGIN SELECT 1; END"
        )
    repository.close()

    restarted = _repository(path)
    try:
        with pytest.raises(SchemaInitializationError, match="user trigger inventory"):
            restarted.initialize()
        with restarted.engine.connect() as connection:
            assert connection.scalar(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'trigger' AND name = :trigger_name"
                ),
                {"trigger_name": trigger_name},
            ) == trigger_name
    finally:
        restarted.close()


def test_missing_named_check_constraint_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "missing-constraint.db"
    repository = _repository(path)
    repository.initialize()
    constraint = (
        "CONSTRAINT ck_cp_replay_batches_cas_version CHECK (cas_version > 0), "
    )
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


def test_postgres_check_signature_accepts_repository_checks_and_pg_rendering() -> None:
    for table in Base.metadata.sorted_tables:
        for constraint in table.constraints:
            sqltext = getattr(constraint, "sqltext", None)
            if sqltext is not None:
                assert _postgres_check_signature(
                    str(sqltext), str(sqltext), table
                ), (table.name, constraint.name)

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
            "state NOT IN ('planned', 'running', 'gating', 'completed', 'failed', "
            "'cancelled')",
            "state IN ('planned', 'running', 'gating', 'completed', 'failed', "
            "'cancelled')",
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
    ],
)
def test_postgres_check_signature_rejects_semantic_or_structural_drift(
    actual: str,
    expected: str,
    table_name: str,
) -> None:
    assert not _postgres_check_signature(
        actual, expected, Base.metadata.tables[table_name]
    )


def _valid_postgres_trigger_row(table_name: str) -> SimpleNamespace:
    suffix = "event" if table_name == "cp_events" else "replay_event"
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
        function_source=(
            f"BEGIN RAISE EXCEPTION '{table_name} is append-only'; END;"
        ),
    )


def test_postgres_append_only_trigger_accepts_exact_managed_definition() -> None:
    for table_name in ("cp_events", "cp_replay_events"):
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


def test_replay_events_are_append_only_and_replay_checks_are_enforced(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "authority-constraints.db")
    repository.initialize()
    now = datetime.now(UTC)
    with repository.transaction() as session:
        session.add(_run("run_replay_constraints"))
        session.flush()
        session.add(_batch("run_replay_constraints"))
        session.flush()
        session.add(
            ReplayEventRecord(
                event_id="event_replay_constraints",
                batch_id="batch_migration",
                item_id=None,
                ticket_id=None,
                job_id=None,
                run_id="run_replay_constraints",
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
        invalid = _batch("run_replay_constraints", "batch_invalid_state")
        invalid.state = "unknown"
        invalid.idempotency_key = "idempotency-invalid-state"
        invalid.created_at = now + timedelta(seconds=1)
        session.add(invalid)
    repository.close()
