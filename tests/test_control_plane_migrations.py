from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event as ThreadEvent
from threading import Thread
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import inspect, select, text, update
from sqlalchemy.exc import DatabaseError, IntegrityError

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import (
    _V2_METADATA,
    _V2_MIGRATION_WRITE_LOCK_TABLES,
    _V3_METADATA,
    _V3_MIGRATION_WRITE_LOCK_TABLES,
    ARTIFACT_AUTHORITY_SCHEMA_VERSION,
    CURRENT_CONTROL_PLANE_TABLES,
    CURRENT_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
    REPLAY_AUTHORITY_SCHEMA_VERSION,
    V2_CONTROL_PLANE_TABLES,
    V3_CONTROL_PLANE_TABLES,
    ArtifactRecord,
    Base,
    ControlPlaneRepository,
    JobRecord,
    ReplayBatchRecord,
    ReplayCompilationRecord,
    ReplayEventRecord,
    ReplayItemRecord,
    RunRecord,
    SchemaInitializationError,
    SchemaVersionRecord,
    _lock_v2_migration_writes,
    _lock_v3_migration_writes,
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


def _job(run_id: str, job_id: str) -> JobRecord:
    now = datetime.now(UTC)
    return JobRecord(
        job_id=job_id,
        run_id=run_id,
        kind="campaign",
        state="succeeded",
        payload={"preserve": True},
        priority=0,
        attempts=1,
        max_attempts=1,
        idempotency_key=f"idempotency-{job_id}",
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
        session.add(_run(source_run_id))
        session.add(_run(replay_run_id))
        session.flush()
        session.add(_job(source_run_id, source_job_id))
        session.flush()
        session.add(_artifact(source_run_id, source_job_id))
        session.flush()
        session.add(_batch(source_run_id))
        session.flush()
        session.add(_item(source_run_id, replay_run_id))
    return source_run_id, source_job_id, replay_run_id


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
            CURRENT_SCHEMA_VERSION,
        ]

        repository.initialize()
        with repository.transaction() as session:
            assert session.scalar(select(text("count(*)")).select_from(SchemaVersionRecord)) == 4
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


def test_legacy_internal_replay_job_is_rejected_before_schema_history_is_created(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "legacy-internal-replay.db")
    run_id = "run_legacy_internal_replay"
    job_id = "job_legacy_internal_replay"
    try:
        _create_legacy_schema(repository)
        with repository.transaction() as session:
            session.add(_run(run_id))
            session.flush()
            job = _job(run_id, job_id)
            job.kind = "internal-replay"
            session.add(job)

        with pytest.raises(SchemaInitializationError, match="internal-replay Jobs: 1"):
            repository.initialize()

        assert "cp_schema_version" not in inspect(repository.engine).get_table_names()
        with repository.transaction() as session:
            preserved = session.get(JobRecord, job_id)
            assert preserved is not None
            assert preserved.kind == "internal-replay"
    finally:
        repository.close()


def test_empty_v2_database_migrates_forward_without_losing_core_rows(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "v2-empty.db")
    try:
        _create_v2_schema(repository)
        with repository.transaction() as session:
            session.add(_run("run_v2_preserved"))

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        with repository.transaction() as session:
            assert session.get(RunRecord, "run_v2_preserved") is not None
            versions = session.scalars(
                select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
            ).all()
        assert versions == [1, 2, 3, 4]
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
            session.add(_run(run_id))
            session.flush()
            session.add(_job(run_id, job_id))
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
        assert versions == [1, 2, 3, 4]
        assert "cp_replay_compilations" in inspect(repository.engine).get_table_names()
        item_unique_names = {
            constraint["name"]
            for constraint in inspect(repository.engine).get_unique_constraints("cp_replay_items")
        }
        assert "uq_cp_replay_items_compilation_plan" in item_unique_names
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
            session.add(_run(run_id))
            session.flush()
            session.add(_job(run_id, job_id))
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
            session.add(_run(run_id))
            session.flush()
            session.add(
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


@pytest.mark.parametrize(
    "table_name",
    ["cp_artifacts", "cp_replay_compilations", "cp_replay_events"],
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
        "cp_replay_events": "replay_event",
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
        "cp_replay_events",
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
