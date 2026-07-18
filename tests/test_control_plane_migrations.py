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
    _V4_METADATA,
    _V4_MIGRATION_WRITE_LOCK_TABLES,
    ARTIFACT_AUTHORITY_SCHEMA_VERSION,
    CURRENT_CONTROL_PLANE_TABLES,
    CURRENT_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
    REPLAY_AUTHORITY_SCHEMA_VERSION,
    REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
    V2_CONTROL_PLANE_TABLES,
    V3_CONTROL_PLANE_TABLES,
    V4_CONTROL_PLANE_TABLES,
    ArtifactRecord,
    Base,
    ControlPlaneRepository,
    JobRecord,
    ReplayBatchRecord,
    ReplayBudgetAccountRecord,
    ReplayBudgetReservationRecord,
    ReplayCompilationRecord,
    ReplayEventRecord,
    ReplayItemRecord,
    ReplayRateAccountRecord,
    ReplayRateReservationRecord,
    ReplayTicketRecord,
    RunRecord,
    SchemaInitializationError,
    SchemaVersionRecord,
    _lock_v2_migration_writes,
    _lock_v3_migration_writes,
    _lock_v4_migration_writes,
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
        session.add(_run(fresh_replay_run_id))
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
        session.add(
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
