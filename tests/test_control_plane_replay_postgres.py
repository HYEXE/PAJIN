from __future__ import annotations

import os
import shutil
import tempfile
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier, Thread
from threading import Event as ThreadEvent
from uuid import uuid4

import pytest
from kisa_control_plane_support import build_kisa_control_plane_source
from sqlalchemy import create_engine, func, inspect, select, text, update
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DatabaseError, IntegrityError

from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.database import (
    _V2_METADATA,
    _V3_METADATA,
    _V4_METADATA,
    CURRENT_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
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
    _install_append_only_trigger,
    _validate_append_only_trigger,
    _validate_current_schema,
)
from pajin.control_plane.models import (
    AdmitSourceArtifactRequest,
    ArtifactLocator,
    CancelRunRequest,
    CreateReplayBatchRequest,
    InternalJobKind,
    JobState,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayItemState,
    ReplayTicketState,
    RunState,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.control_plane.service import ControlPlaneService, StateConflict

POSTGRES_URL = os.environ.get("PAJIN_TEST_POSTGRES_URL")
EXECUTOR_PROFILE = "kisa-exact-v1"
WORKER_A = "postgres-replay-worker-a"
WORKER_B = "postgres-replay-worker-b"
pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="set PAJIN_TEST_POSTGRES_URL to an isolated PAJIN PostgreSQL test database",
)
_POSTGRES_ARTIFACT_ROOT = Path(tempfile.gettempdir()) / f"pajin-pg-artifacts-{os.getpid()}"


@pytest.fixture
def isolated_postgres_schema_url() -> Iterator[str]:
    """Yield a PostgreSQL URL pinned to one disposable, UUID-named schema."""

    assert POSTGRES_URL is not None
    schema_name = f"pajin_replay_v5_{uuid4().hex}"
    admin_engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    with admin_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema_name}"')

    scoped_url = make_url(POSTGRES_URL).update_query_dict(
        {"options": f"-csearch_path={schema_name}"}
    )
    try:
        yield scoped_url.render_as_string(hide_password=False)
    finally:
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema_name}" CASCADE')
        admin_engine.dispose()


def _service(
    database_url: str | None = None,
) -> tuple[ControlPlaneRepository, ControlPlaneService]:
    assert POSTGRES_URL is not None
    repository = ControlPlaneRepository(database_url or POSTGRES_URL)
    repository.initialize()
    return repository, _service_for_repository(repository)


def _service_for_repository(repository: ControlPlaneRepository) -> ControlPlaneService:
    """Build a service without implicitly migrating a deliberately old schema."""

    signer = CheckpointSigner(
        active_key_id="postgres-replay-v1",
        keys={"postgres-replay-v1": b"postgres-replay-signing-key-at-least-32-bytes"},
    )
    return ControlPlaneService(
        repository,
        signer,
        replay_executor_profiles={
            WORKER_A: frozenset({EXECUTOR_PROFILE}),
            WORKER_B: frozenset({EXECUTOR_PROFILE}),
        },
        artifact_repository=ManagedArtifactRepository(
            staging_root=_POSTGRES_ARTIFACT_ROOT / "staging",
            repository_root=_POSTGRES_ARTIFACT_ROOT / "repository",
        ),
    )


def _create_postgres_v2_schema(repository: ControlPlaneRepository) -> None:
    """Create the exact managed v2 schema in the repository's current schema."""

    pending = set(V2_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V2_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        _install_append_only_trigger(connection, "cp_events")
        _install_append_only_trigger(connection, "cp_replay_events")
        now = datetime.now(UTC)
        connection.execute(
            _V2_METADATA.tables["cp_schema_version"].insert(),
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


def _create_postgres_legacy_schema(repository: ControlPlaneRepository) -> None:
    """Create the exact pre-Replay schema in the repository's current schema."""

    pending = set(LEGACY_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        connection.exec_driver_sql("DROP INDEX ux_cp_jobs_job_run")
        _install_append_only_trigger(connection, "cp_events")


def _create_postgres_v3_schema(repository: ControlPlaneRepository) -> None:
    """Create the exact managed v3 schema in the repository's current schema."""

    pending = set(V3_CONTROL_PLANE_TABLES)
    with repository.engine.begin() as connection:
        for table in _V3_METADATA.sorted_tables:
            if table.name in pending:
                table.create(connection, checkfirst=False)
                pending.remove(table.name)
        assert not pending
        _install_append_only_trigger(connection, "cp_events")
        _install_append_only_trigger(connection, "cp_artifacts")
        _install_append_only_trigger(connection, "cp_replay_events")
        now = datetime.now(UTC)
        connection.execute(
            _V3_METADATA.tables["cp_schema_version"].insert(),
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


def _create_postgres_v4_schema(repository: ControlPlaneRepository) -> None:
    """Create the exact managed v4 schema before durable permit authority."""

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
            _install_append_only_trigger(connection, table_name)
        now = datetime.now(UTC)
        connection.execute(
            _V4_METADATA.tables["cp_schema_version"].insert(),
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


def _v2_run_values(suffix: str) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "run_id": f"run_{suffix}",
        "campaign_name": "postgres-v2-migration",
        "state": "completed",
        "input": {"preserve": True},
        "submission_key": f"postgres-v2-run-{suffix}",
        "current_checkpoint_id": None,
        "created_at": now,
        "updated_at": now,
    }


def _v2_job_values(suffix: str) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "job_id": f"job_{sha256(f'job:{suffix}'.encode()).hexdigest()[:32]}",
        "run_id": f"run_{suffix}",
        "kind": "campaign",
        "state": "succeeded",
        "payload": {"preserve": True},
        "priority": 0,
        "attempts": 1,
        "max_attempts": 1,
        "idempotency_key": f"postgres-v2-job-{suffix}",
        "available_at": now,
        "lease_owner": None,
        "lease_token_hash": None,
        "lease_expires_at": None,
        "heartbeat_at": None,
        "result": {"status": "completed"},
        "error": None,
        "created_at": now,
        "updated_at": now,
    }


def _v3_artifact_values(suffix: str) -> dict[str, object]:
    return {
        "artifact_id": f"artifact_{suffix}",
        "repository_version": 1,
        "producer_run_id": f"run_{suffix}",
        "producer_job_id": _v2_job_values(suffix)["job_id"],
        "producer_attempt": 1,
        "sealed_run_id": f"sealed-postgres-v3-{suffix}",
        "media_type": "application/vnd.pajin.run+json",
        "schema_kind": "pajin.run.v1",
        "byte_length": 512,
        "content_digest": "c" * 64,
        "root_digest": "d" * 64,
        "created_by": "postgres-v3-migration",
        "storage_key": f"objects/postgres-v3-{suffix}",
        "idempotency_key": f"postgres-v3-artifact-{suffix}",
        "admission_digest": "e" * 64,
        "created_at": datetime.now(UTC),
    }


def _v2_batch_values(suffix: str, batch_id: str) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "batch_id": batch_id,
        "source_run_id": f"run_{suffix}",
        "idempotency_key": f"postgres-v2-batch-{suffix}",
        "campaign_name": "postgres-v2-migration",
        "created_by": "postgres-v2-test",
        "source_artifact_id": "legacy-unverified-artifact",
        "source_repository_version": 1,
        "source_content_digest": "a" * 64,
        "source_root_digest": "b" * 64,
        "source_media_type": "application/vnd.pajin.run+json",
        "source_schema_kind": "pajin.run.v1",
        "source_byte_length": 512,
        "source_created_by": "postgres-v2-test",
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


def _seed_batch(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    suffix: str,
    *,
    item_count: int = 1,
    max_attempts: int = 3,
) -> str:
    source = _admit_kisa_source(
        repository,
        service,
        suffix,
        item_count=item_count,
    )
    created = service.create_replay_batch(
        CreateReplayBatchRequest(
            source=source,
            idempotency_key=f"postgres-replay-batch-{suffix}",
        ),
        actor="postgres-replay-admission",
    )
    service.issue_replay_batch(
        created.batch_id,
        actor="trusted-replay-issuer",
    )
    with repository.transaction() as session:
        items = list(
            session.scalars(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == created.batch_id)
            ).all()
        )
        assert len(items) == item_count
        for item in items:
            item.max_attempts = max_attempts
    return created.batch_id


def _admit_kisa_source(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    suffix: str,
    *,
    item_count: int = 1,
) -> ArtifactLocator:
    source_run_id = f"run_{suffix}"
    producer_job_id = f"job_{sha256(f'job:{suffix}'.encode()).hexdigest()[:32]}"
    stage_id = f"stage_{sha256(f'stage:{suffix}'.encode()).hexdigest()[:32]}"
    stage_path = _POSTGRES_ARTIFACT_ROOT / "staging" / stage_id
    fixture = build_kisa_control_plane_source(
        _POSTGRES_ARTIFACT_ROOT / "source-builds" / suffix,
        scenario_count=item_count,
        producer_run_id=source_run_id,
        created_by="postgres-replay-admission",
    )
    stage_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(fixture.path, stage_path)
    now = datetime.now(UTC)
    with repository.transaction() as session:
        source_run = RunRecord(
            run_id=source_run_id,
            campaign_name=fixture.campaign.metadata.name,
            state=RunState.COMPLETED.value,
            input={"sealedSource": True, "suffix": suffix},
            submission_key=f"postgres-replay-source-{suffix}",
            current_checkpoint_id=None,
            created_at=now,
            updated_at=now,
        )
        session.add(source_run)
        session.flush()
        session.add(
            JobRecord(
                job_id=producer_job_id,
                run_id=source_run_id,
                kind="campaign",
                state=JobState.SUCCEEDED.value,
                payload={"input": {}},
                priority=0,
                attempts=1,
                max_attempts=3,
                idempotency_key=f"postgres-source-job-{suffix}",
                available_at=now,
                lease_owner=None,
                lease_token_hash=None,
                lease_expires_at=None,
                heartbeat_at=None,
                result={"engineRunId": fixture.artifact_ref.run_id},
                error=None,
                created_at=now,
                updated_at=now,
            )
        )
    source = service.admit_source_artifact(
        AdmitSourceArtifactRequest(
            staging_id=stage_id,
            producer_run_id=source_run_id,
            producer_job_id=producer_job_id,
            idempotency_key=f"postgres-artifact-admission-{suffix}",
        ),
        actor="postgres-replay-admission",
    )
    return ArtifactLocator(
        artifact_id=source.artifact_id,
        repository_version=source.repository_version,
    )


def _plan_v4_batch(
    repository: ControlPlaneRepository,
    suffix: str,
    *,
    item_count: int = 1,
) -> tuple[ControlPlaneService, str]:
    """Create valid planned authority without initializing the v4 repository."""

    service = _service_for_repository(repository)
    source = _admit_kisa_source(
        repository,
        service,
        suffix,
        item_count=item_count,
    )
    batch = service.create_replay_batch(
        CreateReplayBatchRequest(
            source=source,
            idempotency_key=f"postgres-v4-replay-batch-{suffix}",
        ),
        actor="postgres-v4-replay-admission",
    )
    return service, batch.batch_id


def _v4_legacy_job_values(
    *,
    suffix: str,
    replay_run_id: str,
    internal: bool,
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "job_id": f"job_{sha256(f'v4-job:{suffix}'.encode()).hexdigest()[:32]}",
        "run_id": replay_run_id,
        "kind": InternalJobKind.REPLAY.value if internal else "campaign",
        "state": JobState.QUEUED.value,
        "payload": {"legacyV4": True},
        "priority": 0,
        "attempts": 0,
        "max_attempts": 1,
        "idempotency_key": f"postgres-v4-job-{suffix}",
        "available_at": now,
        "lease_owner": None,
        "lease_token_hash": None,
        "lease_expires_at": None,
        "heartbeat_at": None,
        "result": None,
        "error": None,
        "created_at": now,
        "updated_at": now,
    }


def _v4_legacy_ticket_values(
    *,
    suffix: str,
    batch: dict[str, object],
    item: dict[str, object],
    job: dict[str, object],
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "ticket_id": f"replay-ticket_{sha256(f'v4-ticket:{suffix}'.encode()).hexdigest()[:32]}",
        "batch_id": batch["batch_id"],
        "item_id": item["item_id"],
        "job_id": job["job_id"],
        "replay_run_id": item["replay_run_id"],
        "attempt_number": 1,
        "fencing_value": 1,
        "state": ReplayTicketState.ISSUED.value,
        "grant_digest": item["grant_digest"],
        "source_root_digest": batch["source_root_digest"],
        "compilation_digest": item["compilation_digest"],
        "executor_profile": None,
        "claim_principal": None,
        "lease_token_hash": None,
        "result_digest": None,
        "abandon_reason": None,
        "issued_at": now,
        "expires_at": now + timedelta(minutes=5),
        "claimed_at": None,
        "lease_expires_at": None,
        "finalized_at": None,
        "abandoned_at": None,
        "updated_at": now,
    }


def test_postgres_artifact_authority_is_append_only_and_batch_binding_is_exact(
    isolated_postgres_schema_url: str,
) -> None:
    repository, service = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    invalid_batch_id = f"batch_invalid_{suffix}"
    try:
        batch_id = _seed_batch(repository, service, suffix)
        with repository.transaction() as session:
            artifact = session.scalar(select(ArtifactRecord))
            assert artifact is not None
            artifact_key = (artifact.artifact_id, artifact.repository_version)

        with (
            pytest.raises(DatabaseError, match="cp_artifacts is append-only"),
            repository.engine.begin() as connection,
        ):
            connection.execute(
                update(ArtifactRecord)
                .where(
                    ArtifactRecord.artifact_id == artifact_key[0],
                    ArtifactRecord.repository_version == artifact_key[1],
                )
                .values(root_digest="0" * 64)
            )

        with (
            pytest.raises(DatabaseError, match="cp_artifacts is append-only"),
            repository.engine.begin() as connection,
        ):
            connection.execute(
                ArtifactRecord.__table__.delete().where(
                    ArtifactRecord.artifact_id == artifact_key[0],
                    ArtifactRecord.repository_version == artifact_key[1],
                )
            )

        with repository.engine.connect() as connection:
            original = (
                connection.execute(
                    select(ReplayBatchRecord.__table__).where(
                        ReplayBatchRecord.batch_id == batch_id
                    )
                )
                .mappings()
                .one()
            )
        substituted = dict(original)
        substituted["batch_id"] = invalid_batch_id
        substituted["idempotency_key"] = f"postgres-invalid-binding-{suffix}"
        substituted["source_root_digest"] = (
            "0" * 64 if original["source_root_digest"] != "0" * 64 else "1" * 64
        )
        with pytest.raises(IntegrityError), repository.engine.begin() as connection:
            connection.execute(ReplayBatchRecord.__table__.insert().values(**substituted))

        with repository.engine.connect() as connection:
            assert (
                connection.scalar(
                    select(ArtifactRecord.artifact_id).where(
                        ArtifactRecord.artifact_id == artifact_key[0],
                        ArtifactRecord.repository_version == artifact_key[1],
                    )
                )
                == artifact_key[0]
            )
            assert (
                connection.scalar(
                    select(ReplayBatchRecord.batch_id).where(
                        ReplayBatchRecord.batch_id == invalid_batch_id
                    )
                )
                is None
            )
    finally:
        repository.close()


def test_postgres_replay_compilations_are_append_only(
    isolated_postgres_schema_url: str,
) -> None:
    repository, service = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    try:
        source = _admit_kisa_source(repository, service, suffix)
        batch = service.create_replay_batch(
            CreateReplayBatchRequest(
                source=source,
                idempotency_key=f"postgres-compilation-append-only-{suffix}",
            ),
            actor="postgres-compilation-append-only",
        )
        with repository.transaction() as session:
            compilation = session.scalar(
                select(ReplayCompilationRecord).where(
                    ReplayCompilationRecord.batch_id == batch.batch_id
                )
            )
            assert compilation is not None
            compilation_id = compilation.compilation_id
            canonical_compilation = compilation.canonical_compilation

        with (
            pytest.raises(DatabaseError, match="cp_replay_compilations is append-only"),
            repository.engine.begin() as connection,
        ):
            connection.execute(
                update(ReplayCompilationRecord)
                .where(ReplayCompilationRecord.compilation_id == compilation_id)
                .values(canonical_compilation=b"tampered", byte_length=8)
            )

        with (
            pytest.raises(DatabaseError, match="cp_replay_compilations is append-only"),
            repository.engine.begin() as connection,
        ):
            connection.execute(
                ReplayCompilationRecord.__table__.delete().where(
                    ReplayCompilationRecord.compilation_id == compilation_id
                )
            )

        with repository.transaction() as session:
            preserved = session.get(ReplayCompilationRecord, compilation_id)
            assert preserved is not None
            assert preserved.canonical_compilation == canonical_compilation
    finally:
        repository.close()


def test_postgres_reinitialize_rejects_stale_artifact_check_drift(
    isolated_postgres_schema_url: str,
) -> None:
    repository = ControlPlaneRepository(isolated_postgres_schema_url)
    try:
        repository.initialize()
        repository.initialize()

        with repository.engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE cp_artifacts DROP CONSTRAINT ck_cp_artifacts_sealed_run_id")
            )
            connection.execute(
                text(
                    "ALTER TABLE cp_artifacts ADD CONSTRAINT "
                    "ck_cp_artifacts_sealed_run_id "
                    "CHECK (length(sealed_run_id) > 0 AND length(sealed_run_id) <= 64)"
                )
            )

        with pytest.raises(
            SchemaInitializationError,
            match=(
                "cp_artifacts check constraint ck_cp_artifacts_sealed_run_id "
                "does not match managed schema"
            ),
        ):
            repository.initialize()
    finally:
        repository.close()


def test_postgres_v2_to_v5_migration_preserves_core_rows_and_history(
    isolated_postgres_schema_url: str,
) -> None:
    repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    run_id = f"run_{suffix}"
    job_id = str(_v2_job_values(suffix)["job_id"])
    try:
        _create_postgres_v2_schema(repository)
        with repository.engine.begin() as connection:
            connection.execute(
                _V2_METADATA.tables["cp_runs"].insert().values(**_v2_run_values(suffix))
            )
            connection.execute(
                _V2_METADATA.tables["cp_jobs"].insert().values(**_v2_job_values(suffix))
            )

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        assert "cp_artifacts" in inspect(repository.engine).get_table_names()
        assert "cp_replay_compilations" in inspect(repository.engine).get_table_names()
        assert "source_artifact_run_id" in {
            column["name"] for column in inspect(repository.engine).get_columns("cp_replay_batches")
        }
        with repository.transaction() as session:
            preserved_run = session.get(RunRecord, run_id)
            preserved_job = session.get(JobRecord, job_id)
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert preserved_run is not None
        assert preserved_run.input == {"preserve": True}
        assert preserved_job is not None
        assert preserved_job.result == {"status": "completed"}
        assert versions == [1, 2, 3, 4, 5]
    finally:
        repository.close()


def test_postgres_legacy_internal_replay_job_refuses_migration_without_data_loss(
    isolated_postgres_schema_url: str,
) -> None:
    repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    run_values = _v2_run_values(suffix)
    job_values = {
        **_v2_job_values(suffix),
        "kind": "internal-replay",
        "state": "queued",
        "attempts": 0,
        "result": None,
    }
    try:
        _create_postgres_legacy_schema(repository)
        with repository.engine.begin() as connection:
            connection.execute(RunRecord.__table__.insert().values(**run_values))
            connection.execute(JobRecord.__table__.insert().values(**job_values))

        with pytest.raises(SchemaInitializationError, match="internal-replay Jobs: 1"):
            repository.initialize()

        assert "cp_schema_version" not in inspect(repository.engine).get_table_names()
        with repository.engine.connect() as connection:
            assert (
                connection.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == "internal-replay")
                )
                == 1
            )
    finally:
        repository.close()


def test_postgres_v3_to_v5_migration_preserves_core_artifact_rows_and_history(
    isolated_postgres_schema_url: str,
) -> None:
    repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    run_id = f"run_{suffix}"
    job_id = str(_v2_job_values(suffix)["job_id"])
    artifact_id = f"artifact_{suffix}"
    try:
        _create_postgres_v3_schema(repository)
        with repository.engine.begin() as connection:
            connection.execute(
                _V3_METADATA.tables["cp_runs"].insert().values(**_v2_run_values(suffix))
            )
            connection.execute(
                _V3_METADATA.tables["cp_jobs"].insert().values(**_v2_job_values(suffix))
            )
            connection.execute(
                _V3_METADATA.tables["cp_artifacts"].insert().values(**_v3_artifact_values(suffix))
            )

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        assert "cp_replay_compilations" in inspect(repository.engine).get_table_names()
        with repository.transaction() as session:
            preserved_run = session.get(RunRecord, run_id)
            preserved_job = session.get(JobRecord, job_id)
            preserved_artifact = session.get(ArtifactRecord, (artifact_id, 1))
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )
        assert preserved_run is not None
        assert preserved_run.input == {"preserve": True}
        assert preserved_job is not None
        assert preserved_job.result == {"status": "completed"}
        assert preserved_artifact is not None
        assert preserved_artifact.producer_run_id == run_id
        assert preserved_artifact.root_digest == "d" * 64
        assert versions == [1, 2, 3, 4, 5]
    finally:
        repository.close()


def test_postgres_v4_to_v5_preserves_planned_compilation_authority(
    isolated_postgres_schema_url: str,
) -> None:
    repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    try:
        _create_postgres_v4_schema(repository)
        _service_instance, batch_id = _plan_v4_batch(
            repository,
            suffix,
            item_count=2,
        )
        with repository.engine.connect() as connection:
            before_batch = (
                connection.execute(
                    select(_V4_METADATA.tables["cp_replay_batches"]).where(
                        _V4_METADATA.tables["cp_replay_batches"].c.batch_id == batch_id
                    )
                )
                .mappings()
                .one()
            )
            before_items = list(
                connection.execute(
                    select(_V4_METADATA.tables["cp_replay_items"])
                    .where(_V4_METADATA.tables["cp_replay_items"].c.batch_id == batch_id)
                    .order_by(_V4_METADATA.tables["cp_replay_items"].c.ordinal)
                )
                .mappings()
                .all()
            )
            before_compilations = list(
                connection.execute(
                    select(_V4_METADATA.tables["cp_replay_compilations"])
                    .where(_V4_METADATA.tables["cp_replay_compilations"].c.batch_id == batch_id)
                    .order_by(_V4_METADATA.tables["cp_replay_compilations"].c.item_id)
                )
                .mappings()
                .all()
            )

        assert before_batch["state"] == ReplayBatchState.PLANNED.value
        assert len(before_items) == len(before_compilations) == 2
        assert all(item["state"] == ReplayItemState.PENDING.value for item in before_items)
        assert all(item["attempts"] == 0 for item in before_items)

        repository.initialize()

        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        table_names = set(inspect(repository.engine).get_table_names())
        assert {
            "cp_replay_budget_accounts",
            "cp_replay_budget_reservations",
            "cp_replay_rate_accounts",
            "cp_replay_rate_reservations",
        }.issubset(table_names)
        with repository.transaction() as session:
            after_batch = session.get(ReplayBatchRecord, batch_id)
            after_items = list(
                session.scalars(
                    select(ReplayItemRecord)
                    .where(ReplayItemRecord.batch_id == batch_id)
                    .order_by(ReplayItemRecord.ordinal)
                ).all()
            )
            after_compilations = list(
                session.scalars(
                    select(ReplayCompilationRecord)
                    .where(ReplayCompilationRecord.batch_id == batch_id)
                    .order_by(ReplayCompilationRecord.item_id)
                ).all()
            )
            versions = list(
                session.scalars(
                    select(SchemaVersionRecord.version).order_by(SchemaVersionRecord.version)
                ).all()
            )

        assert after_batch is not None
        assert after_batch.state == before_batch["state"]
        assert [item.item_id for item in after_items] == [
            str(item["item_id"]) for item in before_items
        ]
        assert all(item.state == ReplayItemState.PENDING.value for item in after_items)
        assert all(item.attempts == 0 for item in after_items)
        assert [compilation.compilation_id for compilation in after_compilations] == [
            str(compilation["compilation_id"]) for compilation in before_compilations
        ]
        assert [compilation.canonical_compilation for compilation in after_compilations] == [
            bytes(compilation["canonical_compilation"]) for compilation in before_compilations
        ]
        assert versions == [1, 2, 3, 4, 5]
    finally:
        repository.close()


@pytest.mark.parametrize("legacy_authority", ["internal-job", "public-job", "ticket"])
def test_postgres_v4_legacy_issuance_refuses_v5_migration_without_data_loss(
    isolated_postgres_schema_url: str,
    legacy_authority: str,
) -> None:
    repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    try:
        _create_postgres_v4_schema(repository)
        _service_instance, batch_id = _plan_v4_batch(repository, suffix)
        with repository.engine.begin() as connection:
            batch = (
                connection.execute(
                    select(_V4_METADATA.tables["cp_replay_batches"]).where(
                        _V4_METADATA.tables["cp_replay_batches"].c.batch_id == batch_id
                    )
                )
                .mappings()
                .one()
            )
            item = (
                connection.execute(
                    select(_V4_METADATA.tables["cp_replay_items"]).where(
                        _V4_METADATA.tables["cp_replay_items"].c.batch_id == batch_id
                    )
                )
                .mappings()
                .one()
            )
            job = _v4_legacy_job_values(
                suffix=suffix,
                replay_run_id=str(item["replay_run_id"]),
                internal=legacy_authority == "internal-job",
            )
            connection.execute(_V4_METADATA.tables["cp_jobs"].insert().values(**job))
            if legacy_authority == "ticket":
                connection.execute(
                    _V4_METADATA.tables["cp_replay_tickets"]
                    .insert()
                    .values(
                        **_v4_legacy_ticket_values(
                            suffix=suffix,
                            batch=dict(batch),
                            item=dict(item),
                            job=job,
                        )
                    )
                )

        error_pattern = (
            "Replay Run Jobs=1" if legacy_authority == "public-job" else "cannot be trusted"
        )
        with pytest.raises(SchemaInitializationError, match=error_pattern):
            repository.initialize()

        table_names = set(inspect(repository.engine).get_table_names())
        assert "cp_replay_budget_accounts" not in table_names
        assert "cp_replay_rate_accounts" not in table_names
        with repository.engine.connect() as connection:
            job_count = connection.scalar(
                select(func.count())
                .select_from(_V4_METADATA.tables["cp_jobs"])
                .where(_V4_METADATA.tables["cp_jobs"].c.job_id == job["job_id"])
            )
            ticket_count = connection.scalar(
                select(func.count()).select_from(_V4_METADATA.tables["cp_replay_tickets"])
            )
            versions = list(
                connection.scalars(
                    select(_V4_METADATA.tables["cp_schema_version"].c.version).order_by(
                        _V4_METADATA.tables["cp_schema_version"].c.version
                    )
                ).all()
            )
        assert job_count == 1
        assert ticket_count == (1 if legacy_authority == "ticket" else 0)
        assert versions == [1, 2, 3, 4]
    finally:
        repository.close()


def test_postgres_nonempty_v2_replay_authority_refuses_migration_without_data_loss(
    isolated_postgres_schema_url: str,
) -> None:
    repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    batch_id = f"batch_v2_{suffix}"
    try:
        _create_postgres_v2_schema(repository)
        with repository.engine.begin() as connection:
            connection.execute(
                _V2_METADATA.tables["cp_runs"].insert().values(**_v2_run_values(suffix))
            )
            connection.execute(
                _V2_METADATA.tables["cp_replay_batches"]
                .insert()
                .values(**_v2_batch_values(suffix, batch_id))
            )

        with pytest.raises(
            SchemaInitializationError,
            match="cannot be trusted or backfilled",
        ):
            repository.initialize()

        assert "cp_artifacts" not in inspect(repository.engine).get_table_names()
        with repository.engine.connect() as connection:
            preserved = (
                connection.execute(
                    select(_V2_METADATA.tables["cp_replay_batches"]).where(
                        _V2_METADATA.tables["cp_replay_batches"].c.batch_id == batch_id
                    )
                )
                .mappings()
                .one()
            )
            versions = list(
                connection.scalars(
                    select(_V2_METADATA.tables["cp_schema_version"].c.version).order_by(
                        _V2_METADATA.tables["cp_schema_version"].c.version
                    )
                ).all()
            )
        assert preserved["source_artifact_id"] == "legacy-unverified-artifact"
        assert preserved["source_root_digest"] == "b" * 64
        assert versions == [1, 2]
    finally:
        repository.close()


def test_postgres_v2_migration_lock_excludes_late_legacy_writer(
    isolated_postgres_schema_url: str,
) -> None:
    migration_repository = ControlPlaneRepository(isolated_postgres_schema_url)
    writer_repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    migration_locked = ThreadEvent()
    release_migration = ThreadEvent()
    writer_started = ThreadEvent()
    writer_finished = ThreadEvent()
    migration_errors: list[BaseException] = []
    writer_errors: list[BaseException] = []
    migration_thread: Thread | None = None
    writer_thread: Thread | None = None
    listener_installed = False

    def pause_after_migration_lock(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalized = " ".join(statement.split())
        if not normalized.startswith("LOCK TABLE cp_jobs, cp_replay_batches"):
            return
        migration_locked.set()
        if not release_migration.wait(timeout=10):
            raise RuntimeError("timed out waiting to release PostgreSQL v2 migration")

    def migrate() -> None:
        try:
            migration_repository.initialize()
        except BaseException as error:
            migration_errors.append(error)

    def legacy_write() -> None:
        try:
            with writer_repository.engine.begin() as connection:
                connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                writer_started.set()
                connection.execute(
                    _V2_METADATA.tables["cp_replay_batches"]
                    .insert()
                    .values(**_v2_batch_values(suffix, f"batch_late_{suffix}"))
                )
        except BaseException as error:
            writer_errors.append(error)
        finally:
            writer_finished.set()

    try:
        _create_postgres_v2_schema(migration_repository)
        with migration_repository.engine.begin() as connection:
            connection.execute(
                _V2_METADATA.tables["cp_runs"].insert().values(**_v2_run_values(suffix))
            )

        sqlalchemy_event.listen(
            migration_repository.engine,
            "after_cursor_execute",
            pause_after_migration_lock,
        )
        listener_installed = True
        migration_thread = Thread(target=migrate, daemon=True)
        migration_thread.start()
        assert migration_locked.wait(timeout=10)

        writer_thread = Thread(target=legacy_write, daemon=True)
        writer_thread.start()
        assert writer_started.wait(timeout=10)
        assert not writer_finished.wait(timeout=0.25)

        release_migration.set()
        migration_thread.join(timeout=15)
        writer_thread.join(timeout=15)
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
            migration_thread.join(timeout=10)
        if writer_thread is not None:
            writer_thread.join(timeout=10)
        if listener_installed:
            sqlalchemy_event.remove(
                migration_repository.engine,
                "after_cursor_execute",
                pause_after_migration_lock,
            )
        writer_repository.close()
        migration_repository.close()


def test_postgres_v4_migration_lock_excludes_late_legacy_ticket_writer(
    isolated_postgres_schema_url: str,
) -> None:
    migration_repository = ControlPlaneRepository(isolated_postgres_schema_url)
    writer_repository = ControlPlaneRepository(isolated_postgres_schema_url)
    suffix = uuid4().hex
    migration_locked = ThreadEvent()
    release_migration = ThreadEvent()
    writer_started = ThreadEvent()
    writer_finished = ThreadEvent()
    migration_errors: list[BaseException] = []
    writer_errors: list[BaseException] = []
    migration_thread: Thread | None = None
    writer_thread: Thread | None = None
    listener_installed = False

    def pause_after_migration_lock(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalized = " ".join(statement.split())
        if not (
            normalized.startswith("LOCK TABLE ")
            and "cp_replay_tickets" in normalized
            and "cp_replay_compilations" in normalized
        ):
            return
        migration_locked.set()
        if not release_migration.wait(timeout=10):
            raise RuntimeError("timed out waiting to release PostgreSQL v4 migration")

    def migrate() -> None:
        try:
            migration_repository.initialize()
        except BaseException as error:
            migration_errors.append(error)

    def legacy_ticket_write(ticket_values: dict[str, object]) -> None:
        try:
            with writer_repository.engine.begin() as connection:
                connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                writer_started.set()
                connection.execute(
                    _V4_METADATA.tables["cp_replay_tickets"].insert().values(**ticket_values)
                )
        except BaseException as error:
            writer_errors.append(error)
        finally:
            writer_finished.set()

    try:
        _create_postgres_v4_schema(migration_repository)
        _service_instance, batch_id = _plan_v4_batch(migration_repository, suffix)
        with migration_repository.engine.begin() as connection:
            batch = (
                connection.execute(
                    select(_V4_METADATA.tables["cp_replay_batches"]).where(
                        _V4_METADATA.tables["cp_replay_batches"].c.batch_id == batch_id
                    )
                )
                .mappings()
                .one()
            )
            item = (
                connection.execute(
                    select(_V4_METADATA.tables["cp_replay_items"]).where(
                        _V4_METADATA.tables["cp_replay_items"].c.batch_id == batch_id
                    )
                )
                .mappings()
                .one()
            )
            job = _v4_legacy_job_values(
                suffix=suffix,
                replay_run_id=f"run_late_ticket_job_{suffix}",
                internal=False,
            )
            now = datetime.now(UTC)
            connection.execute(
                _V4_METADATA.tables["cp_runs"]
                .insert()
                .values(
                    run_id=job["run_id"],
                    campaign_name="postgres-v4-late-ticket",
                    state=RunState.QUEUED.value,
                    input={"unrelatedToReplayItem": True},
                    submission_key=f"postgres-v4-late-ticket-run-{suffix}",
                    current_checkpoint_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(_V4_METADATA.tables["cp_jobs"].insert().values(**job))
            ticket_values = _v4_legacy_ticket_values(
                suffix=suffix,
                batch=dict(batch),
                item=dict(item),
                job=job,
            )

        sqlalchemy_event.listen(
            migration_repository.engine,
            "after_cursor_execute",
            pause_after_migration_lock,
        )
        listener_installed = True
        migration_thread = Thread(target=migrate, daemon=True)
        migration_thread.start()
        assert migration_locked.wait(timeout=10)

        writer_thread = Thread(
            target=legacy_ticket_write,
            args=(ticket_values,),
            daemon=True,
        )
        writer_thread.start()
        assert writer_started.wait(timeout=10)
        assert not writer_finished.wait(timeout=0.25)

        release_migration.set()
        migration_thread.join(timeout=15)
        writer_thread.join(timeout=15)
        assert not migration_thread.is_alive()
        assert not writer_thread.is_alive()
        assert migration_errors == []
        assert len(writer_errors) == 1
        assert isinstance(writer_errors[0], DatabaseError)
        assert migration_repository.schema_version() == CURRENT_SCHEMA_VERSION
        with migration_repository.engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM cp_replay_tickets")) == 0
            assert (
                connection.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.job_id == job["job_id"])
                )
                == 1
            )
    finally:
        release_migration.set()
        if migration_thread is not None:
            migration_thread.join(timeout=10)
        if writer_thread is not None:
            writer_thread.join(timeout=10)
        if listener_installed:
            sqlalchemy_event.remove(
                migration_repository.engine,
                "after_cursor_execute",
                pause_after_migration_lock,
            )
        writer_repository.close()
        migration_repository.close()


@pytest.mark.parametrize("writer_phase", ["artifact", "source-run"])
def test_postgres_v4_migration_serializes_with_inflight_batch_writer(
    isolated_postgres_schema_url: str,
    writer_phase: str,
) -> None:
    migration_repository = ControlPlaneRepository(isolated_postgres_schema_url)
    writer_repository = ControlPlaneRepository(isolated_postgres_schema_url)
    writer_service = _service_for_repository(writer_repository)
    suffix = uuid4().hex
    writer_locked = ThreadEvent()
    migration_conflicted = ThreadEvent()
    lock_conflicts: list[str] = []
    migration_errors: list[BaseException] = []
    writer_errors: list[BaseException] = []
    writer_batch_ids: list[str] = []
    migration_thread: Thread | None = None
    writer_thread: Thread | None = None
    writer_listener_installed = False
    migration_listener_installed = False

    def pause_inflight_v4_writer(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalized = " ".join(statement.split())
        target_table = "cp_artifacts" if writer_phase == "artifact" else "cp_runs"
        if f"FROM {target_table}" not in normalized or "FOR UPDATE" not in normalized:
            return
        writer_locked.set()
        if not migration_conflicted.wait(timeout=10):
            raise RuntimeError("timed out waiting for PostgreSQL v4 migration contention")

    def observe_nowait_conflict(exception_context: object) -> None:
        statement = str(getattr(exception_context, "statement", ""))
        original = getattr(exception_context, "original_exception", None)
        sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
        if statement.startswith("LOCK TABLE ") and sqlstate == "55P03":
            lock_conflicts.append(sqlstate)
            migration_conflicted.set()

    def migrate() -> None:
        try:
            migration_repository.initialize()
        except BaseException as error:
            migration_errors.append(error)

    def write_batch(source: ArtifactLocator) -> None:
        try:
            batch = writer_service.create_replay_batch(
                CreateReplayBatchRequest(
                    source=source,
                    idempotency_key=f"postgres-v4-inflight-writer-{writer_phase}-{suffix}",
                ),
                actor="postgres-v4-inflight-writer",
            )
            writer_batch_ids.append(batch.batch_id)
        except BaseException as error:
            writer_errors.append(error)

    try:
        _create_postgres_v4_schema(migration_repository)
        source = _admit_kisa_source(
            migration_repository,
            _service_for_repository(migration_repository),
            suffix,
        )
        sqlalchemy_event.listen(
            writer_repository.engine,
            "after_cursor_execute",
            pause_inflight_v4_writer,
        )
        writer_listener_installed = True
        sqlalchemy_event.listen(
            migration_repository.engine,
            "handle_error",
            observe_nowait_conflict,
        )
        migration_listener_installed = True

        writer_thread = Thread(target=write_batch, args=(source,), daemon=True)
        writer_thread.start()
        assert writer_locked.wait(timeout=10)

        migration_thread = Thread(target=migrate, daemon=True)
        migration_thread.start()
        assert migration_conflicted.wait(timeout=10)

        writer_thread.join(timeout=15)
        migration_thread.join(timeout=15)
        assert not writer_thread.is_alive()
        assert not migration_thread.is_alive()
        assert writer_errors == []
        assert migration_errors == []
        assert lock_conflicts
        assert len(writer_batch_ids) == 1
        assert migration_repository.schema_version() == CURRENT_SCHEMA_VERSION

        with migration_repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, writer_batch_ids[0])
            compilation_count = session.scalar(
                select(func.count())
                .select_from(ReplayCompilationRecord)
                .where(ReplayCompilationRecord.batch_id == writer_batch_ids[0])
            )
            version_five_count = session.scalar(
                select(func.count())
                .select_from(SchemaVersionRecord)
                .where(SchemaVersionRecord.version == CURRENT_SCHEMA_VERSION)
            )
        assert batch is not None
        assert batch.state == ReplayBatchState.PLANNED.value
        assert compilation_count == 1
        assert version_five_count == 1
    finally:
        migration_conflicted.set()
        if writer_thread is not None:
            writer_thread.join(timeout=10)
        if migration_thread is not None:
            migration_thread.join(timeout=10)
        if writer_listener_installed:
            sqlalchemy_event.remove(
                writer_repository.engine,
                "after_cursor_execute",
                pause_inflight_v4_writer,
            )
        if migration_listener_installed:
            sqlalchemy_event.remove(
                migration_repository.engine,
                "handle_error",
                observe_nowait_conflict,
            )
        writer_repository.close()
        migration_repository.close()


def test_postgres_concurrent_replay_batch_creation_converges_without_issuance(
    isolated_postgres_schema_url: str,
) -> None:
    repository_a, service_a = _service(isolated_postgres_schema_url)
    repository_b, service_b = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    idempotency_key = f"postgres-replay-concurrent-{suffix}"
    actor = "postgres-replay-concurrency"
    try:
        source = _admit_kisa_source(
            repository_a,
            service_a,
            suffix,
            item_count=2,
        )
        barrier = Barrier(2)

        def create(service: ControlPlaneService):
            barrier.wait(timeout=10)
            return service.create_replay_batch(
                CreateReplayBatchRequest(
                    source=source,
                    idempotency_key=idempotency_key,
                ),
                actor=actor,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(create, service_a)
            second = pool.submit(create, service_b)
            results = [first.result(timeout=30), second.result(timeout=30)]

        assert results[0].batch_id == results[1].batch_id
        assert all(result.state is ReplayBatchState.PLANNED for result in results)
        batch_id = results[0].batch_id

        with repository_a.transaction() as session:
            batches = list(
                session.scalars(
                    select(ReplayBatchRecord).where(
                        ReplayBatchRecord.idempotency_key == idempotency_key
                    )
                ).all()
            )
            items = list(
                session.scalars(
                    select(ReplayItemRecord)
                    .where(ReplayItemRecord.batch_id == batch_id)
                    .order_by(ReplayItemRecord.ordinal)
                ).all()
            )
            compilations = list(
                session.scalars(
                    select(ReplayCompilationRecord)
                    .where(ReplayCompilationRecord.batch_id == batch_id)
                    .order_by(ReplayCompilationRecord.created_at)
                ).all()
            )
            replay_job_count = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket_count = session.scalar(select(func.count()).select_from(ReplayTicketRecord))

        assert [batch.batch_id for batch in batches] == [batch_id]
        assert len(items) == 2
        assert [item.ordinal for item in items] == [0, 1]
        assert all(item.state == ReplayItemState.PENDING.value for item in items)
        assert all(item.attempts == 0 for item in items)
        assert len(compilations) == 2
        assert {compilation.item_id for compilation in compilations} == {
            item.item_id for item in items
        }
        assert len({compilation.compilation_id for compilation in compilations}) == 2
        assert replay_job_count == 0
        assert ticket_count == 0
    finally:
        repository_b.close()
        repository_a.close()


def test_postgres_concurrent_replay_issuance_converges_on_one_permit_graph(
    isolated_postgres_schema_url: str,
) -> None:
    repository_a, service_a = _service(isolated_postgres_schema_url)
    repository_b, service_b = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    try:
        source = _admit_kisa_source(
            repository_a,
            service_a,
            suffix,
            item_count=2,
        )
        planned = service_a.create_replay_batch(
            CreateReplayBatchRequest(
                source=source,
                idempotency_key=f"postgres-replay-issuance-{suffix}",
            ),
            actor="postgres-replay-admission",
        )
        barrier = Barrier(2)

        def issue(service: ControlPlaneService):
            barrier.wait(timeout=10)
            return service.issue_replay_batch(
                planned.batch_id,
                actor="trusted-replay-issuer",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(issue, service_a)
            second = pool.submit(issue, service_b)
            results = [first.result(timeout=30), second.result(timeout=30)]

        assert results[0] == results[1]
        assert results[0].batch.state is ReplayBatchState.RUNNING
        assert len(results[0].items) == len(results[0].tickets) == 2

        with repository_a.transaction() as session:
            items = list(
                session.scalars(
                    select(ReplayItemRecord)
                    .where(ReplayItemRecord.batch_id == planned.batch_id)
                    .order_by(ReplayItemRecord.ordinal)
                ).all()
            )
            jobs = list(
                session.scalars(
                    select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
                ).all()
            )
            tickets = list(
                session.scalars(
                    select(ReplayTicketRecord).where(
                        ReplayTicketRecord.batch_id == planned.batch_id
                    )
                ).all()
            )
            budget_accounts = list(session.scalars(select(ReplayBudgetAccountRecord)).all())
            rate_accounts = list(session.scalars(select(ReplayRateAccountRecord)).all())
            budget_reservations = list(
                session.scalars(
                    select(ReplayBudgetReservationRecord).where(
                        ReplayBudgetReservationRecord.batch_id == planned.batch_id
                    )
                ).all()
            )
            rate_reservations = list(
                session.scalars(
                    select(ReplayRateReservationRecord).where(
                        ReplayRateReservationRecord.batch_id == planned.batch_id
                    )
                ).all()
            )

        assert len(items) == len(jobs) == len(tickets) == 2
        assert len(budget_accounts) == len(rate_accounts) == 1
        assert len(budget_reservations) == len(rate_reservations) == 2
        item_ids = {item.item_id for item in items}
        assert {ticket.item_id for ticket in tickets} == item_ids
        assert {reservation.item_id for reservation in budget_reservations} == item_ids
        assert {reservation.item_id for reservation in rate_reservations} == item_ids
        assert all(item.state == ReplayItemState.QUEUED.value for item in items)
        assert all(item.attempts == 1 for item in items)
        assert all(job.state == JobState.QUEUED.value for job in jobs)
        assert all(ticket.state == ReplayTicketState.ISSUED.value for ticket in tickets)
        assert all(reservation.state == "active" for reservation in budget_reservations)
        assert all(reservation.state == "active" for reservation in rate_reservations)
        assert {ticket.compilation_id for ticket in tickets} == {
            reservation.compilation_id for reservation in budget_reservations
        }
        assert {ticket.compilation_id for ticket in tickets} == {
            reservation.compilation_id for reservation in rate_reservations
        }
        budget_account = budget_accounts[0]
        assert budget_account.reserved_calls == sum(
            reservation.total_calls for reservation in budget_reservations
        )
        assert (
            budget_account.baseline_used_calls
            + budget_account.reserved_calls
            + budget_account.consumed_calls
            <= budget_account.max_tool_calls
        )
        rate_account = rate_accounts[0]
        active_request_units = sum(
            reservation.total_request_units for reservation in rate_reservations
        )
        if rate_account.max_requests_per_minute is not None:
            assert (
                rate_account.observed_request_units + active_request_units
                <= rate_account.max_requests_per_minute
            )
    finally:
        repository_b.close()
        repository_a.close()


def test_postgres_expired_unclaimed_ticket_sweep_releases_exact_capacity(
    isolated_postgres_schema_url: str,
) -> None:
    repository, service = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    try:
        batch_id = _seed_batch(repository, service, suffix)
        now = datetime.now(UTC)
        with repository.transaction() as session:
            ticket = session.scalar(
                select(ReplayTicketRecord).where(ReplayTicketRecord.batch_id == batch_id)
            )
            assert ticket is not None
            ticket.issued_at = now - timedelta(minutes=2)
            ticket.expires_at = now - timedelta(minutes=1)
            ticket_id = ticket.ticket_id

        assert service.requeue_expired(actor="postgres-replay-reaper") == 1
        assert service.requeue_expired(actor="postgres-replay-reaper") == 0

        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, ticket_id)
            assert ticket is not None
            job = session.get(JobRecord, ticket.job_id)
            item = session.get(ReplayItemRecord, ticket.item_id)
            run = session.get(RunRecord, ticket.replay_run_id)
            budget = session.get(
                ReplayBudgetReservationRecord,
                ticket.budget_reservation_id,
            )
            rate = session.get(
                ReplayRateReservationRecord,
                ticket.rate_reservation_id,
            )
            assert budget is not None and rate is not None
            account = session.get(ReplayBudgetAccountRecord, budget.budget_account_id)
            assert job is not None and item is not None and run is not None and account is not None
            assert ticket.state == ReplayTicketState.ABANDONED.value
            assert job.state == JobState.FAILED.value
            assert item.state == ReplayItemState.RETRY_PENDING.value
            assert run.state == RunState.FAILED.value
            assert budget.state == rate.state == "released"
            assert budget.released_calls == budget.total_calls
            assert rate.released_request_units == rate.total_request_units
            assert account.reserved_calls == account.consumed_calls == 0
            assert account.released_calls == budget.total_calls
    finally:
        repository.close()


@pytest.mark.parametrize("release_kind", ["cancel", "expire"])
def test_postgres_shared_source_issuance_and_release_do_not_deadlock_or_drift_ledgers(
    isolated_postgres_schema_url: str,
    release_kind: str,
) -> None:
    repository_a, service_a = _service(isolated_postgres_schema_url)
    repository_b, service_b = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    issuer_holds_budget_account = ThreadEvent()
    allow_issuer_to_continue = ThreadEvent()
    release_reached_budget_account = ThreadEvent()
    issuer_listener_installed = False
    release_listener_installed = False

    def pause_after_issuer_locks_budget_account(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(statement.lower().split())
        if (
            "cp_replay_budget_accounts" in normalized
            and "for update" in normalized
            and not issuer_holds_budget_account.is_set()
        ):
            issuer_holds_budget_account.set()
            if not allow_issuer_to_continue.wait(timeout=15):
                raise RuntimeError("timed out while staging Replay issuance/release lock order")

    def observe_release_budget_account_lock(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(statement.lower().split())
        if "cp_replay_budget_accounts" in normalized and "for update" in normalized:
            release_reached_budget_account.set()

    try:
        with repository_a.engine.connect() as connection:
            assert connection.scalar(text("SHOW transaction_isolation")) == "read committed"

        source = _admit_kisa_source(repository_a, service_a, suffix)
        first_planned = service_a.create_replay_batch(
            CreateReplayBatchRequest(
                source=source,
                idempotency_key=f"postgres-shared-source-first-{release_kind}-{suffix}",
            ),
            actor="postgres-replay-admission",
        )
        first_issued = service_a.issue_replay_batch(
            first_planned.batch_id,
            actor="trusted-replay-issuer",
        )
        assert len(first_issued.items) == len(first_issued.tickets) == 1

        if release_kind == "expire":
            claimed = service_b.claim_replay_job(
                ReplayClaimRequest(
                    executor_profile=EXECUTOR_PROFILE,
                    lease_seconds=300,
                ),
                actor=WORKER_B,
            )
            assert claimed is not None
            assert claimed.batch.batch_id == first_planned.batch_id
            expired_at = datetime.now(UTC) - timedelta(seconds=1)
            with repository_b.transaction() as session:
                session.execute(
                    update(JobRecord)
                    .where(JobRecord.job_id == claimed.job.job_id)
                    .values(lease_expires_at=expired_at)
                )
                session.execute(
                    update(ReplayTicketRecord)
                    .where(ReplayTicketRecord.ticket_id == claimed.ticket.ticket_id)
                    .values(lease_expires_at=expired_at)
                )

        second_planned = service_a.create_replay_batch(
            CreateReplayBatchRequest(
                source=source,
                idempotency_key=f"postgres-shared-source-second-{release_kind}-{suffix}",
            ),
            actor="postgres-replay-admission",
        )
        first_replay_run_id = first_issued.items[0].replay_run_id

        sqlalchemy_event.listen(
            repository_a.engine,
            "after_cursor_execute",
            pause_after_issuer_locks_budget_account,
        )
        issuer_listener_installed = True
        sqlalchemy_event.listen(
            repository_b.engine,
            "before_cursor_execute",
            observe_release_budget_account_lock,
        )
        release_listener_installed = True

        def issue_second_batch():
            return service_a.issue_replay_batch(
                second_planned.batch_id,
                actor="trusted-replay-issuer",
            )

        def release_first_ticket():
            if release_kind == "cancel":
                return service_b.cancel_run(
                    first_replay_run_id,
                    CancelRunRequest(reason="exercise shared-source release lock ordering"),
                    actor="postgres-replay-operator",
                )
            return service_b.requeue_expired(actor="postgres-replay-reaper")

        with ThreadPoolExecutor(max_workers=2) as pool:
            issue_future = pool.submit(issue_second_batch)
            assert issuer_holds_budget_account.wait(timeout=15)
            release_future = pool.submit(release_first_ticket)
            assert release_reached_budget_account.wait(timeout=15)
            allow_issuer_to_continue.set()
            second_issued = issue_future.result(timeout=30)
            release_result = release_future.result(timeout=30)

        assert second_issued.batch.batch_id == second_planned.batch_id
        assert second_issued.batch.state is ReplayBatchState.RUNNING
        if release_kind == "cancel":
            assert release_result.applied is True
        else:
            assert release_result == 1

        with repository_a.transaction() as session:
            budget_accounts = list(session.scalars(select(ReplayBudgetAccountRecord)).all())
            rate_accounts = list(session.scalars(select(ReplayRateAccountRecord)).all())
            budget_reservations = list(
                session.scalars(
                    select(ReplayBudgetReservationRecord).order_by(
                        ReplayBudgetReservationRecord.budget_reservation_id
                    )
                ).all()
            )
            rate_reservations = list(
                session.scalars(
                    select(ReplayRateReservationRecord).order_by(
                        ReplayRateReservationRecord.rate_reservation_id
                    )
                ).all()
            )

        assert len(budget_accounts) == len(rate_accounts) == 1
        assert len(budget_reservations) == len(rate_reservations) == 2
        budget_account = budget_accounts[0]
        assert budget_account.reserved_calls == sum(
            reservation.total_calls - reservation.consumed_calls - reservation.released_calls
            for reservation in budget_reservations
        )
        assert budget_account.consumed_calls == sum(
            reservation.consumed_calls for reservation in budget_reservations
        )
        assert budget_account.released_calls == sum(
            reservation.released_calls for reservation in budget_reservations
        )
        assert {
            (reservation.batch_id, reservation.state) for reservation in budget_reservations
        } == {
            (first_planned.batch_id, "released"),
            (second_planned.batch_id, "active"),
        }
        assert all(
            reservation.consumed_calls + reservation.released_calls == reservation.total_calls
            for reservation in budget_reservations
            if reservation.state == "released"
        )
        assert {(reservation.batch_id, reservation.state) for reservation in rate_reservations} == {
            (first_planned.batch_id, "released"),
            (second_planned.batch_id, "active"),
        }
        assert all(
            reservation.consumed_request_units + reservation.released_request_units
            == reservation.total_request_units
            for reservation in rate_reservations
            if reservation.state == "released"
        )
    finally:
        allow_issuer_to_continue.set()
        if issuer_listener_installed:
            sqlalchemy_event.remove(
                repository_a.engine,
                "after_cursor_execute",
                pause_after_issuer_locks_budget_account,
            )
        if release_listener_installed:
            sqlalchemy_event.remove(
                repository_b.engine,
                "before_cursor_execute",
                observe_release_budget_account_lock,
            )
        repository_b.close()
        repository_a.close()


@pytest.mark.parametrize("transition", ["claim", "cancel"])
def test_postgres_duplicate_issue_reconstruction_never_returns_a_mixed_graph(
    isolated_postgres_schema_url: str,
    transition: str,
) -> None:
    repository_a, service_a = _service(isolated_postgres_schema_url)
    repository_b, service_b = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    transition_holds_item = ThreadEvent()
    allow_transition_to_continue = ThreadEvent()
    reconstruction_reached_job_lock = ThreadEvent()
    transition_listener_installed = False
    reconstruction_listener_installed = False

    def pause_after_transition_locks_item(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(statement.lower().split())
        if (
            "from cp_replay_items" in normalized
            and "for update" in normalized
            and not transition_holds_item.is_set()
        ):
            transition_holds_item.set()
            if not allow_transition_to_continue.wait(timeout=15):
                raise RuntimeError("timed out while staging Replay lifecycle transition")

    def observe_reconstruction_job_lock(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(statement.lower().split())
        if "from cp_jobs" in normalized and "for update" in normalized:
            reconstruction_reached_job_lock.set()

    try:
        with repository_a.engine.connect() as connection:
            assert connection.scalar(text("SHOW transaction_isolation")) == "read committed"

        batch_id = _seed_batch(repository_a, service_a, suffix)
        with repository_a.transaction() as session:
            item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == batch_id)
            )
            assert item is not None
            replay_run_id = item.replay_run_id

        sqlalchemy_event.listen(
            repository_b.engine,
            "after_cursor_execute",
            pause_after_transition_locks_item,
        )
        transition_listener_installed = True
        sqlalchemy_event.listen(
            repository_a.engine,
            "before_cursor_execute",
            observe_reconstruction_job_lock,
        )
        reconstruction_listener_installed = True

        def perform_transition():
            if transition == "claim":
                return service_b.claim_replay_job(
                    ReplayClaimRequest(
                        executor_profile=EXECUTOR_PROFILE,
                        lease_seconds=300,
                    ),
                    actor=WORKER_B,
                )
            return service_b.cancel_run(
                replay_run_id,
                CancelRunRequest(reason="interleave cancellation with issue reconstruction"),
                actor="postgres-replay-operator",
            )

        def reconstruct_issue():
            try:
                return service_a.issue_replay_batch(
                    batch_id,
                    actor="trusted-replay-issuer",
                )
            except StateConflict as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            transition_future = pool.submit(perform_transition)
            assert transition_holds_item.wait(timeout=15)
            reconstruction_future = pool.submit(reconstruct_issue)
            assert reconstruction_reached_job_lock.wait(timeout=15)
            allow_transition_to_continue.set()
            transitioned = transition_future.result(timeout=30)
            if transition == "claim":
                assert transitioned is not None
                assert transitioned.batch.batch_id == batch_id
            else:
                assert transitioned.applied is True
            reconstructed = reconstruction_future.result(timeout=30)

        if transition == "claim":
            assert not isinstance(reconstructed, StateConflict)
            assert reconstructed.batch.state is ReplayBatchState.RUNNING
            assert len(reconstructed.items) == len(reconstructed.tickets) == 1
            reconstructed_item = reconstructed.items[0]
            reconstructed_ticket = reconstructed.tickets[0]
            assert reconstructed_ticket.batch_id == reconstructed.batch.batch_id
            assert reconstructed_ticket.item_id == reconstructed_item.item_id
            assert reconstructed_ticket.replay_run_id == reconstructed_item.replay_run_id
            assert reconstructed_ticket.attempt == reconstructed_item.attempts
            assert (
                reconstructed_ticket.state,
                reconstructed_item.state,
            ) == (ReplayTicketState.CLAIMED, ReplayItemState.RUNNING)
        else:
            assert isinstance(reconstructed, StateConflict)
            assert str(reconstructed) == "Replay batch in cancelled state cannot be issued"
    finally:
        allow_transition_to_continue.set()
        if transition_listener_installed:
            sqlalchemy_event.remove(
                repository_b.engine,
                "after_cursor_execute",
                pause_after_transition_locks_item,
            )
        if reconstruction_listener_installed:
            sqlalchemy_event.remove(
                repository_a.engine,
                "before_cursor_execute",
                observe_reconstruction_job_lock,
            )
        repository_b.close()
        repository_a.close()


@pytest.mark.parametrize(
    ("column_name", "invalid_value"),
    [
        ("compilation_id", f"replay-compilation_{'0' * 32}"),
        ("budget_reservation_id", f"budget-reservation_{'0' * 32}"),
        ("rate_reservation_id", f"rate-reservation_{'0' * 32}"),
    ],
)
def test_postgres_ticket_rejects_nonexistent_exact_permit_authority(
    isolated_postgres_schema_url: str,
    column_name: str,
    invalid_value: str,
) -> None:
    repository, service = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    try:
        batch_id = _seed_batch(repository, service, suffix)
        with repository.transaction() as session:
            ticket = session.scalar(
                select(ReplayTicketRecord).where(ReplayTicketRecord.batch_id == batch_id)
            )
            assert ticket is not None
            ticket_id = ticket.ticket_id
            original_value = str(getattr(ticket, column_name))

        with pytest.raises(IntegrityError), repository.engine.begin() as connection:
            connection.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.ticket_id == ticket_id)
                .values(**{column_name: invalid_value})
            )

        with repository.transaction() as session:
            preserved = session.get(ReplayTicketRecord, ticket_id)
            assert preserved is not None
            assert getattr(preserved, column_name) == original_value
    finally:
        repository.close()


def test_postgres_replay_issuance_rolls_back_every_authority_on_second_ticket_failure(
    isolated_postgres_schema_url: str,
) -> None:
    repository, service = _service(isolated_postgres_schema_url)
    suffix = uuid4().hex
    try:
        source = _admit_kisa_source(
            repository,
            service,
            suffix,
            item_count=2,
        )
        planned = service.create_replay_batch(
            CreateReplayBatchRequest(
                source=source,
                idempotency_key=f"postgres-replay-rollback-{suffix}",
            ),
            actor="postgres-replay-admission",
        )
        with repository.engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE FUNCTION pajin_test_fail_second_replay_ticket() "
                    "RETURNS trigger LANGUAGE plpgsql AS $$ "
                    "BEGIN "
                    "IF EXISTS (SELECT 1 FROM cp_replay_tickets) THEN "
                    "RAISE EXCEPTION 'forced second Replay ticket failure'; "
                    "END IF; "
                    "RETURN NEW; "
                    "END; $$"
                )
            )
            connection.execute(
                text(
                    "CREATE TRIGGER pajin_test_fail_second_replay_ticket "
                    "BEFORE INSERT ON cp_replay_tickets FOR EACH ROW "
                    "EXECUTE FUNCTION pajin_test_fail_second_replay_ticket()"
                )
            )

        with pytest.raises(DatabaseError, match="forced second Replay ticket failure"):
            service.issue_replay_batch(
                planned.batch_id,
                actor="trusted-replay-issuer",
            )

        with repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, planned.batch_id)
            items = list(
                session.scalars(
                    select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
                ).all()
            )
            internal_job_count = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket_count = session.scalar(select(func.count()).select_from(ReplayTicketRecord))
            budget_account_count = session.scalar(
                select(func.count()).select_from(ReplayBudgetAccountRecord)
            )
            rate_account_count = session.scalar(
                select(func.count()).select_from(ReplayRateAccountRecord)
            )
            budget_reservation_count = session.scalar(
                select(func.count()).select_from(ReplayBudgetReservationRecord)
            )
            rate_reservation_count = session.scalar(
                select(func.count()).select_from(ReplayRateReservationRecord)
            )
            issued_event_count = session.scalar(
                select(func.count())
                .select_from(ReplayEventRecord)
                .where(
                    ReplayEventRecord.batch_id == planned.batch_id,
                    ReplayEventRecord.event_type.in_(
                        ["replay.ticket.issued", "replay.batch.issued"]
                    ),
                )
            )

        assert batch is not None
        assert batch.state == ReplayBatchState.PLANNED.value
        assert all(item.state == ReplayItemState.PENDING.value for item in items)
        assert all(item.attempts == 0 for item in items)
        assert internal_job_count == 0
        assert ticket_count == 0
        assert budget_account_count == 0
        assert rate_account_count == 0
        assert budget_reservation_count == 0
        assert rate_reservation_count == 0
        assert issued_event_count == 0
    finally:
        repository.close()


def test_postgres_replay_claim_has_exactly_one_winner_and_atomic_ticket_binding() -> None:
    repository_a, service_a = _service()
    repository_b, service_b = _service()
    suffix = uuid4().hex
    try:
        assert repository_a.schema_version() == CURRENT_SCHEMA_VERSION
        expected_batch_id = _seed_batch(repository_a, service_a, suffix)
        barrier = Barrier(2)

        def claim(service: ControlPlaneService, actor: str):
            barrier.wait()
            return service.claim_replay_job(
                ReplayClaimRequest(
                    executor_profile=EXECUTOR_PROFILE,
                    lease_seconds=30,
                ),
                actor=actor,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(claim, service_a, WORKER_A)
            second = pool.submit(claim, service_b, WORKER_B)
            results = [first.result(timeout=15), second.result(timeout=15)]

        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        winner = winners[0]
        assert winner.batch.batch_id == expected_batch_id
        assert winner.ticket.claimed_by in {WORKER_A, WORKER_B}
        assert winner.job.lease_owner == winner.ticket.claimed_by
        assert winner.ticket.attempt == winner.item.attempts == 1
        assert winner.ticket.fencing_value == 1

        with repository_a.transaction() as session:
            job = session.get(JobRecord, winner.job.job_id)
            ticket = session.get(ReplayTicketRecord, winner.ticket.ticket_id)
            item = session.get(ReplayItemRecord, winner.item.item_id)
            assert job is not None and ticket is not None and item is not None
            lease_digest = token_digest(winner.lease_token)
            assert job.kind == InternalJobKind.REPLAY.value
            assert job.state == JobState.LEASED.value
            assert job.attempts == 1
            assert job.lease_owner == winner.ticket.claimed_by
            assert job.lease_token_hash == lease_digest
            assert ticket.state == ReplayTicketState.CLAIMED.value
            assert ticket.claim_principal == winner.ticket.claimed_by
            assert ticket.lease_token_hash == lease_digest
            assert ticket.job_id == job.job_id
            assert ticket.replay_run_id == job.run_id == item.replay_run_id
            assert ticket.item_id == item.item_id
            assert ticket.attempt_number == item.attempts == 1
            assert ticket.fencing_value == 1
            assert item.state == ReplayItemState.RUNNING.value
    finally:
        repository_b.close()
        repository_a.close()


def test_postgres_expired_replay_sweepers_prelock_shared_batches_in_global_order() -> None:
    repository_a, service_a = _service()
    repository_b, service_b = _service()
    batch_ids: list[str] = []
    allocation: tuple[str, str, list[str], list[str]] | None = None
    try:
        # Find two two-item batches whose random Job IDs permit opposite lazy
        # traversal orders. The explicit row locks below then deterministically
        # reproduce the old X -> Y / Y -> X reaper partition.
        for _ in range(8):
            suffix = uuid4().hex
            batch_ids.append(
                _seed_batch(
                    repository_a,
                    service_a,
                    suffix,
                    item_count=2,
                    max_attempts=1,
                )
            )
            if len(batch_ids) < 2:
                continue
            with repository_a.transaction() as session:
                rows = session.execute(
                    select(JobRecord.job_id, ReplayTicketRecord.batch_id)
                    .join(ReplayTicketRecord, ReplayTicketRecord.job_id == JobRecord.job_id)
                    .where(ReplayTicketRecord.batch_id.in_(batch_ids))
                ).all()
            jobs_by_batch = {
                batch_id: sorted(
                    job_id for job_id, row_batch_id in rows if row_batch_id == batch_id
                )
                for batch_id in batch_ids
            }
            for left_index, left_batch_id in enumerate(batch_ids):
                for right_batch_id in batch_ids[left_index + 1 :]:
                    left_jobs = jobs_by_batch[left_batch_id]
                    right_jobs = jobs_by_batch[right_batch_id]
                    for left_a in left_jobs:
                        left_b = next(job_id for job_id in left_jobs if job_id != left_a)
                        for right_a in right_jobs:
                            right_b = next(job_id for job_id in right_jobs if job_id != right_a)
                            if (left_a < right_a) != (left_b < right_b):
                                allocation = (
                                    left_batch_id,
                                    right_batch_id,
                                    [left_a, right_a],
                                    [left_b, right_b],
                                )
                                break
                        if allocation is not None:
                            break
                    if allocation is not None:
                        break
                if allocation is not None:
                    break
            if allocation is not None:
                break
        assert allocation is not None, "failed to construct crossed Replay Job ordering"

        for _ in range(2 * len(batch_ids)):
            claimed = service_a.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=300),
                actor=WORKER_A,
            )
            assert claimed is not None
            assert claimed.batch.batch_id in batch_ids

        left_batch_id, right_batch_id, worker_a_jobs, worker_b_jobs = allocation
        selected_job_ids = worker_a_jobs + worker_b_jobs
        expired_at = datetime.now(UTC) - timedelta(seconds=1)
        with repository_a.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id.in_(selected_job_ids))
                .values(lease_expires_at=expired_at)
            )
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.job_id.in_(selected_job_ids))
                .values(lease_expires_at=expired_at)
            )
            selected_ticket_ids = list(
                session.scalars(
                    select(ReplayTicketRecord.ticket_id).where(
                        ReplayTicketRecord.job_id.in_(selected_job_ids)
                    )
                ).all()
            )

        barrier = Barrier(2)
        transition_time = datetime.now(UTC)

        def reap_owned_partition(
            repository: ControlPlaneRepository,
            service: ControlPlaneService,
            owned_job_ids: list[str],
            actor: str,
        ) -> int:
            with repository.transaction() as session:
                session.execute(text("SET LOCAL lock_timeout = '5s'"))
                locked_job_ids = list(
                    session.scalars(
                        select(JobRecord.job_id)
                        .where(JobRecord.job_id.in_(owned_job_ids))
                        .order_by(JobRecord.job_id)
                        .with_for_update()
                    ).all()
                )
                assert set(locked_job_ids) == set(owned_job_ids)
                barrier.wait(timeout=10)
                return service._expire_leases(
                    session,
                    now=transition_time,
                    actor=actor,
                )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(
                reap_owned_partition,
                repository_a,
                service_a,
                worker_a_jobs,
                WORKER_A,
            )
            second = pool.submit(
                reap_owned_partition,
                repository_b,
                service_b,
                worker_b_jobs,
                WORKER_B,
            )
            counts = [first.result(timeout=15), second.result(timeout=15)]

        assert counts == [2, 2]
        assert service_a.requeue_expired(actor="postgres-replay-reaper") == 0
        with repository_a.transaction() as session:
            jobs = list(
                session.scalars(
                    select(JobRecord).where(JobRecord.job_id.in_(selected_job_ids))
                ).all()
            )
            tickets = list(
                session.scalars(
                    select(ReplayTicketRecord).where(
                        ReplayTicketRecord.ticket_id.in_(selected_ticket_ids)
                    )
                ).all()
            )
            items = list(
                session.scalars(
                    select(ReplayItemRecord).where(
                        ReplayItemRecord.batch_id.in_([left_batch_id, right_batch_id])
                    )
                ).all()
            )
            expiry_events = list(
                session.scalars(
                    select(ReplayEventRecord).where(
                        ReplayEventRecord.ticket_id.in_(selected_ticket_ids),
                        ReplayEventRecord.event_type == "replay.ticket.lease-expired",
                    )
                ).all()
            )
        assert all(job.state == JobState.FAILED.value for job in jobs)
        assert all(ticket.state == ReplayTicketState.ABANDONED.value for ticket in tickets)
        assert all(item.state == ReplayItemState.FAILED.value for item in items)
        assert Counter(event.ticket_id for event in expiry_events) == Counter(selected_ticket_ids)
        assert service_a.get_replay_batch(left_batch_id).state is ReplayBatchState.FAILED
        assert service_a.get_replay_batch(right_batch_id).state is ReplayBatchState.FAILED
    finally:
        repository_b.close()
        repository_a.close()


def test_postgres_schema_fence_rejects_append_only_trigger_catalog_drift() -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                _validate_append_only_trigger(connection, "cp_replay_events")
                connection.execute(
                    text(
                        "ALTER TABLE cp_replay_events DISABLE TRIGGER cp_replay_events_append_only"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="append-only trigger"):
                    _validate_append_only_trigger(connection, "cp_replay_events")
            finally:
                transaction.rollback()

        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text("DROP TRIGGER cp_replay_events_append_only ON cp_replay_events")
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER cp_replay_events_append_only "
                        "BEFORE UPDATE OF event_type ON cp_replay_events "
                        "FOR EACH ROW EXECUTE FUNCTION "
                        "pajin_cp_reject_replay_event_mutation()"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="append-only trigger"):
                    _validate_append_only_trigger(connection, "cp_replay_events")
            finally:
                transaction.rollback()

        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        "CREATE OR REPLACE FUNCTION "
                        "pajin_cp_reject_replay_event_mutation() RETURNS trigger "
                        "LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END; $$"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="append-only trigger"):
                    _validate_append_only_trigger(connection, "cp_replay_events")
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize("drift_kind", ["trigger", "function"])
def test_postgres_reinitialize_rejects_replay_compilation_trigger_drift(
    isolated_postgres_schema_url: str,
    drift_kind: str,
) -> None:
    repository, _service_instance = _service(isolated_postgres_schema_url)
    try:
        with repository.engine.begin() as connection:
            if drift_kind == "trigger":
                connection.execute(
                    text(
                        "DROP TRIGGER cp_replay_compilations_append_only ON cp_replay_compilations"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER cp_replay_compilations_append_only "
                        "BEFORE UPDATE ON cp_replay_compilations "
                        "FOR EACH ROW EXECUTE FUNCTION "
                        "pajin_cp_reject_replay_compilation_mutation()"
                    )
                )
            else:
                connection.execute(
                    text(
                        "CREATE OR REPLACE FUNCTION "
                        "pajin_cp_reject_replay_compilation_mutation() RETURNS trigger "
                        "LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END; $$"
                    )
                )

        with pytest.raises(
            SchemaInitializationError,
            match="cp_replay_compilations append-only trigger",
        ):
            repository.initialize()
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("table_name", "operation"),
    [
        ("cp_replay_events", "INSERT"),
        ("cp_replay_batches", "UPDATE"),
    ],
)
def test_postgres_schema_fence_rejects_unmanaged_user_trigger_inventory(
    table_name: str,
    operation: str,
) -> None:
    repository, _service_instance = _service()
    trigger_name = f"{table_name}_unmanaged"
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        f"CREATE TRIGGER {trigger_name} "
                        f"BEFORE {operation} ON {table_name} "
                        "FOR EACH ROW EXECUTE FUNCTION "
                        "pajin_cp_reject_replay_event_mutation()"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="user trigger inventory"):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize("table_name", ["cp_replay_events", "cp_replay_batches"])
def test_postgres_schema_fence_rejects_unmanaged_rewrite_rule_inventory(
    table_name: str,
) -> None:
    repository, _service_instance = _service()
    rule_name = f"{table_name}_suppress_insert"
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(f"CREATE RULE {rule_name} AS ON INSERT TO {table_name} DO INSTEAD NOTHING")
                )
                with pytest.raises(SchemaInitializationError, match="rewrite rule inventory"):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


def test_postgres_schema_fence_rejects_managed_table_inheritance_edges() -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text("CREATE TABLE pajin_test_audit_shadow () INHERITS (cp_events)")
                )
                with pytest.raises(SchemaInitializationError, match="inheritance inventory"):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize("table_name", ["cp_events", "cp_replay_events"])
def test_postgres_schema_fence_rejects_unlogged_managed_audit_tables(
    table_name: str,
) -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text(f"ALTER TABLE {table_name} SET UNLOGGED"))
                with pytest.raises(SchemaInitializationError, match="relation persistence"):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize("constraint_option", ["NOT VALID", "NO INHERIT"])
def test_postgres_schema_fence_rejects_unmanaged_check_catalog_flags(
    constraint_option: str,
) -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        "ALTER TABLE cp_replay_batches DROP CONSTRAINT "
                        "ck_cp_replay_batches_cas_version"
                    )
                )
                connection.execute(
                    text(
                        "ALTER TABLE cp_replay_batches ADD CONSTRAINT "
                        "ck_cp_replay_batches_cas_version "
                        f"CHECK (cas_version > 0) {constraint_option}"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="unmanaged"):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()
