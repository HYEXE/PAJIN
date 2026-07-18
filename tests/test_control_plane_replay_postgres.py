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
    CURRENT_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
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
    CreateReplayBatchRequest,
    InternalJobKind,
    JobState,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayItemState,
    ReplayJobPayload,
    ReplayTicketState,
    RunState,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.control_plane.service import ControlPlaneService

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
    schema_name = f"pajin_artifact_v3_{uuid4().hex}"
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
    signer = CheckpointSigner(
        active_key_id="postgres-replay-v1",
        keys={"postgres-replay-v1": b"postgres-replay-signing-key-at-least-32-bytes"},
    )
    return repository, ControlPlaneService(
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
    required_attempts: int = 2,
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
    _activate_batch_for_test(
        repository,
        service,
        created.batch_id,
        item_count=item_count,
        required_attempts=required_attempts,
        max_attempts=max_attempts,
    )
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


def _activate_batch_for_test(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    batch_id: str,
    *,
    item_count: int,
    required_attempts: int,
    max_attempts: int,
) -> None:
    """Issue legacy one-shot authority only for PostgreSQL state-machine tests.

    Production batch creation deliberately stops at planned/pending authority until
    the durable permit slice exists. These tests still exercise the already-built
    claim and fencing state machines, so they install the former issuance boundary
    directly in their isolated database.
    """

    now = datetime.now(UTC)
    with repository.transaction() as session:
        batch = session.get(ReplayBatchRecord, batch_id)
        assert batch is not None
        items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch_id)
                .order_by(ReplayItemRecord.ordinal)
            ).all()
        )
        assert len(items) == item_count
        batch.state = ReplayBatchState.RUNNING.value
        batch.cas_version += 1
        batch.updated_at = now
        source = service._artifact_ref(batch)

        for item in items:
            ticket_id = f"replay-ticket_{uuid4().hex}"
            job_id = f"job_{uuid4().hex}"
            item.required_attempts = required_attempts
            item.max_attempts = max_attempts
            item.attempts = 1
            item.state = ReplayItemState.QUEUED.value
            item.updated_at = now
            payload = ReplayJobPayload.model_validate(
                {
                    "batch_id": batch.batch_id,
                    "item_id": item.item_id,
                    "ticket_id": ticket_id,
                    "replay_run_id": item.replay_run_id,
                    "source": source,
                    "mode": batch.mode,
                    "purpose": batch.purpose,
                    "policy_version": batch.policy_version,
                    "candidate_id": item.candidate_id,
                    "candidate_digest": item.candidate_digest,
                    "contract_digest": item.contract_digest,
                    "compilation_digest": item.compilation_digest,
                    "grant_digest": item.grant_digest,
                    "attempt": 1,
                    "fencing_value": 1,
                }
            )
            replay_run = session.get(RunRecord, item.replay_run_id)
            assert replay_run is not None
            replay_run.input = {"replay": payload.model_dump(mode="json")}
            replay_run.state = RunState.QUEUED.value
            replay_run.updated_at = now
            job = JobRecord(
                job_id=job_id,
                run_id=item.replay_run_id,
                kind=InternalJobKind.REPLAY.value,
                state=JobState.QUEUED.value,
                payload=payload.model_dump(mode="json"),
                priority=0,
                attempts=0,
                max_attempts=1,
                idempotency_key=f"postgres-test-replay:{item.item_id}:1",
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
            session.add(job)
            session.flush()
            ticket = ReplayTicketRecord(
                ticket_id=ticket_id,
                batch_id=batch.batch_id,
                item_id=item.item_id,
                job_id=job.job_id,
                replay_run_id=item.replay_run_id,
                attempt_number=1,
                fencing_value=1,
                state=ReplayTicketState.ISSUED.value,
                grant_digest=item.grant_digest,
                source_root_digest=batch.source_root_digest,
                compilation_digest=item.compilation_digest,
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
            session.add(ticket)
            session.flush()
            service._event(
                session,
                replay_run,
                "run.submitted",
                "postgres-test-authority",
                {
                    "campaignName": batch.campaign_name,
                    "jobId": job.job_id,
                    "jobKind": InternalJobKind.REPLAY.value,
                    "replayBatchId": batch.batch_id,
                    "replayItemId": item.item_id,
                    "replayTicketId": ticket.ticket_id,
                },
            )
            service._replay_event(
                session,
                batch,
                "replay.ticket.issued",
                "postgres-test-authority",
                {
                    "attempt": 1,
                    "fencingValue": 1,
                    "compilationDigest": item.compilation_digest,
                    "expiresAt": ticket.expires_at.isoformat(),
                },
                item=item,
                ticket=ticket,
                job=job,
                run_id=replay_run.run_id,
            )


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


def test_postgres_v2_to_v4_migration_preserves_core_rows_and_history(
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
        assert versions == [1, 2, 3, 4]
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


def test_postgres_v3_to_v4_migration_preserves_core_artifact_rows_and_history(
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
                    required_attempts=1,
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
