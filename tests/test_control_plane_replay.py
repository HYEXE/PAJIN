from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from kisa_control_plane_support import build_kisa_control_plane_source
from sqlalchemy import func, select, update

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.database import (
    ArtifactRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayCompilationRecord,
    ReplayEventRecord,
    ReplayItemRecord,
    ReplayTicketRecord,
    RunRecord,
)
from pajin.control_plane.kisa_derivation import (
    KISA_CONFIRMATION_MAX_ATTEMPTS,
    KISA_CONFIRMATION_POLICY_VERSION,
    KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
)
from pajin.control_plane.models import (
    AdmitSourceArtifactRequest,
    ApprovalIntent,
    ArtifactLocator,
    ArtifactRef,
    CancelRunRequest,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    CreateReplayBatchRequest,
    FailJobRequest,
    InternalJobKind,
    JobState,
    LeaseRequest,
    Principal,
    PrincipalRole,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayItemState,
    ReplayJobPayload,
    ReplayLeaseRequest,
    ReplayTicketState,
    RunState,
    SubmitRunRequest,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.control_plane.service import (
    ControlPlaneService,
    LeaseRejected,
    ResourceNotFound,
    RunCancelled,
    StateConflict,
)
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.domain.replay import ReplayCompilation, ReplayPurpose
from pajin.replay.tickets import replay_context_digest

OPERATOR_TOKEN = "replay-operator-token-that-is-long-and-distinct"
WORKER_TOKEN = "replay-worker-token-that-is-long-and-distinct"
EXECUTOR_PROFILE = "kisa-exact-v1"
REGISTERED_REPLAY_ACTORS = frozenset(
    {
        "replay-worker-a",
        "authenticated-worker-a",
        "authenticated-worker-b",
        "race-worker-a",
        "race-worker-b",
        "heartbeat-worker",
        "stale-worker",
        "expired-worker",
        "replacement-worker",
        "cancelled-worker",
    }
)


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="replay-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="replay-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"replay-v1": b"replay-test-signing-key-at-least-32-bytes"},
        active_checkpoint_key_id="replay-v1",
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _service(path: Path) -> tuple[ControlPlaneRepository, ControlPlaneService]:
    repository = ControlPlaneRepository(f"sqlite:///{path.as_posix()}")
    repository.initialize()
    signer = CheckpointSigner(
        active_key_id="replay-v1",
        keys={"replay-v1": b"replay-test-signing-key-at-least-32-bytes"},
    )
    profiles = {actor: frozenset({EXECUTOR_PROFILE}) for actor in REGISTERED_REPLAY_ACTORS}
    staging_root, artifact_root = _artifact_roots(path)
    return repository, ControlPlaneService(
        repository,
        signer,
        replay_executor_profiles=profiles,
        artifact_repository=ManagedArtifactRepository(
            staging_root=staging_root,
            repository_root=artifact_root,
        ),
    )


def _artifact_roots(database_path: Path) -> tuple[Path, Path]:
    stem = database_path.name.replace(".", "-")
    return (
        database_path.parent / f"{stem}-artifact-staging",
        database_path.parent / f"{stem}-artifact-repository",
    )


def _seed_completed_source(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    suffix: str,
    *,
    item_count: int = 1,
) -> ArtifactRef:
    identity = sha256(suffix.encode()).hexdigest()
    run_id = f"run_{identity[:32]}"
    job_id = f"job_{sha256(f'job:{suffix}'.encode()).hexdigest()[:32]}"
    stage_id = f"stage_{sha256(f'stage:{suffix}'.encode()).hexdigest()[:32]}"
    database_path = Path(str(repository.engine.url.database))
    staging_root, _ = _artifact_roots(database_path)
    stage_path = staging_root / stage_id
    fixture = build_kisa_control_plane_source(
        database_path.parent / f"{database_path.stem}-kisa-source-builds",
        scenario_count=item_count,
        producer_run_id=run_id,
    )
    shutil.copytree(fixture.path, stage_path)
    now = datetime.now(UTC)
    with repository.transaction() as session:
        run = RunRecord(
            run_id=run_id,
            campaign_name=fixture.campaign.metadata.name,
            state=RunState.COMPLETED.value,
            input={"sealedSource": True},
            submission_key=f"sealed-source-{identity}",
            current_checkpoint_id=None,
            created_at=now,
            updated_at=now,
        )
        session.add(run)
        session.flush()
        session.add(
            JobRecord(
                job_id=job_id,
                run_id=run_id,
                kind="campaign",
                state=JobState.SUCCEEDED.value,
                payload={"input": {}},
                priority=0,
                attempts=1,
                max_attempts=3,
                idempotency_key=f"sealed-source-job-{identity}",
                available_at=now,
                lease_owner=None,
                lease_token_hash=None,
                lease_expires_at=None,
                heartbeat_at=None,
                result={
                    "engineRunId": fixture.artifact_ref.run_id,
                    "runPath": "/ignored/untrusted",
                },
                error=None,
                created_at=now,
                updated_at=now,
            )
        )
    return service.admit_source_artifact(
        AdmitSourceArtifactRequest(
            staging_id=stage_id,
            producer_run_id=run_id,
            producer_job_id=job_id,
            idempotency_key=f"artifact-admission-{suffix}",
        ),
        actor="trusted-source-admission",
    )


def _batch_request(
    source: ArtifactRef,
    suffix: str,
) -> CreateReplayBatchRequest:
    return CreateReplayBatchRequest(
        source=ArtifactLocator(
            artifact_id=source.artifact_id,
            repository_version=source.repository_version,
        ),
        idempotency_key=f"replay-batch-{suffix}",
    )


def _activate_planned_batch_for_state_machine_tests(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    request: CreateReplayBatchRequest,
    *,
    required_attempts: int,
    max_attempts: int,
) -> None:
    """Issue legacy execution rows only inside tests of the downstream state machine.

    Production intentionally stops at PLANNED/PENDING until the durable permit slice
    exists. These direct rows keep claim, fencing, cancellation, and reaper regression
    coverage without reintroducing an authority bypass in the service.
    """

    now = datetime.now(UTC)
    with repository.transaction() as session:
        batch = session.scalar(
            select(ReplayBatchRecord).where(
                ReplayBatchRecord.idempotency_key == request.idempotency_key
            )
        )
        assert batch is not None
        assert batch.state == ReplayBatchState.PLANNED.value
        source = service._artifact_ref(batch)
        items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch.batch_id)
                .order_by(ReplayItemRecord.ordinal)
            ).all()
        )
        assert items
        batch.state = ReplayBatchState.RUNNING.value
        batch.cas_version += 1
        batch.updated_at = now
        for item in items:
            replay_run = session.get(RunRecord, item.replay_run_id)
            compilation = session.scalar(
                select(ReplayCompilationRecord)
                .where(ReplayCompilationRecord.item_id == item.item_id)
                .order_by(
                    ReplayCompilationRecord.created_at,
                    ReplayCompilationRecord.compilation_id,
                )
                .limit(1)
            )
            assert replay_run is not None and compilation is not None
            assert compilation.compilation_digest == item.compilation_digest
            ticket_id = f"replay-ticket_{uuid4().hex}"
            job_id = f"job_{uuid4().hex}"
            attempt = 1
            fencing_value = 1
            payload = ReplayJobPayload(
                batch_id=batch.batch_id,
                item_id=item.item_id,
                ticket_id=ticket_id,
                replay_run_id=replay_run.run_id,
                source=source,
                mode=CampaignMode(batch.mode),
                purpose=ReplayPurpose(batch.purpose),
                policy_version=batch.policy_version,
                candidate_id=item.candidate_id,
                candidate_digest=item.candidate_digest,
                contract_digest=item.contract_digest,
                compilation_digest=item.compilation_digest,
                grant_digest=item.grant_digest,
                attempt=attempt,
                fencing_value=fencing_value,
            )
            replay_run.input = {"replay": payload.model_dump(mode="json")}
            replay_run.updated_at = now
            item.state = ReplayItemState.QUEUED.value
            item.required_attempts = required_attempts
            item.max_attempts = max_attempts
            item.attempts = attempt
            item.updated_at = now
            job = JobRecord(
                job_id=job_id,
                run_id=replay_run.run_id,
                kind=InternalJobKind.REPLAY.value,
                state=JobState.QUEUED.value,
                payload=payload.model_dump(mode="json"),
                priority=0,
                attempts=0,
                max_attempts=1,
                idempotency_key=f"replay:{item.item_id}:{attempt}",
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
                replay_run_id=replay_run.run_id,
                attempt_number=attempt,
                fencing_value=fencing_value,
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
                "trusted-replay-test-activation",
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
                "trusted-replay-test-activation",
                {
                    "attempt": attempt,
                    "fencingValue": fencing_value,
                    "compilationDigest": item.compilation_digest,
                    "expiresAt": ticket.expires_at.isoformat(),
                },
                item=item,
                ticket=ticket,
                job=job,
                run_id=replay_run.run_id,
            )


def _create_batch(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    suffix: str,
    *,
    required_attempts: int = 2,
    max_attempts: int = 3,
    item_count: int = 1,
) -> CreateReplayBatchRequest:
    request = _batch_request(
        _seed_completed_source(repository, service, suffix, item_count=item_count),
        suffix,
    )
    service.create_replay_batch(request, actor="trusted-replay-admission")
    _activate_planned_batch_for_state_machine_tests(
        repository,
        service,
        request,
        required_attempts=required_attempts,
        max_attempts=max_attempts,
    )
    return request


def _claim(service: ControlPlaneService, *, actor: str = "replay-worker-a"):
    claimed = service.claim_replay_job(
        ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=30),
        actor=actor,
    )
    assert claimed is not None
    return claimed


def _force_replay_lease_expired(
    repository: ControlPlaneRepository,
    *,
    job_id: str,
    ticket_id: str,
) -> None:
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    with repository.transaction() as session:
        session.execute(
            update(JobRecord).where(JobRecord.job_id == job_id).values(lease_expires_at=expired_at)
        )
        session.execute(
            update(ReplayTicketRecord)
            .where(ReplayTicketRecord.ticket_id == ticket_id)
            .values(lease_expires_at=expired_at)
        )


def test_source_artifact_admission_is_managed_exact_and_idempotent(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "artifact-admission.db")
    suffix = "artifact-admission"
    identity = sha256(suffix.encode()).hexdigest()
    request = AdmitSourceArtifactRequest(
        staging_id=f"stage_{sha256(f'stage:{suffix}'.encode()).hexdigest()[:32]}",
        producer_run_id=f"run_{identity[:32]}",
        producer_job_id=f"job_{sha256(f'job:{suffix}'.encode()).hexdigest()[:32]}",
        idempotency_key=f"artifact-admission-{suffix}",
    )
    try:
        admitted = _seed_completed_source(repository, service, suffix)
        repeated = service.admit_source_artifact(
            request,
            actor="trusted-source-admission",
        )

        assert repeated == admitted
        assert admitted.producer_run_id == request.producer_run_id
        assert admitted.run_id != admitted.producer_run_id
        with repository.transaction() as session:
            artifact = session.scalar(select(ArtifactRecord))
            events = list(
                session.scalars(
                    select(EventRecord).where(EventRecord.event_type == "artifact.source-admitted")
                ).all()
            )
            assert artifact is not None
            assert artifact.producer_job_id == request.producer_job_id
            assert artifact.producer_attempt == 1
            assert artifact.sealed_run_id == admitted.run_id
            assert len(events) == 1
            exposed = f"{admitted.model_dump(mode='json')} {events[0].payload}"
            assert request.staging_id not in exposed
            assert artifact.storage_key not in exposed

        drifted = request.model_copy(update={"staging_id": f"stage_{'f' * 32}"})
        with pytest.raises(StateConflict, match="idempotency"):
            service.admit_source_artifact(
                drifted,
                actor="trusted-source-admission",
            )
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(EventRecord)
                    .where(EventRecord.event_type == "artifact.source-admitted")
                )
                == 1
            )
    finally:
        repository.close()


def test_artifact_admission_and_batch_fail_closed_without_managed_repository(
    tmp_path: Path,
) -> None:
    repository = ControlPlaneRepository(f"sqlite:///{(tmp_path / 'missing-repo.db').as_posix()}")
    repository.initialize()
    signer = CheckpointSigner(
        active_key_id="replay-v1",
        keys={"replay-v1": b"replay-test-signing-key-at-least-32-bytes"},
    )
    service = ControlPlaneService(repository, signer)
    try:
        with pytest.raises(StateConflict, match="repository is not configured"):
            service.admit_source_artifact(
                AdmitSourceArtifactRequest(
                    staging_id=f"stage_{'1' * 32}",
                    producer_run_id=f"run_{'2' * 32}",
                    producer_job_id=f"job_{'3' * 32}",
                    idempotency_key="missing-artifact-repository",
                ),
                actor="trusted-source-admission",
            )
        with pytest.raises(StateConflict, match="repository is not configured"):
            service.create_replay_batch(
                _batch_request(
                    ArtifactRef(
                        artifact_id=f"artifact_{'4' * 32}",
                        repository_version=1,
                        producer_run_id=f"run_{'2' * 32}",
                        media_type="application/vnd.pajin.run+directory",
                        schema_kind="pajin.run.sealed.v1",
                        byte_length=1,
                        content_digest="5" * 64,
                        run_id="sealed-run",
                        integrity_root_digest="6" * 64,
                        created_by="trusted-source-admission",
                    ),
                    "missing-repository",
                ),
                actor="trusted-replay-admission",
            )
    finally:
        repository.close()


@pytest.mark.parametrize("job_kind", ["replay", InternalJobKind.REPLAY.value])
def test_public_api_rejects_replay_submission_and_exposes_no_replay_route(
    tmp_path: Path,
    job_kind: str,
) -> None:
    app = create_app(_settings(tmp_path / f"public-{job_kind}.db"))
    with TestClient(app) as client:
        response = client.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": "public-replay-injection",
                "input": {"runPath": "/tmp/untrusted", "verdict": "confirmed"},
                "idempotency_key": f"public-replay-{job_kind}",
                "job_kind": job_kind,
            },
        )
        assert response.status_code == 422
        generic_claim = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "body-controlled-worker",
                "kinds": [job_kind],
                "lease_seconds": 30,
            },
        )
        assert generic_claim.status_code == 422
        assert all("replay" not in path for path in app.openapi()["paths"])

        with app.state.repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(RunRecord)) == 0
            assert session.scalar(select(func.count()).select_from(JobRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 0


@pytest.mark.parametrize("kind", [InternalJobKind.REPLAY.value, "future-unregistered-kind"])
def test_generic_claim_service_rejects_bypassed_nonpublic_job_kinds(
    tmp_path: Path,
    kind: str,
) -> None:
    repository, service = _service(tmp_path / f"generic-claim-{kind}.db")
    try:
        ordinary = service.submit_run(
            SubmitRunRequest(
                campaign_name="ordinary-campaign",
                idempotency_key=f"ordinary-before-{kind}",
            ),
            actor="ordinary-operator",
        )
        _create_batch(repository, service, f"generic-claim-{kind}")
        bypassed = ClaimJobRequest.model_construct(
            worker_id="body-controlled-worker",
            kinds=[kind],
            lease_seconds=30,
            wait_seconds=0,
        )

        with pytest.raises(StateConflict, match=r"public|Replay|kind"):
            service.claim_job(bypassed, actor="ordinary-worker-principal")

        assert service.get_job(ordinary.job.job_id).state is JobState.QUEUED
        with repository.transaction() as session:
            replay_job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            assert replay_job is not None and ticket is not None
            assert replay_job.state == JobState.QUEUED.value
            assert ticket.state == ReplayTicketState.ISSUED.value
    finally:
        repository.close()


def test_batch_creation_is_atomic_idempotent_and_stops_before_ticket_issuance(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "batch.db")
    try:
        source = _seed_completed_source(repository, service, "batch")
        request = _batch_request(source, "batch")

        created = service.create_replay_batch(request, actor="trusted-replay-admission")
        repeated = service.create_replay_batch(request, actor="trusted-replay-admission")

        assert repeated == created
        assert created.source == source
        assert created.mode is CampaignMode.AI_REDTEAM
        assert created.purpose is ReplayPurpose.CONFIRMATION
        assert created.policy_version == KISA_CONFIRMATION_POLICY_VERSION
        assert created.state is ReplayBatchState.PLANNED
        with repository.transaction() as session:
            batch = session.scalar(
                select(ReplayBatchRecord).where(ReplayBatchRecord.batch_id == created.batch_id)
            )
            items = session.scalars(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == created.batch_id)
            ).all()
            tickets = session.scalars(
                select(ReplayTicketRecord).where(ReplayTicketRecord.batch_id == created.batch_id)
            ).all()
            compilations = session.scalars(
                select(ReplayCompilationRecord).where(
                    ReplayCompilationRecord.batch_id == created.batch_id
                )
            ).all()
            assert batch is not None
            assert len(items) == len(compilations) == 1
            assert tickets == []
            item = items[0]
            compilation = compilations[0]
            replay_run = session.get(RunRecord, item.replay_run_id)
            assert replay_run is not None

            assert batch.source_run_id == source.producer_run_id
            assert batch.source_artifact_run_id == source.run_id
            assert batch.source_artifact_id == source.artifact_id
            assert batch.source_content_digest == source.content_digest
            assert batch.source_root_digest == source.integrity_root_digest
            assert item.state == ReplayItemState.PENDING.value
            assert item.required_attempts == KISA_CONFIRMATION_REQUIRED_ATTEMPTS
            assert item.max_attempts == KISA_CONFIRMATION_MAX_ATTEMPTS
            assert item.attempts == 0
            assert compilation.item_id == item.item_id
            assert compilation.compilation_id.startswith("replay-compilation_")
            assert compilation.replay_run_id == item.replay_run_id
            assert compilation.candidate_digest == item.candidate_digest
            assert compilation.contract_digest == item.contract_digest
            assert compilation.compilation_digest == item.compilation_digest
            assert compilation.grant_digest == item.grant_digest
            assert compilation.byte_length == len(compilation.canonical_compilation)
            assert sha256(compilation.canonical_compilation).hexdigest() == item.compilation_digest
            trusted_compilation = ReplayCompilation.model_validate_json(
                compilation.canonical_compilation
            )
            assert replay_context_digest(trusted_compilation.validation_packet.candidate) == (
                item.candidate_digest
            )
            assert replay_context_digest(trusted_compilation.contract) == item.contract_digest
            assert replay_context_digest(trusted_compilation.grant) == item.grant_digest
            assert replay_run.state == RunState.QUEUED.value
            assert "replayPlan" in replay_run.input
            assert "replay" not in replay_run.input

            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 0
            )

        with pytest.raises(StateConflict, match="idempot"):
            service.create_replay_batch(request, actor="different-replay-admission")

        unknown_locator = ArtifactLocator(
            artifact_id=f"artifact_{'f' * 32}",
            repository_version=1,
        )
        with pytest.raises(StateConflict, match="idempot"):
            service.create_replay_batch(
                request.model_copy(update={"source": unknown_locator}),
                actor="trusted-replay-admission",
            )
        with pytest.raises(ResourceNotFound, match="Artifact"):
            service.create_replay_batch(
                request.model_copy(
                    update={
                        "source": unknown_locator,
                        "idempotency_key": "replay-batch-unknown-locator",
                    }
                ),
                actor="trusted-replay-admission",
            )
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1
    finally:
        repository.close()


def test_batch_creation_rolls_back_every_derived_row_after_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "batch-rollback.db")
    try:
        source = _seed_completed_source(repository, service, "batch-rollback")
        request = _batch_request(source, "batch-rollback")
        original_event = service._event
        reached_late_failure = False

        def fail_after_compilation(session, run, event_type, actor, payload):
            nonlocal reached_late_failure
            if event_type != "run.replay-planned":
                return original_event(session, run, event_type, actor, payload)

            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(RunRecord)) == 2
            reached_late_failure = True
            raise RuntimeError("simulated failure after Replay compilation persistence")

        monkeypatch.setattr(service, "_event", fail_after_compilation)

        with pytest.raises(RuntimeError, match="after Replay compilation persistence"):
            service.create_replay_batch(request, actor="trusted-replay-admission")

        assert reached_late_failure
        with repository.transaction() as session:
            source_run = session.get(RunRecord, source.producer_run_id)
            artifact = session.get(
                ArtifactRecord,
                (source.artifact_id, source.repository_version),
            )
            assert source_run is not None
            assert source_run.state == RunState.COMPLETED.value
            assert artifact is not None
            assert artifact.sealed_run_id == source.run_id

            assert session.scalar(select(func.count()).select_from(RunRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayEventRecord)) == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(EventRecord)
                    .where(EventRecord.event_type == "run.replay-planned")
                )
                == 0
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 0
            )
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("replay_run_id", "source-run"),
        ("compilation_digest", "0" * 64),
        ("grant_digest", "0" * 64),
    ],
)
def test_replay_batch_idempotency_rejects_current_compilation_pointer_drift(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    repository, service = _service(tmp_path / f"batch-pointer-drift-{field}.db")
    try:
        source = _seed_completed_source(repository, service, f"batch-pointer-drift-{field}")
        request = _batch_request(source, f"batch-pointer-drift-{field}")
        created = service.create_replay_batch(request, actor="trusted-replay-admission")

        drifted_value = source.producer_run_id if replacement == "source-run" else replacement
        with repository.transaction() as session:
            session.execute(
                update(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == created.batch_id)
                .values({field: drifted_value})
            )

        with pytest.raises(StateConflict, match="authority input"):
            service.create_replay_batch(request, actor="trusted-replay-admission")
    finally:
        repository.close()


def test_claim_burns_ticket_and_binds_authenticated_actor_token_attempt_and_fence(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "claim.db")
    try:
        _create_batch(repository, service, "claim")
        claimed = _claim(service, actor="authenticated-worker-a")

        assert claimed.job.kind == InternalJobKind.REPLAY.value
        assert claimed.job.state is JobState.LEASED
        assert claimed.job.lease_owner == "authenticated-worker-a"
        assert claimed.item.state is ReplayItemState.RUNNING
        assert claimed.ticket.state is ReplayTicketState.CLAIMED
        assert claimed.ticket.claimed_by == "authenticated-worker-a"
        assert claimed.ticket.executor_profile == EXECUTOR_PROFILE
        assert claimed.ticket.attempt == claimed.item.attempts == 1
        assert claimed.ticket.fencing_value == 1
        assert claimed.ticket.job_id == claimed.job.job_id
        assert claimed.ticket.replay_run_id == claimed.job.run_id
        source_payload = claimed.job.payload["source"]
        assert source_payload["producer_run_id"] == claimed.batch.source.producer_run_id
        assert source_payload["run_id"] == claimed.batch.source.run_id
        assert source_payload["producer_run_id"] != source_payload["run_id"]
        assert not {"storage_key", "staging_id", "path"}.intersection(source_payload)

        with repository.transaction() as session:
            job = session.get(JobRecord, claimed.job.job_id)
            ticket = session.get(ReplayTicketRecord, claimed.ticket.ticket_id)
            assert job is not None and ticket is not None
            expected_digest = token_digest(claimed.lease_token)
            assert job.lease_token_hash == ticket.lease_token_hash == expected_digest
            assert claimed.lease_token not in repr(job.payload)
            assert claimed.lease_token != expected_digest
            assert ticket.claim_principal == "authenticated-worker-a"
            assert ticket.fencing_value == claimed.ticket.fencing_value
            assert ticket.attempt_number == claimed.ticket.attempt

        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="authenticated-worker-b",
            )
            is None
        )
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("actor", "executor_profile"),
    [
        ("unregistered-worker", EXECUTOR_PROFILE),
        ("authenticated-worker-a", "unregistered-executor-profile"),
    ],
)
def test_replay_claim_rejects_unregistered_actor_profile_without_state_change(
    tmp_path: Path,
    actor: str,
    executor_profile: str,
) -> None:
    repository, service = _service(tmp_path / f"registry-{actor}-{executor_profile}.db")
    try:
        _create_batch(repository, service, f"registry-{actor}-{executor_profile}")
        with repository.transaction() as session:
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            item = session.scalar(select(ReplayItemRecord))
            assert job is not None and ticket is not None and item is not None
            identities = (job.job_id, ticket.ticket_id, item.item_id)

        with pytest.raises(StateConflict, match=r"executor|profile|registered"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=executor_profile),
                actor=actor,
            )

        with repository.transaction() as session:
            job = session.get(JobRecord, identities[0])
            ticket = session.get(ReplayTicketRecord, identities[1])
            item = session.get(ReplayItemRecord, identities[2])
            assert job is not None and ticket is not None and item is not None
            assert job.state == JobState.QUEUED.value
            assert job.attempts == 0
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert ticket.state == ReplayTicketState.ISSUED.value
            assert ticket.claim_principal is None
            assert ticket.lease_token_hash is None
            assert item.state == ReplayItemState.QUEUED.value
    finally:
        repository.close()


@pytest.mark.parametrize("tamper", ["extra-run-path", "compilation-digest", "ticket-id"])
def test_replay_claim_rejects_tampered_job_payload_without_burning_ticket(
    tmp_path: Path,
    tamper: str,
) -> None:
    repository, service = _service(tmp_path / f"payload-{tamper}.db")
    try:
        _create_batch(repository, service, f"payload-{tamper}")
        with repository.transaction() as session:
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            item = session.scalar(select(ReplayItemRecord))
            assert job is not None and ticket is not None and item is not None
            payload = dict(job.payload)
            if tamper == "extra-run-path":
                payload["run_path"] = "/tmp/worker-controlled"
            elif tamper == "compilation-digest":
                payload["compilation_digest"] = "0" * 64
            else:
                payload["ticket_id"] = f"replay-ticket_{'0' * 32}"
            job.payload = payload
            identities = (job.job_id, ticket.ticket_id, item.item_id)

        with pytest.raises(StateConflict, match=r"Replay|payload|binding"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="authenticated-worker-a",
            )

        with repository.transaction() as session:
            job = session.get(JobRecord, identities[0])
            ticket = session.get(ReplayTicketRecord, identities[1])
            item = session.get(ReplayItemRecord, identities[2])
            assert job is not None and ticket is not None and item is not None
            assert job.state == JobState.QUEUED.value
            assert job.attempts == 0
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert ticket.state == ReplayTicketState.ISSUED.value
            assert ticket.claim_principal is None
            assert ticket.lease_token_hash is None
            assert item.state == ReplayItemState.QUEUED.value
            assert item.attempts == 1
    finally:
        repository.close()


def test_two_workers_can_burn_one_sqlite_replay_ticket_exactly_once(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "claim-race.db")
    try:
        _create_batch(repository, service, "claim-race")
        barrier = Barrier(2)

        def claim(actor: str):
            barrier.wait()
            return service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor=actor,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, ["race-worker-a", "race-worker-b"]))

        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        winner = winners[0]
        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, winner.ticket.ticket_id)
            job = session.get(JobRecord, winner.job.job_id)
            assert ticket is not None and job is not None
            assert ticket.state == ReplayTicketState.CLAIMED.value
            assert ticket.claim_principal == winner.ticket.claimed_by
            assert job.state == JobState.LEASED.value
            assert job.attempts == 1
    finally:
        repository.close()


def test_replay_heartbeat_requires_exact_actor_ticket_fence_and_dedicated_path(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "heartbeat.db")
    try:
        _create_batch(repository, service, "heartbeat")
        claimed = _claim(service, actor="heartbeat-worker")
        request = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            lease_seconds=45,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )

        refreshed = service.heartbeat_replay_job(
            claimed.job.job_id,
            request,
            actor="heartbeat-worker",
        )
        assert refreshed.ticket.lease_expires_at is not None
        assert refreshed.job.lease_expires_at == refreshed.ticket.lease_expires_at

        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request,
                actor="stale-worker",
            )
        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"fencing_value": claimed.ticket.fencing_value + 1}),
                actor="heartbeat-worker",
            )
        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"lease_token": "x" * 32}),
                actor="heartbeat-worker",
            )
        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"ticket_id": f"replay-ticket_{'0' * 32}"}),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match=r"executor|profile|registered"):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"executor_profile": "unregistered-profile"}),
                actor="heartbeat-worker",
            )

        with pytest.raises(StateConflict, match="Replay"):
            service.heartbeat(
                claimed.job.job_id,
                LeaseRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                ),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.complete_job(
                claimed.job.job_id,
                CompleteJobRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                    result={"workerVerdict": "confirmed"},
                ),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.fail_job(
                claimed.job.job_id,
                FailJobRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                    error="generic retry must not requeue Replay",
                    retryable=True,
                ),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.create_checkpoint(
                claimed.job.job_id,
                CreateCheckpointRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                    state={"untrusted": "checkpoint"},
                    pending_intent=ApprovalIntent(
                        call_fingerprint="a" * 64,
                        tool_id="mock.replay-bypass",
                        target="lab://replay-bypass",
                        risk_tier=ToolRiskTier.T3,
                        expires_at=datetime.now(UTC) + timedelta(minutes=5),
                    ),
                ),
                actor="heartbeat-worker",
            )

        assert service.get_job(claimed.job.job_id).state is JobState.LEASED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.CLAIMED
        )
    finally:
        repository.close()


def test_claimed_replay_lease_is_not_capped_by_issuance_deadline(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "claimed-lease-deadline.db")
    try:
        _create_batch(repository, service, "claimed-lease-deadline")
        now = datetime.now(UTC)
        with repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.ticket_id == ticket.ticket_id)
                .values(
                    issued_at=now - timedelta(minutes=1),
                    expires_at=now + timedelta(seconds=60),
                )
            )
        claimed = service.claim_replay_job(
            ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=300),
            actor="heartbeat-worker",
        )
        assert claimed is not None
        assert claimed.ticket.lease_expires_at is not None
        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, claimed.ticket.ticket_id)
            assert ticket is not None
            issuance_deadline = (
                ticket.expires_at
                if ticket.expires_at.tzinfo is not None
                else ticket.expires_at.replace(tzinfo=UTC)
            )
        assert claimed.ticket.lease_expires_at > issuance_deadline

        refreshed = service.heartbeat_replay_job(
            claimed.job.job_id,
            ReplayLeaseRequest(
                executor_profile=EXECUTOR_PROFILE,
                lease_token=claimed.lease_token,
                lease_seconds=300,
                ticket_id=claimed.ticket.ticket_id,
                fencing_value=claimed.ticket.fencing_value,
            ),
            actor="heartbeat-worker",
        )
        assert refreshed.ticket.lease_expires_at is not None
        assert refreshed.ticket.lease_expires_at > claimed.ticket.lease_expires_at
        assert refreshed.ticket.lease_expires_at > issuance_deadline
    finally:
        repository.close()


def test_expired_issued_replay_ticket_is_abandoned_before_claim(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "expired-issued-ticket.db")
    try:
        _create_batch(
            repository,
            service,
            "expired-issued-ticket",
            required_attempts=1,
            max_attempts=1,
        )
        now = datetime.now(UTC)
        with repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            ticket_id = ticket.ticket_id
            job_id = ticket.job_id
            item_id = ticket.item_id
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.ticket_id == ticket_id)
                .values(issued_at=now - timedelta(minutes=2), expires_at=now - timedelta(minutes=1))
            )

        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="expired-worker",
            )
            is None
        )
        assert service.get_job(job_id).state is JobState.FAILED
        assert service.get_replay_ticket(ticket_id).state is ReplayTicketState.ABANDONED
        assert service.get_replay_item(item_id).state is ReplayItemState.FAILED
        with repository.transaction() as session:
            batch = session.scalar(select(ReplayBatchRecord))
            assert batch is not None
            assert batch.state == ReplayBatchState.FAILED.value

        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replacement-worker",
            )
            is None
        )
    finally:
        repository.close()


def test_expired_replay_claim_is_abandoned_without_requeue_and_stale_mutations_fail(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "expiry.db")
    try:
        _create_batch(repository, service, "expiry", required_attempts=2, max_attempts=3)
        claimed = _claim(service, actor="expired-worker")
        expired_at = datetime.now(UTC) - timedelta(seconds=1)
        with repository.transaction() as session:
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

        assert service.requeue_expired(actor="lease-reaper") == 1
        assert service.requeue_expired(actor="lease-reaper") == 0
        assert service.get_job(claimed.job.job_id).state is JobState.FAILED
        assert service.get_run(claimed.job.run_id).state is RunState.FAILED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.ABANDONED
        )
        assert service.get_replay_item(claimed.item.item_id).state is (
            ReplayItemState.RETRY_PENDING
        )
        assert service.get_replay_batch(claimed.batch.batch_id).state is (ReplayBatchState.RUNNING)
        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replacement-worker",
            )
            is None
        )

        stale = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )
        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                stale,
                actor="expired-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.complete_job(
                claimed.job.job_id,
                CompleteJobRequest(
                    worker_id="expired-worker",
                    lease_token=claimed.lease_token,
                    result={"late": True},
                ),
                actor="expired-worker",
            )

        with repository.transaction() as session:
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
    finally:
        repository.close()


def test_cancelling_single_replay_run_abandons_ticket_and_cancels_item_and_batch(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "cancel.db")
    try:
        _create_batch(repository, service, "cancel")
        claimed = _claim(service, actor="cancelled-worker")

        cancelled = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="operator cancelled Replay validation"),
            actor="replay-operator",
        )
        assert cancelled.applied is True
        assert cancelled.cancelled_job_ids == [claimed.job.job_id]
        assert cancelled.run.state is RunState.CANCELLED
        assert service.get_job(claimed.job.job_id).state is JobState.CANCELLED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.ABANDONED
        )
        assert service.get_replay_item(claimed.item.item_id).state is ReplayItemState.CANCELLED
        assert service.get_replay_batch(claimed.batch.batch_id).state is (
            ReplayBatchState.CANCELLED
        )

        stale = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )
        with pytest.raises((RunCancelled, LeaseRejected)):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                stale,
                actor="cancelled-worker",
            )

        repeated = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="idempotent cancellation retry"),
            actor="replay-operator",
        )
        assert repeated.applied is False
    finally:
        repository.close()


def test_expired_retry_pending_authority_can_be_cancelled_without_rewriting_history(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "expiry-cancel.db")
    try:
        _create_batch(repository, service, "expiry-cancel", required_attempts=2, max_attempts=3)
        claimed = _claim(service, actor="heartbeat-worker")
        service.heartbeat_replay_job(
            claimed.job.job_id,
            ReplayLeaseRequest(
                executor_profile=EXECUTOR_PROFILE,
                lease_token=claimed.lease_token,
                ticket_id=claimed.ticket.ticket_id,
                fencing_value=claimed.ticket.fencing_value,
            ),
            actor="heartbeat-worker",
        )
        _force_replay_lease_expired(
            repository,
            job_id=claimed.job.job_id,
            ticket_id=claimed.ticket.ticket_id,
        )

        assert service.requeue_expired(actor="lease-reaper") == 1
        assert service.get_run(claimed.job.run_id).state is RunState.FAILED
        assert service.get_job(claimed.job.job_id).state is JobState.FAILED
        assert service.get_replay_item(claimed.item.item_id).state is (
            ReplayItemState.RETRY_PENDING
        )

        cancelled = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="operator fenced future Replay retries"),
            actor="replay-operator",
        )
        assert cancelled.applied is True
        assert cancelled.cancelled_job_ids == []
        assert cancelled.run.state is RunState.FAILED
        assert service.get_run(claimed.job.run_id).state is RunState.FAILED
        assert service.get_job(claimed.job.job_id).state is JobState.FAILED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.ABANDONED
        )
        assert service.get_replay_item(claimed.item.item_id).state is ReplayItemState.CANCELLED
        assert service.get_replay_batch(claimed.batch.batch_id).state is (
            ReplayBatchState.CANCELLED
        )

        repeated = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="idempotent retry authority cancellation"),
            actor="replay-operator",
        )
        assert repeated.applied is False
        assert repeated.run.state is RunState.FAILED

        with repository.transaction() as session:
            events = list(
                session.scalars(
                    select(ReplayEventRecord)
                    .where(ReplayEventRecord.batch_id == claimed.batch.batch_id)
                    .order_by(ReplayEventRecord.sequence)
                ).all()
            )
        event_types = {event.event_type for event in events}
        assert {
            "replay.batch.created",
            "replay.ticket.issued",
            "replay.ticket.claimed",
            "replay.ticket.heartbeat",
            "replay.ticket.lease-expired",
            "replay.batch.cancelled",
        }.issubset(event_types)
        assert [event.sequence for event in events] == list(range(1, len(events) + 1))
    finally:
        repository.close()


@pytest.mark.parametrize("cancel_first", [True, False])
def test_multi_item_batch_terminal_state_is_order_independent(
    tmp_path: Path,
    cancel_first: bool,
) -> None:
    repository, service = _service(tmp_path / f"multi-order-{cancel_first}.db")
    try:
        _create_batch(
            repository,
            service,
            f"multi-order-{cancel_first}",
            required_attempts=1,
            max_attempts=1,
            item_count=2,
        )
        first = _claim(service, actor="replay-worker-a")
        if cancel_first:
            service.cancel_run(
                first.item.replay_run_id,
                CancelRunRequest(reason="cancel one Replay item first"),
                actor="replay-operator",
            )
            assert service.get_replay_item(first.item.item_id).state is ReplayItemState.CANCELLED
        else:
            _force_replay_lease_expired(
                repository,
                job_id=first.job.job_id,
                ticket_id=first.ticket.ticket_id,
            )
            assert service.requeue_expired(actor="lease-reaper") == 1
            assert service.get_replay_item(first.item.item_id).state is ReplayItemState.FAILED
        assert service.get_replay_batch(first.batch.batch_id).state is ReplayBatchState.RUNNING

        second = _claim(service, actor="replay-worker-a")
        assert second.item.item_id != first.item.item_id
        if cancel_first:
            _force_replay_lease_expired(
                repository,
                job_id=second.job.job_id,
                ticket_id=second.ticket.ticket_id,
            )
            assert service.requeue_expired(actor="lease-reaper") == 1
        else:
            service.cancel_run(
                second.item.replay_run_id,
                CancelRunRequest(reason="cancel one Replay item last"),
                actor="replay-operator",
            )

        with repository.transaction() as session:
            final_states = set(
                session.scalars(
                    select(ReplayItemRecord.state).where(
                        ReplayItemRecord.batch_id == first.batch.batch_id
                    )
                ).all()
            )
        assert final_states == {
            ReplayItemState.CANCELLED.value,
            ReplayItemState.FAILED.value,
        }
        assert service.get_replay_batch(first.batch.batch_id).state is (ReplayBatchState.CANCELLED)
    finally:
        repository.close()


def test_ordinary_campaign_lease_expiry_still_requeues_the_same_job(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "ordinary-regression.db")
    try:
        submitted = service.submit_run(
            SubmitRunRequest(
                campaign_name="ordinary-campaign",
                input={"regression": "at-least-once"},
                idempotency_key="ordinary-regression-submission",
                max_attempts=3,
            ),
            actor="ordinary-operator",
        )
        first = service.claim_job(
            ClaimJobRequest(worker_id="ordinary-worker-a", lease_seconds=30),
            actor="ordinary-worker-principal",
        )
        assert first is not None
        assert first.job.job_id == submitted.job.job_id
        with repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == first.job.job_id)
                .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )

        assert service.requeue_expired(actor="lease-reaper") == 1
        second = service.claim_job(
            ClaimJobRequest(worker_id="ordinary-worker-b", lease_seconds=30),
            actor="ordinary-worker-principal",
        )
        assert second is not None
        assert second.job.job_id == first.job.job_id
        assert second.job.attempts == 2
        assert second.lease_token != first.lease_token
    finally:
        repository.close()
