from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from kisa_control_plane_support import build_kisa_control_plane_source
from sqlalchemy import func, select, update

import pajin.control_plane.service as control_plane_service_module
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.database import (
    ArtifactRecord,
    ControlPlaneRepository,
    EventRecord,
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
    ReplayBatchIssuanceView,
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
from pajin.replay.tickets import canonical_replay_compilation_bytes, replay_context_digest
from pajin.tools.ai import AIChatProbeTool

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


def _issue_planned_batch_for_state_machine_tests(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    request: CreateReplayBatchRequest,
    *,
    required_attempts: int,
    max_attempts: int,
) -> ReplayBatchIssuanceView:
    """Use production issuance, then tune only state-machine policy counts for tests."""

    with repository.transaction() as session:
        batch = session.scalar(
            select(ReplayBatchRecord).where(
                ReplayBatchRecord.idempotency_key == request.idempotency_key
            )
        )
        assert batch is not None
        assert batch.state == ReplayBatchState.PLANNED.value
        batch_id = batch.batch_id

    issued = service.issue_replay_batch(
        batch_id,
        actor="trusted-replay-admission",
    )
    if (
        required_attempts != KISA_CONFIRMATION_REQUIRED_ATTEMPTS
        or max_attempts != KISA_CONFIRMATION_MAX_ATTEMPTS
    ):
        with repository.transaction() as session:
            session.execute(
                update(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch_id)
                .values(
                    required_attempts=required_attempts,
                    max_attempts=max_attempts,
                )
            )
    return issued


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
    _issue_planned_batch_for_state_machine_tests(
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
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 0
            )
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


def test_replay_issuance_appends_fresh_compilation_and_exact_durable_reservations(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "issuance.db")
    try:
        source = _seed_completed_source(repository, service, "issuance")
        request = _batch_request(source, "issuance")
        planned = service.create_replay_batch(request, actor="trusted-replay-admission")
        with repository.transaction() as session:
            planned_item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
            )
            planned_compilation = session.scalar(
                select(ReplayCompilationRecord).where(
                    ReplayCompilationRecord.batch_id == planned.batch_id
                )
            )
            assert planned_item is not None and planned_compilation is not None
            planned_run_id = planned_item.replay_run_id
            planned_compilation_id = planned_compilation.compilation_id
            planned_canonical = bytes(planned_compilation.canonical_compilation)

        issued = service.issue_replay_batch(
            planned.batch_id,
            actor="trusted-replay-admission",
        )

        assert issued.batch.state is ReplayBatchState.RUNNING
        assert len(issued.items) == len(issued.tickets) == 1
        assert issued.items[0].state is ReplayItemState.QUEUED
        assert issued.items[0].attempts == issued.tickets[0].attempt == 1
        assert issued.items[0].replay_run_id != planned_run_id
        with repository.transaction() as session:
            item = session.get(ReplayItemRecord, issued.items[0].item_id)
            ticket = session.get(ReplayTicketRecord, issued.tickets[0].ticket_id)
            job = session.get(JobRecord, issued.tickets[0].job_id)
            fresh_compilation = session.get(
                ReplayCompilationRecord,
                issued.tickets[0].compilation_id,
            )
            preserved_proof = session.get(ReplayCompilationRecord, planned_compilation_id)
            planned_run = session.get(RunRecord, planned_run_id)
            fresh_run = session.get(RunRecord, issued.items[0].replay_run_id)
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget_reservation = session.scalar(select(ReplayBudgetReservationRecord))
            rate_account = session.scalar(select(ReplayRateAccountRecord))
            rate_reservation = session.scalar(select(ReplayRateReservationRecord))
            assert all(
                record is not None
                for record in (
                    item,
                    ticket,
                    job,
                    fresh_compilation,
                    preserved_proof,
                    planned_run,
                    fresh_run,
                    budget_account,
                    budget_reservation,
                    rate_account,
                    rate_reservation,
                )
            )
            assert item is not None
            assert ticket is not None
            assert job is not None
            assert fresh_compilation is not None
            assert preserved_proof is not None
            assert planned_run is not None
            assert fresh_run is not None
            assert budget_account is not None
            assert budget_reservation is not None
            assert rate_account is not None
            assert rate_reservation is not None

            assert preserved_proof.canonical_compilation == planned_canonical
            assert preserved_proof.replay_run_id == planned_run_id
            assert fresh_compilation.compilation_id != preserved_proof.compilation_id
            assert fresh_compilation.replay_run_id == item.replay_run_id == ticket.replay_run_id
            assert fresh_compilation.compilation_digest == item.compilation_digest
            assert fresh_compilation.grant_digest == item.grant_digest
            assert sha256(fresh_compilation.canonical_compilation).hexdigest() == (
                item.compilation_digest
            )
            trusted = ReplayCompilation.model_validate_json(fresh_compilation.canonical_compilation)
            assert canonical_replay_compilation_bytes(trusted) == (
                fresh_compilation.canonical_compilation
            )
            assert trusted.spec.binding.replay_run_id == item.replay_run_id
            assert replay_context_digest(trusted.grant) == item.grant_digest
            assert planned_run.state == RunState.QUEUED.value
            assert "replayPlan" in planned_run.input and "replay" not in planned_run.input
            assert fresh_run.state == RunState.QUEUED.value

            payload = ReplayJobPayload.model_validate(job.payload)
            assert job.kind == InternalJobKind.REPLAY.value
            assert job.state == JobState.QUEUED.value
            assert payload.compilation_id == ticket.compilation_id
            assert payload.budget_reservation_id == ticket.budget_reservation_id
            assert payload.rate_reservation_id == ticket.rate_reservation_id
            assert payload.replay_run_id == fresh_compilation.replay_run_id
            assert payload.compilation_digest == fresh_compilation.compilation_digest
            assert payload.grant_digest == fresh_compilation.grant_digest
            assert fresh_run.input == {"replay": payload.model_dump(mode="json")}

            assert budget_reservation.budget_reservation_id == ticket.budget_reservation_id
            assert budget_reservation.compilation_id == ticket.compilation_id
            assert budget_reservation.attempt_number == ticket.attempt_number == 1
            assert budget_reservation.total_calls == trusted.spec.max_calls
            assert budget_reservation.consumed_calls == budget_reservation.released_calls == 0
            assert budget_reservation.state == "active"
            assert budget_account.source_run_id == source.producer_run_id
            assert budget_account.reserved_calls == budget_reservation.total_calls
            assert budget_account.consumed_calls == 0
            assert (
                budget_account.baseline_used_calls
                + budget_account.reserved_calls
                + budget_account.consumed_calls
                <= budget_account.max_tool_calls
            )

            expected_rate_units = (
                AIChatProbeTool().network_request_cost(trusted.original_request)
                * trusted.spec.repetitions
            )
            assert rate_reservation.rate_reservation_id == ticket.rate_reservation_id
            assert rate_reservation.compilation_id == ticket.compilation_id
            assert rate_reservation.attempt_number == ticket.attempt_number == 1
            assert rate_reservation.total_request_units == expected_rate_units
            assert (
                rate_reservation.consumed_request_units
                == rate_reservation.released_request_units
                == 0
            )
            assert rate_reservation.state == "active"
            assert rate_account.source_run_id == source.producer_run_id
            assert ticket.compilation_id == fresh_compilation.compilation_id

            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 2
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 1
            )
    finally:
        repository.close()


def test_replay_issuance_exact_retry_is_idempotent_without_double_reservation(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "issuance-idempotent.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-idempotent")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-idempotent"),
            actor="trusted-replay-admission",
        )

        first = service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")
        repeated = service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        assert repeated == first
        with repository.transaction() as session:
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget_reservations = list(session.scalars(select(ReplayBudgetReservationRecord)))
            rate_reservations = list(session.scalars(select(ReplayRateReservationRecord)))
            assert budget_account is not None
            assert len(budget_reservations) == len(rate_reservations) == len(first.items)
            assert budget_account.reserved_calls == sum(
                reservation.total_calls for reservation in budget_reservations
            )
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == (
                len(first.items) * 2
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == len(
                first.items
            )
            assert session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.kind == InternalJobKind.REPLAY.value)
            ) == len(first.items)
    finally:
        repository.close()


def test_two_sqlite_issuers_converge_on_one_replay_authority_graph(tmp_path: Path) -> None:
    database_path = tmp_path / "issuance-race.db"
    repository_a, service_a = _service(database_path)
    repository_b, service_b = _service(database_path)
    try:
        source = _seed_completed_source(repository_a, service_a, "issuance-race")
        planned = service_a.create_replay_batch(
            _batch_request(source, "issuance-race"),
            actor="trusted-replay-admission",
        )
        barrier = Barrier(2)

        def issue(service: ControlPlaneService) -> ReplayBatchIssuanceView:
            barrier.wait()
            return service.issue_replay_batch(
                planned.batch_id,
                actor="trusted-replay-admission",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(issue, (service_a, service_b)))

        assert results[0] == results[1]
        with repository_a.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 2
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 1
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 1
            )
    finally:
        repository_b.close()
        repository_a.close()


@pytest.mark.parametrize("limit", ["budget", "rate"])
def test_replay_issuance_fails_closed_when_aggregate_reservation_is_insufficient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
) -> None:
    repository, service = _service(tmp_path / f"issuance-insufficient-{limit}.db")
    try:
        source = _seed_completed_source(repository, service, f"issuance-insufficient-{limit}")
        planned = service.create_replay_batch(
            _batch_request(source, f"issuance-insufficient-{limit}"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_insufficient(**kwargs):
            derived = real_derive(**kwargs)
            if limit == "budget":
                return replace(
                    derived,
                    max_tool_calls=(derived.used_tool_calls + derived.required_tool_calls - 1),
                )
            return replace(
                derived,
                max_requests_per_minute=(
                    derived.observed_campaign_request_units + derived.required_request_units - 1
                ),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_insufficient,
        )
        with pytest.raises(StateConflict, match=r"budget|rate|reservation|eligible"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, planned.batch_id)
            item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
            )
            assert batch is not None and item is not None
            assert batch.state == ReplayBatchState.PLANNED.value
            assert item.state == ReplayItemState.PENDING.value
            assert item.attempts == 0
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 0
            )
    finally:
        repository.close()


def test_replay_issuance_rolls_back_all_fresh_authority_after_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-rollback.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-rollback")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-rollback"),
            actor="trusted-replay-admission",
        )
        original_event = service._replay_event
        reached_late_failure = False

        def fail_after_ticket(session, batch, event_type, actor, payload, **context):
            nonlocal reached_late_failure
            if event_type != "replay.ticket.issued":
                return original_event(
                    session,
                    batch,
                    event_type,
                    actor,
                    payload,
                    **context,
                )
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 2
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 1
            )
            reached_late_failure = True
            raise RuntimeError("simulated failure after durable Replay issuance")

        monkeypatch.setattr(service, "_replay_event", fail_after_ticket)
        with pytest.raises(RuntimeError, match="after durable Replay issuance"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        assert reached_late_failure
        with repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, planned.batch_id)
            item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
            )
            assert batch is not None and item is not None
            assert batch.state == ReplayBatchState.PLANNED.value
            assert batch.cas_version == 1
            assert item.state == ReplayItemState.PENDING.value
            assert item.attempts == 0
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 0
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


def test_replay_issuance_rejects_cancelled_or_drifted_planned_authority(
    tmp_path: Path,
) -> None:
    for condition in ("cancelled", "drifted"):
        repository, service = _service(tmp_path / f"issuance-{condition}.db")
        try:
            source = _seed_completed_source(repository, service, f"issuance-{condition}")
            planned = service.create_replay_batch(
                _batch_request(source, f"issuance-{condition}"),
                actor="trusted-replay-admission",
            )
            with repository.transaction() as session:
                item = session.scalar(
                    select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
                )
                assert item is not None
                replay_run_id = item.replay_run_id
                if condition == "drifted":
                    item.grant_digest = "0" * 64
            if condition == "cancelled":
                service.cancel_run(
                    replay_run_id,
                    CancelRunRequest(reason="cancel planned Replay before issuance"),
                    actor="replay-operator",
                )

            with pytest.raises(StateConflict, match=r"cancelled|planned|authority|binding"):
                service.issue_replay_batch(
                    planned.batch_id,
                    actor="trusted-replay-admission",
                )
            with repository.transaction() as session:
                assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
                assert (
                    session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord))
                    == 0
                )
                assert (
                    session.scalar(select(func.count()).select_from(ReplayRateReservationRecord))
                    == 0
                )
        finally:
            repository.close()


def test_replay_issuance_rejects_an_expired_fresh_grant_without_partial_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-expired-grant.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-expired-grant")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-expired-grant"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_expired(**kwargs):
            derived = real_derive(**kwargs)
            compiled_at = datetime.now(UTC) - timedelta(minutes=10)
            expires_at = compiled_at + timedelta(minutes=5)
            expired_items = []
            for item in derived.items:
                grant = item.compilation.grant.model_copy(
                    update={"issued_at": compiled_at, "expires_at": expires_at}
                )
                spec = item.compilation.spec.model_copy(
                    update={"compiled_at": compiled_at, "expires_at": expires_at}
                )
                compilation = item.compilation.model_copy(update={"grant": grant, "spec": spec})
                canonical = canonical_replay_compilation_bytes(compilation)
                expired_items.append(
                    replace(
                        item,
                        compilation=compilation,
                        canonical_compilation=canonical,
                        compilation_digest=sha256(canonical).hexdigest(),
                        grant_digest=replay_context_digest(grant),
                    )
                )
            return replace(
                derived,
                compiled_at=compiled_at,
                items=tuple(expired_items),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_expired,
        )
        with pytest.raises(StateConflict, match=r"expired|Grant|compilation"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
    finally:
        repository.close()


def test_replay_issuance_rejects_misreported_fresh_request_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-request-units.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-request-units")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-request-units"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_underreported(**kwargs):
            derived = real_derive(**kwargs)
            original = derived.items[0]
            assert original.required_request_units > 1
            underreported = replace(
                original,
                required_request_units=original.required_request_units - 1,
            )
            return replace(
                derived,
                required_request_units=derived.required_request_units - 1,
                items=(underreported, *derived.items[1:]),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_underreported,
        )
        with pytest.raises(StateConflict, match=r"compilation|authority|eligible"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
    finally:
        repository.close()


def test_replay_issuance_rejects_a_future_fresh_grant_without_partial_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-future-grant.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-future-grant")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-future-grant"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_future(**kwargs):
            derived = real_derive(**kwargs)
            compiled_at = datetime.now(UTC) + timedelta(minutes=10)
            expires_at = compiled_at + timedelta(minutes=5)
            future_items = []
            for item in derived.items:
                grant = item.compilation.grant.model_copy(
                    update={"issued_at": compiled_at, "expires_at": expires_at}
                )
                spec = item.compilation.spec.model_copy(
                    update={"compiled_at": compiled_at, "expires_at": expires_at}
                )
                compilation = item.compilation.model_copy(update={"grant": grant, "spec": spec})
                canonical = canonical_replay_compilation_bytes(compilation)
                future_items.append(
                    replace(
                        item,
                        compilation=compilation,
                        canonical_compilation=canonical,
                        compilation_digest=sha256(canonical).hexdigest(),
                        grant_digest=replay_context_digest(grant),
                    )
                )
            return replace(
                derived,
                compiled_at=compiled_at,
                items=tuple(future_items),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_future,
        )
        with pytest.raises(StateConflict, match=r"compilation|authority|eligible"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
    finally:
        repository.close()


def test_expired_unclaimed_replay_ticket_is_swept_and_releases_capacity(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "expired-unclaimed-ticket.db")
    try:
        _create_batch(repository, service, "expired-unclaimed-ticket")
        now = datetime.now(UTC)
        expired_at = now - timedelta(minutes=1)
        with repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            ticket.issued_at = now - timedelta(minutes=2)
            ticket.expires_at = expired_at
            ticket_id = ticket.ticket_id

        assert service.requeue_expired(actor="lease-reaper") == 1
        assert service.requeue_expired(actor="lease-reaper") == 0

        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, ticket_id)
            assert ticket is not None
            job = session.get(JobRecord, ticket.job_id)
            item = session.get(ReplayItemRecord, ticket.item_id)
            batch = session.get(ReplayBatchRecord, ticket.batch_id)
            run = session.get(RunRecord, ticket.replay_run_id)
            budget = session.get(
                ReplayBudgetReservationRecord,
                ticket.budget_reservation_id,
            )
            rate = session.get(
                ReplayRateReservationRecord,
                ticket.rate_reservation_id,
            )
            account = session.scalar(select(ReplayBudgetAccountRecord))
            assert all(
                record is not None for record in (job, item, batch, run, budget, rate, account)
            )
            assert job is not None
            assert item is not None
            assert batch is not None
            assert run is not None
            assert budget is not None
            assert rate is not None
            assert account is not None
            assert ticket.state == ReplayTicketState.ABANDONED.value
            assert ticket.abandon_reason == "Replay ticket expired before claim"
            assert job.state == JobState.FAILED.value
            assert item.state == ReplayItemState.RETRY_PENDING.value
            assert batch.state == ReplayBatchState.RUNNING.value
            assert run.state == RunState.FAILED.value
            assert budget.state == rate.state == "released"
            assert budget.released_calls == budget.total_calls
            assert rate.released_request_units == rate.total_request_units
            assert account.reserved_calls == account.consumed_calls == 0
            assert account.released_calls == budget.total_calls
    finally:
        repository.close()


def test_replay_issuance_fails_closed_on_budget_account_ledger_drift(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "budget-ledger-drift.db")
    try:
        source = _seed_completed_source(repository, service, "budget-ledger-drift")
        first = service.create_replay_batch(
            _batch_request(source, "budget-ledger-drift-first"),
            actor="trusted-replay-admission",
        )
        second = service.create_replay_batch(
            _batch_request(source, "budget-ledger-drift-second"),
            actor="trusted-replay-admission",
        )
        service.issue_replay_batch(first.batch_id, actor="trusted-replay-admission")
        with repository.transaction() as session:
            account = session.scalar(select(ReplayBudgetAccountRecord))
            assert account is not None and account.reserved_calls > 0
            account.reserved_calls = 0

        with pytest.raises(StateConflict, match=r"budget.*ledger|account counters"):
            service.issue_replay_batch(second.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            stored_second = session.get(ReplayBatchRecord, second.batch_id)
            assert stored_second is not None
            assert stored_second.state == ReplayBatchState.PLANNED.value
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
    finally:
        repository.close()


def test_replay_release_rejects_a_reservation_bound_to_another_source_account(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "reservation-account-drift.db")
    try:
        source_a = _seed_completed_source(repository, service, "reservation-account-drift-a")
        source_b = _seed_completed_source(repository, service, "reservation-account-drift-b")
        planned_a = service.create_replay_batch(
            _batch_request(source_a, "reservation-account-drift-a"),
            actor="trusted-replay-admission",
        )
        planned_b = service.create_replay_batch(
            _batch_request(source_b, "reservation-account-drift-b"),
            actor="trusted-replay-admission",
        )
        issued_a = service.issue_replay_batch(
            planned_a.batch_id,
            actor="trusted-replay-admission",
        )
        service.issue_replay_batch(
            planned_b.batch_id,
            actor="trusted-replay-admission",
        )

        with repository.transaction() as session:
            ticket_a = session.get(ReplayTicketRecord, issued_a.tickets[0].ticket_id)
            account_a = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_a.producer_run_id
                )
            )
            account_b = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_b.producer_run_id
                )
            )
            assert ticket_a is not None and account_a is not None and account_b is not None
            reservation_a = session.get(
                ReplayBudgetReservationRecord,
                ticket_a.budget_reservation_id,
            )
            assert reservation_a is not None
            moved_calls = reservation_a.total_calls
            account_a.reserved_calls -= moved_calls
            account_b.reserved_calls += moved_calls
            reservation_a.budget_account_id = account_b.budget_account_id
            counters_before = (
                account_a.reserved_calls,
                account_a.released_calls,
                account_b.reserved_calls,
                account_b.released_calls,
            )

        with pytest.raises(StateConflict, match=r"binding|source|account"):
            service.cancel_run(
                issued_a.items[0].replay_run_id,
                CancelRunRequest(reason="reject drifted reservation account"),
                actor="replay-operator",
            )

        with repository.transaction() as session:
            ticket_a = session.get(ReplayTicketRecord, issued_a.tickets[0].ticket_id)
            job_a = session.get(JobRecord, issued_a.tickets[0].job_id)
            item_a = session.get(ReplayItemRecord, issued_a.items[0].item_id)
            run_a = session.get(RunRecord, issued_a.items[0].replay_run_id)
            account_a = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_a.producer_run_id
                )
            )
            account_b = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_b.producer_run_id
                )
            )
            assert all(
                record is not None
                for record in (ticket_a, job_a, item_a, run_a, account_a, account_b)
            )
            assert ticket_a is not None
            assert job_a is not None
            assert item_a is not None
            assert run_a is not None
            assert account_a is not None
            assert account_b is not None
            assert ticket_a.state == ReplayTicketState.ISSUED.value
            assert job_a.state == JobState.QUEUED.value
            assert item_a.state == ReplayItemState.QUEUED.value
            assert run_a.state == RunState.QUEUED.value
            assert (
                account_a.reserved_calls,
                account_a.released_calls,
                account_b.reserved_calls,
                account_b.released_calls,
            ) == counters_before
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
            compilation = session.get(ReplayCompilationRecord, ticket.compilation_id)
            budget_reservation = session.get(
                ReplayBudgetReservationRecord,
                ticket.budget_reservation_id,
            )
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                ticket.rate_reservation_id,
            )
            assert compilation is not None
            assert budget_reservation is not None
            assert rate_reservation is not None
            payload = ReplayJobPayload.model_validate(job.payload)
            assert payload.compilation_id == ticket.compilation_id
            assert payload.budget_reservation_id == ticket.budget_reservation_id
            assert payload.rate_reservation_id == ticket.rate_reservation_id
            assert compilation.replay_run_id == ticket.replay_run_id
            assert budget_reservation.compilation_id == ticket.compilation_id
            assert rate_reservation.compilation_id == ticket.compilation_id

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


@pytest.mark.parametrize(
    "tamper",
    [
        "extra-run-path",
        "compilation-id",
        "budget-reservation-id",
        "rate-reservation-id",
        "compilation-digest",
        "ticket-id",
    ],
)
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
            elif tamper == "compilation-id":
                payload["compilation_id"] = f"replay-compilation_{'0' * 32}"
            elif tamper == "budget-reservation-id":
                payload["budget_reservation_id"] = f"budget-reservation_{'0' * 32}"
            elif tamper == "rate-reservation-id":
                payload["rate_reservation_id"] = f"rate-reservation_{'0' * 32}"
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
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                ticket.rate_reservation_id,
            )
            assert rate_reservation is not None
            rate_deadline = (
                rate_reservation.expires_at
                if rate_reservation.expires_at.tzinfo is not None
                else rate_reservation.expires_at.replace(tzinfo=UTC)
            )
            issuance_deadline = rate_deadline - timedelta(seconds=1)
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.ticket_id == ticket.ticket_id)
                .values(
                    issued_at=now - timedelta(minutes=1),
                    expires_at=issuance_deadline,
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
            stored_issuance_deadline = (
                ticket.expires_at
                if ticket.expires_at.tzinfo is not None
                else ticket.expires_at.replace(tzinfo=UTC)
            )
        assert stored_issuance_deadline == issuance_deadline
        assert claimed.ticket.lease_expires_at > stored_issuance_deadline

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
        assert refreshed.ticket.lease_expires_at > stored_issuance_deadline
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
        with pytest.raises((LeaseRejected, StateConflict)):
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
        with repository.transaction() as session:
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget_reservation = session.get(
                ReplayBudgetReservationRecord,
                claimed.ticket.budget_reservation_id,
            )
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                claimed.ticket.rate_reservation_id,
            )
            assert budget_account is not None
            assert budget_reservation is not None
            assert rate_reservation is not None
            assert budget_account.reserved_calls == 0
            assert budget_reservation.state == "released"
            assert budget_reservation.released_calls == budget_reservation.total_calls
            assert rate_reservation.state == "released"
            assert rate_reservation.released_request_units == rate_reservation.total_request_units

        stale = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )
        with pytest.raises((RunCancelled, LeaseRejected, StateConflict)):
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
