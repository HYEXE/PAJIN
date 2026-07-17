from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import (
    ControlPlaneRepository,
    JobRecord,
    ReplayBatchRecord,
    ReplayEventRecord,
    ReplayItemRecord,
    ReplayTicketRecord,
    RunRecord,
)
from pajin.control_plane.models import (
    ApprovalIntent,
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
    ReplayBatchItemInput,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayItemState,
    ReplayLeaseRequest,
    ReplayTicketState,
    RunState,
    SubmitRunRequest,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.control_plane.service import (
    ControlPlaneService,
    LeaseRejected,
    RunCancelled,
    StateConflict,
)
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.domain.replay import ReplayPurpose

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
    return repository, ControlPlaneService(
        repository,
        signer,
        replay_executor_profiles=profiles,
    )


def _seed_completed_source(
    repository: ControlPlaneRepository,
    suffix: str,
) -> ArtifactRef:
    identity = sha256(suffix.encode()).hexdigest()
    run_id = f"run_source_{identity[:24]}"
    now = datetime.now(UTC)
    with repository.transaction() as session:
        session.add(
            RunRecord(
                run_id=run_id,
                campaign_name="kisa-replay",
                state=RunState.COMPLETED.value,
                input={"sealedSource": True},
                submission_key=f"sealed-source-{identity}",
                current_checkpoint_id=None,
                created_at=now,
                updated_at=now,
            )
        )
    return ArtifactRef(
        artifact_id=f"artifact_{identity[:32]}",
        repository_version=1,
        media_type="application/vnd.pajin.run+tar",
        schema_kind="pajin.run.v1",
        byte_length=4_096,
        content_digest=sha256(f"content:{suffix}".encode()).hexdigest(),
        run_id=run_id,
        integrity_root_digest=sha256(f"root:{suffix}".encode()).hexdigest(),
        created_by="trusted-source-admission",
    )


def _batch_request(
    source: ArtifactRef,
    suffix: str,
    *,
    required_attempts: int = 2,
    max_attempts: int = 3,
    item_count: int = 1,
) -> CreateReplayBatchRequest:
    item_suffixes = [suffix] if item_count == 1 else [f"{suffix}-{i}" for i in range(item_count)]
    return CreateReplayBatchRequest(
        campaign_name="kisa-replay",
        source=source,
        mode=CampaignMode.AI_REDTEAM,
        purpose=ReplayPurpose.CONFIRMATION,
        policy_version="policy-v1",
        idempotency_key=f"replay-batch-{suffix}",
        items=[
            ReplayBatchItemInput(
                candidate_id=f"candidate-{sha256(item_suffix.encode()).hexdigest()[:16]}",
                candidate_digest=sha256(f"candidate:{item_suffix}".encode()).hexdigest(),
                contract_digest=sha256(f"contract:{item_suffix}".encode()).hexdigest(),
                compilation_digest=sha256(f"compilation:{item_suffix}".encode()).hexdigest(),
                grant_digest=sha256(f"grant:{item_suffix}".encode()).hexdigest(),
                required_attempts=required_attempts,
                max_attempts=max_attempts,
            )
            for item_suffix in item_suffixes
        ],
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
        _seed_completed_source(repository, suffix),
        suffix,
        required_attempts=required_attempts,
        max_attempts=max_attempts,
        item_count=item_count,
    )
    service.create_replay_batch(request, actor="trusted-replay-admission")
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
            update(JobRecord)
            .where(JobRecord.job_id == job_id)
            .values(lease_expires_at=expired_at)
        )
        session.execute(
            update(ReplayTicketRecord)
            .where(ReplayTicketRecord.ticket_id == ticket_id)
            .values(lease_expires_at=expired_at)
        )


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


def test_batch_creation_is_atomic_idempotent_and_binds_one_initial_attempt(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "batch.db")
    try:
        source = _seed_completed_source(repository, "batch")
        request = _batch_request(source, "batch", required_attempts=2, max_attempts=4)

        created = service.create_replay_batch(request, actor="trusted-replay-admission")
        repeated = service.create_replay_batch(request, actor="trusted-replay-admission")

        assert repeated == created
        assert created.source == source
        assert created.state is ReplayBatchState.RUNNING
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
            assert batch is not None
            assert len(items) == len(tickets) == 1
            item = items[0]
            ticket = tickets[0]
            job = session.get(JobRecord, ticket.job_id)
            replay_run = session.get(RunRecord, ticket.replay_run_id)
            assert job is not None and replay_run is not None

            assert batch.source_run_id == source.run_id
            assert batch.source_artifact_id == source.artifact_id
            assert batch.source_content_digest == source.content_digest
            assert batch.source_root_digest == source.integrity_root_digest
            assert item.state == ReplayItemState.QUEUED.value
            assert item.required_attempts == 2
            assert item.max_attempts == 4
            assert item.attempts == 1
            assert item.replay_run_id == ticket.replay_run_id == job.run_id
            assert ticket.state == ReplayTicketState.ISSUED.value
            assert ticket.attempt_number == ticket.fencing_value == 1
            assert ticket.compilation_digest == item.compilation_digest
            assert ticket.grant_digest == item.grant_digest
            assert job.kind == InternalJobKind.REPLAY.value
            assert job.state == JobState.QUEUED.value
            assert job.max_attempts == 1
            assert replay_run.state == RunState.QUEUED.value

            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1

        drifted = request.model_copy(update={"policy_version": "policy-v2"})
        with pytest.raises(StateConflict, match="idempot"):
            service.create_replay_batch(drifted, actor="trusted-replay-admission")
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
        assert service.get_replay_batch(first.batch.batch_id).state is (
            ReplayBatchState.CANCELLED
        )
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
