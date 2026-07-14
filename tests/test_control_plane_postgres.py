from __future__ import annotations

import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import DatabaseError

from pajin.control_plane.database import (
    ApprovalRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
)
from pajin.control_plane.models import (
    ApprovalIntent,
    CancelRunRequest,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    DecideApprovalRequest,
    SubmitRunRequest,
)
from pajin.control_plane.security import CheckpointIntegrityError, CheckpointSigner
from pajin.control_plane.service import ControlPlaneService, LeaseRejected, StateConflict

POSTGRES_URL = os.environ.get("PAJIN_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="set PAJIN_TEST_POSTGRES_URL to an isolated PAJIN PostgreSQL test database",
)


def _service() -> tuple[ControlPlaneRepository, ControlPlaneService]:
    assert POSTGRES_URL is not None
    repository = ControlPlaneRepository(POSTGRES_URL)
    repository.initialize()
    signer = CheckpointSigner(
        active_key_id="integration-v1",
        keys={"integration-v1": b"postgres-integration-signing-key-32-bytes-minimum"},
    )
    return repository, ControlPlaneService(repository, signer)


def test_postgres_skip_locked_approval_recovery_and_tamper_boundary() -> None:
    repository, service = _service()
    suffix = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    try:
        submitted = [
            service.submit_run(
                SubmitRunRequest(
                    campaign_name="postgres-control-plane",
                    input={"slot": slot},
                    idempotency_key=f"postgres-{suffix}-{slot}",
                ),
                actor="integration-operator",
            )
            for slot in (1, 2)
        ]
        assert len({item.run.run_id for item in submitted}) == 2

        def claim(worker_id: str) -> object:
            return service.claim_job(
                ClaimJobRequest(worker_id=worker_id, lease_seconds=30),
                actor="integration-worker-service",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(claim, ["pg-worker-1", "pg-worker-2"]))
        assert all(item is not None for item in claims)
        first, second = claims
        assert first is not None and second is not None
        assert first.job.job_id != second.job.job_id

        created = service.create_checkpoint(
            first.job.job_id,
            CreateCheckpointRequest(
                worker_id="pg-worker-1",
                lease_token=first.lease_token,
                state={"turn": 2, "source": "postgres"},
                pending_intent=ApprovalIntent(
                    call_fingerprint="c" * 64,
                    tool_id="mock.approval-probe",
                    target="lab://postgres-approval",
                    risk_tier=3,
                    expires_at=datetime.now(UTC) + timedelta(minutes=5),
                ),
            ),
            actor="integration-worker-service",
        )
        decided = service.decide_approval(
            created.approval.approval_id,
            DecideApprovalRequest(approve=True, reason="integration scope verified"),
            actor="integration-approver",
        )
        assert decided.decided_by == "integration-approver"
        resumed = service.resume_checkpoint(
            created.checkpoint.checkpoint_id,
            created.approval.approval_id,
            actor="integration-operator",
        )
        with pytest.raises(StateConflict, match="already been claimed"):
            service.resume_checkpoint(
                created.checkpoint.checkpoint_id,
                created.approval.approval_id,
                actor="integration-operator",
            )
        continuation = service.claim_job(
            ClaimJobRequest(worker_id="pg-worker-3", lease_seconds=30),
            actor="integration-worker-service",
        )
        assert continuation is not None
        assert continuation.job.job_id == resumed.job.job_id
        completed = service.complete_job(
            continuation.job.job_id,
            CompleteJobRequest(
                worker_id="pg-worker-3",
                lease_token=continuation.lease_token,
                result={"validated": True},
            ),
            actor="integration-worker-service",
        )
        assert completed.state.value == "succeeded"

        service.complete_job(
            second.job.job_id,
            CompleteJobRequest(
                worker_id="pg-worker-2",
                lease_token=second.lease_token,
                result={"validated": True},
            ),
            actor="integration-worker-service",
        )

        recovery_submission = service.submit_run(
            SubmitRunRequest(
                campaign_name="postgres-control-plane",
                input={"crashRecovery": True},
                idempotency_key=f"postgres-{suffix}-recovery",
            ),
            actor="integration-operator",
        )
        crashed = service.claim_job(
            ClaimJobRequest(worker_id="pg-worker-crashed", lease_seconds=30),
            actor="integration-worker-service",
        )
        assert crashed is not None
        assert crashed.job.job_id == recovery_submission.job.job_id
        with repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == crashed.job.job_id)
                .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
        assert service.requeue_expired(actor="integration-operator") == 1
        recovered = service.claim_job(
            ClaimJobRequest(worker_id="pg-worker-recovered", lease_seconds=30),
            actor="integration-worker-service",
        )
        assert recovered is not None
        assert recovered.job.job_id == crashed.job.job_id
        assert recovered.job.attempts == 2
        assert recovered.lease_token != crashed.lease_token
        service.complete_job(
            recovered.job.job_id,
            CompleteJobRequest(
                worker_id="pg-worker-recovered",
                lease_token=recovered.lease_token,
                result={"recovered": True},
            ),
            actor="integration-worker-service",
        )

        tamper_submission = service.submit_run(
            SubmitRunRequest(
                campaign_name="postgres-control-plane",
                input={"tamper": True},
                idempotency_key=f"postgres-{suffix}-tamper",
            ),
            actor="integration-operator",
        )
        tamper_claim = service.claim_job(
            ClaimJobRequest(worker_id="pg-worker-tamper", lease_seconds=30),
            actor="integration-worker-service",
        )
        assert tamper_claim is not None
        assert tamper_claim.job.job_id == tamper_submission.job.job_id
        tamper_checkpoint = service.create_checkpoint(
            tamper_claim.job.job_id,
            CreateCheckpointRequest(
                worker_id="pg-worker-tamper",
                lease_token=tamper_claim.lease_token,
                state={"turn": 1},
                pending_intent=ApprovalIntent(
                    call_fingerprint="d" * 64,
                    tool_id="mock.approval-probe",
                    target="lab://tamper",
                    risk_tier=4,
                    expires_at=datetime.now(UTC) + timedelta(minutes=5),
                ),
            ),
            actor="integration-worker-service",
        )
        service.decide_approval(
            tamper_checkpoint.approval.approval_id,
            DecideApprovalRequest(approve=True, reason="test tamper detection"),
            actor="integration-approver",
        )
        with repository.transaction() as session:
            record = session.scalar(
                select(CheckpointRecord).where(
                    CheckpointRecord.checkpoint_id == tamper_checkpoint.checkpoint.checkpoint_id
                )
            )
            assert record is not None
            record.payload = {**record.payload, "state": {"tampered": True}}
        with pytest.raises(CheckpointIntegrityError):
            service.resume_checkpoint(
                tamper_checkpoint.checkpoint.checkpoint_id,
                tamper_checkpoint.approval.approval_id,
                actor="integration-operator",
            )
        with (
            pytest.raises(DatabaseError, match="append-only"),
            repository.transaction() as session,
        ):
            event = session.scalar(
                select(EventRecord)
                .where(EventRecord.run_id == tamper_submission.run.run_id)
                .limit(1)
            )
            assert event is not None
            event.event_type = "event.tampered"
    finally:
        repository.close()


def test_postgres_cancel_and_complete_have_one_terminal_winner() -> None:
    repository, service = _service()
    suffix = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    try:
        submission = service.submit_run(
            SubmitRunRequest(
                campaign_name="postgres-cancel-complete",
                input={"race": "cancel-complete"},
                idempotency_key=f"postgres-{suffix}-cancel-complete",
            ),
            actor="integration-operator",
        )
        claimed = service.claim_job(
            ClaimJobRequest(worker_id="pg-race-worker", lease_seconds=30),
            actor="integration-worker-service",
        )
        assert claimed is not None
        barrier = Barrier(2)

        def cancel() -> object:
            barrier.wait()
            return service.cancel_run(
                submission.run.run_id,
                CancelRunRequest(reason="concurrent operator cancellation"),
                actor="integration-operator",
            )

        def complete() -> object:
            barrier.wait()
            return service.complete_job(
                claimed.job.job_id,
                CompleteJobRequest(
                    worker_id="pg-race-worker",
                    lease_token=claimed.lease_token,
                    result={"race": "completed"},
                ),
                actor="integration-worker-service",
            )

        def capture(action: Callable[[], object]) -> tuple[str, object]:
            try:
                return "ok", action()
            except (LeaseRejected, StateConflict) as exc:
                return "conflict", exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            cancel_future = pool.submit(capture, cancel)
            complete_future = pool.submit(capture, complete)
            outcomes = [cancel_future.result(timeout=15), complete_future.result(timeout=15)]

        assert sorted(status for status, _result in outcomes) == ["conflict", "ok"]
        run = service.get_run(submission.run.run_id)
        job = service.get_job(claimed.job.job_id)
        if run.state.value == "cancelled":
            assert job.state.value == "cancelled"
        else:
            assert run.state.value == "completed"
            assert job.state.value == "succeeded"
        terminal_events = [
            event.event_type
            for event in service.list_events(run.run_id)
            if event.event_type in {"run.cancelled", "run.completed"}
        ]
        assert len(terminal_events) == 1
    finally:
        repository.close()


def test_postgres_cancel_fences_concurrent_checkpoint_resume() -> None:
    repository, service = _service()
    suffix = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    try:
        submission = service.submit_run(
            SubmitRunRequest(
                campaign_name="postgres-cancel-resume",
                input={"race": "cancel-resume"},
                idempotency_key=f"postgres-{suffix}-cancel-resume",
            ),
            actor="integration-operator",
        )
        claimed = service.claim_job(
            ClaimJobRequest(worker_id="pg-resume-worker", lease_seconds=30),
            actor="integration-worker-service",
        )
        assert claimed is not None
        created = service.create_checkpoint(
            claimed.job.job_id,
            CreateCheckpointRequest(
                worker_id="pg-resume-worker",
                lease_token=claimed.lease_token,
                state={"race": "cancel-resume"},
                pending_intent=ApprovalIntent(
                    call_fingerprint="e" * 64,
                    tool_id="mock.approval-probe",
                    target="lab://postgres-cancel-resume",
                    risk_tier=3,
                    expires_at=datetime.now(UTC) + timedelta(minutes=5),
                ),
            ),
            actor="integration-worker-service",
        )
        service.decide_approval(
            created.approval.approval_id,
            DecideApprovalRequest(approve=True, reason="race fixture approved"),
            actor="integration-approver",
        )
        barrier = Barrier(2)

        def cancel() -> object:
            barrier.wait()
            return service.cancel_run(
                submission.run.run_id,
                CancelRunRequest(reason="cancel while resume competes"),
                actor="integration-operator",
            )

        def resume() -> object:
            barrier.wait()
            return service.resume_checkpoint(
                created.checkpoint.checkpoint_id,
                created.approval.approval_id,
                actor="integration-operator",
            )

        def capture(action: Callable[[], object]) -> tuple[str, object]:
            try:
                return "ok", action()
            except StateConflict as exc:
                return "conflict", exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            cancel_future = pool.submit(capture, cancel)
            resume_future = pool.submit(capture, resume)
            outcomes = [cancel_future.result(timeout=15), resume_future.result(timeout=15)]

        assert outcomes[0][0] == "ok"
        assert outcomes[1][0] in {"ok", "conflict"}
        assert service.get_run(submission.run.run_id).state.value == "cancelled"
        with repository.transaction() as session:
            approval = session.scalar(
                select(ApprovalRecord).where(
                    ApprovalRecord.approval_id == created.approval.approval_id
                )
            )
            checkpoint = session.scalar(
                select(CheckpointRecord).where(
                    CheckpointRecord.checkpoint_id == created.checkpoint.checkpoint_id
                )
            )
            active_jobs = session.scalars(
                select(JobRecord).where(
                    JobRecord.run_id == submission.run.run_id,
                    JobRecord.state.in_({"queued", "leased"}),
                )
            ).all()
            assert approval is not None and approval.state in {"consumed", "revoked"}
            assert checkpoint is not None
            if approval.state == "consumed":
                assert checkpoint.claimed_at is not None
                assert checkpoint.continuation_job_id is not None
            else:
                assert checkpoint.claimed_at is None
                assert checkpoint.continuation_job_id is None
            assert not active_jobs
        assert [
            event.event_type for event in service.list_events(submission.run.run_id)
        ].count("run.cancelled") == 1
    finally:
        repository.close()
