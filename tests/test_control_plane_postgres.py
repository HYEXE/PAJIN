from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import DatabaseError

from pajin.control_plane.database import (
    CheckpointRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
)
from pajin.control_plane.models import (
    ApprovalIntent,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    DecideApprovalRequest,
    SubmitRunRequest,
)
from pajin.control_plane.security import CheckpointIntegrityError, CheckpointSigner
from pajin.control_plane.service import ControlPlaneService, StateConflict

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
