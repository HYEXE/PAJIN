from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import (
    ApprovalRecord,
    CheckpointRecord,
    EventRecord,
    JobRecord,
    RunRecord,
)
from pajin.control_plane.models import (
    ControlPlaneConflictCode,
    Principal,
    PrincipalRole,
)
from pajin.control_plane.pentest_replay import (
    PentestReplayOperatorDispatchRequest,
    PentestReplayOperatorDispatchView,
)
from pajin.control_plane.pentest_workflow import (
    PentestOperatorWorkflowRequest,
    PentestOperatorWorkflowView,
)

OPERATOR_TOKEN = "actions-operator-token-that-is-long-and-distinct"
APPROVER_TOKEN = "actions-approver-token-that-is-long-and-distinct"
AUDITOR_TOKEN = "actions-auditor-token-that-is-long-and-distinct"
WORKER_TOKEN = "actions-worker-token-that-is-long-and-distinct"


@dataclass(frozen=True)
class ApprovalWorkflow:
    run_id: str
    source_job_id: str
    checkpoint_id: str
    approval_id: str
    lease_token: str
    expires_at: datetime


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="actions-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="actions-approver",
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            AUDITOR_TOKEN: Principal(
                subject="actions-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="actions-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"actions-v1": b"actions-signing-key-that-is-at-least-32-bytes"},
        active_checkpoint_key_id="actions-v1",
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class _PentestWorkflowRuntime:
    def __init__(self) -> None:
        self.principals: list[Principal] = []

    def run(
        self,
        request: PentestOperatorWorkflowRequest,
        *,
        principal: Principal,
    ) -> PentestOperatorWorkflowView:
        self.principals.append(principal)
        return PentestOperatorWorkflowView(
            deploymentId=request.deployment_id,
            workflowId="pentest-operator-workflow-api",
            workflowDigest="a" * 64,
            status="awaiting-signed-finalization",
            controlledValidityEvidenceId="pentest-controlled-validity-api",
            controlledValidityEvidenceDigest="b" * 64,
            confirmationIntentId="pentest-confirmation-intent-api",
            confirmationIntentDigest="c" * 64,
            reportingPerformed=False,
        )


class _PentestReplayRuntime:
    def __init__(self) -> None:
        self.principals: list[Principal] = []

    async def dispatch_once(
        self,
        request: PentestReplayOperatorDispatchRequest,
        *,
        worker_scope: object,
        worker_principal: Principal,
    ) -> PentestReplayOperatorDispatchView:
        assert worker_scope is not None
        self.principals.append(worker_principal)
        return PentestReplayOperatorDispatchView(
            deploymentId=request.deployment_id,
            compilationAuthorityDigest=request.compilation_authority_digest,
            intentDigest=request.intent_digest,
            approvalId=request.approval_id,
            sourceAdmissionId="pentest-recon-discovery-admission_api",
            sourceAdmissionDigest=request.source_admission_digest,
            replayPlanId="pentest-recon-replay-plan_api",
            replayPlanDigest="b" * 64,
            replayBindingId="pentest-recon-replay-authorization_api",
            replayBindingDigest="c" * 64,
            approvalReceiptId="approval-receipt-api",
            approvalReceiptDigest="d" * 64,
            permitId="permit-api",
            permitDigest="e" * 64,
            runId="run_20260819T000000Z_1234abcd",
            dispatched=True,
            outcomeId="pentest-recon-outcome-api",
            outcomeDigest="f" * 64,
            sealedRunRootDigest="1" * 64,
        )


def test_pentest_workflow_route_requires_operator_and_returns_non_bearer_view(
    tmp_path: Path,
) -> None:
    runtime = _PentestWorkflowRuntime()
    app = create_app(
        _settings(tmp_path / "pentest-workflow-route.db"),
        pentest_workflow_runtime=runtime,
    )
    request = {
        "apiVersion": "pajin.dev/pentest-operator-workflow-request/v1alpha1",
        "kind": "PentestOperatorWorkflowRequest",
        "deploymentId": "pentest-workflow-deployment-api",
        "replayComparisonDigest": "d" * 64,
        "hypothesisId": "health-metadata-exposure",
    }
    with TestClient(app) as client:
        forbidden = client.post(
            "/v1/pentest/workflows/run",
            headers=_auth(AUDITOR_TOKEN),
            json=request,
        )
        response = client.post(
            "/v1/pentest/workflows/run",
            headers=_auth(OPERATOR_TOKEN),
            json=request,
        )

    assert forbidden.status_code == 403
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "awaiting-signed-finalization"
    assert response.json()["reportingPerformed"] is False
    assert runtime.principals == [
        Principal(
            subject="actions-operator",
            roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
        )
    ]


def test_pentest_replay_route_requires_dedicated_replay_worker(
    tmp_path: Path,
) -> None:
    runtime = _PentestReplayRuntime()
    settings = replace(
        _settings(tmp_path / "pentest-replay-route.db"),
        replay_executor_profiles={"actions-worker": frozenset({"pentest-replay"})},
    )
    app = create_app(settings, pentest_replay_runtime=runtime)
    request = {
        "apiVersion": "pajin.dev/pentest-replay-operator-dispatch-request/v1alpha1",
        "kind": "PentestReplayOperatorDispatchRequest",
        "deploymentId": "pentest-replay-deployment-api",
        "compilationAuthorityDigest": "a" * 64,
        "intentDigest": "b" * 64,
        "approvalId": "pentest-replay-approval-api",
        "sourceAdmissionDigest": "c" * 64,
    }
    with TestClient(app) as client:
        forbidden = client.post(
            "/v1/worker/pentest/replay/dispatch",
            headers=_auth(OPERATOR_TOKEN),
            json=request,
        )
        response = client.post(
            "/v1/worker/pentest/replay/dispatch",
            headers=_auth(WORKER_TOKEN),
            json=request,
        )

    assert forbidden.status_code == 403
    assert response.status_code == 200, response.text
    assert response.json()["dispatched"] is True
    assert response.json()["comparisonAuthority"] is False
    assert response.json()["executionAuthority"] is False
    assert runtime.principals == [
        Principal(
            subject="actions-worker",
            roles=frozenset({PrincipalRole.WORKER}),
        )
    ]


def _submit(client: TestClient, suffix: str) -> tuple[str, str]:
    response = client.post(
        "/v1/runs",
        headers=_auth(OPERATOR_TOKEN),
        json={
            "campaign_name": f"actions-{suffix}",
            "input": {"objective": "authorized action workflow", "suffix": suffix},
            "idempotency_key": f"actions-submission-{suffix}",
            "max_attempts": 3,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return str(body["run"]["run_id"]), str(body["job"]["job_id"])


def _claim(client: TestClient, job_id: str, *, worker_id: str = "actions-worker-1") -> str:
    response = client.post(
        "/v1/worker/jobs/claim",
        headers=_auth(WORKER_TOKEN),
        json={
            "worker_id": worker_id,
            "kinds": ["campaign"],
            "lease_seconds": 30,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job"]["job_id"] == job_id
    return str(body["lease_token"])


def _create_checkpoint(
    client: TestClient,
    job_id: str,
    lease_token: str,
    *,
    expires_at: datetime,
) -> tuple[str, str]:
    response = client.post(
        f"/v1/worker/jobs/{job_id}/checkpoints",
        headers=_auth(WORKER_TOKEN),
        json={
            "worker_id": "actions-worker-1",
            "lease_token": lease_token,
            "state": {"turn": 2, "messages": ["bounded approval state"]},
            "pending_intent": {
                "call_fingerprint": "a" * 64,
                "tool_id": "mock.approval-probe",
                "target": "lab://control-plane-actions",
                "risk_tier": 3,
                "expires_at": expires_at.isoformat(),
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return (
        str(body["checkpoint"]["checkpoint_id"]),
        str(body["approval"]["approval_id"]),
    )


def _awaiting_approval(client: TestClient, suffix: str) -> ApprovalWorkflow:
    run_id, job_id = _submit(client, suffix)
    lease_token = _claim(client, job_id)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    checkpoint_id, approval_id = _create_checkpoint(
        client,
        job_id,
        lease_token,
        expires_at=expires_at,
    )
    return ApprovalWorkflow(
        run_id=run_id,
        source_job_id=job_id,
        checkpoint_id=checkpoint_id,
        approval_id=approval_id,
        lease_token=lease_token,
        expires_at=expires_at,
    )


def _decide(
    client: TestClient,
    approval_id: str,
    *,
    approve: bool,
    reason: str,
):
    return client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=_auth(APPROVER_TOKEN),
        json={"approve": approve, "reason": reason},
    )


def _cancel(client: TestClient, run_id: str, *, reason: str = "operator requested stop"):
    return client.post(
        f"/v1/runs/{run_id}/cancel",
        headers=_auth(OPERATOR_TOKEN),
        json={"reason": reason},
    )


def _events(client: TestClient, run_id: str) -> list[dict[str, object]]:
    response = client.get(f"/v1/runs/{run_id}/events", headers=_auth(AUDITOR_TOKEN))
    assert response.status_code == 200, response.text
    return response.json()


def test_worker_conflict_contract_is_declared_in_openapi(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "worker-conflict-openapi.db"))
    with TestClient(app) as client:
        document = client.get("/openapi.json").json()

    schemas = document["components"]["schemas"]
    assert schemas["ControlPlaneConflictCode"]["enum"] == [
        ControlPlaneConflictCode.RUN_CANCELLED.value,
        ControlPlaneConflictCode.LEASE_LOST.value,
    ]
    conflict_schema = schemas["ControlPlaneConflictResponse"]
    assert conflict_schema["required"] == ["detail"]
    assert conflict_schema["properties"]["detail"]["minLength"] == 1
    assert conflict_schema["properties"]["detail"]["maxLength"] == 500
    assert "409" not in document["paths"]["/v1/worker/jobs/claim"]["post"]["responses"]
    expected_schema = {"$ref": "#/components/schemas/ControlPlaneConflictResponse"}
    for path in (
        "/v1/worker/jobs/{job_id}/heartbeat",
        "/v1/worker/jobs/{job_id}/complete",
        "/v1/worker/jobs/{job_id}/fail",
        "/v1/worker/jobs/{job_id}/checkpoints",
    ):
        conflict = document["paths"][path]["post"]["responses"]["409"]
        assert conflict["content"]["application/json"]["schema"] == expected_schema


def test_current_approval_is_nullable_minimized_and_read_role_protected(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "current-approval.db"))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, "current-approval")

        for token in (OPERATOR_TOKEN, APPROVER_TOKEN, AUDITOR_TOKEN):
            empty = client.get(f"/v1/runs/{run_id}/approval", headers=_auth(token))
            assert empty.status_code == 200
            assert empty.json() is None

        assert client.get(f"/v1/runs/{run_id}/approval").status_code == 401
        assert (
            client.get(f"/v1/runs/{run_id}/approval", headers=_auth(WORKER_TOKEN)).status_code
            == 403
        )

        lease_token = _claim(client, job_id)
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        checkpoint_id, approval_id = _create_checkpoint(
            client,
            job_id,
            lease_token,
            expires_at=expires_at,
        )

        expected_keys = {
            "approval_id",
            "run_id",
            "checkpoint_id",
            "intent",
            "state",
            "requested_by",
            "requested_at",
            "decided_by",
            "decided_at",
            "decision_reason",
            "consumed_by",
            "consumed_at",
        }
        for token in (OPERATOR_TOKEN, APPROVER_TOKEN, AUDITOR_TOKEN):
            response = client.get(f"/v1/runs/{run_id}/approval", headers=_auth(token))
            assert response.status_code == 200, response.text
            body = response.json()
            assert set(body) == expected_keys
            assert body["approval_id"] == approval_id
            assert body["run_id"] == run_id
            assert body["checkpoint_id"] == checkpoint_id
            assert body["state"] == "pending"
            assert body["intent"]["tool_id"] == "mock.approval-probe"
            assert body["intent"]["target"] == "lab://control-plane-actions"
            assert "state" not in body["intent"]
            assert "signature" not in response.text
            assert "bounded approval state" not in response.text


def test_current_approval_and_decision_reject_unsigned_field_drift(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "approval-drift.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "approval-drift")
        with app.state.repository.transaction() as session:
            session.execute(
                update(ApprovalRecord)
                .where(ApprovalRecord.approval_id == workflow.approval_id)
                .values(target="lab://tampered-approval-target")
            )

        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(APPROVER_TOKEN),
        )
        assert current.status_code == 409
        decision = _decide(
            client,
            workflow.approval_id,
            approve=True,
            reason="must not authorize unsigned field drift",
        )
        assert decision.status_code == 409
        with app.state.repository.transaction() as session:
            approval = session.scalar(
                select(ApprovalRecord).where(ApprovalRecord.approval_id == workflow.approval_id)
            )
            assert approval is not None and approval.state == "pending"


def test_cross_run_approval_ownership_drift_is_fenced(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "approval-ownership.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "approval-ownership")
        other_run_id, _other_job_id = _submit(client, "approval-ownership-other")
        with app.state.repository.transaction() as session:
            session.execute(
                update(ApprovalRecord)
                .where(ApprovalRecord.approval_id == workflow.approval_id)
                .values(run_id=other_run_id)
            )

        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(APPROVER_TOKEN),
        )
        assert current.status_code == 409
        decision = _decide(
            client,
            workflow.approval_id,
            approve=True,
            reason="must not authorize a cross-Run approval",
        )
        assert decision.status_code == 409
        resume = client.post(
            f"/v1/checkpoints/{workflow.checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": workflow.approval_id},
        )
        assert resume.status_code == 409
        run = client.get(f"/v1/runs/{workflow.run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.json()["state"] == "awaiting-approval"


def test_cancel_queued_run_is_operator_only_idempotent_and_unclaimable(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "cancel-queued.db"))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, "cancel-queued")
        request = {"reason": "queued run is no longer required"}

        assert client.post(f"/v1/runs/{run_id}/cancel", json=request).status_code == 401
        for token in (APPROVER_TOKEN, AUDITOR_TOKEN, WORKER_TOKEN):
            denied = client.post(
                f"/v1/runs/{run_id}/cancel",
                headers=_auth(token),
                json=request,
            )
            assert denied.status_code == 403

        cancelled = _cancel(client, run_id, reason=str(request["reason"]))
        assert cancelled.status_code == 200, cancelled.text
        body = cancelled.json()
        assert set(body) == {
            "run",
            "applied",
            "cancelled_job_ids",
            "revoked_approval_ids",
        }
        assert body["applied"] is True
        assert body["run"]["state"] == "cancelled"
        assert body["cancelled_job_ids"] == [job_id]
        assert body["revoked_approval_ids"] == []

        job = client.get(f"/v1/jobs/{job_id}", headers=_auth(AUDITOR_TOKEN))
        assert job.status_code == 200
        assert job.json()["state"] == "cancelled"
        claim = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={"worker_id": "actions-worker-after-cancel", "lease_seconds": 30},
        )
        assert claim.status_code == 204

        events_before = _events(client, run_id)
        repeated = _cancel(client, run_id, reason="a different repeated reason")
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["applied"] is False
        assert repeated.json()["run"]["state"] == "cancelled"
        assert _events(client, run_id) == events_before
        assert [event["event_type"] for event in events_before].count("run.cancelled") == 1


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1_001])
def test_cancel_reason_is_bounded_and_non_blank(tmp_path: Path, reason: str) -> None:
    app = create_app(_settings(tmp_path / f"cancel-reason-{len(reason)}.db"))
    with TestClient(app) as client:
        run_id, _job_id = _submit(client, f"cancel-reason-{len(reason)}")
        response = _cancel(client, run_id, reason=reason)
        assert response.status_code == 422
        run = client.get(f"/v1/runs/{run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.json()["state"] == "queued"


def test_cancel_leased_run_revokes_lease_and_rejects_stale_worker(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "cancel-leased.db"))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, "cancel-leased")
        lease_token = _claim(client, job_id)

        rejected_heartbeat = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "actions-worker-1",
                "lease_token": "invalid-lease-token-with-sufficient-length-0001",
                "lease_seconds": 30,
            },
        )
        assert rejected_heartbeat.status_code == 409
        assert rejected_heartbeat.json() == {
            "detail": "job lease token is invalid",
            "code": ControlPlaneConflictCode.LEASE_LOST.value,
        }

        cancelled = _cancel(client, run_id, reason="stop the active worker safely")
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["applied"] is True
        assert cancelled.json()["cancelled_job_ids"] == [job_id]

        with app.state.repository.transaction() as session:
            job = session.scalar(select(JobRecord).where(JobRecord.job_id == job_id))
            assert job is not None
            assert job.state == "cancelled"
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert job.lease_expires_at is None
            assert job.heartbeat_at is None

        heartbeat = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "actions-worker-1",
                "lease_token": lease_token,
                "lease_seconds": 30,
            },
        )
        assert heartbeat.status_code == 409
        assert heartbeat.json() == {
            "detail": "run has been cancelled",
            "code": ControlPlaneConflictCode.RUN_CANCELLED.value,
        }
        completion = client.post(
            f"/v1/worker/jobs/{job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "actions-worker-1",
                "lease_token": lease_token,
                "result": {"shouldNotPersist": True},
            },
        )
        assert completion.status_code == 409
        assert completion.json()["code"] == ControlPlaneConflictCode.RUN_CANCELLED.value
        failure = client.post(
            f"/v1/worker/jobs/{job_id}/fail",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "actions-worker-1",
                "lease_token": lease_token,
                "error": "must not overwrite cancellation",
                "retryable": True,
            },
        )
        assert failure.status_code == 409
        assert failure.json()["code"] == ControlPlaneConflictCode.RUN_CANCELLED.value
        checkpoint = client.post(
            f"/v1/worker/jobs/{job_id}/checkpoints",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "actions-worker-1",
                "lease_token": lease_token,
                "state": {"mustNotPersist": True},
                "pending_intent": {
                    "call_fingerprint": "b" * 64,
                    "tool_id": "mock.approval-probe",
                    "target": "lab://cancelled-worker",
                    "risk_tier": 3,
                    "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                },
            },
        )
        assert checkpoint.status_code == 409
        assert checkpoint.json()["code"] == ControlPlaneConflictCode.RUN_CANCELLED.value
        swept = client.post(
            "/v1/maintenance/requeue-expired",
            headers=_auth(OPERATOR_TOKEN),
        )
        assert swept.status_code == 200
        assert swept.json()["requeuedOrDeadLettered"] == 0
        run = client.get(f"/v1/runs/{run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.json()["state"] == "cancelled"


def test_cancel_after_approval_revokes_approval_and_blocks_resume(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "cancel-approved.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "cancel-approved")
        decision = _decide(
            client,
            workflow.approval_id,
            approve=True,
            reason="scope and target verified",
        )
        assert decision.status_code == 200, decision.text
        assert decision.json()["state"] == "approved"

        cancelled = _cancel(client, workflow.run_id, reason="authorization was withdrawn")
        assert cancelled.status_code == 200, cancelled.text
        body = cancelled.json()
        assert body["applied"] is True
        assert body["run"]["state"] == "cancelled"
        assert body["cancelled_job_ids"] == []
        assert body["revoked_approval_ids"] == [workflow.approval_id]

        approval = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(APPROVER_TOKEN),
        )
        assert approval.status_code == 200
        assert approval.json()["state"] == "revoked"
        resume = client.post(
            f"/v1/checkpoints/{workflow.checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": workflow.approval_id},
        )
        assert resume.status_code == 409

        with app.state.repository.transaction() as session:
            approval_record = session.scalar(
                select(ApprovalRecord).where(ApprovalRecord.approval_id == workflow.approval_id)
            )
            checkpoint = session.scalar(
                select(CheckpointRecord).where(
                    CheckpointRecord.checkpoint_id == workflow.checkpoint_id
                )
            )
            job_count = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.run_id == workflow.run_id)
            )
            assert approval_record is not None and approval_record.state == "revoked"
            assert checkpoint is not None and checkpoint.claimed_at is None
            assert checkpoint.continuation_job_id is None
            assert job_count == 1


def test_denial_cancels_run_and_cannot_be_resumed(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "deny.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "deny")
        denied = _decide(
            client,
            workflow.approval_id,
            approve=False,
            reason="target is outside the approved change window",
        )
        assert denied.status_code == 200, denied.text
        assert denied.json()["state"] == "denied"
        assert denied.json()["decision_reason"] == ("target is outside the approved change window")

        run = client.get(f"/v1/runs/{workflow.run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.status_code == 200
        assert run.json()["state"] == "cancelled"
        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(AUDITOR_TOKEN),
        )
        assert current.json()["state"] == "denied"

        resume = client.post(
            f"/v1/checkpoints/{workflow.checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": workflow.approval_id},
        )
        assert resume.status_code == 409
        repeated_cancel = _cancel(client, workflow.run_id, reason="already denied")
        assert repeated_cancel.status_code == 200
        assert repeated_cancel.json()["applied"] is False

        event_types = [event["event_type"] for event in _events(client, workflow.run_id)]
        assert event_types.count("approval.denied") == 1
        assert event_types.count("run.cancelled") == 1
        assert event_types.index("approval.denied") < event_types.index("run.cancelled")


def test_approval_decision_reason_is_non_blank(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "decision-reason.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "decision-reason")
        response = _decide(
            client,
            workflow.approval_id,
            approve=True,
            reason="   ",
        )
        assert response.status_code == 422
        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(AUDITOR_TOKEN),
        )
        assert current.json()["state"] == "pending"


@pytest.mark.parametrize("invalid_run_field", ["state", "current_checkpoint_id"])
def test_approval_decision_requires_current_awaiting_checkpoint(
    tmp_path: Path,
    invalid_run_field: str,
) -> None:
    app = create_app(_settings(tmp_path / f"decision-invariant-{invalid_run_field}.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, f"decision-invariant-{invalid_run_field}")
        values = (
            {"state": "queued"} if invalid_run_field == "state" else {"current_checkpoint_id": None}
        )
        with app.state.repository.transaction() as session:
            session.execute(
                update(RunRecord).where(RunRecord.run_id == workflow.run_id).values(**values)
            )

        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(AUDITOR_TOKEN),
        )
        assert current.status_code == 409
        decision = _decide(
            client,
            workflow.approval_id,
            approve=True,
            reason="must not approve stale workflow state",
        )
        assert decision.status_code == 409
        with app.state.repository.transaction() as session:
            approval = session.scalar(
                select(ApprovalRecord).where(ApprovalRecord.approval_id == workflow.approval_id)
            )
            assert approval is not None and approval.state == "pending"


@pytest.mark.parametrize("invalid_run_field", ["state", "current_checkpoint_id"])
def test_resume_requires_current_awaiting_checkpoint(
    tmp_path: Path,
    invalid_run_field: str,
) -> None:
    app = create_app(_settings(tmp_path / f"resume-invariant-{invalid_run_field}.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, f"resume-invariant-{invalid_run_field}")
        decision = _decide(
            client,
            workflow.approval_id,
            approve=True,
            reason="valid before the Run invariant is made stale",
        )
        assert decision.status_code == 200
        values = (
            {"state": "queued"} if invalid_run_field == "state" else {"current_checkpoint_id": None}
        )
        with app.state.repository.transaction() as session:
            session.execute(
                update(RunRecord).where(RunRecord.run_id == workflow.run_id).values(**values)
            )

        resume = client.post(
            f"/v1/checkpoints/{workflow.checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": workflow.approval_id},
        )
        assert resume.status_code == 409
        with app.state.repository.transaction() as session:
            approval = session.scalar(
                select(ApprovalRecord).where(ApprovalRecord.approval_id == workflow.approval_id)
            )
            checkpoint = session.scalar(
                select(CheckpointRecord).where(
                    CheckpointRecord.checkpoint_id == workflow.checkpoint_id
                )
            )
            job_count = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.run_id == workflow.run_id)
            )
            assert approval is not None and approval.state == "approved"
            assert checkpoint is not None and checkpoint.claimed_at is None
            assert checkpoint.continuation_job_id is None
            assert job_count == 1


@pytest.mark.parametrize("terminal_state", ["completed", "failed"])
def test_cancel_rejects_completed_and_failed_runs(
    tmp_path: Path,
    terminal_state: str,
) -> None:
    app = create_app(_settings(tmp_path / f"cancel-{terminal_state}.db"))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, f"terminal-{terminal_state}")
        lease_token = _claim(client, job_id)
        if terminal_state == "completed":
            finalized = client.post(
                f"/v1/worker/jobs/{job_id}/complete",
                headers=_auth(WORKER_TOKEN),
                json={
                    "worker_id": "actions-worker-1",
                    "lease_token": lease_token,
                    "result": {"validated": True},
                },
            )
        else:
            finalized = client.post(
                f"/v1/worker/jobs/{job_id}/fail",
                headers=_auth(WORKER_TOKEN),
                json={
                    "worker_id": "actions-worker-1",
                    "lease_token": lease_token,
                    "error": "non-retryable deterministic failure",
                    "retryable": False,
                },
            )
        assert finalized.status_code == 200, finalized.text
        run = client.get(f"/v1/runs/{run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.json()["state"] == terminal_state
        events_before = _events(client, run_id)

        cancelled = _cancel(client, run_id, reason="terminal state must not be overwritten")
        assert cancelled.status_code == 409
        assert _events(client, run_id) == events_before
        run_after = client.get(f"/v1/runs/{run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run_after.json()["state"] == terminal_state


def test_expired_approval_is_persisted_and_cannot_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(_settings(tmp_path / "expired-approval.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "expired-approval")
        approved = _decide(
            client,
            workflow.approval_id,
            approve=True,
            reason="approval is valid only inside its original window",
        )
        assert approved.status_code == 200, approved.text
        future = workflow.expires_at + timedelta(minutes=1)
        monkeypatch.setattr("pajin.control_plane.service.utc_now", lambda: future)

        for _attempt in range(2):
            resume = client.post(
                f"/v1/checkpoints/{workflow.checkpoint_id}/resume",
                headers=_auth(OPERATOR_TOKEN),
                json={"approval_id": workflow.approval_id},
            )
            assert resume.status_code == 409

        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(AUDITOR_TOKEN),
        )
        assert current.status_code == 200
        assert current.json()["state"] == "expired"
        with app.state.repository.transaction() as session:
            approval = session.scalar(
                select(ApprovalRecord).where(ApprovalRecord.approval_id == workflow.approval_id)
            )
            checkpoint = session.scalar(
                select(CheckpointRecord).where(
                    CheckpointRecord.checkpoint_id == workflow.checkpoint_id
                )
            )
            continuation_count = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(
                    JobRecord.run_id == workflow.run_id,
                    JobRecord.idempotency_key == f"resume:{workflow.checkpoint_id}",
                )
            )
            assert approval is not None and approval.state == "expired"
            assert checkpoint is not None and checkpoint.claimed_at is None
            assert checkpoint.continuation_job_id is None
            assert continuation_count == 0


def test_pending_approval_expiry_is_committed_before_decision_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(_settings(tmp_path / "expired-pending-approval.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "expired-pending-approval")
        future = workflow.expires_at + timedelta(minutes=1)
        monkeypatch.setattr("pajin.control_plane.service.utc_now", lambda: future)

        for _attempt in range(2):
            decision = _decide(
                client,
                workflow.approval_id,
                approve=True,
                reason="decision arrived after expiry",
            )
            assert decision.status_code == 409

        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(AUDITOR_TOKEN),
        )
        assert current.status_code == 200
        assert current.json()["state"] == "expired"
        run = client.get(f"/v1/runs/{workflow.run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.json()["state"] == "cancelled"
        event_types = [event["event_type"] for event in _events(client, workflow.run_id)]
        assert event_types.count("approval.expired") == 1
        assert event_types.count("run.cancelled") == 1


def test_pending_approval_current_read_reports_elapsed_intent_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(_settings(tmp_path / "expired-pending-approval-read.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "expired-pending-approval-read")
        future = workflow.expires_at + timedelta(minutes=1)
        monkeypatch.setattr("pajin.control_plane.service.utc_now", lambda: future)

        for token in (OPERATOR_TOKEN, APPROVER_TOKEN, AUDITOR_TOKEN):
            current = client.get(
                f"/v1/runs/{workflow.run_id}/approval",
                headers=_auth(token),
            )
            assert current.status_code == 200
            assert current.json()["state"] == "pending"
            assert datetime.fromisoformat(current.json()["intent"]["expires_at"]) < future

        run = client.get(f"/v1/runs/{workflow.run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.json()["state"] == "awaiting-approval"
        event_types = [event["event_type"] for event in _events(client, workflow.run_id)]
        assert "approval.expired" not in event_types
        assert "run.cancelled" not in event_types
        with app.state.repository.transaction() as session:
            approval = session.get(ApprovalRecord, workflow.approval_id)
            checkpoint = session.get(CheckpointRecord, workflow.checkpoint_id)
            assert approval is not None and approval.state == "pending"
            assert checkpoint is not None and checkpoint.claimed_at is None
            assert checkpoint.continuation_job_id is None


def test_pending_approval_expiry_is_atomically_committed_by_maintenance_reaper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(_settings(tmp_path / "expired-pending-approval-reaper.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "expired-pending-approval-reaper")
        future = workflow.expires_at + timedelta(minutes=1)
        monkeypatch.setattr("pajin.control_plane.service.utc_now", lambda: future)

        for _attempt in range(2):
            swept = client.post(
                "/v1/maintenance/requeue-expired",
                headers=_auth(OPERATOR_TOKEN),
            )
            assert swept.status_code == 200
            assert swept.json()["requeuedOrDeadLettered"] == 0

        current = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(AUDITOR_TOKEN),
        )
        assert current.status_code == 200
        assert current.json()["state"] == "expired"
        run = client.get(f"/v1/runs/{workflow.run_id}", headers=_auth(AUDITOR_TOKEN))
        assert run.json()["state"] == "cancelled"
        event_types = [event["event_type"] for event in _events(client, workflow.run_id)]
        assert event_types.count("approval.expired") == 1
        assert event_types.count("run.cancelled") == 1


def test_current_approval_read_does_not_append_audit_events(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "approval-read-only.db"))
    with TestClient(app) as client:
        workflow = _awaiting_approval(client, "approval-read-only")
        with app.state.repository.transaction() as session:
            count_before = session.scalar(
                select(func.count())
                .select_from(EventRecord)
                .where(EventRecord.run_id == workflow.run_id)
            )
        response = client.get(
            f"/v1/runs/{workflow.run_id}/approval",
            headers=_auth(AUDITOR_TOKEN),
        )
        assert response.status_code == 200
        with app.state.repository.transaction() as session:
            count_after = session.scalar(
                select(func.count())
                .select_from(EventRecord)
                .where(EventRecord.run_id == workflow.run_id)
            )
        assert count_after == count_before
