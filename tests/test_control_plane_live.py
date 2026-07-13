from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

BASE_URL = os.environ.get("PAJIN_TEST_CONTROL_PLANE_URL")
pytestmark = pytest.mark.skipif(
    BASE_URL is None,
    reason="set PAJIN_TEST_CONTROL_PLANE_URL to an isolated PAJIN Control Plane",
)


def test_live_control_plane_submit_approve_resume_complete() -> None:
    assert BASE_URL is not None
    tokens = {
        "operator": os.environ.get(
            "PAJIN_TEST_OPERATOR_TOKEN", "pajin-lab-operator-token-0000000000000001"
        ),
        "approver": os.environ.get(
            "PAJIN_TEST_APPROVER_TOKEN", "pajin-lab-approver-token-0000000000000001"
        ),
        "worker": os.environ.get(
            "PAJIN_TEST_WORKER_TOKEN", "pajin-lab-worker-token-000000000000000001"
        ),
    }

    def headers(role: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {tokens[role]}"}

    suffix = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    with httpx.Client(base_url=BASE_URL, timeout=10) as client:
        submitted = client.post(
            "/v1/runs",
            headers=headers("operator"),
            json={
                "campaign_name": "live-control-plane",
                "input": {"source": "docker-http"},
                "idempotency_key": f"live-{suffix}",
            },
        )
        assert submitted.status_code == 200, submitted.text
        run_id = submitted.json()["run"]["run_id"]
        job_id = submitted.json()["job"]["job_id"]

        claimed = client.post(
            "/v1/worker/jobs/claim",
            headers=headers("worker"),
            json={"worker_id": "live-worker-1", "lease_seconds": 30},
        )
        assert claimed.status_code == 200, claimed.text
        assert claimed.json()["job"]["job_id"] == job_id
        lease_token = claimed.json()["lease_token"]
        heartbeat = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=headers("worker"),
            json={
                "worker_id": "live-worker-1",
                "lease_token": lease_token,
                "lease_seconds": 45,
            },
        )
        assert heartbeat.status_code == 200

        checkpoint = client.post(
            f"/v1/worker/jobs/{job_id}/checkpoints",
            headers=headers("worker"),
            json={
                "worker_id": "live-worker-1",
                "lease_token": lease_token,
                "state": {"turn": 3},
                "pending_intent": {
                    "call_fingerprint": "e" * 64,
                    "tool_id": "mock.approval-probe",
                    "target": "lab://live-http",
                    "risk_tier": 3,
                    "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                },
            },
        )
        assert checkpoint.status_code == 200, checkpoint.text
        checkpoint_id = checkpoint.json()["checkpoint"]["checkpoint_id"]
        approval_id = checkpoint.json()["approval"]["approval_id"]

        denied_role = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=headers("operator"),
            json={"approve": True, "reason": "must be denied by role"},
        )
        assert denied_role.status_code == 403
        decision = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=headers("approver"),
            json={"approve": True, "reason": "live lab scope verified"},
        )
        assert decision.status_code == 200, decision.text
        resumed = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=headers("operator"),
            json={"approval_id": approval_id},
        )
        assert resumed.status_code == 200, resumed.text
        continuation_id = resumed.json()["job"]["job_id"]

        continuation = client.post(
            "/v1/worker/jobs/claim",
            headers=headers("worker"),
            json={"worker_id": "live-worker-2", "lease_seconds": 30},
        )
        assert continuation.status_code == 200, continuation.text
        assert continuation.json()["job"]["job_id"] == continuation_id
        completed = client.post(
            f"/v1/worker/jobs/{continuation_id}/complete",
            headers=headers("worker"),
            json={
                "worker_id": "live-worker-2",
                "lease_token": continuation.json()["lease_token"],
                "result": {"validated": True},
            },
        )
        assert completed.status_code == 200, completed.text
        run = client.get(f"/v1/runs/{run_id}", headers=headers("operator"))
        assert run.json()["state"] == "completed"
