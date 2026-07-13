from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
import pytest

from pajin.domain.manifest import load_manifest

BASE_URL = os.environ.get("PAJIN_TEST_CONTROL_PLANE_URL")
pytestmark = pytest.mark.skipif(
    BASE_URL is None,
    reason="set PAJIN_TEST_CONTROL_PLANE_URL with the Docker Worker daemon running",
)


def test_live_daemon_executes_real_tool_loop_across_durable_approval() -> None:
    assert BASE_URL is not None
    operator = os.environ.get(
        "PAJIN_TEST_OPERATOR_TOKEN", "pajin-lab-operator-token-0000000000000001"
    )
    approver = os.environ.get(
        "PAJIN_TEST_APPROVER_TOKEN", "pajin-lab-approver-token-0000000000000001"
    )
    campaign = load_manifest(Path("examples/tool-loop-approval-lab.yaml"))
    suffix = time.time_ns()

    def auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    with httpx.Client(base_url=BASE_URL, timeout=10) as client:
        submitted = client.post(
            "/v1/runs",
            headers=auth(operator),
            json={
                "campaign_name": "daemon-tool-loop-lab",
                "job_kind": "tool-loop",
                "idempotency_key": f"daemon-tool-loop-{suffix}",
                "input": {
                    "manifest": campaign.model_dump(mode="json", by_alias=True),
                    "prompt": "Request the approval-gated mock probe exactly once.",
                },
            },
        )
        assert submitted.status_code == 200, submitted.text
        run_id = submitted.json()["run"]["run_id"]
        deadline = time.monotonic() + 15
        run: dict[str, object] = {}
        while time.monotonic() < deadline:
            response = client.get(f"/v1/runs/{run_id}", headers=auth(operator))
            run = response.json()
            if run.get("state") == "awaiting-approval":
                break
            time.sleep(0.2)
        assert run.get("state") == "awaiting-approval", run
        checkpoint_id = str(run["current_checkpoint_id"])
        events = client.get(f"/v1/runs/{run_id}/events", headers=auth(operator)).json()
        approval_event = next(item for item in events if item["event_type"] == "approval.requested")
        approval_id = approval_event["payload"]["approvalId"]

        decision = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=auth(approver),
            json={"approve": True, "reason": "Docker daemon lab scope verified"},
        )
        assert decision.status_code == 200, decision.text
        resumed = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=auth(operator),
            json={"approval_id": approval_id},
        )
        assert resumed.status_code == 200, resumed.text
        continuation_job_id = resumed.json()["job"]["job_id"]

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            response = client.get(f"/v1/runs/{run_id}", headers=auth(operator))
            run = response.json()
            if run.get("state") == "completed":
                break
            time.sleep(0.2)
        assert run.get("state") == "completed", run
        job = client.get(f"/v1/jobs/{continuation_job_id}", headers=auth(operator)).json()
        assert job["state"] == "succeeded"
        assert job["result"]["engine"] == "policy-tool-loop"
        assert job["result"]["toolCalls"] == 1
