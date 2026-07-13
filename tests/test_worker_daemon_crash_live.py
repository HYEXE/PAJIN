from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from pajin.domain.manifest import load_manifest

BASE_URL = os.environ.get("PAJIN_TEST_CONTROL_PLANE_URL")
WORKER_CONTAINER = os.environ.get("PAJIN_TEST_WORKER_CRASH_CONTAINER")
pytestmark = pytest.mark.skipif(
    BASE_URL is None or WORKER_CONTAINER is None,
    reason="set Control Plane URL and an isolated Docker Worker container for crash testing",
)


def test_live_worker_crash_is_recovered_after_lease_expiry() -> None:
    assert BASE_URL is not None
    assert WORKER_CONTAINER is not None
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", WORKER_CONTAINER) is None:
        raise ValueError("invalid isolated Worker container name")
    operator = os.environ.get(
        "PAJIN_TEST_OPERATOR_TOKEN", "pajin-lab-operator-token-0000000000000001"
    )
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    target = campaign.spec.targets[0].model_copy(update={"simulation": {"seconds": 5}})
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"targets": [target]})}
    )
    auth = {"Authorization": f"Bearer {operator}"}
    worker_restarted = False

    with httpx.Client(base_url=BASE_URL, timeout=10) as client:
        submitted = client.post(
            "/v1/runs",
            headers=auth,
            json={
                "campaign_name": "daemon-crash-recovery-lab",
                "job_kind": "campaign",
                "idempotency_key": f"daemon-crash-{time.time_ns()}",
                "input": {"manifest": campaign.model_dump(mode="json", by_alias=True)},
            },
        )
        assert submitted.status_code == 200, submitted.text
        run_id = submitted.json()["run"]["run_id"]
        job_id = submitted.json()["job"]["job_id"]
        try:
            deadline = time.monotonic() + 10
            job: dict[str, object] = {}
            while time.monotonic() < deadline:
                job = client.get(f"/v1/jobs/{job_id}", headers=auth).json()
                if job.get("state") == "leased":
                    break
                time.sleep(0.1)
            assert job.get("state") == "leased", job
            assert job.get("attempts") == 1
            subprocess.run(
                ["docker", "kill", WORKER_CONTAINER],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            time.sleep(7)
            subprocess.run(
                ["docker", "start", WORKER_CONTAINER],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            worker_restarted = True
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                job = client.get(f"/v1/jobs/{job_id}", headers=auth).json()
                if job.get("state") == "succeeded":
                    break
                time.sleep(0.2)
            assert job.get("state") == "succeeded", job
            assert job.get("attempts") == 2
            assert job.get("result", {}).get("engine") == "local-campaign"
            events = client.get(f"/v1/runs/{run_id}/events", headers=auth).json()
            event_types = {event["event_type"] for event in events}
            assert "job.lease-expired-requeued" in event_types
            assert "run.completed" in event_types
        finally:
            if not worker_restarted:
                subprocess.run(
                    ["docker", "start", WORKER_CONTAINER],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
