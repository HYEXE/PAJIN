"""Owned Linux OPS-003 fixture. The Tool Loop payload is explicitly deterministic."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import httpx
from operational_linux_probe import CONTROL, ORIGIN, STATE, serve, tls_context
from operational_postgres_probe import owned_url
from test_control_plane_checkpoint_recovery import (
    _APPROVER_TOKEN,
    _OPERATOR_TOKEN,
    _WORKER_TOKEN,
    _auth,
)
from test_graph_sqlite_store import (
    CAMPAIGN,
    DIGEST_B,
    NOW,
    SNAPSHOT_CREATOR_ID,
    _seeded_store,
)

from pajin.control_plane.client import ControlPlaneClient
from pajin.control_plane.database import (
    ControlPlaneRepository,
    RunRecord,
)
from pajin.control_plane.executors import CampaignJobInput, ExecutorRegistry, ToolLoopJobExecutor
from pajin.control_plane.run_budgets import RunBudgetRegistry
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig
from pajin.domain.manifest import load_manifest
from pajin.graph import GraphProjectionCoordinator, GraphSnapshotAuthority, GraphSnapshotReason
from pajin.runtime.budget_state import parse_budget_checkpoint
from pajin.runtime.store import verify_run_integrity
from pajin.supervision.run_binding import stored_run_binding


async def worker() -> None:
    async with ControlPlaneClient(
        base_url=ORIGIN,
        bearer_token=_WORKER_TOKEN,
        tls_ca_file=str(CONTROL / "api/server.crt"),
        tls_client_cert_file=str(CONTROL / "api/worker.crt"),
        tls_client_key_file=str(CONTROL / "api/worker.key"),
    ) as client:
        daemon = WorkerDaemon(
            client=client,
            executors=ExecutorRegistry(
                [
                    ToolLoopJobExecutor(
                        output_root=STATE / "runs",
                        budget_registry=RunBudgetRegistry(STATE / "budgets"),
                    ),
                ]
            ),
            config=WorkerDaemonConfig(
                worker_id="recovery-worker",
                kinds=["tool-loop"],
                lease_seconds=30,
                heartbeat_seconds=0.2,
                long_poll_seconds=0,
            ),
        )
        assert await daemon.run_once()


@contextmanager
def server():
    with Path("/evidence/server-v2.log").open("ab") as log:
        child = subprocess.Popen([sys.executable, __file__, "serve"], stdout=log, stderr=log)
        try:
            with httpx.Client(
                base_url=ORIGIN, verify=tls_context(), trust_env=False, timeout=2
            ) as client:
                deadline = time.monotonic() + 60
                while True:
                    if child.poll() is not None:
                        raise RuntimeError("owned API process failed during startup")
                    try:
                        if client.get("/healthz").status_code == 200:
                            break
                    except httpx.ConnectError:
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("owned API readiness exceeded 60 seconds")
                    time.sleep(0.2)
                yield client
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def dispatch_worker():
    identity = os.environ["PAJIN_OPS003_WORKER_CONTAINER"]
    result = subprocess.run(
        ["docker", "exec", identity, "python", __file__, "worker"], capture_output=True, timeout=60
    )
    assert result.returncode == 0, result.stderr


def ready():
    deadline = time.monotonic() + 60
    with httpx.Client(base_url=ORIGIN, verify=tls_context(), trust_env=False, timeout=2) as client:
        while True:
            try:
                if client.get("/healthz").status_code == 200:
                    return
            except httpx.ConnectError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("restored API readiness exceeded 60 seconds")
            time.sleep(0.2)


def uncertain_call(client, campaign):
    value = CampaignJobInput(manifest=campaign).model_dump(mode="json")
    submitted = client.post(
        "/v1/runs",
        headers=_auth(_OPERATOR_TOKEN),
        json={
            "campaign_name": campaign.metadata.name,
            "job_kind": "campaign",
            "idempotency_key": "owned-uncertain-reservation",
            "input": value,
        },
    )
    assert submitted.status_code == 200, submitted.text
    claimed = client.post(
        "/v1/worker/jobs/claim",
        headers=_auth(_WORKER_TOKEN),
        json={
            "worker_id": "lost-worker",
            "kinds": ["campaign"],
            "lease_seconds": 300,
        },
    )
    assert claimed.status_code == 200, claimed.text
    job = claimed.json()["job"]
    # Lose the process after a conservative durable call reservation. There is no
    # acknowledged result, no recreated success evidence and no refund at restoration.
    script = """
import json, os, sys
from pathlib import Path
from pajin.control_plane.executors import CampaignJobInput
from pajin.control_plane.models import JobView
from pajin.control_plane.run_budgets import RunBudgetRegistry
job = JobView.model_validate(json.load(sys.stdin))
inputs = CampaignJobInput.model_validate(job.payload['input'])
budget = RunBudgetRegistry(Path('/state/host/budgets')).bind(
    job, inputs.manifest, original_input=inputs,
)
budget.reserve_tool_usage()
os._exit(23)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps(job).encode(),
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 23, result.stderr
    return job["run_id"]


def seed() -> None:
    STATE.mkdir(mode=0o700)
    graph, _ = _seeded_store(STATE / "graph.sqlite3")
    GraphProjectionCoordinator(
        event_log=graph.event_log,
        projection_store=graph.projection_store,
    ).refresh()
    GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_B,
        projection_store=graph.projection_store,
        snapshot_store=graph.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    campaign = load_manifest(Path("examples/tool-loop-approval-lab.yaml"))
    campaign = campaign.model_copy(
        update={
            "spec": campaign.spec.model_copy(
                update={
                    "budgets": campaign.spec.budgets.model_copy(update={"duration_seconds": 3600}),
                }
            )
        }
    )
    with server() as client:
        assert client.get("/v1/runs").status_code == 401
        submitted = client.post(
            "/v1/runs",
            headers=_auth(_OPERATOR_TOKEN),
            json={
                "campaign_name": campaign.metadata.name,
                "job_kind": "tool-loop",
                "idempotency_key": "owned-hybrid-tool-loop",
                "input": {
                    "manifest": campaign.model_dump(mode="json", by_alias=True),
                    "prompt": "Request the approval-gated mock probe exactly once.",
                },
            },
        )
        assert submitted.status_code == 200, submitted.text
        run_id = submitted.json()["run"]["run_id"]
        dispatch_worker()
        run = client.get(f"/v1/runs/{run_id}", headers=_auth(_OPERATOR_TOKEN)).json()
        assert run["state"] == "awaiting-approval", run
        events = client.get(f"/v1/runs/{run_id}/events", headers=_auth(_OPERATOR_TOKEN)).json()
        event = next(e for e in events if e["event_type"] == "approval.requested")
        state = dict(
            run_id=run_id,
            checkpoint_id=run["current_checkpoint_id"],
            approval_id=event["payload"]["approvalId"],
        )
        denied = client.post(
            f"/v1/checkpoints/{state['checkpoint_id']}/resume",
            headers=_auth(_OPERATOR_TOKEN),
            json={"approval_id": state["approval_id"]},
        )
        assert denied.status_code == 409
        state["uncertain_run"] = uncertain_call(client, campaign)
    journals = []
    for path in sorted((STATE / "budgets").glob("*.sqlite3")):
        with sqlite3.connect(path) as db:
            db.row_factory = sqlite3.Row
            binding = stored_run_binding(db)
            assert binding is not None
        journals.append(
            dict(path=path.relative_to(STATE).as_posix(), binding=binding.model_dump(mode="json"))
        )
    runs = []
    for path in sorted((STATE / "runs").rglob("run_*")):
        if path.is_dir():
            verified = verify_run_integrity(path)
            runs.append(dict(path=path.relative_to(STATE).as_posix(), run_id=verified.run_id))
    state.update(
        graphs=[dict(path="graph.sqlite3", campaign_id=CAMPAIGN)],
        journals=journals,
        runs=runs,
        system=platform.system(),
        machine=platform.machine(),
        python=platform.python_version(),
    )
    (Path("/evidence") / "seed.json").write_text(json.dumps(state))
    print("created actual TLS/mTLS checkpoint and abrupt unacknowledged call reservation")


def approve() -> None:
    import httpx

    state = json.loads(sys.stdin.read())
    with httpx.Client(base_url=ORIGIN, verify=tls_context(), trust_env=False) as client:
        path = f"/v1/approvals/{state['approval_id']}/decision"
        assert (
            client.post(
                path,
                headers=_auth(_OPERATOR_TOKEN),
                json={
                    "approve": True,
                    "reason": "role boundary negative check",
                },
            ).status_code
            == 403
        )
        decision = client.post(
            path,
            headers=_auth(_APPROVER_TOKEN),
            json={
                "approve": True,
                "reason": "isolated recovery verified by operator",
            },
        )
        assert decision.status_code == 200, decision.text


def finish() -> None:
    import httpx

    state = json.loads(sys.stdin.read())
    dispatch_worker()
    with httpx.Client(base_url=ORIGIN, verify=tls_context(), trust_env=False) as client:
        run = client.get(f"/v1/runs/{state['run_id']}", headers=_auth(_OPERATOR_TOKEN)).json()
        assert run["state"] == "completed", run
        repeated = client.post(
            f"/v1/checkpoints/{state['checkpoint_id']}/resume",
            headers=_auth(_OPERATOR_TOKEN),
            json={"approval_id": state["approval_id"]},
        )
        assert repeated.status_code == 409
    repository = ControlPlaneRepository(owned_url())
    try:
        with repository.read_transaction() as session:
            assert session.get(RunRecord, state["uncertain_run"]).current_checkpoint_id is None
    finally:
        repository.close()
    journal = STATE / "budgets" / (sha256(state["uncertain_run"].encode()).hexdigest() + ".sqlite3")
    with sqlite3.connect(journal) as db:
        row = db.execute(
            "SELECT payload FROM supervisor_budget_checkpoints ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        assert parse_budget_checkpoint(row[0]).usage.tool_calls == 1
    verified = [verify_run_integrity(p) for p in (STATE / "runs").rglob("run_*") if p.is_dir()]
    assert len(verified) == 2
    print(
        json.dumps(
            {
                "approved_continuation_completed": True,
                "sealed_runs": len(verified),
                "unacknowledged_call_charge": 1,
                "payload": "deterministic-fixture",
            }
        )
    )


if __name__ == "__main__":
    assert os.environ.get("PAJIN_OPS002_OWNED") == "1"
    assert platform.system() == "Linux"
    {
        "seed": seed,
        "approve": approve,
        "finish": finish,
        "serve": lambda: serve("v2"),
        "worker": lambda: asyncio.run(worker()),
        "ready": ready,
    }[sys.argv[1]]()
