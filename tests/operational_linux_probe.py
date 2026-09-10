"""Explicit selected-configuration probe, run only inside the owned Linux controller."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import uvicorn
from cryptography import x509
from fastapi.testclient import TestClient
from operational_postgres_probe import ObservedDockerWorker, containers, fingerprint, owned_url
from sqlalchemy import create_engine, select
from test_control_plane_checkpoint_recovery import _OPERATOR_TOKEN, _auth, _checkpoint
from test_control_plane_checkpoint_recovery import _settings as checkpoint_settings
from test_control_plane_replay_postgres import (
    EXECUTOR_PROFILE,
    WORKER_A,
    _permit_request,
    _seed_batch,
    _service,
)
from test_urgent_stop_runtime import (
    NOW,
    WORKER_TOKEN,
    _alerts,
    _deployment,
    _runtime,
    _scenario,
    _submit,
)

from pajin.control_plane.api import create_app
from pajin.control_plane.client import ControlPlaneClient, ControlPlaneRunCancelled
from pajin.control_plane.database import (
    ControlPlaneRepository,
    EventRecord,
    ReplayBudgetAccountRecord,
    ReplayToolPermitRecord,
    RunRecord,
)
from pajin.control_plane.executors import CampaignJobExecutor, ExecutorRegistry
from pajin.control_plane.models import ReplayClaimRequest
from pajin.control_plane.run_budgets import RunBudgetRegistry
from pajin.control_plane.stop_observations import STOP_OBSERVATION_EVENT, load_stop_observation
from pajin.control_plane.tls_protocol import WorkerMTLSH11Protocol
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSTrustPolicy,
    certificate_spki_sha256,
)
from pajin.domain.manifest import load_manifest
from pajin.graph.sqlite_store import SQLiteGraphStore, load_verified_current_graph_snapshot
from pajin.runtime.budget_persistence import _verified_history
from pajin.runtime.budget_state import BudgetScope
from pajin.runtime.control import BudgetController, BudgetExceeded
from pajin.runtime.store import verify_run_integrity
from pajin.supervision.invocation_journal import SupervisorInvocationJournal
from pajin.supervision.run_binding import stored_run_binding
from scripts.operations_cold_checkpoint import ColdFiles, collect, encode, restore

STATE = Path("/state/host")
EVIDENCE = Path("/evidence")
CONTROL = Path("/control")
ORIGIN = "https://127.0.0.1:8443"


def campaign():
    return load_manifest(Path("examples/multi-agent-cancel.yaml"))


def settings(rotation="v2"):
    initial, _, _ = _deployment(STATE, campaign())
    keys = json.loads((CONTROL / "keys.json").read_text())
    keyring = {"v1": bytes.fromhex(keys["v1"])}
    if rotation != "v1":
        keyring["v2"] = bytes.fromhex(keys["v2"])
    if rotation == "wrong":
        keyring["v1"] = b"incorrect-isolated-key-rebinding-0000"
    if rotation == "missing":
        del keyring["v1"]
    return replace(
        initial,
        database_url=owned_url(),
        credentials={**initial.credentials, **checkpoint_settings(STATE).credentials},
        checkpoint_keys=keyring,
        active_checkpoint_key_id="v1" if rotation == "v1" else "v2",
        worker_mtls_trust_policy=WorkerMTLSTrustPolicy(
            policy_id="worker-mtls-policy_0123456789abcdef0123456789abcdef",
            bindings=tuple(
                WorkerCertificateBinding(
                    principal_subject=subject,
                    certificate_spki_sha256=certificate_spki_sha256(
                        x509.load_pem_x509_certificate((CONTROL / "api/worker.crt").read_bytes()),
                    ),
                )
                for subject in ("worker-service", "worker")
            ),
        ),
    )


def tls_context(*, worker=True):
    context = ssl.create_default_context(cafile=str(CONTROL / "api/server.crt"))
    if worker:
        context.load_cert_chain(str(CONTROL / "api/worker.crt"), str(CONTROL / "api/worker.key"))
    return context


def serve(rotation):
    uvicorn.run(
        create_app(settings(rotation)),
        host="127.0.0.1",
        port=8443,
        ssl_certfile=str(CONTROL / "api/server.crt"),
        ssl_keyfile=str(CONTROL / "api/server.key"),
        proxy_headers=False,
        access_log=False,
        server_header=False,
        http=WorkerMTLSH11Protocol,
        ssl_cert_reqs=ssl.CERT_OPTIONAL,
        ssl_ca_certs=str(CONTROL / "api/server.crt"),
    )


@contextmanager
def server(rotation="v2"):
    with (EVIDENCE / f"server-{rotation}.log").open("ab") as log:
        child = subprocess.Popen(
            [sys.executable, __file__, "server", rotation],
            stdout=log,
            stderr=log,
        )
        try:
            with httpx.Client(
                base_url=ORIGIN, verify=tls_context(), trust_env=False, timeout=2
            ) as c:
                for attempt in range(60):
                    if child.poll() is not None:
                        raise RuntimeError("Linux API startup failed; inspect private server log")
                    try:
                        if c.get("/healthz").status_code == 200:
                            break
                    except httpx.ConnectError:
                        pass
                    if attempt == 59:
                        raise TimeoutError("Linux API did not become ready")
                    time.sleep(0.1)
                yield c
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


async def urgent_worker(client, producer, graph):
    manifest = campaign()
    _, body, digest = _deployment(STATE, manifest)
    scenario = _scenario(STATE, manifest, durable_store=graph)
    run_id = _submit(client, body)
    runtime, observation = _runtime(producer, manifest, digest, run_id, scenario)
    worker = ObservedDockerWorker(os.environ["PAJIN_OPS002_WORKER_IMAGE"])
    output = STATE / "execution"
    async with ControlPlaneClient(
        base_url=ORIGIN,
        bearer_token=WORKER_TOKEN,
        tls_ca_file=str(CONTROL / "api/server.crt"),
        tls_client_cert_file=str(CONTROL / "api/worker.crt"),
        tls_client_key_file=str(CONTROL / "api/worker.key"),
    ) as control:
        daemon = WorkerDaemon(
            client=control,
            stop_reporter=control,
            executors=ExecutorRegistry(
                [
                    CampaignJobExecutor(
                        output_root=output,
                        worker=worker,
                        budget_registry=RunBudgetRegistry(STATE / "budgets"),
                    )
                ]
            ),
            config=WorkerDaemonConfig(
                worker_id="worker-test",
                kinds=["campaign"],
                lease_seconds=30,
                heartbeat_seconds=0.1,
                long_poll_seconds=0,
                cancellation_grace_seconds=2,
            ),
        )
        task = asyncio.create_task(daemon.run_once())
        try:
            await asyncio.wait_for(worker.started.wait(), 15)
            for _ in range(60):
                observed = await asyncio.to_thread(containers, worker.execution_id)
                if observed:
                    break
                await asyncio.sleep(0.1)
            assert len(observed) == 1
            details = json.loads(
                subprocess.run(
                    ["docker", "inspect", observed[0]],
                    capture_output=True,
                    check=True,
                    timeout=10,
                ).stdout
            )[0]
            assert details["State"]["Running"] is True
            assert details["Image"] == os.environ["PAJIN_OPS002_WORKER_IMAGE"]
            assert details["HostConfig"]["NetworkMode"] == "none"
            runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
            with pytest.raises(ControlPlaneRunCancelled):
                await asyncio.wait_for(task, 30)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    assert containers(worker.execution_id) == []
    alert = _alerts(client)["items"][0]
    assert alert["fencedWorkers"] == alert["observedWorkers"] == alert["quiescedWorkers"] == 1
    assert alert["incompleteWorkers"] == 0
    run_path = next((output / manifest.metadata.name).glob("run_*"))
    assert verify_run_integrity(run_path).seal_count == 2
    with producer.app.state.repository.read_transaction() as session:
        rows = list(
            session.scalars(
                select(EventRecord).where(
                    EventRecord.run_id == run_id,
                    EventRecord.event_type == STOP_OBSERVATION_EVENT,
                )
            )
        )
        assert len(rows) == 1
        report = load_stop_observation(rows[0]).report
        assert report.resource_cleanup_verified is False
        assert report.execution_authorized is False and report.resume_authorized is False
    return {
        "run_id": run_id,
        "execution_id": worker.execution_id,
        "alert": alert,
        "worker_report": report.model_dump(mode="json", by_alias=True),
        "resource_cleanup": "observed-container-absent",
        "external_rollback": "unknown",
    }


def rejected_keys(rotation):
    with (EVIDENCE / f"server-{rotation}.log").open("wb") as log:
        result = subprocess.run(
            [sys.executable, __file__, "server", rotation],
            stdout=log,
            stderr=log,
            timeout=20,
            check=False,
        )
    assert result.returncode != 0


def seed():
    STATE.mkdir(mode=0o700)
    engine = create_engine(owned_url())
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    engine.dispose()
    graph = SQLiteGraphStore(STATE / "graph.sqlite3", campaign_id=campaign().metadata.name)
    with server("v1") as client, TestClient(create_app(settings("v1"))) as producer:
        assert client.get("/v1/runs").status_code == 401
        with httpx.Client(verify=tls_context(worker=False), trust_env=False) as unauthenticated:
            denied = unauthenticated.post(
                ORIGIN + "/v1/worker/jobs/claim",
                headers={"Authorization": f"Bearer {WORKER_TOKEN}"},
                json={"worker_id": "worker-test", "kinds": ["campaign"], "lease_seconds": 30},
            )
            assert denied.status_code == 401
        with (
            socket.create_connection(("127.0.0.1", 8443), timeout=2) as connection,
            pytest.raises(ssl.SSLCertVerificationError),
        ):
            tls_context().wrap_socket(connection, server_hostname="wrong-certificate-host")
        with pytest.raises(httpx.ConnectError):
            httpx.get(ORIGIN + "/healthz", trust_env=False)
        with pytest.raises(httpx.RemoteProtocolError):
            httpx.get("http://127.0.0.1:8443/healthz", trust_env=False)
        stopped = asyncio.run(urgent_worker(client, producer, graph))
        print("verified TLS/mTLS denials and actual Worker stop with independent container absence")
        checkpoint, approval = _checkpoint(client, "linux-first")
    with server() as client:
        rotated_checkpoint, _ = _checkpoint(client, "linux-rotated")
    rejected_keys("wrong")
    rejected_keys("missing")
    print("verified actual Linux API key rotation and wrong/missing verifier rejection")
    repository, service = _service(owned_url())
    try:
        _seed_batch(repository, service, uuid4().hex)
        claim = service.claim_replay_job(
            ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=300),
            actor=WORKER_A,
        )
        assert claim is not None
        permit = service.issue_replay_tool_permit(
            claim.job.job_id,
            _permit_request(claim, 1),
            actor=WORKER_A,
        )
        # An issued call without a receipt is retained, never inferred successful or refunded.
        snapshots = graph.snapshot_store.snapshots()
        assert snapshots
        current = snapshots[-1]
        state = {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "checkpoint": checkpoint,
            "approval": approval,
            "rotated_checkpoint": rotated_checkpoint,
            "uncertain_permit": permit.permit_id,
            "postgres_rows": fingerprint(repository),
            "graph_snapshot": current.snapshot_id,
            "graph_digest": current.snapshot_digest,
            "runs": {
                path.relative_to(STATE).as_posix(): verify_run_integrity(path).root_digest
                for path in STATE.rglob("run_*")
                if path.is_dir()
            },
            "stop": stopped,
        }
        assert state["system"] == "Linux"
        state["local_files"] = {f.path: f.sha256 for f in collect(STATE).files}
        (EVIDENCE / "state.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    finally:
        repository.close()
    print("Linux TLS API, real Worker stop, Graph/RunStore and uncertain CP permit retained")


def verify():
    content = (EVIDENCE / "state.json").read_bytes()
    assert sha256(content).hexdigest() == os.environ["PAJIN_OPS002_EXPECTED_STATE_SHA256"]
    state = json.loads(content)
    assert {f.path: f.sha256 for f in collect(STATE).files} == state["local_files"]
    repository = ControlPlaneRepository(owned_url())
    try:
        assert fingerprint(repository) == state["postgres_rows"]
        with repository.read_transaction() as session:
            assert session.get(ReplayToolPermitRecord, state["uncertain_permit"]) is not None
            assert session.scalar(select(ReplayBudgetAccountRecord)).consumed_calls == 1
            run_ids = {row.run_id for row in session.scalars(select(RunRecord))}
        snapshot = load_verified_current_graph_snapshot(
            STATE / "graph.sqlite3",
            campaign_id=campaign().metadata.name,
            snapshot_id=state["graph_snapshot"],
        )
        assert snapshot is not None and snapshot.snapshot_digest == state["graph_digest"]
        for path, root in state["runs"].items():
            assert verify_run_integrity(STATE / path).root_digest == root
        budgets = []
        for journal_path in (STATE / "budgets").glob("*.sqlite3"):
            with sqlite3.connect(journal_path) as connection:
                connection.row_factory = sqlite3.Row
                binding = stored_run_binding(connection)
                assert binding is not None and binding.control_plane_run_id in run_ids
                saved = _verified_history(
                    connection,
                    BudgetScope(
                        campaign_digest=binding.campaign_digest,
                        role="campaign",
                        policy_digest=None,
                        limits=campaign().spec.budgets,
                    ),
                )
                assert saved is not None and saved.usage.tool_calls >= 1
            # Rehydration writes elapsed budget history: use a private copy for a passive check.
            copied = Path("/tmp") / (uuid4().hex + ".sqlite3")
            shutil.copyfile(journal_path, copied)
            try:
                journal = SupervisorInvocationJournal(
                    copied, run_binding=binding, allow_create=False
                )
                remaining = BudgetController(campaign().spec.budgets)
                before = copied.read_bytes()
                try:
                    journal.bind_campaign_budget(
                        campaign_digest=binding.campaign_digest,
                        campaign=remaining,
                    )
                except BudgetExceeded as exc:
                    assert str(exc) == "restored duration exceeds campaign budget"
                    elapsed = (datetime.now(UTC) - saved.origin_at).total_seconds()
                    assert elapsed >= saved.scope.limits.duration_seconds
                    assert copied.read_bytes() == before
                    outcome = "expired-execution-denied"
                else:
                    assert remaining.tool_calls == saved.usage.tool_calls
                    outcome = "conservative-usage-restored"
                budgets.append({"tool_calls": saved.usage.tool_calls, "outcome": outcome})
            finally:
                copied.unlink()
        assert len(budgets) == 1
        with server() as client:
            alert = _alerts(client)["items"][0]
            assert alert == state["stop"]["alert"]
            denied = client.post(
                f"/v1/checkpoints/{state['checkpoint']}/resume",
                headers=_auth(_OPERATOR_TOKEN),
                json={"approval_id": state["approval"]},
            )
            assert denied.status_code == 409, denied.text
        print("budget verification: " + json.dumps(budgets, sort_keys=True))
        assert fingerprint(repository) == state["postgres_rows"]
        assert {f.path: f.sha256 for f in collect(STATE).files} == state["local_files"]
        assert containers(state["stop"]["execution_id"]) == []
        print(
            "verified Linux full-state rows, original rotated verifier, budgets, Graph, Runs, alert"
        )
    finally:
        repository.close()


def hold():
    with server() as client:
        assert client.get("/healthz").status_code == 200
        (EVIDENCE / "ready-for-loss").write_text("Linux API is serving over TLS\n")
        while True:
            time.sleep(1)


if __name__ == "__main__":
    assert platform.system() == "Linux" and os.environ["PAJIN_OPS002_OWNED"] == "1"
    mode = sys.argv[1]
    if mode == "server":
        serve(sys.argv[2])
    elif mode == "collect":
        (EVIDENCE / "local.json").write_bytes(encode(collect(STATE)))
    elif mode == "restore":
        content = (EVIDENCE / "local.json").read_bytes()
        assert sha256(content).hexdigest() == os.environ["PAJIN_OPS002_LOCAL_SHA256"]
        restore(ColdFiles.model_validate_json(content), STATE)
    else:
        {"seed": seed, "verify": verify, "hold": hold}[mode]()
