"""Explicit live probes; collected only by the owned OPS-002 runner, never silently skipped."""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

# Running this file as a child needs the same fixture helper path as pytest.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_control_plane_checkpoint_recovery as checkpoint_tests
import test_control_plane_replay_postgres as replay_tests
import test_urgent_stop_runtime as urgent_tests

from pajin.control_plane.api import create_app
from pajin.control_plane.checkpoint_keys import CheckpointKeyringGuard
from pajin.control_plane.client import ControlPlaneClient, ControlPlaneRunCancelled
from pajin.control_plane.database import (
    CheckpointRecord,
    ControlPlaneRepository,
    ReplayBudgetAccountRecord,
    ReplayToolPermitRecord,
)
from pajin.control_plane.executors import CampaignJobExecutor, ExecutorRegistry
from pajin.control_plane.models import ReplayClaimRequest
from pajin.control_plane.security import CheckpointIntegrityError, CheckpointSigner
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig
from pajin.domain.manifest import load_manifest
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import DockerWorkerBackend


def owned_url() -> str:
    value = os.environ["PAJIN_TEST_POSTGRES_URL"]
    url = make_url(value)
    if (
        os.environ.get("PAJIN_OPS002_OWNED") != "1"
        or url.host != "127.0.0.1"
        or url.database not in {"pajin_ops002", "pajin_ops002_restored"}
        or url.query.get("sslmode") != "verify-full"
    ):
        raise ValueError("probe requires the runner's owned TLS PostgreSQL database")
    return value


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch):
    url = owned_url()
    engine = create_engine(url)
    with engine.begin() as connection:
        assert (
            connection.scalar(text("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"))
            is True
        )
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    original = checkpoint_tests._settings
    monkeypatch.setattr(
        checkpoint_tests, "_settings", lambda path: replace(original(path), database_url=url)
    )
    original_urgent = urgent_tests._settings
    monkeypatch.setattr(
        urgent_tests, "_settings", lambda path: replace(original_urgent(path), database_url=url)
    )
    yield
    engine.dispose()


@pytest.mark.parametrize(
    "case",
    [
        "default_server_rejects_rebound_key_even_before_first_checkpoint",
        "rotation_verifies_previous_checkpoints_and_signs_only_with_active_key",
        "unreferenced_key_may_be_omitted_but_its_id_cannot_be_reassigned",
        "corrupt_checkpoint_prevents_new_key_registration_without_repair",
        "embedded_signing_guard_checks_recovery_even_if_active_key_was_previously_pinned",
        "new_process_rotates_keys_and_consumes_previous_approval_only_once",
        "v15_upgrade_preserves_checkpoints_and_pins_keys_only_after_verification",
        "simultaneous_first_admission_does_not_allow_different_keys_under_one_id",
        "pin_transaction_failure_leaves_no_partial_keyring",
    ],
)
def test_real_postgres_checkpoint_contract(tmp_path, case):
    # Reuse the contract assertions with an actual DB; no repository/SQL calls are mocked.
    getattr(checkpoint_tests, "test_" + case)(tmp_path)


def test_real_postgres_urgent_cancellation_and_alerts(tmp_path, sample_campaign):
    urgent_tests.test_urgent_admission_cancels_once_and_persists_human_ack_after_restart(
        tmp_path, sample_campaign
    )


class ObservedDockerWorker(DockerWorkerBackend):
    """Observe the actual assigned execution ID without replacing dispatch or cleanup."""

    def __init__(self, image):
        super().__init__(
            allowed_images={"pajin-worker:dev"}, runtime_image_bindings={"pajin-worker:dev": image}
        )
        self.started = asyncio.Event()
        self.execution_id = None

    async def run(self, job, *, secrets=None):
        self.execution_id = job.execution_id
        self.started.set()
        return await super().run(job, secrets=secrets)


def containers(execution_id):
    result = subprocess.run(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "-q",
            "--filter",
            f"label=pajin.execution-id={execution_id}",
        ],
        capture_output=True,
        check=True,
        timeout=10,
    )
    return result.stdout.decode().split()


@pytest.mark.asyncio
async def test_actual_docker_worker_urgent_stop_and_physical_cleanup(tmp_path):
    image = os.environ["PAJIN_OPS002_WORKER_IMAGE"]
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", image)
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    settings, body, digest = urgent_tests._deployment(tmp_path, campaign)
    scenario = urgent_tests._scenario(tmp_path, campaign)
    output = tmp_path / "execution"
    worker = ObservedDockerWorker(image)
    with TestClient(create_app(settings)) as client:
        run_id = urgent_tests._submit(client, body)
        runtime, observation = urgent_tests._runtime(client, campaign, digest, run_id, scenario)
        async with ControlPlaneClient(
            base_url="http://localhost",
            bearer_token=urgent_tests.WORKER_TOKEN,
            allow_plaintext_http_for_lab=True,
            transport=httpx.ASGITransport(app=client.app),
        ) as control:
            daemon = WorkerDaemon(
                client=control,
                stop_reporter=control,
                executors=ExecutorRegistry(
                    [CampaignJobExecutor(output_root=output, worker=worker)]
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
                await asyncio.wait_for(worker.started.wait(), 10)
                observed = []
                for _ in range(30):
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
                assert details["Image"] == image
                assert details["HostConfig"]["NetworkMode"] == "none"
                runtime.admit(
                    observation=observation, decided_at=urgent_tests.NOW + timedelta(seconds=6)
                )
                with pytest.raises(ControlPlaneRunCancelled):
                    await asyncio.wait_for(task, 25)
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        assert containers(worker.execution_id) == []
        run_path = next((output / campaign.metadata.name).glob("run_*"))
        assert verify_run_integrity(run_path).seal_count == 2
        alert = urgent_tests._alerts(client)["items"][0]
        assert alert["fencedWorkers"] == alert["observedWorkers"] == alert["quiescedWorkers"] == 1
        assert alert["incompleteWorkers"] == 0
    # Actual Docker absence and the report remain separate facts. There was no external target.


def test_tls_mismatch_and_plaintext_are_rejected():
    url = make_url(owned_url())
    for query, error in (
        ({"sslmode": "disable"}, "no pg_hba.conf entry"),
        (
            {**url.query, "host": "wrong-certificate-host", "hostaddr": "127.0.0.1"},
            "does not match host name",
        ),
    ):
        engine = create_engine(url.set(query=query), connect_args={"connect_timeout": 2})
        try:
            with pytest.raises(OperationalError, match=error), engine.connect():
                pytest.fail("TLS boundary was bypassed")
        finally:
            engine.dispose()


def fingerprint(repository: ControlPlaneRepository) -> str:
    """Pin all tables and logical rows independently of physical backup layout."""
    from hashlib import sha256

    from sqlalchemy import inspect

    rows = {}
    with repository.engine.connect() as connection:
        for name in sorted(inspect(connection).get_table_names()):
            if not name.startswith("cp_") or not name.replace("_", "").isalnum():
                raise ValueError("unexpected table in owned database")
            values = [
                dict(row) for row in connection.execute(text(f'SELECT * FROM "{name}"')).mappings()
            ]
            rows[name] = sorted(json.dumps(row, sort_keys=True, default=str) for row in values)
    return sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def seed(state: Path) -> None:
    engine = create_engine(owned_url())
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    engine.dispose()
    settings = replace(checkpoint_tests._settings(state), database_url=owned_url())
    with TestClient(create_app(settings)) as client:
        checkpoint_id, _ = checkpoint_tests._checkpoint(client, "durable")
    repository, service = replay_tests._service(owned_url())
    try:
        replay_tests._seed_batch(repository, service, uuid4().hex)
        claim = service.claim_replay_job(
            ReplayClaimRequest(executor_profile=replay_tests.EXECUTOR_PROFILE, lease_seconds=300),
            actor=replay_tests.WORKER_A,
        )
        assert claim is not None
        permit = service.issue_replay_tool_permit(
            claim.job.job_id, replay_tests._permit_request(claim, 1), actor=replay_tests.WORKER_A
        )
        # Deliberately leave issued execution uncertain: no completion/refund is written.
        data = {
            "checkpoint": checkpoint_id,
            "permit": permit.permit_id,
            "fingerprint": fingerprint(repository),
        }
        state.write_text(json.dumps(data, indent=2) + "\n")
    finally:
        repository.close()


def verify(state: Path) -> None:
    data = json.loads(state.read_text())
    repository = ControlPlaneRepository(owned_url())
    try:
        repository.initialize()
        assert fingerprint(repository) == data["fingerprint"]
        with repository.read_transaction() as session:
            assert session.get(CheckpointRecord, data["checkpoint"]) is not None
            assert session.get(ReplayToolPermitRecord, data["permit"]) is not None
            assert session.scalar(select(ReplayBudgetAccountRecord)).consumed_calls == 1
        wrong = CheckpointSigner(
            active_key_id="v1", keys={"v1": b"wrong-key-material-32-bytes-long"}
        )
        with pytest.raises(CheckpointIntegrityError):
            CheckpointKeyringGuard(repository, wrong).activate()
        original = CheckpointSigner(active_key_id="v1", keys={"v1": checkpoint_tests._KEY_V1})
        CheckpointKeyringGuard(repository, original).activate()
        assert fingerprint(repository) == data["fingerprint"]
        print("verified retained rows, uncertain-call charge and original verifier")
    finally:
        repository.close()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in {"seed", "verify"}:
        raise SystemExit("expected seed|verify and private state path")
    {"seed": seed, "verify": verify}[sys.argv[1]](Path(sys.argv[2]))
