from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

import httpx
import pytest
import test_control_plane_replay as replay_fixtures
import uvicorn
from fastapi import FastAPI
from sqlalchemy import func, select

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import (
    ArtifactRecord,
    JobRecord,
    ReplayExecutionContextRecord,
    ReplayFinalizationRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
)
from pajin.control_plane.kisa_derivation import (
    KISA_CONFIRMATION_MAX_ATTEMPTS,
    KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
)
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.replay_worker import ReplayWorkerStatus

_OPERATOR_TOKEN = "process-replay-operator-token-that-is-long-and-distinct"
_REPLAY_WORKER_TOKEN = "process-replay-worker-token-that-is-long-and-distinct"
_REPLAY_WORKER_SUBJECT = "process-replay-worker"
_CHECKPOINT_KEY = b"replay-test-signing-key-at-least-32-bytes"
_DIGEST_PROBE = """
import json
import os
import sys

from pajin.control_plane.models import (
    ReplayExecutionContext,
    replay_execution_component_digest,
)
from pajin.replay.tickets import replay_context_digest

context = ReplayExecutionContext.model_validate_json(sys.stdin.read())
components = {
    "campaign": context.campaign,
    "scenario": context.scenario,
    "tool_spec": context.tool_spec,
}
print(json.dumps({
    "hash_seed": {"value": os.environ["PYTHONHASHSEED"]},
    "stored": {
        "campaign": context.campaign_digest,
        "scenario": context.scenario_digest,
        "tool_spec": context.tool_spec_digest,
    },
    "canonical": {
        name: replay_execution_component_digest(component)
        for name, component in components.items()
    },
    "typed": {
        name: replay_context_digest(component)
        for name, component in components.items()
    },
}, sort_keys=True))
"""


def _start_server(
    app: FastAPI,
) -> tuple[uvicorn.Server, threading.Thread, str, list[BaseException]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            access_log=False,
            log_level="critical",
        )
    )
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            asyncio.run(server.serve(sockets=[listener]))
        except BaseException as exc:  # pragma: no cover - surfaced by the parent assertion
            errors.append(exc)

    thread = threading.Thread(target=serve, name="replay-process-control-plane", daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if errors or not thread.is_alive():
            break
        try:
            if httpx.get(f"{base_url}/healthz", timeout=0.5).status_code == 200:
                return server, thread, base_url, errors
        except httpx.HTTPError:
            pass
        time.sleep(0.02)
    server.should_exit = True
    thread.join(timeout=5)
    raise AssertionError(f"Control Plane loopback server did not start: {errors!r}")


def _fake_docker_executable(tmp_path: Path) -> Path:
    executable = tmp_path / "fake-docker"
    executable.write_text(
        f"#!{sys.executable}\nfrom replay_fake_docker import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def _worker_environment(
    *,
    root: Path,
    tmp_path: Path,
    base_url: str,
    staging_root: Path,
    status_path: Path,
) -> dict[str, str]:
    python_paths = [str(root / "src"), str(root / "tests")]
    if existing := os.environ.get("PYTHONPATH"):
        python_paths.append(existing)
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(python_paths),
        "PAJIN_CP_URL": base_url,
        "PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB": "true",
        "PAJIN_CP_REPLAY_WORKER_TOKEN": _REPLAY_WORKER_TOKEN,
        "PAJIN_REPLAY_WORKER_ID": "process-replay-daemon",
        "PAJIN_REPLAY_EXECUTOR_PROFILE": "kisa-exact-v1",
        "PAJIN_REPLAY_STAGING_ROOT": str(staging_root),
        "PAJIN_REPLAY_LEASE_SECONDS": "30",
        "PAJIN_REPLAY_HEARTBEAT_SECONDS": "0.1",
        "PAJIN_REPLAY_LONG_POLL_SECONDS": "1",
        "PAJIN_REPLAY_IDLE_DELAY_SECONDS": "0.05",
        "PAJIN_REPLAY_RETRY_BASE_SECONDS": "0.05",
        "PAJIN_REPLAY_RETRY_MAX_SECONDS": "0.1",
        "PAJIN_REPLAY_FINALIZE_ATTEMPTS": "3",
        "PAJIN_REPLAY_CANCELLATION_GRACE_SECONDS": "0.1",
        "PAJIN_REPLAY_CANCELLATION_FORCE_SECONDS": "25",
        "PAJIN_REPLAY_STATUS_PATH": str(status_path),
        "PAJIN_REPLAY_HEALTH_MAX_AGE_SECONDS": "10",
        "PAJIN_REPLAY_DOCKER_EXECUTABLE": str(_fake_docker_executable(tmp_path)),
        "PAJIN_REPLAY_WORKER_IMAGE": "pajin-worker:dev",
        "PAJIN_REPLAY_EGRESS_PROXY_IMAGE": "pajin-egress-proxy:dev",
        "PAJIN_REPLAY_EXTERNAL_NETWORK": "bridge",
        "PAJIN_FAKE_DOCKER_STATE": str(tmp_path / "fake-docker-state"),
        "PYTHONHASHSEED": "2",
    }


def _probe_component_digests(
    *,
    root: Path,
    canonical_context: bytes,
    hash_seed: str,
) -> dict[str, dict[str, str]]:
    python_paths = [str(root / "src"), str(root / "tests")]
    if existing := os.environ.get("PYTHONPATH"):
        python_paths.append(existing)
    completed = subprocess.run(
        [sys.executable, "-c", _DIGEST_PROBE],
        cwd=root,
        env={
            **os.environ,
            "PYTHONHASHSEED": hash_seed,
            "PYTHONPATH": os.pathsep.join(python_paths),
        },
        input=canonical_context.decode("utf-8"),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert isinstance(result, dict)
    return result


def _wait_for_replay_success(
    *,
    client: httpx.Client,
    job_id: str,
    worker: subprocess.Popen[str],
) -> dict[str, object]:
    deadline = time.monotonic() + 60
    last_job: dict[str, object] = {}
    while time.monotonic() < deadline:
        if worker.poll() is not None:
            stdout, stderr = worker.communicate()
            raise AssertionError(
                f"Replay Worker exited before success\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )
        response = client.get(f"/v1/jobs/{job_id}")
        assert response.status_code == 200, response.text
        last_job = response.json()
        if last_job.get("state") == "succeeded":
            return last_job
        time.sleep(0.05)
    raise AssertionError(f"Replay Job did not succeed: {last_job!r}")


@pytest.mark.skipif(  # type: ignore[untyped-decorator]
    os.name != "posix",
    reason="the process E2E asserts POSIX SIGTERM",
)
def test_replay_worker_entrypoint_process_executes_one_exact_replay(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "replay-process.db"
    staging_root, repository_root = replay_fixtures._artifact_roots(database_path)
    settings = ControlPlaneSettings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject="process-replay-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            _REPLAY_WORKER_TOKEN: Principal(
                subject=_REPLAY_WORKER_SUBJECT,
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"replay-v1": _CHECKPOINT_KEY},
        active_checkpoint_key_id="replay-v1",
        artifact_staging_root=staging_root,
        artifact_repository_root=repository_root,
        replay_executor_profiles={_REPLAY_WORKER_SUBJECT: frozenset({"kisa-exact-v1"})},
    )
    seed_repository, seed_service = replay_fixtures._service(
        database_path,
        replay_executor_profiles={_REPLAY_WORKER_SUBJECT: frozenset({"kisa-exact-v1"})},
    )
    try:
        replay_fixtures._create_batch(
            seed_repository,
            seed_service,
            "replay-process-e2e",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        with seed_repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            job_id = ticket.job_id
            run_id = ticket.replay_run_id
            execution_context = session.scalar(
                select(ReplayExecutionContextRecord).where(
                    ReplayExecutionContextRecord.replay_run_id == run_id
                )
            )
            assert execution_context is not None
            canonical_context = execution_context.canonical_context
    finally:
        seed_repository.close()

    server_seed_digests = _probe_component_digests(
        root=root,
        canonical_context=canonical_context,
        hash_seed="1",
    )
    worker_seed_digests = _probe_component_digests(
        root=root,
        canonical_context=canonical_context,
        hash_seed="2",
    )
    assert server_seed_digests["stored"] == server_seed_digests["canonical"]
    assert server_seed_digests["stored"] == server_seed_digests["typed"]
    assert worker_seed_digests["stored"] == worker_seed_digests["canonical"]
    assert worker_seed_digests["stored"] == worker_seed_digests["typed"]
    assert server_seed_digests["stored"] == worker_seed_digests["stored"]
    assert server_seed_digests["hash_seed"]["value"] == "1"
    assert worker_seed_digests["hash_seed"]["value"] == "2"

    app = create_app(settings)
    server, server_thread, base_url, server_errors = _start_server(app)
    status_path = tmp_path / "replay-worker-status.json"
    environment = _worker_environment(
        root=root,
        tmp_path=tmp_path,
        base_url=base_url,
        staging_root=staging_root,
        status_path=status_path,
    )
    worker: subprocess.Popen[str] | None = None
    worker_output: tuple[str, str] | None = None
    try:
        worker = subprocess.Popen(
            [sys.executable, "-m", "pajin.control_plane.replay_worker_main"],
            cwd=root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        headers = {"Authorization": f"Bearer {_OPERATOR_TOKEN}"}
        with httpx.Client(base_url=base_url, headers=headers, timeout=5) as client:
            job = _wait_for_replay_success(client=client, job_id=job_id, worker=worker)
            assert job["run_id"] == run_id
            run = client.get(f"/v1/runs/{run_id}")
            assert run.status_code == 200, run.text
            assert run.json()["state"] == "completed"

        deadline = time.monotonic() + 5
        status: ReplayWorkerStatus | None = None
        while time.monotonic() < deadline:
            with suppress(OSError, ValueError):
                status = ReplayWorkerStatus.model_validate_json(
                    status_path.read_text(encoding="utf-8")
                )
            if status is not None and status.state == "idle" and status.handled_replays == 1:
                break
            time.sleep(0.02)
        assert status is not None
        assert status.state == "idle"
        assert status.handled_replays == 1

        health = subprocess.run(
            [sys.executable, "-m", "pajin.control_plane.replay_worker_health"],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert health.returncode == 0, health.stdout + health.stderr

        with app.state.repository.transaction() as session:
            permits = list(
                session.scalars(
                    select(ReplayToolPermitRecord)
                    .where(ReplayToolPermitRecord.job_id == job_id)
                    .order_by(ReplayToolPermitRecord.call_ordinal)
                ).all()
            )
            assert [permit.call_ordinal for permit in permits] == [1, 2]
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ArtifactRecord)
                    .where(ArtifactRecord.schema_kind == "pajin.replay.output.sealed.v1")
                )
                == 1
            )
            stored_job = session.get(JobRecord, job_id)
            assert stored_job is not None
            assert stored_job.state == "succeeded"

        worker.send_signal(signal.SIGTERM)
        worker_output = worker.communicate(timeout=10)
        assert worker.returncode == 0, "\n".join(worker_output)
        stopped = ReplayWorkerStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
        assert stopped.state == "stopped"
        assert stopped.handled_replays == 1
    finally:
        if worker is not None and worker.poll() is None:
            worker.terminate()
            try:
                worker_output = worker.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker_output = worker.communicate(timeout=5)
        server.should_exit = True
        server_thread.join(timeout=10)
        assert not server_thread.is_alive()
        assert server_errors == []
