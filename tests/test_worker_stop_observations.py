from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from test_control_plane import OPERATOR_TOKEN, WORKER_TOKEN, _auth, _settings
from test_worker_daemon import BlockingCampaignWorker

from pajin.control_plane.api import create_app
from pajin.control_plane.client import ControlPlaneClient, ControlPlaneRunCancelled
from pajin.control_plane.database import EventRecord, JobRecord
from pajin.control_plane.executors import CampaignJobExecutor, ExecutorRegistry
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.stop_observations import (
    STOP_FENCE_EVENT,
    STOP_OBSERVATION_EVENT,
    WorkerStopObservationRequest,
    WorkerStopReport,
)
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig, WorkerDaemonStatus
from pajin.domain.manifest import load_manifest
from pajin.runtime.control import CancellationCleanupStatus, CancellationKind
from pajin.runtime.store import verify_run_integrity

_OTHER = "other-worker-stop-observation-token-000000000"
_REPLAY = "replay-worker-stop-observation-token-0000000"


def _configured(path: Path):
    settings = _settings(path)
    return replace(
        settings,
        credentials={
            **settings.credentials,
            _OTHER: Principal(subject="other-worker", roles=frozenset({PrincipalRole.WORKER})),
            _REPLAY: Principal(subject="replay-worker", roles=frozenset({PrincipalRole.WORKER})),
        },
        replay_executor_profiles={"replay-worker": frozenset({"kisa-exact-v1"})},
    )


def _submit(client: TestClient, *, manifest=None):
    response = client.post(
        "/v1/runs",
        headers=_auth(OPERATOR_TOKEN),
        json={
            "campaign_name": "worker-stop-test",
            "job_kind": "campaign",
            "idempotency_key": "worker-stop-test",
            "input": {"manifest": manifest} if manifest else {},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["run"]["run_id"], response.json()["job"]["job_id"]


def _claim(client: TestClient):
    response = client.post(
        "/v1/worker/jobs/claim",
        headers=_auth(WORKER_TOKEN),
        json={"worker_id": "worker-test", "kinds": ["campaign"], "lease_seconds": 30},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _cancel(client: TestClient, run_id: str):
    response = client.post(
        f"/v1/runs/{run_id}/cancel",
        headers=_auth(OPERATOR_TOKEN),
        json={"reason": "Stop this bounded test Run"},
    )
    assert response.status_code == 200, response.text


def _request(claim):
    now = datetime.now(UTC)
    return WorkerStopObservationRequest(
        workerId="worker-test",
        leaseToken=claim["lease_token"],
        report=WorkerStopReport(
            kind=CancellationKind.RUN_CANCELLED,
            cleanupStatus=CancellationCleanupStatus.QUIESCED,
            observedAt=now,
            cleanupCompletedAt=now,
            executorDrainedAt=now,
        ),
    )


def _report(client, job_id, request, *, token=WORKER_TOKEN, replay=False):
    family = "worker/replay" if replay else "worker"
    return client.post(
        f"/v1/{family}/jobs/{job_id}/stop-observations",
        headers=_auth(token),
        json=request.model_dump(mode="json", by_alias=True),
    )


def test_default_api_persists_minimized_stop_and_exact_retry_after_restart(tmp_path: Path):
    settings = _configured(tmp_path / "cp.db")
    with TestClient(create_app(settings)) as client:
        run_id, job_id = _submit(client)
        claim = _claim(client)
        assert _report(client, job_id, _request(claim)).status_code == 409
        _cancel(client, run_id)
        request = _request(claim)
        first = _report(client, job_id, request)
        assert first.status_code == 200, first.text
        assert first.json()["report"]["resourceCleanupVerified"] is False
        assert first.json()["report"]["resumeAuthorized"] is False
        with client.app.state.repository.transaction() as session:
            job = session.get(JobRecord, job_id)
            assert job.lease_owner is None and job.lease_token_hash is None
            events = list(session.scalars(select(EventRecord).order_by(EventRecord.sequence)))
            assert len([r for r in events if r.event_type == STOP_FENCE_EVENT]) == 1
            assert len([r for r in events if r.event_type == STOP_OBSERVATION_EVENT]) == 1
            payload = json.dumps([r.payload for r in events])
            assert claim["lease_token"] not in payload
            assert "cleanupError" not in payload and "leaseHash" not in payload
        _cancel(client, run_id)
    with TestClient(create_app(settings)) as client:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: _report(client, job_id, request), range(4)))
        assert all(r.status_code == 200 and r.json() == first.json() for r in results)
        heartbeat = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={"worker_id": "worker-test", "lease_token": claim["lease_token"]},
        )
        assert heartbeat.status_code == 409
        response = client.post(
            f"/v1/worker/jobs/{job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json={"worker_id": "worker-test", "lease_token": claim["lease_token"], "result": {}},
        )
        assert response.status_code == 409

    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from fastapi.testclient import TestClient
from pajin.control_plane.api import create_app
from pajin.control_plane.stop_observations import WorkerStopObservationRequest
from test_worker_stop_observations import _configured, _report
data = json.load(sys.stdin)
with TestClient(create_app(_configured(Path(data['database'])))) as client:
    request = WorkerStopObservationRequest.model_validate(data['request'])
    response = _report(client, data['job'], request)
    print(json.dumps({'status': response.status_code, 'body': response.json()}))
""",
            str(Path(__file__).parent),
        ],
        input=json.dumps(
            {
                "database": str(tmp_path / "cp.db"),
                "job": job_id,
                "request": request.model_dump(mode="json", by_alias=True),
            }
        ),
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert json.loads(child.stdout) == {"status": 200, "body": first.json()}


@pytest.mark.parametrize(
    "case", ["actor", "worker", "token", "operator", "replay-route", "replay-actor"]
)
def test_stop_api_rejects_other_identity_and_route(tmp_path: Path, case: str):
    with TestClient(create_app(_configured(tmp_path / "cp.db"))) as client:
        run_id, job_id = _submit(client)
        claim = _claim(client)
        _cancel(client, run_id)
        request = _request(claim)
        if case == "worker":
            request = request.model_copy(update={"worker_id": "not-owner"})
        elif case == "token":
            request = request.model_copy(update={"lease_token": "x" * 43})
        token = {"actor": _OTHER, "operator": OPERATOR_TOKEN, "replay-actor": _REPLAY}.get(
            case, WORKER_TOKEN
        )
        response = _report(client, job_id, request, token=token, replay=case == "replay-route")
        assert response.status_code == 403, response.text
        assert _report(client, job_id, _request(claim)).status_code == 200


@pytest.mark.parametrize("case", ["future", "before-fence", "contradiction"])
def test_stop_api_rejects_impossible_or_conflicting_report(tmp_path: Path, case: str):
    with TestClient(create_app(_configured(tmp_path / "cp.db"))) as client:
        run_id, job_id = _submit(client)
        claim = _claim(client)
        _cancel(client, run_id)
        request = _request(claim)
        if case == "contradiction":
            assert _report(client, job_id, request).status_code == 200
            report = request.report.model_copy(update={"forced_at": request.report.observed_at})
        else:
            when = datetime.now(UTC) + timedelta(minutes=2 if case == "future" else -2)
            report = WorkerStopReport(
                kind=CancellationKind.RUN_CANCELLED,
                cleanupStatus="observed",
                observedAt=when,
            )
        response = _report(client, job_id, request.model_copy(update={"report": report}))
        assert response.status_code == 409, response.text


@pytest.mark.parametrize(
    "field", ["resourceCleanupVerified", "executionAuthorized", "resumeAuthorized"]
)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_stop_report_never_coerces_authority_flags(field, value):
    with pytest.raises(ValidationError):
        WorkerStopReport.model_validate(
            {
                "kind": "run-cancelled",
                "cleanupStatus": "observed",
                "observedAt": datetime.now(UTC),
                field: value,
            }
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("delivery_fails", [False, True])
async def test_actual_cp_client_and_campaign_cleanup_publish_stop(tmp_path: Path, delivery_fails):
    app = create_app(_configured(tmp_path / "cp.db"))
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://localhost"
        ) as operator,
    ):
        response = await operator.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": campaign.metadata.name,
                "job_kind": "campaign",
                "idempotency_key": "stop-running-campaign",
                "input": {"manifest": campaign.model_dump(mode="json", by_alias=True)},
            },
        )
        assert response.status_code == 200, response.text
        run_id = response.json()["run"]["run_id"]
        worker = BlockingCampaignWorker()
        status_path = tmp_path / "status.json"

        class UnavailableReporter:
            async def observe_worker_stop(self, *args, **kwargs):
                raise OSError("test-only transport failure; never disclose credentials")

        async with ControlPlaneClient(
            base_url="http://localhost",
            bearer_token=WORKER_TOKEN,
            allow_plaintext_http_for_lab=True,
            transport=httpx.ASGITransport(app=app),
        ) as control:
            daemon = WorkerDaemon(
                client=control,
                stop_reporter=UnavailableReporter() if delivery_fails else control,
                executors=ExecutorRegistry(
                    [CampaignJobExecutor(output_root=tmp_path, worker=worker)]
                ),
                config=WorkerDaemonConfig(
                    worker_id="worker-test",
                    kinds=["campaign"],
                    lease_seconds=5,
                    heartbeat_seconds=0.05,
                    long_poll_seconds=0,
                    status_path=status_path,
                    cancellation_grace_seconds=1,
                ),
            )
            task = asyncio.create_task(daemon.run_once())
            try:
                await asyncio.wait_for(worker.started.wait(), timeout=5)
                cancelled = await operator.post(
                    f"/v1/runs/{run_id}/cancel",
                    headers=_auth(OPERATOR_TOKEN),
                    json={"reason": "Bounded stop test"},
                )
                assert cancelled.status_code == 200, cancelled.text
                with pytest.raises(ControlPlaneRunCancelled):
                    await asyncio.wait_for(task, timeout=5)
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        assert worker.cancelled
        run_path = next((tmp_path / campaign.metadata.name).glob("run_*"))
        assert verify_run_integrity(run_path).seal_count == 2
        assert (
            json.loads((run_path / "quiescence.json").read_text())["cancellation"]["cleanupStatus"]
            == "quiesced"
        )
        status = WorkerDaemonStatus.model_validate_json(status_path.read_text())
        assert status.stop_reporting_status == ("failed" if delivery_fails else "recorded")
        with app.state.repository.transaction() as session:
            reports = list(
                session.scalars(
                    select(EventRecord).where(EventRecord.event_type == STOP_OBSERVATION_EVENT)
                )
            )
            assert len(reports) == (0 if delivery_fails else 1)
            if reports:
                assert reports[0].payload["report"]["cleanupStatus"] == "quiesced"
                assert reports[0].payload["report"]["resourceCleanupVerified"] is False
