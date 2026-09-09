from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_collaboration_urgent_observation import DIGEST_A, NOW, _scenario
from test_control_plane import APPROVER_TOKEN, OPERATOR_TOKEN, WORKER_TOKEN, _auth, _settings
from test_worker_daemon import BlockingCampaignWorker
from test_worker_stop_observations import _claim

from pajin.collaboration import UrgentObservationFastGateAuthority
from pajin.control_plane.abac import ControlPlaneRunCancellationABACPolicy, RunCancellationRule
from pajin.control_plane.api import create_app
from pajin.control_plane.client import ControlPlaneClient, ControlPlaneRunCancelled
from pajin.control_plane.database import EventRecord
from pajin.control_plane.errors import AuthorizationDenied, StateConflict
from pajin.control_plane.executors import CampaignJobExecutor, ExecutorRegistry
from pajin.control_plane.models import Principal, PrincipalRole, submission_authority_digest
from pajin.control_plane.urgent_stop_runtime import UrgentStopRuntime
from pajin.control_plane.urgent_stops import URGENT_STOP_EVENT, UrgentStopBinding
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig
from pajin.domain.manifest import load_manifest
from pajin.domain.models import campaign_manifest_digest
from pajin.graph.models import graph_node_ref
from pajin.runtime.store import verify_run_integrity

_AUTHORITY = "pajin.test.urgent-stop"
_HYBRID = "hybrid-worker-stop-test-token-0000000000000"


def _deployment(tmp_path, campaign, *, authorized=True):
    body = {
        "campaign_name": campaign.metadata.name,
        "job_kind": "campaign",
        "max_attempts": 3,
        "idempotency_key": "urgent-stop-test",
        "input": {"manifest": campaign.model_dump(mode="json", by_alias=True)},
    }
    digest = submission_authority_digest(
        actor="alice-operator",
        campaign_name=body["campaign_name"],
        input_value=body["input"],
        idempotency_key=body["idempotency_key"],
        job_kind="campaign",
        max_attempts=3,
    )
    settings = _settings(tmp_path / "cp.db")
    settings = replace(
        settings,
        run_cancellation_abac_policy=ControlPlaneRunCancellationABACPolicy(
            policy_id="run-cancel-policy_0123456789abcdef0123456789abcdef",
            run_cancellation_rules=(
                RunCancellationRule(
                    principal_subject="alice-operator",
                    action="run.cancel",
                    submission_authority_digest=digest if authorized else "f" * 64,
                ),
            ),
        ),
    )
    return settings, body, digest


def _runtime(client, campaign, digest, run_id, scenario, *, binding_change=None):
    terminal_authority, terminal, snapshot, store, source, observations = scenario
    binding = UrgentStopBinding(
        runId=run_id,
        submissionDigest=digest,
        campaignDigest=campaign_manifest_digest(campaign),
        sourceRunId=source.reference.source_run_id,
        sourceRootDigest=source.reference.source_root_digest,
        resultArtifactId=source.reference.shared_artifact_id,
        resultArtifactDigest=source.reference.shared_artifact_digest,
        terminalHandoffId=terminal.result_handoff_id,
        terminalHandoffDigest=terminal.result_handoff_digest,
        authorityId=_AUTHORITY,
        authorityDigest=DIGEST_A,
        actor="alice-operator",
    )
    if binding_change:
        binding = binding.model_copy(update=binding_change)
    runtime = UrgentStopRuntime(
        service=client.app.state.control_plane.urgent_stops,
        binding=binding,
        fast_gate=UrgentObservationFastGateAuthority(
            authority_id=_AUTHORITY, authority_digest=DIGEST_A
        ),
        terminal_result_authority=terminal_authority,
        terminal_result=terminal,
        collaboration_snapshot=snapshot,
        graph_snapshot_store=store,
        shared_artifact_sources=(source,),
    )
    return runtime, graph_node_ref(observations[0])


def _submit(client, body):
    response = client.post("/v1/runs", headers=_auth(OPERATOR_TOKEN), json=body)
    assert response.status_code == 200, response.text
    return response.json()["run"]["run_id"]


def _alerts(client, **params):
    response = client.get("/v1/urgent-stops", headers=_auth(OPERATOR_TOKEN), params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_urgent_admission_cancels_once_and_persists_human_ack_after_restart(
    tmp_path, sample_campaign
):
    settings, body, digest = _deployment(tmp_path, sample_campaign)
    scenario = _scenario(tmp_path, sample_campaign)
    with TestClient(create_app(settings)) as client:
        run_id = _submit(client, body)
        _claim(client)
        runtime, observation = _runtime(client, sample_campaign, digest, run_id, scenario)
        with ThreadPoolExecutor(max_workers=3) as pool:
            values = list(
                pool.map(
                    lambda _: runtime.admit(
                        observation=observation, decided_at=NOW + timedelta(seconds=6)
                    ),
                    range(3),
                )
            )
        assert values[0] == values[1] == values[2]
        alert = _alerts(client)["items"][0]
        assert alert["fencedWorkers"] == 1 and alert["observedWorkers"] == 0
        assert alert["application"]["decision"]["decisionState"] == "admitted-not-applied"
        assert alert["application"]["state"] == "control-plane-cancelled"
        endpoint = f"/v1/urgent-stops/{alert['alertId']}/acknowledgment"
        request = {"applicationDigest": alert["application"]["applicationDigest"]}
        for token in (WORKER_TOKEN, APPROVER_TOKEN):
            assert client.post(endpoint, headers=_auth(token), json=request).status_code == 403
        for token in (WORKER_TOKEN,):
            assert client.get("/v1/urgent-stops", headers=_auth(token)).status_code == 403
        assert (
            client.post(
                endpoint, headers=_auth(OPERATOR_TOKEN), json={"applicationDigest": "0" * 64}
            ).status_code
            == 409
        )
        ack = client.post(endpoint, headers=_auth(OPERATOR_TOKEN), json=request)
        assert ack.status_code == 200, ack.text
        assert _alerts(client)["items"][0]["acknowledgment"] == ack.json()
    with TestClient(create_app(settings)) as client:
        # A reconstructed fast gate must use the durable decision time and reverify sources.
        runtime, observation = _runtime(client, sample_campaign, digest, run_id, scenario)
        assert (
            runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=30))
            == values[0]
        )
        assert len(_alerts(client)["items"]) == 1
        assert (
            client.post(endpoint, headers=_auth(OPERATOR_TOKEN), json=request).json() == ack.json()
        )
        run = client.get(f"/v1/runs/{run_id}", headers=_auth(OPERATOR_TOKEN))
        assert run.json()["state"] == "cancelled"
        assert _alerts(client, cursor=alert["alertId"])["items"] == []


@pytest.mark.parametrize(
    "field",
    [
        "campaign_digest",
        "source_run_id",
        "source_root_digest",
        "result_artifact_id",
        "result_artifact_digest",
        "terminal_handoff_id",
        "terminal_handoff_digest",
        "authority_id",
        "authority_digest",
        "submission_digest",
    ],
)
def test_urgent_runtime_rejects_changed_deployment_binding(tmp_path, sample_campaign, field):
    settings, body, digest = _deployment(tmp_path, sample_campaign)
    scenario = _scenario(tmp_path, sample_campaign)
    with TestClient(create_app(settings)) as client:
        run_id = _submit(client, body)
        runtime, observation = _runtime(
            client,
            sample_campaign,
            digest,
            run_id,
            scenario,
            binding_change={field: "f" * 64 if "digest" in field else "not-the-pinned-identity"},
        )
        with pytest.raises((AuthorizationDenied, StateConflict)):
            runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
        assert (
            client.get(f"/v1/runs/{run_id}", headers=_auth(OPERATOR_TOKEN)).json()["state"]
            == "queued"
        )
        assert _alerts(client)["items"] == []


def test_urgent_stop_requires_existing_cancellation_abac(tmp_path, sample_campaign):
    settings, body, digest = _deployment(tmp_path, sample_campaign, authorized=False)
    scenario = _scenario(tmp_path, sample_campaign)
    with TestClient(create_app(settings)) as client:
        run_id = _submit(client, body)
        runtime, observation = _runtime(client, sample_campaign, digest, run_id, scenario)
        with pytest.raises(AuthorizationDenied):
            runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
        assert _alerts(client)["items"] == []


def test_urgent_runtime_cannot_retarget_a_second_run_of_the_same_campaign(
    tmp_path, sample_campaign
):
    settings, body, digest = _deployment(tmp_path, sample_campaign)
    scenario = _scenario(tmp_path, sample_campaign)
    with TestClient(create_app(settings)) as client:
        first = _submit(client, body)
        second = _submit(client, {**body, "idempotency_key": "another-submission"})
        runtime, observation = _runtime(client, sample_campaign, digest, second, scenario)
        with pytest.raises(AuthorizationDenied):
            runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
        for run_id in (first, second):
            assert (
                client.get(f"/v1/runs/{run_id}", headers=_auth(OPERATOR_TOKEN)).json()["state"]
                == "queued"
            )
        assert _alerts(client)["items"] == []


@pytest.mark.parametrize("fail_event", ["job.stop-fenced", "run.cancelled", URGENT_STOP_EVENT])
def test_urgent_stop_failure_rolls_back_cancel_and_alert(
    tmp_path, sample_campaign, monkeypatch, fail_event
):
    settings, body, digest = _deployment(tmp_path, sample_campaign)
    scenario = _scenario(tmp_path, sample_campaign)
    with TestClient(create_app(settings)) as client:
        run_id = _submit(client, body)
        _claim(client)
        runtime, observation = _runtime(client, sample_campaign, digest, run_id, scenario)
        service = client.app.state.control_plane
        original = service._event

        def broken_event(session, run, event_type, actor, payload):
            result = original(session, run, event_type, actor, payload)
            if event_type == fail_event:
                raise OSError("Injected write failure after flush")
            return result

        monkeypatch.setattr(service, "_event", broken_event)
        with pytest.raises(OSError):
            runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
        assert (
            client.get(f"/v1/runs/{run_id}", headers=_auth(OPERATOR_TOKEN)).json()["state"]
            == "running"
        )
        assert _alerts(client)["items"] == []
        with client.app.state.repository.transaction() as session:
            assert not list(
                session.scalars(
                    select(EventRecord).where(EventRecord.event_type == "job.stop-fenced")
                )
            )
        monkeypatch.setattr(service, "_event", original)
        runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=7))
        assert len(_alerts(client)["items"]) == 1


@pytest.mark.asyncio
async def test_urgent_producer_stops_running_campaign_and_exposes_worker_report(tmp_path):
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    settings, body, digest = _deployment(tmp_path, campaign)
    scenario = _scenario(tmp_path, campaign)
    with TestClient(create_app(settings)) as client:
        run_id = _submit(client, body)
        runtime, observation = _runtime(client, campaign, digest, run_id, scenario)
        worker = BlockingCampaignWorker()
        output = tmp_path / "execution"
        async with ControlPlaneClient(
            base_url="http://localhost",
            bearer_token=WORKER_TOKEN,
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
                    lease_seconds=5,
                    heartbeat_seconds=0.05,
                    long_poll_seconds=0,
                    cancellation_grace_seconds=1,
                ),
            )
            task = asyncio.create_task(daemon.run_once())
            try:
                await asyncio.wait_for(worker.started.wait(), timeout=5)
                runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
                with pytest.raises(ControlPlaneRunCancelled):
                    await asyncio.wait_for(task, timeout=5)
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        assert worker.cancelled
        run_path = next((output / campaign.metadata.name).glob("run_*"))
        assert verify_run_integrity(run_path).seal_count == 2
        alert = _alerts(client)["items"][0]
        assert alert["fencedWorkers"] == alert["observedWorkers"] == alert["quiescedWorkers"] == 1
        assert alert["incompleteWorkers"] == 0


def test_urgent_console_credentials_cannot_combine_human_and_worker_roles(tmp_path):
    settings = _settings(tmp_path / "cp.db")
    with pytest.raises(ValueError, match="Worker authority cannot be combined"):
        replace(
            settings,
            credentials={
                **settings.credentials,
                _HYBRID: Principal(
                    subject="hybrid-worker",
                    roles=frozenset({PrincipalRole.WORKER, PrincipalRole.OPERATOR}),
                ),
            },
        )
