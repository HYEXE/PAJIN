from __future__ import annotations

import asyncio
import os
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from test_control_plane_checkpoint_recovery import _OPERATOR_TOKEN, _auth, _settings
from test_host_activity import _enroll

from pajin.control_plane.api import create_app
from pajin.control_plane.executors import CampaignJobInput
from pajin.control_plane.models import replay_execution_component_digest
from pajin.graph import GraphSnapshotAuthority, GraphSnapshotReason, graph_snapshot_ref
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime.host_gate import runtime_activity
from pajin.runtime.host_recovery import RecoveryEnrollmentError
from pajin.runtime.store import verify_run_integrity
from pajin.supervision.run_binding import SupervisorRunBinding
from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile

pytestmark = pytest.mark.skipif(os.name != "posix", reason="recovery enrollment uses POSIX locking")


@pytest.mark.parametrize("changed", [None, "input", "source", "graph"])
def test_enrolled_supervisor_verifies_original_cp_input_before_dispatch(
    tmp_path,
    monkeypatch,
    sample_campaign,
    changed,
):
    from test_supervisor_checkpoint_scheduler import (
        _campaign,
        _graph,
        _invocation_environment,
        _policy,
        _runtime,
        _schedule,
    )

    from pajin.supervision.checkpoint_scheduler import (
        SupervisorCheckpointScheduleError,
        SupervisorCheckpointScheduler,
    )
    from pajin.supervision.invocation_runtime import SupervisorInvocationRuntimeError

    state = tmp_path / "host/state"
    settings = _settings(state / "cp.db")
    _enroll(tmp_path, monkeypatch, role="control-plane", configuration=settings, recovery=True)
    campaign = _campaign(sample_campaign)
    with TestClient(create_app(settings)) as client:
        submitted = client.post(
            "/v1/runs",
            headers=_auth(_OPERATOR_TOKEN),
            json={
                "campaign_name": campaign.metadata.name,
                "idempotency_key": "enrolled-supervisor",
                "input": {"manifest": campaign.model_dump(mode="json", by_alias=True)},
            },
        )
        assert submitted.status_code == 200, submitted.text
    original = CampaignJobInput(manifest=campaign)
    binding = SupervisorRunBinding(
        controlPlaneRunId=submitted.json()["run"]["run_id"],
        campaignDigest=compile_legacy_campaign_profile(campaign).input_digest,
        inputDigest="e" * 64
        if changed == "input"
        else replay_execution_component_digest(
            {
                "kind": "campaign",
                "input": original,
            }
        ),
        budgetMode="campaign-and-supervisor",
    )
    with runtime_activity("control-plane", configuration=settings):
        graph_database = SQLiteGraphStore(state / "graph.db", campaign_id=campaign.metadata.name)
        if changed == "graph":
            graph, _, _, collaboration = _graph(campaign)
        else:
            from pajin.collaboration import create_collaboration_snapshot

            graph = graph_database.snapshot_store
            captured = GraphSnapshotAuthority(
                creator_id="pajin.supervision.scheduler-test-authority",
                creator_digest="b" * 64,
                projection_store=graph_database.projection_store,
                snapshot_store=graph,
            ).capture(GraphSnapshotReason.CHECKPOINT)
            collaboration = create_collaboration_snapshot(
                graph_snapshot_ref(captured),
                graph_snapshot_store=graph,
            )
        runtime = _runtime(campaign, graph, collaboration)
        snapshot, model_binding, provider, configuration = runtime
        policy = _policy()
        scheduled = _schedule(
            SupervisorCheckpointScheduler(output_root=state / "schedules", budget_policy=policy),
            runtime,
            campaign,
            collaboration,
            graph,
        )
        invoker, journal, authorities, worker, campaign_budget, dedicated = _invocation_environment(
            state,
            campaign,
            provider,
            policy,
            snapshot,
            model_binding,
            configuration,
            collaboration,
            graph,
            run_binding=binding,
        )
        if changed == "source":
            (scheduled.run_path / "unexpected.txt").write_text("unsealed replacement")
        if changed is not None:
            with pytest.raises(
                (
                    SupervisorInvocationRuntimeError,
                    RecoveryEnrollmentError,
                    SupervisorCheckpointScheduleError,
                )
            ):
                asyncio.run(invoker.invoke(scheduled, authorities))
            assert worker.calls == campaign_budget.model_calls == dedicated.model_calls == 0
            return
        first = asyncio.run(invoker.invoke(scheduled, authorities))
        assert asyncio.run(invoker.invoke(scheduled, authorities)) == first
        assert worker.calls == campaign_budget.model_calls == dedicated.model_calls == 1
        assert journal.inspect(first.publication.journal_entry.intent.intent_id).state == (
            "terminal-success"
        )
        assert verify_run_integrity(first.publication.run_path).seal_count == 2


def test_enrolled_urgent_producer_cancels_registered_cp_once(
    tmp_path, monkeypatch, sample_campaign
):
    from test_collaboration_urgent_observation import NOW, _scenario
    from test_urgent_stop_runtime import _alerts, _deployment, _runtime, _submit

    state = tmp_path / "host/state"
    settings, body, digest = _deployment(state, sample_campaign)
    _enroll(tmp_path, monkeypatch, role="control-plane", configuration=settings, recovery=True)
    with TestClient(create_app(settings)) as client:
        run_id = _submit(client, body)
        with runtime_activity("control-plane", configuration=settings):
            graph = SQLiteGraphStore(state / "graph.db", campaign_id=sample_campaign.metadata.name)
            scenario = _scenario(state, sample_campaign, durable_store=graph)
            runtime, observation = _runtime(client, sample_campaign, digest, run_id, scenario)
            first = runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
            assert (
                runtime.admit(
                    observation=observation,
                    decided_at=NOW + timedelta(seconds=7),
                )
                == first
            )
            assert first.state == "control-plane-cancelled"
        assert len(_alerts(client)["items"]) == 1
