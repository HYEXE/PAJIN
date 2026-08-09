from __future__ import annotations

import asyncio
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.capabilities import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    CapabilityUseProfile,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
)
from pajin.control_plane.capability_deployment import (
    CapabilityGraphCompilerIdentity,
    CapabilityGraphDeploymentRuntime,
    CapabilityGraphWorkerDeployment,
    load_capability_graph_deployment,
)
from pajin.control_plane.executors import CampaignJobExecutor, PermanentExecutionError
from pajin.control_plane.models import JobState, JobView
from pajin.domain.models import CampaignManifest
from pajin.runtime.store import load_verified_run_events
from tests.test_existing_capability_rollout import (
    NOW as RELEASE_NOW,
)
from tests.test_existing_capability_rollout import (
    _release_for,
    _rollout_inputs,
)
from tests.test_general_attack_action_execution import (
    _GATE_NOW,
    _CountingWorker,
    _PermitContext,
    _prepared_and_grant,
)
from tests.test_general_attack_action_execution import (
    low_risk_context as _low_risk_context,
)
from tests.test_general_attack_action_execution import (
    permit_context_fixture as _permit_context_fixture,
)


@pytest.fixture
def low_risk_context(tmp_path: Path) -> _PermitContext:
    return _low_risk_context.__wrapped__(tmp_path)


@pytest.fixture
def permit_context_fixture(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> _PermitContext:
    return _permit_context_fixture.__wrapped__(tmp_path, sample_campaign)


def _runtime(
    tmp_path: Path,
    context: _PermitContext,
    *,
    graph_path: Path,
) -> CapabilityGraphDeploymentRuntime:
    bundle, policy, keys, releases = _rollout_inputs()
    rollout = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=keys,
        releases=releases,
        clock=lambda: RELEASE_NOW,
    )
    release = _release_for(rollout, context.definition.capability_id)
    activation = activate_existing_mode_capabilities(
        rollout=rollout,
        releases=(release,),
        profile=CapabilityUseProfile.RANGE,
    )
    assert activation.activation_set == context.activation.activation_set
    envelope = context.envelope
    compiler = CapabilityGraphCompilerIdentity(
        compilerId=envelope.compiler_id,
        compilerVersion=envelope.compiler_version,
        compilerDigest=envelope.compiler_digest,
    )
    deployment = CapabilityGraphWorkerDeployment(
        deploymentId="deployment:general-attack-control-plane-test",
        campaign=context.campaign,
        campaignDigest=context.envelope.source_campaign_digest,
        missionEnvelope=envelope,
        lifecyclePolicy=policy,
        trustKeys=keys,
        releases=releases,
        activatedReleases=(release,),
        profile=CapabilityUseProfile.RANGE,
        releaseSetDigest=rollout.release_set.release_set_digest,
        activationSetDigest=activation.activation_set.activation_set_digest,
        graphDatabase=str(graph_path.resolve()),
        runRoot=str((tmp_path / "control-plane-runs").resolve()),
        compiler=compiler,
        permitTtlSeconds=30,
    )
    content = deployment.model_dump_json(by_alias=True).encode()
    path = tmp_path / "general-attack-control-plane-deployment.json"
    path.write_bytes(content)
    return load_capability_graph_deployment(
        path,
        expected_sha256=sha256(content).hexdigest(),
        clock=lambda: _GATE_NOW,
    )


def _job_input(context: _PermitContext) -> dict[str, object]:
    _, grant = _prepared_and_grant(context)
    return {
        "profile": "general-attack-v1",
        "hypothesisSet": context.hypotheses.model_dump(mode="json", by_alias=True),
        "plan": context.plan.model_dump(mode="json", by_alias=True),
        "taskDigest": context.task.task_digest,
        "actionDefinition": context.definition.reference().model_dump(mode="json", by_alias=True),
        "codeBackedCapability": context.code_backed.model_dump(mode="json", by_alias=True),
        "decision": context.decision.model_dump(mode="json", by_alias=True),
        "grant": grant.model_dump(mode="json", by_alias=True),
    }


def _job(value: dict[str, object], *, attempts: int = 1) -> JobView:
    return JobView(
        job_id="job_" + "1" * 32,
        run_id="run_" + "2" * 32,
        kind="campaign",
        state=JobState.LEASED,
        payload={"input": value},
        priority=0,
        attempts=attempts,
        max_attempts=3,
        available_at=_GATE_NOW,
        lease_owner="general-attack-worker-test",
        lease_expires_at=_GATE_NOW + timedelta(minutes=1),
        heartbeat_at=_GATE_NOW,
        result=None,
        error=None,
        created_at=_GATE_NOW,
        updated_at=_GATE_NOW,
    )


class _CancellingWorker(_CountingWorker):
    async def run(self, *_args, **_kwargs):
        self.calls += 1
        raise asyncio.CancelledError


@pytest.mark.asyncio
async def test_control_plane_profile_executes_t0_once_and_authenticates_outcome(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    runtime = _runtime(
        tmp_path,
        context,
        graph_path=tmp_path / "graph" / "sup-007a.sqlite3",
    )
    worker = _CountingWorker()
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=worker,
        capability_deployment=runtime,
    )
    job = _job(_job_input(context))

    completed = await executor.execute(job)

    assert completed.result["engine"] == "general-attack-gateway"
    assert completed.result["executionProfile"] == "general-attack-v1"
    assert completed.result["deploymentId"] == runtime.deployment.deployment_id
    assert completed.result["graphRunId"] == context.envelope.run_id
    assert completed.result["dispatched"] is True
    assert completed.result["oracleDecision"] == "succeeded"
    assert worker.calls == 1

    with pytest.raises(PermanentExecutionError, match="failed closed"):
        await executor.execute(_job(_job_input(context), attempts=2))
    assert worker.calls == 1


@pytest.mark.asyncio
async def test_control_plane_profile_seals_cancellation_and_never_redispatches(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    runtime = _runtime(
        tmp_path,
        context,
        graph_path=tmp_path / "graph" / "sup-007a.sqlite3",
    )
    worker = _CancellingWorker()
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=worker,
        capability_deployment=runtime,
    )

    with pytest.raises(asyncio.CancelledError):
        await executor.execute(_job(_job_input(context)))

    run_path = (
        Path(runtime.deployment.run_root) / context.campaign.metadata.name / context.envelope.run_id
    )
    dispatch = [
        CapabilityDispatchAuditEvent.model_validate(event.payload)
        for event in load_verified_run_events(run_path)
        if event.event_type.startswith("capability.dispatch.")
    ]
    assert [event.stage for event in dispatch] == [
        CapabilityDispatchStage.CLAIMED,
        CapabilityDispatchStage.CANCELLED,
    ]

    with pytest.raises(PermanentExecutionError, match="failed closed"):
        await executor.execute(_job(_job_input(context), attempts=2))
    assert worker.calls == 1


@pytest.mark.asyncio
async def test_control_plane_profile_rejects_t2_before_worker(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    context = permit_context_fixture
    runtime = _runtime(
        tmp_path,
        context,
        graph_path=tmp_path / "graph" / "canonical.sqlite3",
    )
    worker = _CountingWorker()
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=worker,
        capability_deployment=runtime,
    )

    with pytest.raises(PermanentExecutionError, match="approval-free"):
        await executor.execute(_job(_job_input(context)))

    assert worker.calls == 0
    assert runtime.graph_store.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_control_plane_profile_rejects_substituted_decision_and_grant(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    runtime = _runtime(
        tmp_path,
        context,
        graph_path=tmp_path / "graph" / "sup-007a.sqlite3",
    )
    worker = _CountingWorker()
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=worker,
        capability_deployment=runtime,
    )
    wrong_decision = _job_input(context)
    decision = dict(wrong_decision["decision"])
    decision.pop("decisionId")
    decision.pop("decisionDigest")
    decision["decisionPayloadDigest"] = "f" * 64
    wrong_decision["decision"] = decision
    with pytest.raises(PermanentExecutionError, match="failed closed"):
        await executor.execute(_job(wrong_decision))

    wrong_grant = _job_input(context)
    wrong_grant["grant"] = {
        **wrong_grant["grant"],
        "targets": ["http://artifact.invalid/foreign"],
    }
    with pytest.raises(PermanentExecutionError, match="failed closed"):
        await executor.execute(_job(wrong_grant))

    assert worker.calls == 0
    assert runtime.graph_store.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_control_plane_profile_requires_deployment_and_strict_source_payload(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    worker = _CountingWorker()
    missing_runtime = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=worker,
    )
    with pytest.raises(PermanentExecutionError, match="startup-pinned"):
        await missing_runtime.execute(_job({"profile": "general-attack-v1"}))

    runtime = _runtime(
        tmp_path,
        low_risk_context,
        graph_path=tmp_path / "graph" / "sup-007a.sqlite3",
    )
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=worker,
        capability_deployment=runtime,
    )
    with pytest.raises(PermanentExecutionError, match="Job input is invalid"):
        await executor.execute(_job({"profile": "general-attack-v1"}))
    assert worker.calls == 0


@pytest.mark.parametrize(
    "definition_update",
    [
        {"approval_required": True},
        {"network_access": True},
    ],
)
def test_control_plane_profile_rejects_unavailable_product_authority(
    low_risk_context: _PermitContext,
    definition_update: dict[str, object],
) -> None:
    definition = low_risk_context.definition.model_copy(update=definition_update)

    with pytest.raises(PermanentExecutionError, match="approval-free"):
        CampaignJobExecutor._require_general_attack_profile_policy(
            low_risk_context.campaign,
            definition,
        )


def test_control_plane_profile_rejects_nonzero_cost_campaign(
    low_risk_context: _PermitContext,
) -> None:
    campaign = low_risk_context.campaign.model_copy(
        update={
            "spec": low_risk_context.campaign.spec.model_copy(
                update={
                    "budgets": low_risk_context.campaign.spec.budgets.model_copy(
                        update={"max_cost_usd": 1.0}
                    )
                }
            )
        }
    )

    with pytest.raises(PermanentExecutionError, match="zero-cost"):
        CampaignJobExecutor._require_general_attack_profile_policy(
            campaign,
            low_risk_context.definition,
        )
