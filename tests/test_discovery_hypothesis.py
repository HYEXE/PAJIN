import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import JsonValue, ValidationError

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.discovery import (
    CompiledHypothesisWave,
    DeterministicHypothesisCompiler,
    DynamicHypothesisWaveRunner,
    HypothesisWaveError,
    MCPInterfaceSurfaceAdapter,
    ReconWaveOutcome,
    RegisteredHypothesisRule,
    RegisteredMCPReconPlanner,
    SingleReconWaveRunner,
    SurfaceBoundPlan,
    TrustedSurfaceProducer,
)
from pajin.domain.models import CampaignManifest
from pajin.policy.capability import CapabilityError
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import load_verified_run_events, verify_run_integrity
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerResult,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import RegisteredMCPTool, demo_mcp_tool
from pajin.tools.mock import MockAgentProbe, SleepCheckTool
from pajin.workflow.discovery import DiscoveryCampaignRunner
from pajin.workflow.local import LocalCampaignRunner

_INPUT_SCHEMA_DIGEST = "a" * 64


class _CountingSimulatedWorker(SimulatedWorkerBackend):
    def __init__(self) -> None:
        self.calls = 0

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        self.calls += 1
        return await super().run(job, secrets=secrets)


def _a4_campaign(campaign: CampaignManifest) -> CampaignManifest:
    budgets = campaign.spec.budgets.model_copy(
        update={
            "max_agents": 4,
            "max_spawn_depth": 1,
        }
    )
    return CampaignManifest.model_validate(
        campaign.model_copy(
            update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
        ).model_dump(mode="python", by_alias=True)
    )


def _rule(
    recon_tool: RegisteredMCPTool,
    *,
    rule_id: str = "pajin.test.tool-authorization.v1",
    required_tool_id: str = MockAgentProbe.spec.tool_id,
    arguments: dict[str, JsonValue] | None = None,
) -> RegisteredHypothesisRule:
    registration = recon_tool.registration
    return RegisteredHypothesisRule(
        ruleId=rule_id,
        sourceRegistryId=registration.server_id,
        sourceToolId=registration.remote_tool_name,
        sourceToolVersion=recon_tool.spec.version,
        sourceInputSchemaDigest=_INPUT_SCHEMA_DIGEST,
        threatClass="A02",
        statement="The discovered Tool interface may accept an unauthorized delegated action.",
        expectedObservable="The target invokes a protected Tool for an untrusted instruction.",
        requiredToolId=required_tool_id,
        method="POST",
        arguments=arguments
        if arguments is not None
        else {"simulation": {"unauthorizedToolCall": True}},
        estimatedCostUsd=0,
        successCondition="The registered Tool returns one successful bounded observation.",
    )


def _recon_runner(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    tools: ToolRegistry,
    recon_tool: RegisteredMCPTool,
) -> SingleReconWaveRunner:
    adapter = MCPInterfaceSurfaceAdapter(
        tool=recon_tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    return SingleReconWaveRunner(
        planner=RegisteredMCPReconPlanner(
            tool=recon_tool,
            target_id=campaign.spec.targets[0].id,
            arguments={"text": "describe the registered local lab interface"},
        ),
        producer=TrustedSurfaceProducer(tools=tools, adapters=[adapter]),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )


def _a4_stack(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    rules: list[RegisteredHypothesisRule] | None = None,
) -> tuple[
    SingleReconWaveRunner,
    DynamicHypothesisWaveRunner,
    ToolRegistry,
    RegisteredMCPTool,
]:
    tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    tools.register(MockAgentProbe())
    compiler = DeterministicHypothesisCompiler(
        tools=tools,
        rules=rules or [_rule(recon_tool)],
    )
    return (
        _recon_runner(
            tmp_path,
            campaign,
            tools=tools,
            recon_tool=recon_tool,
        ),
        DynamicHypothesisWaveRunner(
            compiler=compiler,
            tools=tools,
            policy=PolicyEngine(),
            worker=SimulatedWorkerBackend(),
            output_root=tmp_path,
        ),
        tools,
        recon_tool,
    )


def test_hypothesis_compiler_is_deterministic_and_surface_bound(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    recon_runner, _, tools, recon_tool = _a4_stack(tmp_path, campaign)
    recon = asyncio.run(recon_runner.run(campaign))
    compiler = DeterministicHypothesisCompiler(
        tools=tools,
        rules=[_rule(recon_tool)],
    )

    first = compiler.compile(campaign, recon)
    second = compiler.compile(campaign.model_copy(deep=True), recon)

    assert first == second
    assert len(first.hypothesis_set.hypotheses) == 1
    hypothesis = first.hypothesis_set.hypotheses[0]
    surface = recon.surface_set.surfaces[0]
    assert hypothesis.surface_set_id == recon.surface_set.surface_set_id
    assert hypothesis.surface_id == surface.surface_id
    assert hypothesis.target_id == surface.target_id
    assert hypothesis.required_tool_id == MockAgentProbe.spec.tool_id
    assert hypothesis.required_tool_version == MockAgentProbe.spec.version
    assert hypothesis.risk_tier == MockAgentProbe.spec.risk_tier
    assert hypothesis.estimated_tool_calls == 1
    assert first.plan.steps[0].hypothesis_id == hypothesis.hypothesis_id
    assert first.plan.steps[0].request.target == campaign.spec.targets[0].endpoint
    assert first.plan.steps[0].request.agent_id.startswith("hypothesis-specialist:")
    assert first.plan.max_waves == 1
    assert first.plan.stop_condition == "hypothesis-wave-complete"
    snapshot = first.surface_bound_plan.surface_snapshot
    task = first.surface_bound_plan.tasks[0]
    assert snapshot.revision == 1
    assert snapshot.surface_set_id == recon.surface_set.surface_set_id
    assert snapshot.projection_run_id == recon.publication.projection_run_id
    assert snapshot.projection_root_digest == recon.publication.projection_root_digest
    assert snapshot.artifact_sha256 == recon.publication.artifact_sha256
    assert task.surface_snapshot_id == snapshot.snapshot_id
    assert task.surface_snapshot_revision == snapshot.revision
    assert task.surface_snapshot_digest == snapshot.snapshot_digest
    assert task.hypothesis_set_id == first.hypothesis_set.hypothesis_set_id
    assert task.wave_plan_id == first.plan.wave_plan_id
    assert task.step == first.plan.steps[0]


def test_surface_bound_plan_rejects_snapshot_task_and_plan_digest_tampering(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    recon_runner, _, tools, recon_tool = _a4_stack(tmp_path, campaign)
    recon = asyncio.run(recon_runner.run(campaign))
    compiled = DeterministicHypothesisCompiler(
        tools=tools,
        rules=[_rule(recon_tool)],
    ).compile(campaign, recon)
    payload = compiled.surface_bound_plan.model_dump(mode="json", by_alias=True)

    forged_snapshot = json.loads(json.dumps(payload))
    forged_snapshot["surfaceSnapshot"]["snapshotDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="Surface Snapshot Digest"):
        SurfaceBoundPlan.model_validate(forged_snapshot)

    forged_task = json.loads(json.dumps(payload))
    forged_task["tasks"][0]["surfaceSnapshotDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="Task Digest"):
        SurfaceBoundPlan.model_validate(forged_task)

    forged_plan = json.loads(json.dumps(payload))
    forged_plan["planDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="Plan Digest"):
        SurfaceBoundPlan.model_validate(forged_plan)


def test_surface_bound_plan_rejects_task_from_another_snapshot(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    recon_runner, _, tools, recon_tool = _a4_stack(tmp_path, campaign)
    first_recon = asyncio.run(recon_runner.run(campaign))
    second_recon = asyncio.run(recon_runner.run(campaign))
    compiler = DeterministicHypothesisCompiler(
        tools=tools,
        rules=[_rule(recon_tool)],
    )
    first = compiler.compile(campaign, first_recon)
    second = compiler.compile(campaign, second_recon)
    payload = first.surface_bound_plan.model_dump(mode="json", by_alias=True)
    payload["tasks"] = second.surface_bound_plan.model_dump(
        mode="json",
        by_alias=True,
    )["tasks"]

    with pytest.raises(ValidationError, match="another Plan authority"):
        SurfaceBoundPlan.model_validate(payload)


def test_hypothesis_compiler_orders_registered_rules_canonically(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    tools.register(MockAgentProbe())
    tools.register(SleepCheckTool())
    recon_runner = _recon_runner(
        tmp_path,
        campaign,
        tools=tools,
        recon_tool=recon_tool,
    )
    recon = asyncio.run(recon_runner.run(campaign))
    mock_rule = _rule(recon_tool)
    sleep_rule = _rule(
        recon_tool,
        rule_id="pajin.test.bounded-delay.v1",
        required_tool_id=SleepCheckTool.spec.tool_id,
        arguments={"seconds": 0.1},
    )

    first = DeterministicHypothesisCompiler(
        tools=tools,
        rules=[mock_rule, sleep_rule],
    ).compile(campaign, recon)
    second = DeterministicHypothesisCompiler(
        tools=tools,
        rules=[sleep_rule, mock_rule],
    ).compile(campaign, recon)

    assert first == second
    hypothesis_ids = [hypothesis.hypothesis_id for hypothesis in first.hypothesis_set.hypotheses]
    assert hypothesis_ids == sorted(hypothesis_ids)
    assert [step.hypothesis_id for step in first.plan.steps] == hypothesis_ids
    assert {step.request.tool_id for step in first.plan.steps} == {
        MockAgentProbe.spec.tool_id,
        SleepCheckTool.spec.tool_id,
    }


def test_hypothesis_compiler_rejects_forged_in_memory_surface_set(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    recon_runner, _, tools, recon_tool = _a4_stack(tmp_path, campaign)
    recon = asyncio.run(recon_runner.run(campaign))
    forged = replace(
        recon,
        surface_set=recon.surface_set.model_copy(
            update={"campaign": "forged-campaign"},
            deep=True,
        ),
    )
    compiler = DeterministicHypothesisCompiler(
        tools=tools,
        rules=[_rule(recon_tool)],
    )

    with pytest.raises(HypothesisWaveError, match="sealed projection"):
        compiler.compile(campaign, forged)


def test_hypothesis_compiler_rejects_unregistered_surface_mapping(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    recon_runner, _, tools, recon_tool = _a4_stack(tmp_path, campaign)
    recon = asyncio.run(recon_runner.run(campaign))
    registration = recon_tool.registration
    unmatched = _rule(recon_tool).model_copy(
        update={"source_tool_id": f"{registration.remote_tool_name}_other"},
        deep=True,
    )
    compiler = DeterministicHypothesisCompiler(tools=tools, rules=[unmatched])

    with pytest.raises(HypothesisWaveError, match="no registered Hypothesis rule"):
        compiler.compile(campaign, recon)


def test_hypothesis_wave_requires_compiler_and_gateway_registry_identity(
    tmp_path: Path,
) -> None:
    compiler_tools = ToolRegistry()
    gateway_tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    compiler_tools.register(recon_tool)
    compiler_tools.register(MockAgentProbe())
    gateway_tools.register(demo_mcp_tool())
    gateway_tools.register(MockAgentProbe())
    compiler = DeterministicHypothesisCompiler(
        tools=compiler_tools,
        rules=[_rule(recon_tool)],
    )

    with pytest.raises(ValueError, match="share one Tool registry"):
        DynamicHypothesisWaveRunner(
            compiler=compiler,
            tools=gateway_tools,
            policy=PolicyEngine(),
            worker=SimulatedWorkerBackend(),
            output_root=tmp_path,
        )


def test_dynamic_hypothesis_wave_uses_fresh_single_call_capability_and_seals(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    recon_runner, wave_runner, _, _ = _a4_stack(tmp_path, campaign)
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))

    outcome = asyncio.run(wave_runner.run(campaign, recon, budget=budget))

    verification = verify_run_integrity(outcome.run_path)
    assert verification.valid
    assert verification.run_id == outcome.run_id
    assert len(outcome.hypothesis_set.hypotheses) == 1
    assert len(outcome.tool_results) == 1
    assert outcome.tool_results[0].success
    assert outcome.tool_results[0].tool_id == MockAgentProbe.spec.tool_id
    assert [result.request_id for result in outcome.tool_results] == [
        step.request.request_id for step in outcome.plan.steps
    ]
    bound_plan = json.loads(
        (outcome.run_path / "surface-bound-plan.json").read_text(encoding="utf-8")
    )
    assert bound_plan == outcome.surface_bound_plan.model_dump(mode="json", by_alias=True)
    assert bound_plan["surfaceSnapshot"]["revision"] == 1
    assert bound_plan["planDigest"] == outcome.surface_bound_plan.plan_digest
    assert bound_plan["tasks"][0]["taskDigest"] == (outcome.surface_bound_plan.tasks[0].task_digest)
    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    assert len(capabilities) == 2
    root, specialist = capabilities
    assert root["grant"]["depth"] == 0
    assert specialist["grant"]["depth"] == 1
    assert specialist["grant"]["parent_grant_id"] == root["grant"]["grant_id"]
    assert specialist["grant"]["max_calls"] == 1
    assert specialist["remaining_calls"] == 0
    assert specialist["grant"]["tools"] == [MockAgentProbe.spec.tool_id]
    assert budget.tool_calls == 2
    assert budget.agent_count == 1

    state = json.loads((outcome.run_path / "run.json").read_text(encoding="utf-8"))
    assert state["status"] == "completed"
    assert state["stopCondition"] == "hypothesis-wave-complete"
    events = load_verified_run_events(outcome.run_path)
    assert sum(event.event_type == "discovery.hypothesis-set.compiled" for event in events) == 1
    assert (
        sum(event.event_type == "discovery.hypothesis-specialist.created" for event in events) == 1
    )
    assert sum(event.event_type == "discovery.hypothesis-wave.completed" for event in events) == 1
    created = next(
        event for event in events if event.event_type == "discovery.hypothesis-specialist.created"
    )
    assert created.payload["surfaceSnapshotDigest"] == (
        outcome.surface_bound_plan.surface_snapshot.snapshot_digest
    )
    assert created.payload["surfaceBoundPlanDigest"] == (outcome.surface_bound_plan.plan_digest)
    assert created.payload["surfaceBoundTaskDigest"] == (
        outcome.surface_bound_plan.tasks[0].task_digest
    )


def test_hypothesis_wave_revalidates_surface_snapshot_before_capability_issuance(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    tools.register(MockAgentProbe())
    recon_runner = _recon_runner(
        tmp_path,
        campaign,
        tools=tools,
        recon_tool=recon_tool,
    )
    recon = asyncio.run(recon_runner.run(campaign))

    class _TamperingCompiler(DeterministicHypothesisCompiler):
        def compile(
            self,
            campaign: CampaignManifest,
            recon: ReconWaveOutcome,
        ) -> CompiledHypothesisWave:
            compiled = super().compile(campaign, recon)
            artifact = recon.projection_run_path / recon.publication.artifact_path
            artifact.write_bytes(artifact.read_bytes() + b" ")
            return compiled

    compiler = _TamperingCompiler(
        tools=tools,
        rules=[_rule(recon_tool)],
    )
    worker = _CountingSimulatedWorker()
    runner = DynamicHypothesisWaveRunner(
        compiler=compiler,
        tools=tools,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    with pytest.raises(HypothesisWaveError, match="projection Run is not integrity-valid"):
        asyncio.run(runner.run(campaign, recon))

    assert worker.calls == 0


def test_hypothesis_wave_rejects_replayed_plan_from_another_surface_snapshot(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    tools.register(MockAgentProbe())
    recon_runner = _recon_runner(
        tmp_path,
        campaign,
        tools=tools,
        recon_tool=recon_tool,
    )
    current_recon = asyncio.run(recon_runner.run(campaign))
    foreign_recon = asyncio.run(recon_runner.run(campaign))
    foreign = DeterministicHypothesisCompiler(
        tools=tools,
        rules=[_rule(recon_tool)],
    ).compile(campaign, foreign_recon)

    class _ReplayingCompiler(DeterministicHypothesisCompiler):
        def compile(
            self,
            campaign: CampaignManifest,
            recon: ReconWaveOutcome,
        ) -> CompiledHypothesisWave:
            return foreign

    worker = _CountingSimulatedWorker()
    runner = DynamicHypothesisWaveRunner(
        compiler=_ReplayingCompiler(
            tools=tools,
            rules=[_rule(recon_tool)],
        ),
        tools=tools,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    with pytest.raises(HypothesisWaveError, match="Hypothesis Set differs"):
        asyncio.run(runner.run(campaign, current_recon))

    assert worker.calls == 0


def test_dynamic_hypothesis_wave_requires_attenuated_capability_depth(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    recon_runner, wave_runner, _, _ = _a4_stack(tmp_path, sample_campaign)
    recon = asyncio.run(recon_runner.run(sample_campaign))

    with pytest.raises(CapabilityError, match="requires depth"):
        asyncio.run(wave_runner.run(sample_campaign, recon))

    run_paths = list((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    failed_paths = [
        path
        for path in run_paths
        if (path / "run.json").exists()
        and json.loads((path / "run.json").read_text(encoding="utf-8")).get("purpose")
        == "dynamic-hypothesis-wave"
    ]
    assert len(failed_paths) == 1
    failed = failed_paths[0]
    assert verify_run_integrity(failed).valid
    state = json.loads((failed / "run.json").read_text(encoding="utf-8"))
    assert state["status"] == "failed"
    assert not (failed / "hypothesis-results.json").exists()


def _composed_a4_runner(
    tmp_path: Path,
    campaign: CampaignManifest,
) -> DiscoveryCampaignRunner:
    recon, hypothesis_wave, tools, _ = _a4_stack(tmp_path, campaign)
    local = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    return DiscoveryCampaignRunner(
        campaign=local,
        recon=recon,
        hypothesis_wave=hypothesis_wave,
    )


def test_a4_composition_is_opt_in_and_does_not_replan_existing_campaign(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    runner = _composed_a4_runner(tmp_path, campaign)

    outcome = asyncio.run(
        runner.run(
            campaign,
            enable_recon=True,
            enable_hypothesis_wave=True,
        )
    )

    assert outcome.recon is not None
    assert outcome.hypothesis_wave is not None
    assert outcome.hypothesis_wave.tool_results[0].tool_id == MockAgentProbe.spec.tool_id
    assert outcome.campaign.tool_results[0].tool_id == MockAgentProbe.spec.tool_id
    existing_plan = json.loads(
        (outcome.campaign.run_path / "plan.json").read_text(encoding="utf-8")
    )
    assert all(step.get("attack_surface") is None for step in existing_plan["steps"])
    assert all(
        step["request"]["request_id"] != outcome.hypothesis_wave.plan.steps[0].request.request_id
        for step in existing_plan["steps"]
    )
    shared_budget = json.loads(
        (outcome.campaign.run_path / "budget.json").read_text(encoding="utf-8")
    )
    assert shared_budget["toolCalls"] == 3
    assert shared_budget["agentCount"] == 1
    assert verify_run_integrity(outcome.campaign.run_path).valid


def test_hypothesis_wave_flag_requires_recon_and_configured_runner(
    sample_campaign: CampaignManifest,
) -> None:
    class _NeverCalledCampaign:
        async def run(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("campaign must not start")

    runner = DiscoveryCampaignRunner(campaign=_NeverCalledCampaign())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="requires the trusted Recon projection"):
        asyncio.run(runner.run(sample_campaign, enable_hypothesis_wave=True))
    with pytest.raises(ValueError, match="without a configured Recon runner"):
        asyncio.run(
            runner.run(
                sample_campaign,
                enable_recon=True,
                enable_hypothesis_wave=True,
            )
        )
