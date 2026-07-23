import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.discovery import (
    MCPInterfaceSurfaceAdapter,
    ReconWaveError,
    ReconWavePlan,
    RegisteredMCPReconPlanner,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import load_verified_run_events, verify_run_integrity
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import RegisteredMCPTool, demo_mcp_tool
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.discovery import DiscoveryCampaignRunner
from pajin.workflow.local import LocalCampaignRunner

_INPUT_SCHEMA_DIGEST = "a" * 64


def _recon_runner(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    tools: ToolRegistry | None = None,
    tool: RegisteredMCPTool | None = None,
    planner: object | None = None,
) -> tuple[SingleReconWaveRunner, ToolRegistry, RegisteredMCPTool]:
    registry = tools or ToolRegistry()
    recon_tool = tool or demo_mcp_tool()
    if recon_tool.spec.tool_id not in registry.tool_ids():
        registry.register(recon_tool)
    adapter = MCPInterfaceSurfaceAdapter(
        tool=recon_tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    producer = TrustedSurfaceProducer(tools=registry, adapters=[adapter])
    selected_planner = planner or RegisteredMCPReconPlanner(
        tool=recon_tool,
        target_id=campaign.spec.targets[0].id,
        arguments={"text": "describe the registered local lab interface"},
    )
    return (
        SingleReconWaveRunner(
            planner=selected_planner,  # type: ignore[arg-type]
            producer=producer,
            tools=registry,
            policy=PolicyEngine(),
            worker=SimulatedWorkerBackend(),
            output_root=tmp_path,
        ),
        registry,
        recon_tool,
    )


def test_registered_mcp_recon_plan_is_deterministic_and_campaign_bound(
    sample_campaign: CampaignManifest,
) -> None:
    tool = demo_mcp_tool()
    planner = RegisteredMCPReconPlanner(
        tool=tool,
        target_id=sample_campaign.spec.targets[0].id,
        arguments={"text": "describe the registered local lab interface"},
    )

    first = planner.plan(sample_campaign)
    second = planner.plan(sample_campaign.model_copy(deep=True))

    assert first == second
    assert first.max_tool_calls == 1
    assert first.stop_condition == "single-wave-complete"
    assert first.request.target == sample_campaign.spec.targets[0].endpoint
    assert first.request.tool_id == tool.spec.tool_id
    assert first.request.method == "POST"
    assert first.request.agent_id == f"recon-specialist:{planner.planner_id}"


def test_registered_mcp_recon_plan_rejects_undeclared_target(
    sample_campaign: CampaignManifest,
) -> None:
    planner = RegisteredMCPReconPlanner(
        tool=demo_mcp_tool(),
        target_id="missing-target",
        arguments={"text": "describe interface"},
    )

    with pytest.raises(ReconWaveError, match="not declared exactly once"):
        planner.plan(sample_campaign)


def test_mcp_surface_adapter_uses_registered_result_identity_only(
    sample_campaign: CampaignManifest,
) -> None:
    tool = demo_mcp_tool()
    adapter = MCPInterfaceSurfaceAdapter(
        tool=tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    request = RegisteredMCPReconPlanner(
        tool=tool,
        target_id=sample_campaign.spec.targets[0].id,
        arguments={"text": "describe interface"},
    ).plan(sample_campaign).request
    now = datetime.now(UTC)
    result = ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        data={
            "target": request.target,
            "mcpServerId": tool.registration.server_id,
            "mcpToolName": tool.registration.remote_tool_name,
            "mcpContent": [],
        },
    )

    candidates = adapter.extract_surfaces(request, result)

    assert len(candidates) == 1
    locator = candidates[0].locator
    assert locator.kind == "tool-interface"
    assert locator.registry_id == tool.registration.server_id
    assert locator.tool_id == tool.registration.remote_tool_name
    assert locator.tool_version == tool.spec.version
    assert locator.input_schema_digest == _INPUT_SCHEMA_DIGEST

    forged = result.model_copy(
        update={"data": {**result.data, "mcpToolName": "forged-tool"}},
        deep=True,
    )
    with pytest.raises(ValueError, match="registered interface"):
        adapter.extract_surfaces(request, forged)


def test_single_recon_wave_seals_source_admits_and_publishes_projection(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    runner, _, tool = _recon_runner(tmp_path, sample_campaign)

    outcome = asyncio.run(runner.run(sample_campaign))

    assert outcome.source_run_path != outcome.projection_run_path
    source = verify_run_integrity(outcome.source_run_path)
    projection = verify_run_integrity(outcome.projection_run_path)
    assert source.valid
    assert projection.valid
    assert source.run_id == outcome.source_run_id
    assert projection.root_digest == outcome.publication.projection_root_digest
    assert outcome.publication.source_root_digest == source.root_digest
    assert outcome.publication.surface_set_id == outcome.surface_set.surface_set_id
    assert outcome.tool_result.tool_id == tool.spec.tool_id
    assert len(outcome.surface_set.observations) == 1
    assert len(outcome.surface_set.surfaces) == 1
    assert outcome.surface_set.surfaces[0].locator.kind == "tool-interface"

    budget = json.loads((outcome.source_run_path / "budget.json").read_text(encoding="utf-8"))
    run_state = json.loads(
        (outcome.source_run_path / "run.json").read_text(encoding="utf-8")
    )
    assert budget["toolCalls"] == 1
    assert run_state["status"] == "completed"
    assert run_state["stopCondition"] == "single-wave-complete"

    source_events = load_verified_run_events(outcome.source_run_path)
    projection_events = load_verified_run_events(outcome.projection_run_path)
    assert sum(event.event_type == "discovery.recon-plan.created" for event in source_events) == 1
    assert sum(event.event_type == "discovery.recon-wave.completed" for event in source_events) == 1
    assert (
        sum(
            event.event_type == "discovery.attack-surface-set.published"
            for event in projection_events
        )
        == 1
    )
    assert verify_run_integrity(outcome.source_run_path) == source


class _MismatchedTargetPlanner:
    planner_id = "test.mismatched-target-recon"

    def plan(self, campaign: CampaignManifest) -> ReconWavePlan:
        target = campaign.spec.targets[0]
        return ReconWavePlan(
            plannerId=self.planner_id,
            targetId=target.id,
            request=ToolRequest(
                request_id="recon_mismatched_target",
                agent_id=f"recon-specialist:{self.planner_id}",
                tool_id=demo_mcp_tool().spec.tool_id,
                target="https://outside.example.invalid/api",
                method="POST",
                arguments={"text": "describe interface"},
            ),
        )


def test_single_recon_wave_rejects_planner_target_before_tool_execution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    runner, _, _ = _recon_runner(
        tmp_path,
        sample_campaign,
        planner=_MismatchedTargetPlanner(),
    )

    with pytest.raises(ReconWaveError, match="target differs"):
        asyncio.run(runner.run(sample_campaign))

    run_paths = list((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    assert len(run_paths) == 1
    failed = run_paths[0]
    assert verify_run_integrity(failed).valid
    state = json.loads((failed / "run.json").read_text(encoding="utf-8"))
    assert state["status"] == "failed"
    assert not list((failed / "evidence").glob("*.json"))


def _composed_runner(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> DiscoveryCampaignRunner:
    tools = ToolRegistry()
    tools.register(MockAgentProbe())
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    recon, _, _ = _recon_runner(
        tmp_path,
        sample_campaign,
        tools=tools,
        tool=recon_tool,
    )
    local = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    return DiscoveryCampaignRunner(campaign=local, recon=recon)


def test_discovery_composition_preserves_default_execution_without_opt_in(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    runner = _composed_runner(tmp_path, sample_campaign)

    outcome = asyncio.run(runner.run(sample_campaign))

    assert outcome.recon is None
    assert outcome.campaign.tool_results[0].tool_id == MockAgentProbe.spec.tool_id
    run_paths = list((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    assert run_paths == [outcome.campaign.run_path]


def test_opt_in_recon_precedes_but_does_not_replan_existing_attack(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    runner = _composed_runner(tmp_path, sample_campaign)

    outcome = asyncio.run(runner.run(sample_campaign, enable_recon=True))

    assert outcome.recon is not None
    assert outcome.recon.tool_result.tool_id == demo_mcp_tool().spec.tool_id
    assert outcome.campaign.tool_results[0].tool_id == MockAgentProbe.spec.tool_id
    plan = json.loads((outcome.campaign.run_path / "plan.json").read_text(encoding="utf-8"))
    assert [step["request"]["tool_id"] for step in plan["steps"]] == [
        MockAgentProbe.spec.tool_id
    ]
    assert all(step.get("attack_surface") is None for step in plan["steps"])
    shared_budget = json.loads(
        (outcome.campaign.run_path / "budget.json").read_text(encoding="utf-8")
    )
    assert shared_budget["toolCalls"] == 2
    assert verify_run_integrity(outcome.campaign.run_path).valid


def test_recon_feature_flag_requires_configured_runner(
    sample_campaign: CampaignManifest,
) -> None:
    class _NeverCalledCampaign:
        async def run(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("campaign must not start")

    runner = DiscoveryCampaignRunner(campaign=_NeverCalledCampaign())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="without a configured Recon runner"):
        asyncio.run(runner.run(sample_campaign, enable_recon=True))
