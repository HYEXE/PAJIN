import asyncio
import json
from dataclasses import replace
from pathlib import Path
from typing import Literal

import pytest
from pydantic import JsonValue

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.discovery import (
    BoundedReplanningError,
    BoundedReplanningPolicy,
    BoundedReplanningRunner,
    CompiledHypothesisWave,
    DeterministicHypothesisCompiler,
    DeterministicMultiWaveAuthority,
    DynamicHypothesisWaveRunner,
    MCPInterfaceSurfaceAdapter,
    ObservationGraphSnapshot,
    ObservationRelationship,
    ReconWaveOutcome,
    RegisteredHypothesisRule,
    RegisteredMCPReconPlanner,
    RegisteredObservationRule,
    RegisteredReplanTransition,
    ReplanDecision,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
)
from pajin.domain.models import CampaignManifest
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController, BudgetExceeded
from pajin.runtime.store import load_verified_run_events, verify_run_integrity
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import RegisteredMCPTool, demo_mcp_tool
from pajin.tools.mock import MockAgentProbe, SleepCheckTool
from pajin.workflow.discovery import DiscoveryCampaignRunner
from pajin.workflow.local import LocalCampaignRunner

_INPUT_SCHEMA_DIGEST = "a" * 64
_INITIAL_RULE_ID = "pajin.test.initial-tool-authorization.v1"
_NEXT_RULE_ID = "pajin.test.followup-delay.v1"
_NEXT_COMPILER_ID = "pajin.test.followup-compiler.v1"
_THIRD_RULE_ID = "pajin.test.third-safe-probe.v1"
_THIRD_COMPILER_ID = "pajin.test.third-compiler.v1"


def _a5_campaign(
    campaign: CampaignManifest,
    *,
    max_agents: int = 4,
    max_cost_usd: float = 0,
) -> CampaignManifest:
    budgets = campaign.spec.budgets.model_copy(
        update={
            "max_agents": max_agents,
            "max_spawn_depth": 1,
            "max_tool_calls": 5,
            "max_cost_usd": max_cost_usd,
        }
    )
    return CampaignManifest.model_validate(
        campaign.model_copy(
            update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
        ).model_dump(mode="python", by_alias=True)
    )


def _hypothesis_rule(
    recon_tool: RegisteredMCPTool,
    *,
    rule_id: str,
    required_tool_id: str,
    arguments: dict[str, JsonValue],
    estimated_cost_usd: float = 0,
) -> RegisteredHypothesisRule:
    registration = recon_tool.registration
    return RegisteredHypothesisRule(
        ruleId=rule_id,
        sourceRegistryId=registration.server_id,
        sourceToolId=registration.remote_tool_name,
        sourceToolVersion=recon_tool.spec.version,
        sourceInputSchemaDigest=_INPUT_SCHEMA_DIGEST,
        threatClass="A02",
        statement="A registered follow-up action can test the admitted Tool interface.",
        expectedObservable="The registered Tool returns its bounded exact observation.",
        requiredToolId=required_tool_id,
        method="POST",
        arguments=arguments,
        estimatedCostUsd=estimated_cost_usd,
        successCondition="The exact registered result field matches its expected value.",
    )


def _recon_runner(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    tools: ToolRegistry,
    recon_tool: RegisteredMCPTool,
) -> SingleReconWaveRunner:
    return SingleReconWaveRunner(
        planner=RegisteredMCPReconPlanner(
            tool=recon_tool,
            target_id=campaign.spec.targets[0].id,
            arguments={"text": "describe the registered local lab interface"},
        ),
        producer=TrustedSurfaceProducer(
            tools=tools,
            adapters=[
                MCPInterfaceSurfaceAdapter(
                    tool=recon_tool,
                    input_schema_digest=_INPUT_SCHEMA_DIGEST,
                )
            ],
        ),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )


def _wave_runner(
    tmp_path: Path,
    *,
    tools: ToolRegistry,
    rules: list[RegisteredHypothesisRule],
    compiler_id: str | None = None,
) -> DynamicHypothesisWaveRunner:
    return DynamicHypothesisWaveRunner(
        compiler=DeterministicHypothesisCompiler(
            tools=tools,
            rules=rules,
            compiler_id=compiler_id,
        ),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )


def _observation_rules() -> list[RegisteredObservationRule]:
    return [
        RegisteredObservationRule(
            ruleId="pajin.test.observe-initial-vulnerable.v1",
            sourceHypothesisRuleId=_INITIAL_RULE_ID,
            fieldPath=["data", "vulnerable"],
            expectedValue=True,
        ),
        RegisteredObservationRule(
            ruleId="pajin.test.observe-followup-slept.v1",
            sourceHypothesisRuleId=_NEXT_RULE_ID,
            fieldPath=["data", "slept"],
            expectedValue=True,
        ),
    ]


def _transition(
    *,
    transition_id: str = "pajin.test.initial-support-enables-delay.v1",
    source_rule_id: str = _INITIAL_RULE_ID,
    required_relation: Literal["new-surface", "supports", "contradicts"] = "supports",
    next_compiler_id: str = _NEXT_COMPILER_ID,
    next_rule_ids: list[str] | None = None,
) -> RegisteredReplanTransition:
    return RegisteredReplanTransition(
        transitionId=transition_id,
        sourceHypothesisRuleId=source_rule_id,
        requiredRelation=required_relation,
        nextCompilerId=next_compiler_id,
        nextRuleIds=next_rule_ids or [_NEXT_RULE_ID],
        rationale="A supported authorization signal enables one distinct bounded follow-up.",
    )


def _a5_stack(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    transition: RegisteredReplanTransition | None = None,
    repeated_next: bool = False,
    partial_novelty: bool = False,
    initial_cost_usd: float = 0,
    next_cost_usd: float = 0,
) -> tuple[
    SingleReconWaveRunner,
    DynamicHypothesisWaveRunner,
    BoundedReplanningRunner,
    ToolRegistry,
]:
    tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    tools.register(MockAgentProbe())
    tools.register(SleepCheckTool())
    initial_rule = _hypothesis_rule(
        recon_tool,
        rule_id=_INITIAL_RULE_ID,
        required_tool_id=MockAgentProbe.spec.tool_id,
        arguments={"simulation": {"unauthorizedToolCall": True}},
        estimated_cost_usd=initial_cost_usd,
    )
    initial_wave = _wave_runner(
        tmp_path,
        tools=tools,
        rules=[initial_rule],
    )
    if repeated_next:
        next_wave = _wave_runner(
            tmp_path,
            tools=tools,
            rules=[initial_rule],
        )
        configured_transition = _transition(
            next_compiler_id=next_wave.compiler_id,
            next_rule_ids=[_INITIAL_RULE_ID],
        )
    else:
        next_rule = _hypothesis_rule(
            recon_tool,
            rule_id=_NEXT_RULE_ID,
            required_tool_id=SleepCheckTool.spec.tool_id,
            arguments={"seconds": 0.1},
            estimated_cost_usd=next_cost_usd,
        )
        next_wave = _wave_runner(
            tmp_path,
            tools=tools,
            rules=[initial_rule, next_rule] if partial_novelty else [next_rule],
            compiler_id=_NEXT_COMPILER_ID,
        )
        configured_transition = transition or _transition(
            next_rule_ids=(sorted([_INITIAL_RULE_ID, _NEXT_RULE_ID]) if partial_novelty else None)
        )
    replanning = BoundedReplanningRunner(
        observation_rules=_observation_rules(),
        transitions=[configured_transition],
        next_wave=next_wave,
        output_root=tmp_path,
    )
    return (
        _recon_runner(
            tmp_path,
            campaign,
            tools=tools,
            recon_tool=recon_tool,
        ),
        initial_wave,
        replanning,
        tools,
    )


def _three_wave_stack(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    third_transition_compiler_id: str = _THIRD_COMPILER_ID,
    third_transition_rule_ids: list[str] | None = None,
    include_cycle_runner: bool = False,
    repeat_second_state: bool = False,
) -> tuple[
    SingleReconWaveRunner,
    DynamicHypothesisWaveRunner,
    BoundedReplanningRunner,
    ToolRegistry,
]:
    tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    tools.register(MockAgentProbe())
    tools.register(SleepCheckTool())

    initial_rule = _hypothesis_rule(
        recon_tool,
        rule_id=_INITIAL_RULE_ID,
        required_tool_id=MockAgentProbe.spec.tool_id,
        arguments={"simulation": {"unauthorizedToolCall": True}},
    )
    next_rule = _hypothesis_rule(
        recon_tool,
        rule_id=_NEXT_RULE_ID,
        required_tool_id=SleepCheckTool.spec.tool_id,
        arguments={"seconds": 0.1},
    )
    third_rule = _hypothesis_rule(
        recon_tool,
        rule_id=_THIRD_RULE_ID,
        required_tool_id=MockAgentProbe.spec.tool_id,
        arguments={"simulation": {"unauthorizedToolCall": False}},
    )
    initial_wave = _wave_runner(tmp_path, tools=tools, rules=[initial_rule])
    next_wave = _wave_runner(
        tmp_path,
        tools=tools,
        rules=[next_rule],
        compiler_id=_NEXT_COMPILER_ID,
    )
    third_wave = _wave_runner(
        tmp_path,
        tools=tools,
        rules=[third_rule],
        compiler_id=_THIRD_COMPILER_ID,
    )
    configured_waves = [next_wave, third_wave]
    if include_cycle_runner:
        configured_waves[1] = _wave_runner(
            tmp_path,
            tools=tools,
            rules=[initial_rule],
        )
    elif repeat_second_state:
        configured_waves = [next_wave]
    observation_rules = [
        *_observation_rules(),
        RegisteredObservationRule(
            ruleId="pajin.test.observe-third-safe.v1",
            sourceHypothesisRuleId=_THIRD_RULE_ID,
            fieldPath=["data", "vulnerable"],
            expectedValue=False,
        ),
    ]
    transitions = [
        _transition(),
        _transition(
            transition_id="pajin.test.delay-support-enables-third.v1",
            source_rule_id=_NEXT_RULE_ID,
            next_compiler_id=third_transition_compiler_id,
            next_rule_ids=third_transition_rule_ids or [_THIRD_RULE_ID],
        ),
    ]
    replanning = BoundedReplanningRunner(
        observation_rules=observation_rules,
        transitions=transitions,
        next_waves=configured_waves,
        output_root=tmp_path,
        policy=BoundedReplanningPolicy(maxWaves=3, maxReplans=2),
    )
    return (
        _recon_runner(
            tmp_path,
            campaign,
            tools=tools,
            recon_tool=recon_tool,
        ),
        initial_wave,
        replanning,
        tools,
    )


def test_bounded_replanning_changes_the_second_wave_and_seals_lineage(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon, initial_wave, replanning, tools = _a5_stack(tmp_path, campaign)
    local = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    runner = DiscoveryCampaignRunner(
        campaign=local,
        recon=recon,
        hypothesis_wave=initial_wave,
        replanning=replanning,
    )

    outcome = asyncio.run(
        runner.run(
            campaign,
            enable_recon=True,
            enable_hypothesis_wave=True,
            enable_replanning=True,
        )
    )

    assert outcome.hypothesis_wave is not None
    assert outcome.replanning is not None
    assert outcome.replanning.next_wave is not None
    assert outcome.hypothesis_wave.plan.steps[0].request.tool_id == MockAgentProbe.spec.tool_id
    assert outcome.replanning.next_wave.plan.steps[0].request.tool_id == SleepCheckTool.spec.tool_id
    assert outcome.hypothesis_wave.run_id != outcome.replanning.next_wave.run_id
    assert [item.action for item in outcome.replanning.decisions] == [
        "execute-next-wave",
        "stop",
    ]
    assert [item.reason for item in outcome.replanning.decisions] == [
        "transition-selected",
        "max-waves-reached",
    ]
    first_graph, final_graph = outcome.replanning.graphs
    assert first_graph.wave_count == 1
    assert final_graph.wave_count == 2
    assert final_graph.previous_snapshot_id == first_graph.snapshot_id
    assert {item.relation for item in final_graph.relationships} == {
        "supports",
        "enables",
        "depends-on",
    }
    assert len(final_graph.observations) == 2
    assert {item.source_run_id for item in final_graph.observations} == {
        outcome.hypothesis_wave.run_id,
        outcome.replanning.next_wave.run_id,
    }
    assert verify_run_integrity(outcome.replanning.run_path).valid
    assert verify_run_integrity(outcome.replanning.next_wave.run_path).valid
    state = json.loads((outcome.replanning.run_path / "run.json").read_text(encoding="utf-8"))
    assert state["status"] == "completed"
    assert state["waveCount"] == 2
    assert state["replanCount"] == 1
    events = load_verified_run_events(outcome.replanning.run_path)
    assert (
        sum(event.event_type == "discovery.observation-graph.snapshotted" for event in events) == 2
    )
    assert sum(event.event_type == "discovery.replan.decided" for event in events) == 2
    assert sum(event.event_type == "discovery.replan.wave-dispatched" for event in events) == 1
    shared_budget = json.loads(
        (outcome.campaign.run_path / "budget.json").read_text(encoding="utf-8")
    )
    assert shared_budget["toolCalls"] == 4
    assert shared_budget["agentCount"] == 2

    legacy_graph_payload = first_graph.model_dump(mode="python", by_alias=True)
    legacy_graph_payload.pop("surfaceBoundPlanDigests")
    legacy_graph_payload["snapshotId"] = ""
    legacy_graph = ObservationGraphSnapshot.model_validate(legacy_graph_payload)
    legacy_graph_payload["snapshotId"] = legacy_graph.snapshot_id
    assert ObservationGraphSnapshot.model_validate(legacy_graph_payload) == legacy_graph
    legacy_decision_payload = outcome.replanning.decisions[0].model_dump(
        mode="python",
        by_alias=True,
    )
    legacy_decision_payload.pop("multiWaveAuthorityId")
    legacy_decision_payload.pop("multiWaveAuthorityDigest")
    legacy_decision_payload["decisionId"] = ""
    legacy_decision = ReplanDecision.model_validate(legacy_decision_payload)
    legacy_decision_payload["decisionId"] = legacy_decision.decision_id
    assert ReplanDecision.model_validate(legacy_decision_payload) == legacy_decision


def test_deterministic_three_wave_baseline_changes_each_plan_and_seals_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _three_wave_stack(
        tmp_path,
        campaign,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))

    outcome = asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert outcome.authority is not None
    assert len(outcome.follow_up_waves) == 2
    assert outcome.next_wave == outcome.follow_up_waves[0]
    waves = (initial, *outcome.follow_up_waves)
    assert [item.plan.steps[0].request.tool_id for item in waves] == [
        MockAgentProbe.spec.tool_id,
        SleepCheckTool.spec.tool_id,
        MockAgentProbe.spec.tool_id,
    ]
    assert [item.action for item in outcome.decisions] == [
        "execute-next-wave",
        "execute-next-wave",
        "stop",
    ]
    assert [item.reason for item in outcome.decisions] == [
        "transition-selected",
        "transition-selected",
        "max-waves-reached",
    ]
    assert [item.wave_count for item in outcome.graphs] == [1, 2, 3]
    assert [item.surface_bound_plan_digests for item in outcome.graphs] == [
        [waves[0].surface_bound_plan.plan_digest],
        [
            waves[0].surface_bound_plan.plan_digest,
            waves[1].surface_bound_plan.plan_digest,
        ],
        [item.surface_bound_plan.plan_digest for item in waves],
    ]
    assert all(
        item.surface_bound_plan.surface_snapshot == outcome.authority.surface_snapshot
        for item in waves
    )
    assert all(
        item.multi_wave_authority_id == outcome.authority.authority_id
        and item.multi_wave_authority_digest == outcome.authority.authority_digest
        for item in outcome.decisions
    )
    assert budget.tool_calls == 4
    assert budget.agent_count == 3
    assert verify_run_integrity(outcome.run_path).valid
    assert (outcome.run_path / "deterministic-multi-wave-authority.json").is_file()
    state = json.loads((outcome.run_path / "run.json").read_text(encoding="utf-8"))
    assert state["waveCount"] == 3
    assert state["replanCount"] == 2
    assert state["followUpWaveRunIds"] == [item.run_id for item in outcome.follow_up_waves]
    events = load_verified_run_events(outcome.run_path)
    assert sum(item.event_type == "discovery.multi-wave.authority-bound" for item in events) == 1
    assert sum(item.event_type == "discovery.replan.wave-dispatched" for item in events) == 2


def test_three_wave_baseline_blocks_repeated_intermediate_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _three_wave_stack(
        tmp_path,
        campaign,
        third_transition_compiler_id=_NEXT_COMPILER_ID,
        third_transition_rule_ids=[_NEXT_RULE_ID],
        repeat_second_state=True,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))

    outcome = asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert len(outcome.follow_up_waves) == 1
    assert [item.reason for item in outcome.decisions] == [
        "transition-selected",
        "repeated-state",
    ]
    assert [item.wave_count for item in outcome.graphs] == [1, 2]
    assert budget.tool_calls == 3
    assert budget.agent_count == 2


def test_three_wave_baseline_blocks_cycle_before_third_wave_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _three_wave_stack(
        tmp_path,
        campaign,
        third_transition_compiler_id=(DeterministicHypothesisCompiler.default_compiler_id),
        third_transition_rule_ids=[_INITIAL_RULE_ID],
        include_cycle_runner=True,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))

    outcome = asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert len(outcome.follow_up_waves) == 1
    assert [item.reason for item in outcome.decisions] == [
        "transition-selected",
        "cycle-detected",
    ]
    assert [item.wave_count for item in outcome.graphs] == [1, 2]
    assert budget.tool_calls == 3
    assert budget.agent_count == 2
    events = load_verified_run_events(outcome.run_path)
    assert sum(item.event_type == "discovery.replan.wave-dispatched" for item in events) == 1


def test_multi_wave_compiler_drift_fails_before_follow_up_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _three_wave_stack(
        tmp_path,
        campaign,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))
    next_runner, foreign_runner = replanning._next_waves
    original_compile = next_runner.compile_authority
    call_count = 0

    def drifting_compile(
        campaign_authority: CampaignManifest,
        recon_authority: ReconWaveOutcome,
    ) -> CompiledHypothesisWave:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return original_compile(campaign_authority, recon_authority)
        return foreign_runner.compile_authority(
            campaign_authority,
            recon_authority,
        )

    monkeypatch.setattr(next_runner, "compile_authority", drifting_compile)

    with pytest.raises(
        BoundedReplanningError,
        match="preview differs from its registration",
    ):
        asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert budget.tool_calls == 2
    assert budget.agent_count == 1
    control_runs = [
        path
        for path in (tmp_path / campaign.metadata.name).glob("run_*")
        if (path / "run.json").exists()
        and json.loads((path / "run.json").read_text(encoding="utf-8")).get("purpose")
        == "bounded-replanning"
    ]
    assert len(control_runs) == 1
    assert verify_run_integrity(control_runs[0]).valid
    assert not any(
        item.event_type == "discovery.replan.wave-dispatched"
        for item in load_verified_run_events(control_runs[0])
    )


def test_multi_wave_authority_rejects_retained_digest_scope_expansion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _three_wave_stack(
        tmp_path,
        campaign,
    )
    recon = asyncio.run(recon_runner.run(campaign))
    initial = asyncio.run(initial_runner.run(campaign, recon))
    outcome = asyncio.run(replanning.run(campaign, recon, initial))
    assert outcome.authority is not None
    payload = outcome.authority.model_dump(mode="python", by_alias=True)
    campaign_payload = payload["campaignAuthority"]
    assert isinstance(campaign_payload, dict)
    spec_payload = campaign_payload["spec"]
    assert isinstance(spec_payload, dict)
    scope_payload = spec_payload["scope"]
    assert isinstance(scope_payload, dict)
    allow = scope_payload["allow"]
    assert isinstance(allow, list)
    allow.append("https://scope-expansion.invalid/*")

    with pytest.raises(ValueError, match="Authority Digest"):
        DeterministicMultiWaveAuthority.model_validate(payload)


def test_observation_classification_is_exact_and_graph_supports_new_surface_edge(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, _, _ = _a5_stack(tmp_path, campaign)
    recon = asyncio.run(recon_runner.run(campaign))
    initial = asyncio.run(initial_runner.run(campaign, recon))
    hypothesis = initial.hypothesis_set.hypotheses[0]
    result = initial.tool_results[0]
    contradicting = RegisteredObservationRule(
        ruleId="pajin.test.observe-initial-safe.v1",
        sourceHypothesisRuleId=_INITIAL_RULE_ID,
        fieldPath=["data", "vulnerable"],
        expectedValue=False,
    )

    assert contradicting.classify(hypothesis, result) == "contradicts"

    supporting = _observation_rules()[0]
    assert supporting.classify(hypothesis, result) == "supports"
    _, _, replanning, _ = _a5_stack(tmp_path / "graph", campaign)
    outcome = asyncio.run(replanning.run(campaign, recon, initial))
    graph = outcome.graphs[0]
    new_surface = ObservationRelationship(
        sourceId=graph.observations[0].observation_id,
        targetId=graph.surface_ids[0],
        relation="new-surface",
        authorityId="pajin.test.trusted-surface-admission.v1",
    )
    augmented = ObservationGraphSnapshot.model_validate(
        graph.model_copy(
            update={
                "snapshot_id": "",
                "relationships": sorted(
                    [*graph.relationships, new_surface],
                    key=lambda item: item.relationship_id,
                ),
            },
            deep=True,
        ).model_dump(mode="python", by_alias=True)
    )
    assert augmented.snapshot_id != graph.snapshot_id
    assert any(item.relation == "new-surface" for item in augmented.relationships)


def test_bounded_replanning_rejects_forged_initial_wave_outcome(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _a5_stack(tmp_path, campaign)
    recon = asyncio.run(recon_runner.run(campaign))
    initial = asyncio.run(initial_runner.run(campaign, recon))
    forged_result = initial.tool_results[0].model_copy(
        update={"data": {"vulnerable": False}},
        deep=True,
    )
    forged = replace(initial, tool_results=(forged_result,))

    with pytest.raises(BoundedReplanningError, match="sealed Run"):
        asyncio.run(replanning.run(campaign, recon, forged))

    control_runs = [
        path
        for path in (tmp_path / campaign.metadata.name).glob("run_*")
        if (path / "run.json").exists()
        and json.loads((path / "run.json").read_text(encoding="utf-8")).get("purpose")
        == "bounded-replanning"
    ]
    assert len(control_runs) == 1
    assert verify_run_integrity(control_runs[0]).valid
    state = json.loads((control_runs[0] / "run.json").read_text(encoding="utf-8"))
    assert state["status"] == "failed"


def test_bounded_replanning_stops_when_no_transition_matches(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _a5_stack(
        tmp_path,
        campaign,
        transition=_transition(required_relation="contradicts"),
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))

    outcome = asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert outcome.next_wave is None
    assert len(outcome.graphs) == 1
    assert len(outcome.decisions) == 1
    assert outcome.decisions[0].action == "stop"
    assert outcome.decisions[0].reason == "no-transition"
    assert budget.tool_calls == 2
    assert budget.agent_count == 1
    assert verify_run_integrity(outcome.run_path).valid


def test_bounded_replanning_blocks_repeated_plan_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _a5_stack(
        tmp_path,
        campaign,
        repeated_next=True,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))

    outcome = asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert outcome.next_wave is None
    assert outcome.decisions[0].reason == "repeated-state"
    assert outcome.decisions[0].novelty_score == 0
    assert budget.tool_calls == 2
    assert budget.agent_count == 1


def test_bounded_replanning_applies_novelty_threshold_before_execution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign)
    recon_runner, initial_runner, replanning, _ = _a5_stack(
        tmp_path,
        campaign,
        partial_novelty=True,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))

    outcome = asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert outcome.next_wave is None
    assert outcome.decisions[0].reason == "novelty-below-threshold"
    assert outcome.decisions[0].novelty_score == 0.5
    assert budget.tool_calls == 2
    assert budget.agent_count == 1


def test_second_wave_respects_shared_agent_budget_and_terminalizes(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign, max_agents=1)
    recon_runner, initial_runner, replanning, _ = _a5_stack(tmp_path, campaign)
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))

    with pytest.raises(BudgetExceeded, match="more agents"):
        asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    control_runs = [
        path
        for path in (tmp_path / campaign.metadata.name).glob("run_*")
        if (path / "run.json").exists()
        and json.loads((path / "run.json").read_text(encoding="utf-8")).get("purpose")
        == "bounded-replanning"
    ]
    assert len(control_runs) == 1
    assert verify_run_integrity(control_runs[0]).valid
    control_state = json.loads((control_runs[0] / "run.json").read_text(encoding="utf-8"))
    assert control_state["status"] == "budget-exhausted"


def test_second_wave_respects_cumulative_shared_cost_budget(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a5_campaign(sample_campaign, max_cost_usd=1)
    recon_runner, initial_runner, replanning, _ = _a5_stack(
        tmp_path,
        campaign,
        initial_cost_usd=0.6,
        next_cost_usd=0.6,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    initial = asyncio.run(initial_runner.run(campaign, recon, budget=budget))
    assert budget.cost_usd == 0.6

    with pytest.raises(BudgetExceeded, match="estimated cost"):
        asyncio.run(replanning.run(campaign, recon, initial, budget=budget))

    assert budget.cost_usd == 0.6
    control_runs = [
        path
        for path in (tmp_path / campaign.metadata.name).glob("run_*")
        if (path / "run.json").exists()
        and json.loads((path / "run.json").read_text(encoding="utf-8")).get("purpose")
        == "bounded-replanning"
    ]
    assert len(control_runs) == 1
    assert verify_run_integrity(control_runs[0]).valid
    state = json.loads((control_runs[0] / "run.json").read_text(encoding="utf-8"))
    assert state["status"] == "budget-exhausted"


def test_replanning_flag_requires_prior_waves_and_configuration(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    class _NeverCalledCampaign:
        async def run(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("campaign must not start")

    runner = DiscoveryCampaignRunner(campaign=_NeverCalledCampaign())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="requires the initial Hypothesis Wave"):
        asyncio.run(runner.run(sample_campaign, enable_replanning=True))
    campaign = _a5_campaign(sample_campaign)
    recon, hypothesis_wave, _, _ = _a5_stack(tmp_path, campaign)
    configured_prior_waves = DiscoveryCampaignRunner(
        campaign=_NeverCalledCampaign(),  # type: ignore[arg-type]
        recon=recon,
        hypothesis_wave=hypothesis_wave,
    )
    with pytest.raises(ValueError, match="without a configured Replanning runner"):
        asyncio.run(
            configured_prior_waves.run(
                campaign,
                enable_recon=True,
                enable_hypothesis_wave=True,
                enable_replanning=True,
            )
        )
