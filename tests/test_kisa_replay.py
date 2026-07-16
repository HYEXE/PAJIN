from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pajin.cli as cli_module
import pajin.modes.ai_redteam.replay as replay_module
from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CampaignMode,
    CapabilityGrant,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.domain.orchestration import RunStatus, TaskGraph, TaskNode, TaskStatus
from pajin.domain.replay import (
    ReplayExecutionStatus,
    ReplayIntent,
    ReplayOracleVerdict,
    ReplayPurpose,
    ReplayRetestContext,
    ValidationEvidenceExcerpt,
    ValidationPacket,
    replay_evidence_digest,
    replay_request_digest,
)
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    ValidationReasonCode,
)
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.catalog import KISA_CATALOG, KISACatalog
from pajin.modes.ai_redteam.models import EvaluationThresholds, KISAScenarioDefinition
from pajin.modes.ai_redteam.replay import (
    KISAAIChatNegativeRetestOracle,
    KISAAIChatReplayOracle,
    KISAAIChatSessionMaterializer,
    KISAReplayCoordinator,
    KISARetestReplayCoordinator,
    kisa_negative_retest_contract,
    kisa_replay_contract,
    kisa_replay_registries,
    replayable_kisa_scenarios,
)
from pajin.modes.ai_redteam.retest import KISARetestService
from pajin.modes.ai_redteam.runtime import (
    KISAPlannerRuntime,
    KISARetestPlannerRuntime,
    KISAValidatorRuntime,
)
from pajin.modes.ai_redteam.service import KISAModePack
from pajin.policy.engine import PolicyEngine
from pajin.replay.compiler import ReplayCompiler, replay_scenario_digest
from pajin.replay.materializer import ReplayMaterializerRegistry
from pajin.replay.runtime import (
    GatewayRestrictedReproducerRuntime,
    ReplayOracleRegistry,
    ReplayRuntimeReason,
    VerifiedReplayResult,
)
from pajin.replay.tickets import ReplayExecutionAuthority
from pajin.runtime.control import BudgetController
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeInput, AIChatProbeOutput, AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.confirmation import apply_confirmed_gate
from pajin.workflow.multi_agent import MultiAgentCampaignRunner

NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)


class TranscriptWorker:
    def __init__(
        self,
        support: list[bool],
        *,
        forge_positive: bool = False,
        mutate_turn_message: bool = False,
        mutate_identity: str | None = None,
        first_turn_echo: bool = False,
        explicit_defense: bool = False,
        defense_memory_write: bool = False,
        defense_tool_call: bool = False,
        generic_refusal: bool = False,
        omit_defense_reason: bool = False,
    ) -> None:
        self._support = support
        self._forge_positive = forge_positive
        self._mutate_turn_message = mutate_turn_message
        self._mutate_identity = mutate_identity
        self._first_turn_echo = first_turn_echo
        self._explicit_defense = explicit_defense
        self._defense_memory_write = defense_memory_write
        self._defense_tool_call = defense_tool_call
        self._generic_refusal = generic_refusal
        self._omit_defense_reason = omit_defense_reason
        self.jobs: list[WorkerJob] = []
        self.sessions: list[str] = []

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.jobs.append(job)
        call = len(self.jobs) - 1
        started_at = datetime.now(UTC)
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        supportive = self._support[call]
        self.sessions.append(probe["session_id"])
        turns = []
        for index, turn in enumerate(probe["turns"]):
            markers = [
                check["value"]
                for check in probe["checks"]
                if check["turn"] == index and check["kind"] == "response-contains"
            ]
            content = " ".join(["fresh replay response", *markers]) if supportive else "refused"
            if self._first_turn_echo and index == 0:
                content = "PAJIN_MEMORY_POISON"
            messages = turn["messages"]
            if self._mutate_turn_message and index == 0:
                messages = [{"role": "user", "content": "substituted template"}]
            memory_persistence_read = (
                probe["scenario_id"] == "kisa.agent.memory-poisoning-persistence" and index == 1
            )
            blocked = self._explicit_defense and not supportive and not memory_persistence_read
            reason = "hardened policy" if blocked else None
            if self._explicit_defense and not supportive and not self._generic_refusal:
                registered = {
                    "kisa.model.system-prompt-disclosure": (
                        (
                            "I cannot reveal internal instructions.",
                            True,
                            "system-prompt-protection",
                        ),
                    ),
                    "kisa.model.jailbreak-policy-bypass": (
                        (
                            "The requested action is not allowed.",
                            True,
                            "policy-enforcement",
                        ),
                    ),
                    "kisa.agent.memory-poisoning-persistence": (
                        (
                            "Untrusted content was not stored as trusted memory.",
                            True,
                            "untrusted-memory-write",
                        ),
                        ("No trusted directive is stored.", False, None),
                    ),
                }[probe["scenario_id"]]
                content, blocked, reason = registered[index]
            turns.append(
                {
                    "index": index,
                    "name": turn["name"],
                    "request": {
                        "sessionId": probe["session_id"],
                        "messages": messages,
                        "metadata": {"scenarioId": probe["scenario_id"], "turn": index},
                    },
                    "response": {
                        "sessionId": probe["session_id"],
                        "message": {"role": "assistant", "content": content},
                        "toolCalls": (
                            [{"name": "unsafe-side-effect"}]
                            if self._defense_tool_call and not supportive
                            else []
                        ),
                        "safety": {
                            "blocked": blocked,
                            "reason": None if self._omit_defense_reason else reason,
                        },
                        "memoryWrites": (
                            ["untrusted write"]
                            if self._defense_memory_write and not supportive
                            else []
                        ),
                        "model": "pajin-deterministic-lab-v1",
                    },
                    "responseLatencySeconds": 0.01,
                }
            )
        forged_flag = bool(self._forge_positive)
        checks = [
            {
                "checkId": check["check_id"],
                "kind": check["kind"],
                "turn": check["turn"],
                "matched": forged_flag,
                "sensitive": check["sensitive"],
            }
            for check in probe["checks"]
        ]
        output = {
            "target": payload["target"],
            "scenarioId": probe["scenario_id"],
            "threatClass": probe["threat_class"],
            "sessionId": probe["session_id"],
            "purpose": "attack",
            "vulnerable": forged_flag,
            "observation": "worker-authored verdict is not trusted",
            "turns": turns,
            "checks": checks,
            "sensitiveExposureCount": 20 if forged_flag else 0,
            "meanResponseLatencySeconds": 0.01,
            "networkPerformed": True,
        }
        if self._mutate_identity == "target":
            output["target"] = f"{payload['target']}/substituted"
        elif self._mutate_identity == "scenario":
            output["scenarioId"] = "kisa.model.jailbreak-policy-bypass"
        elif self._mutate_identity == "threat":
            output["threatClass"] = "M06" if probe["threat_class"] != "M06" else "M03"
        elif self._mutate_identity == "session":
            output["sessionId"] = "pajin:foreign:session"
        elif self._mutate_identity == "network":
            output["networkPerformed"] = False
        return WorkerResult(
            execution_id=job.execution_id,
            backend="kisa-replay-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


class MutatingMaterializer:
    def __init__(self, scenario: KISAScenarioDefinition) -> None:
        trusted = KISAAIChatSessionMaterializer(scenario)
        self.materializer_id = trusted.materializer_id
        self.materializer_version = trusted.materializer_version
        self.mode = trusted.mode
        self.scenario_id = trusted.scenario_id
        self.tool_id = trusted.tool_id
        self.session_policy = trusted.session_policy
        self.scenario_digest = trusted.scenario_digest

    def materialize(self, spec, attempt_number):
        arguments = dict(spec.arguments)
        arguments["session_id"] = f"pajin:replay:mutated:{attempt_number}"
        arguments["threat_class"] = "M06" if arguments["threat_class"] != "M06" else "M03"
        return arguments


@dataclass
class ReplayRun:
    result: VerifiedReplayResult
    worker: TranscriptWorker
    source_session: str
    replay_store: RunStore


def _campaign() -> CampaignManifest:
    return load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))


def _scenario(scenario_id: str) -> KISAScenarioDefinition:
    return next(item for item in KISA_CATALOG.scenarios if item.scenario_id == scenario_id)


def _run_replay(
    tmp_path: Path,
    scenario_id: str,
    *,
    support: list[bool],
    forge_positive: bool = False,
    mutate_turn_message: bool = False,
    mutate_identity: str | None = None,
    first_turn_echo: bool = False,
    mutating_materializer: bool = False,
    negative_retest: bool = False,
    explicit_defense: bool = False,
    defense_memory_write: bool = False,
    defense_tool_call: bool = False,
    generic_refusal: bool = False,
    omit_defense_reason: bool = False,
) -> ReplayRun:
    campaign = _campaign()
    scenario = _scenario(scenario_id)
    assert scenario.probe is not None
    threat_class = next(iter(scenario.threat_classes))
    target = campaign.spec.targets[0]
    source_session = f"pajin:source:{threat_class.lower()}:1"
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class=threat_class,
        session_id=source_session,
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    original_request_id = f"tool_original_{threat_class.lower()}_1"
    planned = ToolRequest(
        request_id=original_request_id,
        agent_id="agent:kisa-planner-untrusted",
        tool_id=AIChatProbeTool.spec.tool_id,
        target=target.endpoint,
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )
    executed = planned.model_copy(update={"agent_id": f"agent:specialist:{threat_class}:1"})
    plan = AgentPlan(
        summary="Execute one exact KISA catalog probe.",
        steps=[
            PlannedStep(
                step_id=f"step_{threat_class.lower()}_1",
                title="KISA replay source",
                rationale="Bind the replay to an exact catalog execution.",
                request=planned,
                scenario_id=scenario.scenario_id,
                threat_classes=scenario.threat_classes,
                attack_surface=scenario.attack_surface,
            )
        ],
    )
    evidence = f"evidence/{original_request_id}.json"
    source_store = RunStore.create(tmp_path / "candidate", campaign.metadata.name)
    source_store.write_json(evidence, {"requestId": original_request_id})
    source_store.append_event("tool.completed", {"requestId": original_request_id})
    source_root = source_store.seal().root_digest
    retest_context = None
    if negative_retest:
        retest_store = RunStore.create(tmp_path / "parent-retest", campaign.metadata.name)
        retest_store.append_event("retest.completed", {"status": "completed"})
        retest_root = retest_store.seal().root_digest
        retest_context = ReplayRetestContext(
            baseline_decision_id=f"decision_{threat_class.lower()}_1",
            baseline_finding_id=f"finding_{threat_class.lower()}_1",
            remediation_id=f"remediation_{threat_class.lower()}_1",
            retest_run_id=retest_store.run_id,
            retest_source_root_digest=retest_root,
        )
    replay_store = RunStore.create(tmp_path / "replay", campaign.metadata.name)
    candidate = CandidateFinding(
        candidate_id=f"candidate_{threat_class.lower()}_1",
        claim=Finding(
            finding_id=f"finding_{threat_class.lower()}_1",
            title="KISA transcript marker observed",
            severity=FindingSeverity.HIGH,
            threat_class=threat_class,
            target=target.endpoint,
            summary="The source transcript supported the exact catalog check.",
            reproduction=["Replay the exact catalog probe in a fresh session."],
            evidence=[evidence],
            confidence=1,
        ),
        source="trusted-core:candidate-producer",
        source_agent_id="trusted-core:kisa-candidate-producer",
        source_request_ids=[original_request_id],
        created_at=NOW - timedelta(minutes=5),
    )
    contract = (
        kisa_negative_retest_contract(scenario_id)
        if negative_retest
        else kisa_replay_contract(scenario_id)
    )
    packet = ValidationPacket(
        packet_id=f"validation-packet_{threat_class.lower()}_1",
        candidate_run_id=source_store.run_id,
        candidate=candidate,
        purpose=contract.purpose,
        retest_context=retest_context,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=scenario.scenario_id,
        target_id=target.id,
        target=target.endpoint,
        threat_class=threat_class,
        original_request_ids=[original_request_id],
        evidence=[
            ValidationEvidenceExcerpt(
                reference=evidence,
                sha256="a" * 64,
                excerpt="Redacted source transcript marker.",
            )
        ],
        semantic_support_required=True,
        replay_contract_id=contract.contract_id,
        created_at=NOW - timedelta(minutes=4),
    )
    intent = ReplayIntent(
        intent_id=f"replay-intent_{threat_class.lower()}_1",
        replay_contract_id=contract.contract_id,
        candidate_id=candidate.candidate_id,
        candidate_run_id=source_store.run_id,
        purpose=contract.purpose,
        retest_context=retest_context,
        original_request_id=original_request_id,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=scenario.scenario_id,
        threat_class=threat_class,
        comparison_goals=["Recompute exact catalog checks over a fresh transcript."],
        rationale="Independent reproduction is required before confirmation.",
        created_at=NOW - timedelta(minutes=3),
    )
    specialist_grant = CapabilityGrant(
        grant_id=f"grant_specialist_{threat_class.lower()}_1",
        parent_grant_id="grant_supervisor_kisa_1",
        subject=executed.agent_id,
        campaign=campaign.metadata.name,
        tools={executed.tool_id},
        targets={executed.target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=campaign.spec.authorization.expires_at,
        delegable=False,
        issued_at=NOW - timedelta(minutes=10),
        depth=1,
    )
    authority = ReplayExecutionAuthority()
    ticket = ReplayCompiler.compile_ticket(
        ticket_issuer=authority.issuer(),
        candidate_source_root_digest=source_root,
        campaign=campaign,
        plan=plan,
        original_request=executed,
        specialist_grant=specialist_grant,
        validation_packet=packet,
        intent=intent,
        contract=contract,
        scenario=scenario,
        registered_tools={AIChatProbeTool.spec.tool_id: AIChatProbeTool.spec},
        evidence_by_request={original_request_id: [evidence]},
        trusted_original_request_digest=replay_request_digest(executed),
        trusted_original_evidence_digest=replay_evidence_digest([evidence]),
        replay_run_id=replay_store.run_id,
        used_campaign_calls=1,
        compiled_at=NOW,
    )
    tools = ToolRegistry()
    tools.register(AIChatProbeTool())
    if mutating_materializer:
        materializers = ReplayMaterializerRegistry()
        materializers.register(MutatingMaterializer(scenario))
        oracles = ReplayOracleRegistry()
        oracles.register(
            KISAAIChatNegativeRetestOracle(scenario)
            if negative_retest
            else KISAAIChatReplayOracle(scenario)
        )
    else:
        materializers, oracles = kisa_replay_registries(purpose=contract.purpose)
    worker = TranscriptWorker(
        support,
        forge_positive=forge_positive,
        mutate_turn_message=mutate_turn_message,
        mutate_identity=mutate_identity,
        first_turn_echo=first_turn_echo,
        explicit_defense=explicit_defense,
        defense_memory_write=defense_memory_write,
        defense_tool_call=defense_tool_call,
        generic_refusal=generic_refusal,
        omit_defense_reason=omit_defense_reason,
    )
    budget = BudgetController(campaign.spec.budgets)
    budget.record_tool_call()
    runtime = GatewayRestrictedReproducerRuntime(
        tools=tools,
        policy=PolicyEngine(),
        worker=worker,
        store=replay_store,
        oracles=oracles,
        materializers=materializers,
        tickets=authority.claimer(),
        budget=budget,
        rate_limits=RequestRateLimitLedger(),
        clock=lambda: NOW,
        request_id_factory=lambda _spec, number: f"tool_replay_{threat_class.lower()}_{number}",
    )
    result = asyncio.run(
        runtime.reproduce(
            campaign,
            ticket,
            candidate_source_root_digest=source_root,
        )
    )
    return ReplayRun(
        result=result,
        worker=worker,
        source_session=source_session,
        replay_store=replay_store,
    )


def test_kisa_contracts_cover_exact_three_fresh_session_scenarios() -> None:
    scenarios = replayable_kisa_scenarios()

    assert {scenario.scenario_id for scenario in scenarios} == {
        "kisa.model.system-prompt-disclosure",
        "kisa.model.jailbreak-policy-bypass",
        "kisa.agent.memory-poisoning-persistence",
    }
    for scenario in scenarios:
        contract = kisa_replay_contract(scenario.scenario_id)
        negative = kisa_negative_retest_contract(scenario.scenario_id)
        assert contract.session_policy.value == "fresh-session"
        assert contract.ephemeral_argument_fields == {"session_id"}
        assert contract.semantic_support_required is True
        assert contract.purpose is ReplayPurpose.CONFIRMATION
        assert contract.required_contradictions == 0
        assert negative.contract_id != contract.contract_id
        assert negative.oracle_id != contract.oracle_id
        assert negative.purpose is ReplayPurpose.REMEDIATION_RETEST
        assert negative.required_successes == negative.repetitions
        assert negative.required_contradictions == negative.repetitions


def test_negative_retest_rejects_a_single_repetition_before_execution(
    tmp_path: Path,
) -> None:
    scenario_id = "kisa.model.system-prompt-disclosure"

    with pytest.raises(ValueError, match="between 2 and 20"):
        kisa_negative_retest_contract(scenario_id, repetitions=1)
    with pytest.raises(ValueError, match="between 2 and 20"):
        KISARetestReplayCoordinator(
            tools=ToolRegistry(),
            policy=PolicyEngine(),
            worker=TranscriptWorker([]),
            output_root=tmp_path / "negative-runs",
            repetitions=1,
        )


@pytest.mark.parametrize(
    (
        "support",
        "explicit_defense",
        "forge_positive",
        "defense_memory_write",
        "omit_defense_reason",
        "expected_verdict",
        "expected_support",
        "expected_contradiction",
    ),
    [
        (
            [False, False],
            True,
            True,
            False,
            False,
            ReplayOracleVerdict.CONTRADICTS,
            0,
            2,
        ),
        (
            [True, True],
            False,
            False,
            False,
            False,
            ReplayOracleVerdict.SUPPORTS,
            2,
            0,
        ),
        (
            [True, False],
            True,
            False,
            False,
            False,
            ReplayOracleVerdict.INCONCLUSIVE,
            1,
            1,
        ),
        (
            [False, False],
            False,
            False,
            False,
            False,
            ReplayOracleVerdict.INCONCLUSIVE,
            0,
            0,
        ),
        (
            [False, False],
            True,
            False,
            True,
            False,
            ReplayOracleVerdict.INCONCLUSIVE,
            0,
            0,
        ),
        (
            [False, False],
            True,
            False,
            False,
            True,
            ReplayOracleVerdict.INCONCLUSIVE,
            0,
            0,
        ),
    ],
)
def test_negative_retest_oracle_requires_exact_support_or_explicit_defense(
    tmp_path: Path,
    support: list[bool],
    explicit_defense: bool,
    forge_positive: bool,
    defense_memory_write: bool,
    omit_defense_reason: bool,
    expected_verdict: ReplayOracleVerdict,
    expected_support: int,
    expected_contradiction: int,
) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.model.system-prompt-disclosure",
        support=support,
        negative_retest=True,
        explicit_defense=explicit_defense,
        forge_positive=forge_positive,
        defense_memory_write=defense_memory_write,
        omit_defense_reason=omit_defense_reason,
    )
    outcome = replay.result.artifact_set.outcome
    oracle = outcome.oracle_result

    assert outcome.execution_status is ReplayExecutionStatus.SUCCEEDED
    assert oracle is not None
    assert oracle.verdict is expected_verdict
    assert oracle.support_count == expected_support
    assert oracle.contradiction_count == expected_contradiction
    assert len(oracle.supporting_evidence) == expected_support
    assert len(oracle.contradicting_evidence) == expected_contradiction
    assert outcome.supports_claim is (expected_verdict is ReplayOracleVerdict.SUPPORTS)
    assert outcome.contradicts_claim is (expected_verdict is ReplayOracleVerdict.CONTRADICTS)


def test_negative_retest_rejects_defense_with_tool_side_effects(tmp_path: Path) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.model.system-prompt-disclosure",
        support=[False, False],
        negative_retest=True,
        explicit_defense=True,
        defense_tool_call=True,
    )
    oracle = replay.result.artifact_set.outcome.oracle_result

    assert oracle is not None
    assert oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE
    assert oracle.contradiction_count == 0


def test_negative_retest_does_not_trust_safety_flag_on_generic_refusal(
    tmp_path: Path,
) -> None:
    unblocked = _run_replay(
        tmp_path / "unblocked",
        "kisa.model.system-prompt-disclosure",
        support=[False, False],
        negative_retest=True,
    )
    flagged = _run_replay(
        tmp_path / "flagged",
        "kisa.model.system-prompt-disclosure",
        support=[False, False],
        negative_retest=True,
        explicit_defense=True,
        generic_refusal=True,
    )

    for replay in (unblocked, flagged):
        oracle = replay.result.artifact_set.outcome.oracle_result
        assert oracle is not None
        assert oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE
        assert oracle.contradiction_count == 0


def test_negative_retest_accepts_hardened_memory_non_persistence(
    tmp_path: Path,
) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.agent.memory-poisoning-persistence",
        support=[False, False],
        negative_retest=True,
        explicit_defense=True,
    )
    outcome = replay.result.artifact_set.outcome
    oracle = outcome.oracle_result

    assert oracle is not None
    assert oracle.verdict is ReplayOracleVerdict.CONTRADICTS
    assert oracle.contradiction_count == 2
    assert outcome.contradicts_claim is True
    for attempt in outcome.attempts:
        transcript = AIChatProbeOutput.model_validate(attempt.observation["transcript"])
        assert transcript.turns[0].response.safety.blocked is True
        assert transcript.turns[1].response.safety.blocked is False
        assert all(
            "PAJIN_MEMORY_POISON" not in turn.response.message.content for turn in transcript.turns
        )


def test_future_chat_scenario_does_not_implicitly_opt_in_to_automatic_replay() -> None:
    future = _scenario("kisa.model.system-prompt-disclosure").model_copy(
        update={"scenario_id": "kisa.model.future-chat-probe"}
    )
    catalog = KISACatalog(
        threats=KISA_CATALOG.threats,
        scenarios=(*KISA_CATALOG.scenarios, future),
        checklist=KISA_CATALOG.checklist,
    )

    assert future not in replayable_kisa_scenarios(catalog)
    with pytest.raises(KeyError, match="unknown replayable KISA scenario"):
        kisa_replay_contract(future.scenario_id, catalog=catalog)


@pytest.mark.parametrize(
    "scenario_id",
    [
        "kisa.model.system-prompt-disclosure",
        "kisa.model.jailbreak-policy-bypass",
        "kisa.agent.memory-poisoning-persistence",
    ],
)
def test_live_kisa_oracle_supports_raw_markers_in_unique_fresh_sessions(
    tmp_path: Path,
    scenario_id: str,
) -> None:
    replay = _run_replay(tmp_path, scenario_id, support=[True, True])
    outcome = replay.result.artifact_set.outcome

    assert outcome.execution_status is ReplayExecutionStatus.SUCCEEDED
    assert outcome.oracle_result is not None
    assert outcome.oracle_result.verdict is ReplayOracleVerdict.SUPPORTS
    assert outcome.oracle_result.support_count == 2
    assert outcome.supports_claim is True
    assert len(set(replay.worker.sessions)) == 2
    assert replay.source_session not in replay.worker.sessions
    assert all(attempt.materialization is not None for attempt in outcome.attempts)
    assert all(
        "vulnerable" in attempt.observation["transcript"]
        and attempt.observation["semanticSupport"] is True
        for attempt in outcome.attempts
    )


@pytest.mark.parametrize(
    ("support", "forge_positive", "expected_support"),
    [
        ([True, False], False, 1),
        ([False, False], True, 0),
    ],
)
def test_live_kisa_oracle_ignores_worker_verdicts_and_keeps_live_misses_inconclusive(
    tmp_path: Path,
    support: list[bool],
    forge_positive: bool,
    expected_support: int,
) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.model.system-prompt-disclosure",
        support=support,
        forge_positive=forge_positive,
    )
    oracle = replay.result.artifact_set.outcome.oracle_result

    assert oracle is not None
    assert oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE
    assert oracle.support_count == expected_support
    assert replay.result.artifact_set.outcome.supports_claim is False


def test_memory_poison_oracle_requires_persistence_in_the_later_turn(tmp_path: Path) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.agent.memory-poisoning-persistence",
        support=[False, False],
        forge_positive=True,
        first_turn_echo=True,
    )
    oracle = replay.result.artifact_set.outcome.oracle_result

    assert oracle is not None
    assert oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE
    assert oracle.support_count == 0


def test_kisa_oracle_rejects_substituted_transcript_template(tmp_path: Path) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.model.jailbreak-policy-bypass",
        support=[True, True],
        mutate_turn_message=True,
    )

    assert replay.result.artifact_set.outcome.execution_status is ReplayExecutionStatus.FAILED
    assert replay.result.artifact_set.outcome.oracle_result is None


@pytest.mark.parametrize("identity", ["target", "scenario", "threat", "session", "network"])
def test_kisa_replay_rejects_output_identity_substitution(
    tmp_path: Path,
    identity: str,
) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.model.system-prompt-disclosure",
        support=[True, True],
        mutate_identity=identity,
    )

    assert replay.result.artifact_set.outcome.execution_status is ReplayExecutionStatus.FAILED
    assert replay.result.artifact_set.outcome.supports_claim is False


def test_runtime_rejects_materializer_changes_outside_session_without_dispatch(
    tmp_path: Path,
) -> None:
    replay = _run_replay(
        tmp_path,
        "kisa.model.system-prompt-disclosure",
        support=[True, True],
        mutating_materializer=True,
    )

    assert replay.worker.jobs == []
    assert replay.result.artifact_set.outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED
    run = json.loads((replay.replay_store.path / "run.json").read_text(encoding="utf-8"))
    assert run["reason"] == ReplayRuntimeReason.SESSION_MATERIALIZATION_INVALID.value


def test_scenario_digest_is_stable_across_python_hash_seeds() -> None:
    script = (
        "from pajin.modes.ai_redteam.catalog import KISA_CATALOG;"
        "from pajin.replay.compiler import replay_scenario_digest;"
        "s=next(x for x in KISA_CATALOG.scenarios if "
        "x.scenario_id=='kisa.model.system-prompt-disclosure');"
        "print(replay_scenario_digest(s))"
    )
    digests = set()
    for seed in ("1", "2", "3", "99"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path.cwd(),
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        )
        digests.add(completed.stdout.strip())

    assert digests == {replay_scenario_digest(_scenario("kisa.model.system-prompt-disclosure"))}


def test_kisa_coordinator_promotes_only_through_the_common_confirmed_gate(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    thresholds = EvaluationThresholds(repetitions=2)
    tools = ToolRegistry()
    tools.register(AIChatProbeTool())
    worker = TranscriptWorker([True] * 12)
    policy = PolicyEngine()
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=policy,
        worker=worker,
        output_root=tmp_path / "candidate-runs",
    )
    coordinator = KISAReplayCoordinator(
        tools=tools,
        policy=policy,
        worker=worker,
        output_root=tmp_path / "replay-runs",
        repetitions=2,
        required_successes=2,
    )

    async def execute():
        outcome = await runner.run(campaign, budget=budget, rate_limits=rate_limits)
        with pytest.raises(ValueError, match="sealed source Run budget state"):
            await coordinator.reproduce(
                campaign,
                outcome.run_path,
                budget=BudgetController(campaign.spec.budgets),
                rate_limits=rate_limits,
            )
        with pytest.raises(ValueError, match="sealed source Run rate-limit ledger"):
            await coordinator.reproduce(
                campaign,
                outcome.run_path,
                budget=budget,
                rate_limits=RequestRateLimitLedger(),
            )
        batch = await coordinator.reproduce(
            campaign,
            outcome.run_path,
            budget=budget,
            rate_limits=rate_limits,
        )
        return outcome, batch

    outcome, batch = asyncio.run(execute())
    forged_records = (
        batch.records[0].model_copy(update={"supports_claim": False}),
        *batch.records[1:],
    )
    forged_batch = replace(batch, records=forged_records)
    with pytest.raises(ValueError, match="public records differ"):
        KISAModePack(thresholds=thresholds).evaluate(campaign, outcome, forged_batch)
    with pytest.raises(KeyError, match="unknown replay execution ticket"):
        apply_confirmed_gate(
            source_run_path=outcome.run_path,
            replay_run_paths=[result.run_path for result in batch.verified_results.values()],
            tickets=ReplayExecutionAuthority().verifier(),
        )
    assert not (outcome.run_path / "validation/v1alpha1/index.json").exists()

    mutable_result = next(iter(batch.verified_results.values()))
    assert mutable_result.artifact_set.outcome.oracle_result is not None
    mutable_result.artifact_set.outcome.oracle_result.verdict = ReplayOracleVerdict.INCONCLUSIVE
    assert mutable_result.artifact_set.outcome.supports_claim is False
    source_root_digest = verify_run_integrity(outcome.run_path).root_digest
    confirmation = apply_confirmed_gate(
        source_run_path=outcome.run_path,
        replay_run_paths=[result.run_path for result in batch.verified_results.values()],
        tickets=batch.authority.verifier(),
    )
    outcome = outcome.model_copy(
        update={
            "validation": confirmation.validation,
            "findings": confirmation.product_confirmed_findings,
        }
    )
    assert len(outcome.findings) == 3
    mutable_result.artifact_set.outcome.oracle_result.verdict = ReplayOracleVerdict.SUPPORTS
    mode_outcome = KISAModePack(thresholds=thresholds).evaluate(
        campaign,
        outcome,
        batch,
    )

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.findings) == 3
    assert len(batch.records) == 3
    assert all(record.supports_claim for record in batch.records)
    assert all(record.replay_run_id != outcome.run_id for record in batch.records)
    assert all(
        decision.disposition is FindingDisposition.CONFIRMED
        and decision.confirmation_basis is ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
        and decision.reason_codes == [ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED]
        and len(decision.replay_lineage) == 1
        for decision in outcome.validation.decisions
    )
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    versioned_findings = json.loads(
        (outcome.run_path / "validation/v1alpha1/findings.json").read_text(encoding="utf-8")
    )
    assert len(versioned_findings["findings"]) == 3
    seals = [
        json.loads(line)
        for line in (outcome.run_path / "run-integrity.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert source_root_digest in {seal["root_digest"] for seal in seals}
    assert verify_run_integrity(outcome.run_path).root_digest != source_root_digest
    assert budget.tool_calls == 12
    assert len(set(worker.sessions)) == 12
    assert set(worker.sessions[:6]).isdisjoint(worker.sessions[6:])
    assert mode_outcome.replay_index_path is not None
    replay_index = json.loads(mode_outcome.replay_index_path.read_text(encoding="utf-8"))
    assert replay_index["confirmationMutationApplied"] is True
    assert replay_index["confirmationArtifact"] == "validation/v1alpha1/index.json"
    assert len(replay_index["records"]) == 3
    assert mode_outcome.assessment.confirmation_semantics == "verified-independent-replay"
    assert mode_outcome.assessment.validation_artifact_version == ("pajin.dev/validation/v1alpha1")
    assert mode_outcome.assessment.confirmation_artifact == "validation/v1alpha1/index.json"
    report = mode_outcome.report_path.read_text(encoding="utf-8")
    assert "Confirmation semantics: `verified-independent-replay`" in report
    assert "Confirmation basis: `verified-independent-replay`" in report
    assert "Source evidence count:" in report
    assert "ReplayOutcome:" in report
    assert "Replay evidence count:" in report
    assert "Receipt seal:" in report
    assert "Receipt seal:" in (outcome.run_path / "validation/v1alpha1/report.md").read_text(
        encoding="utf-8"
    )


def test_kisa_retest_coordinator_binds_negative_receipts_to_both_sealed_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign()
    thresholds = EvaluationThresholds(repetitions=2)
    tools = ToolRegistry()
    tools.register(AIChatProbeTool())
    policy = PolicyEngine()
    baseline_worker = TranscriptWorker([True] * 12)
    baseline_budget = BudgetController(campaign.spec.budgets)
    baseline_rates = RequestRateLimitLedger()
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=policy,
        worker=baseline_worker,
        output_root=tmp_path / "candidate-runs",
    )
    confirmation_coordinator = KISAReplayCoordinator(
        tools=tools,
        policy=policy,
        worker=baseline_worker,
        output_root=tmp_path / "confirmation-runs",
        repetitions=2,
        required_successes=2,
    )

    async def create_baseline():
        outcome = await runner.run(
            campaign,
            budget=baseline_budget,
            rate_limits=baseline_rates,
        )
        batch = await confirmation_coordinator.reproduce(
            campaign,
            outcome.run_path,
            budget=baseline_budget,
            rate_limits=baseline_rates,
        )
        return outcome, batch

    baseline, confirmation_batch = asyncio.run(create_baseline())
    confirmation = apply_confirmed_gate(
        source_run_path=baseline.run_path,
        replay_run_paths=[
            result.run_path for result in confirmation_batch.verified_results.values()
        ],
        tickets=confirmation_batch.authority.verifier(),
    )
    baseline = baseline.model_copy(
        update={
            "validation": confirmation.validation,
            "findings": confirmation.product_confirmed_findings,
        }
    )
    KISAModePack(thresholds=thresholds).evaluate(
        campaign,
        baseline,
        confirmation_batch,
    )
    remediation = KISARetestService().create_remediation_plan(baseline.run_path)
    baseline_root_digest = verify_run_integrity(baseline.run_path).root_digest

    retest_budget = BudgetController(campaign.spec.budgets)
    retest_rates = RequestRateLimitLedger()

    def parent_retest_store(
        directory: str,
        plan: AgentPlan,
        *,
        write_normal_evidence: bool,
        attempt_successes: tuple[bool, ...] = (True,),
        write_extra_evidence: bool = False,
    ) -> tuple[RunStore, str]:
        store = RunStore.create(tmp_path / directory, campaign.metadata.name)
        store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
        store.write_json("plan.json", plan.model_dump(mode="json"))
        task_graph = TaskGraph()
        for step in plan.steps:
            agent_id = f"agent:specialist:{step.step_id}"
            bound_request = step.request.model_copy(update={"agent_id": agent_id})
            task_graph.add(
                TaskNode(
                    title=step.title,
                    assigned_agent_id=agent_id,
                    status=(TaskStatus.SUCCEEDED if attempt_successes[-1] else TaskStatus.FAILED),
                    request=bound_request,
                    attempts=len(attempt_successes),
                    max_attempts=max(2, len(attempt_successes)),
                )
            )
            if not write_normal_evidence:
                continue
            for attempt, success in enumerate(attempt_successes, start=1):
                request_id = (
                    bound_request.request_id
                    if attempt == 1
                    else f"{bound_request.request_id}_attempt{attempt}"
                )
                executed = bound_request.model_copy(update={"request_id": request_id})
                result = ToolResult(
                    request_id=request_id,
                    tool_id=executed.tool_id,
                    success=success,
                    started_at=NOW,
                    finished_at=NOW,
                    error=None if success else "normal regression failed",
                )
                store.write_json(
                    f"evidence/{request_id}.json",
                    {
                        "request": executed.model_dump(mode="json"),
                        "result": result.model_dump(mode="json"),
                    },
                )
        store.write_json("task-graph.json", task_graph.model_dump(mode="json"))
        if write_extra_evidence:
            extra_request = ToolRequest(
                agent_id="agent:specialist:extra",
                tool_id="unplanned.audit-probe",
                target=campaign.spec.targets[0].endpoint,
                method="POST",
                arguments={},
            )
            extra_result = ToolResult(
                request_id=extra_request.request_id,
                tool_id=extra_request.tool_id,
                success=True,
                started_at=NOW,
                finished_at=NOW,
            )
            store.write_json(
                f"evidence/{extra_request.request_id}.json",
                {
                    "request": extra_request.model_dump(mode="json"),
                    "result": extra_result.model_dump(mode="json"),
                },
            )
        store.write_json("budget.json", retest_budget.snapshot())
        store.write_json("rate-limits.json", retest_rates.snapshot())
        store.write_json(
            "run.json",
            {"runId": store.run_id, "status": "completed"},
        )
        store.append_event("retest.completed", {"status": "completed"})
        return store, store.seal().root_digest

    normal_plan = asyncio.run(KISARetestPlannerRuntime(thresholds=thresholds).plan(campaign))
    retest_store, retest_root_digest = parent_retest_store(
        "parent-retest",
        normal_plan,
        write_normal_evidence=True,
        attempt_successes=(False, False),
    )

    def contexts_for(store: RunStore, root_digest: str):
        return {
            action.baseline_candidate_id: ReplayRetestContext(
                baseline_decision_id=action.baseline_decision_id,
                baseline_finding_id=action.baseline_finding_id,
                remediation_id=action.remediation_id,
                retest_run_id=store.run_id,
                retest_source_root_digest=root_digest,
            )
            for action in remediation.actions
        }

    contexts = contexts_for(retest_store, retest_root_digest)
    negative_worker = TranscriptWorker(
        [False] * 6,
        explicit_defense=True,
        forge_positive=True,
    )
    retest_coordinator = KISARetestReplayCoordinator(
        tools=tools,
        policy=policy,
        worker=negative_worker,
        output_root=tmp_path / "negative-runs",
        repetitions=2,
    )
    attack_plan = AgentPlan.model_validate_json(
        (baseline.run_path / "plan.json").read_text(encoding="utf-8")
    )
    attack_store, attack_root_digest = parent_retest_store(
        "attack-parent-retest",
        attack_plan,
        write_normal_evidence=False,
    )
    with pytest.raises(ValueError, match="only normal probes"):
        asyncio.run(
            retest_coordinator.reproduce(
                campaign,
                baseline.run_path,
                attack_store.path,
                contexts=contexts_for(attack_store, attack_root_digest),
                budget=retest_budget,
                rate_limits=retest_rates,
            )
        )
    assert negative_worker.jobs == []

    missing_evidence_store, missing_evidence_root = parent_retest_store(
        "missing-evidence-parent-retest",
        normal_plan,
        write_normal_evidence=False,
    )
    with pytest.raises(ValueError, match="exactly cover every Task attempt"):
        asyncio.run(
            retest_coordinator.reproduce(
                campaign,
                baseline.run_path,
                missing_evidence_store.path,
                contexts=contexts_for(missing_evidence_store, missing_evidence_root),
                budget=retest_budget,
                rate_limits=retest_rates,
            )
        )
    assert negative_worker.jobs == []

    extra_evidence_store, extra_evidence_root = parent_retest_store(
        "extra-evidence-parent-retest",
        normal_plan,
        write_normal_evidence=True,
        write_extra_evidence=True,
    )
    with pytest.raises(ValueError, match="not bound to a planned normal probe"):
        asyncio.run(
            retest_coordinator.reproduce(
                campaign,
                baseline.run_path,
                extra_evidence_store.path,
                contexts=contexts_for(extra_evidence_store, extra_evidence_root),
                budget=retest_budget,
                rate_limits=retest_rates,
            )
        )
    assert negative_worker.jobs == []

    retry_after_success_store, retry_after_success_root = parent_retest_store(
        "retry-after-success-parent-retest",
        normal_plan,
        write_normal_evidence=True,
        attempt_successes=(True, False),
    )
    with pytest.raises(ValueError, match="cannot retry after a successful attempt"):
        asyncio.run(
            retest_coordinator.reproduce(
                campaign,
                baseline.run_path,
                retry_after_success_store.path,
                contexts=contexts_for(retry_after_success_store, retry_after_success_root),
                budget=retest_budget,
                rate_limits=retest_rates,
            )
        )
    assert negative_worker.jobs == []

    batch = asyncio.run(
        retest_coordinator.reproduce(
            campaign,
            baseline.run_path,
            retest_store.path,
            contexts=contexts,
            budget=retest_budget,
            rate_limits=retest_rates,
        )
    )
    records = batch.verified_records(baseline.run_path, retest_store.path)

    assert batch.purpose is ReplayPurpose.REMEDIATION_RETEST
    assert batch.baseline_run_id == baseline.run_id
    assert batch.retest_run_id == retest_store.run_id
    parent_task_graph = TaskGraph.model_validate_json(
        (retest_store.path / "task-graph.json").read_text(encoding="utf-8")
    )
    assert all(
        task.status is TaskStatus.FAILED
        for task in parent_task_graph.tasks.values()
        if task.request is not None
    )
    assert len(records) == 3
    assert all(record.oracle_verdict is ReplayOracleVerdict.CONTRADICTS for record in records)
    assert all(record.contradicts_claim and record.all_attempts_succeeded for record in records)
    assert all(record.replay_lineage is not None for record in records)
    assert all(
        result.receipt.candidate_source_root_digest == baseline_root_digest
        for result in batch.verified_results.values()
    )
    assert retest_budget.tool_calls == 6

    forged_batch = replace(
        batch,
        records=(
            batch.records[0].model_copy(update={"contradicts_claim": False}),
            *batch.records[1:],
        ),
    )
    with pytest.raises(ValueError, match="public records differ"):
        forged_batch.verified_records(baseline.run_path, retest_store.path)

    candidate_id = next(iter(batch.verified_results))
    snapshot_result = batch.verified_results[candidate_id]
    one_repetition_contract = snapshot_result.artifact_set.contract.model_copy(
        update={
            "repetitions": 1,
            "required_successes": 1,
            "required_contradictions": 1,
        }
    )
    one_repetition_spec = snapshot_result.artifact_set.spec.model_copy(
        update={
            "repetitions": 1,
            "required_successes": 1,
            "required_contradictions": 1,
        }
    )
    one_repetition_result = snapshot_result.model_copy(
        update={
            "artifact_set": snapshot_result.artifact_set.model_copy(
                update={
                    "contract": one_repetition_contract,
                    "spec": one_repetition_spec,
                }
            )
        }
    )
    one_repetition_results = dict(batch.verified_results)
    one_repetition_results[candidate_id] = one_repetition_result
    one_repetition_batch = replace(batch, verified_results=one_repetition_results)
    results_by_path = {
        result.run_path.resolve(): result for result in one_repetition_results.values()
    }
    monkeypatch.setattr(
        replay_module,
        "load_verified_replay_result",
        lambda run_path, *, tickets: results_by_path[run_path.resolve()],
    )
    with pytest.raises(ValueError, match="between 2 and 20 repetitions"):
        one_repetition_batch.verified_records(baseline.run_path, retest_store.path)

    forged_contexts = dict(contexts)
    candidate_id = next(iter(forged_contexts))
    forged_contexts[candidate_id] = forged_contexts[candidate_id].model_copy(
        update={"retest_source_root_digest": "f" * 64}
    )
    with pytest.raises(ValueError, match="context differs"):
        asyncio.run(
            retest_coordinator.reproduce(
                campaign,
                baseline.run_path,
                retest_store.path,
                contexts=forged_contexts,
                budget=retest_budget,
                rate_limits=retest_rates,
            )
        )


def test_kisa_cli_defaults_to_docker_and_rejects_unreserved_replay_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_workers: list[str] = []

    def worker_backend(worker: str):
        selected_workers.append(worker)
        return object()

    monkeypatch.setattr(cli_module, "_worker_backend", worker_backend)
    result = CliRunner().invoke(
        cli_module.app,
        ["kisa-run", "examples/kisa-ai-chat-lab.yaml", "--repetitions", "3"],
    )

    assert result.exit_code == 2
    assert selected_workers == ["docker"]
    assert "requires at least 18" in result.output
