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
    ToolRiskTier,
)
from pajin.domain.orchestration import RunStatus
from pajin.domain.replay import (
    ReplayExecutionStatus,
    ReplayIntent,
    ReplayOracleVerdict,
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
    KISAAIChatReplayOracle,
    KISAAIChatSessionMaterializer,
    KISAReplayCoordinator,
    kisa_replay_contract,
    kisa_replay_registries,
    replayable_kisa_scenarios,
)
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime, KISAValidatorRuntime
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
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
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
    ) -> None:
        self._support = support
        self._forge_positive = forge_positive
        self._mutate_turn_message = mutate_turn_message
        self._mutate_identity = mutate_identity
        self._first_turn_echo = first_turn_echo
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
                        "safety": {"blocked": False, "reason": None},
                        "memoryWrites": [],
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
    contract = kisa_replay_contract(scenario_id)
    packet = ValidationPacket(
        packet_id=f"validation-packet_{threat_class.lower()}_1",
        candidate_run_id=source_store.run_id,
        candidate=candidate,
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
        oracles.register(KISAAIChatReplayOracle(scenario))
    else:
        materializers, oracles = kisa_replay_registries()
    worker = TranscriptWorker(
        support,
        forge_positive=forge_positive,
        mutate_turn_message=mutate_turn_message,
        mutate_identity=mutate_identity,
        first_turn_echo=first_turn_echo,
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
        assert contract.session_policy.value == "fresh-session"
        assert contract.ephemeral_argument_fields == {"session_id"}
        assert contract.semantic_support_required is True


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
