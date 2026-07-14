import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import (
    AgentPlan,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
    ToolResult,
)
from pajin.domain.orchestration import RunStatus
from pajin.domain.validation import FindingDisposition, ValidationReasonCode
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.modes.ai_redteam.models import EvaluationThresholds, MetricStatus
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime, KISAValidatorRuntime
from pajin.modes.ai_redteam.service import KISAModePack
from pajin.policy.engine import PolicyEngine
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _campaign():
    return load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))


class ContractAIWorker:
    """Return a vulnerable transcript while preserving the real Worker contract."""

    def __init__(self, *, expose_markers: bool = True) -> None:
        self._expose_markers = expose_markers

    async def run(self, job: WorkerJob) -> WorkerResult:
        started_at = datetime.now(UTC)
        assert job.command == ["ai-chat-probe"]
        assert job.network is NetworkMode.EGRESS_PROXY
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        turns = []
        for index, turn in enumerate(probe["turns"]):
            markers = [
                check["value"]
                for check in probe["checks"]
                if check["turn"] == index and check["kind"] == "response-contains"
            ]
            content = (
                " ".join(["lab response", *markers])
                if self._expose_markers
                else "lab response without a catalog compromise marker"
            )
            turns.append(
                {
                    "index": index,
                    "name": turn["name"],
                    "request": {
                        "sessionId": probe["session_id"],
                        "messages": turn["messages"],
                    },
                    "response": {
                        "sessionId": probe["session_id"],
                        "message": {"role": "assistant", "content": content},
                        "safety": {"blocked": False, "reason": None},
                        "memoryWrites": [],
                    },
                }
            )
        checks = [
            {
                "checkId": check["check_id"],
                "kind": check["kind"],
                "turn": check["turn"],
                "matched": True,
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
            "vulnerable": True,
            "observation": "all scenario compromise indicators were observed",
            "turns": turns,
            "checks": checks,
            "sensitiveExposureCount": sum(
                check["matched"] and check["sensitive"] for check in checks
            ),
            "meanResponseLatencySeconds": 0.01,
            "networkPerformed": True,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="contract-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


class OmissionValidator:
    """Model a semantic Validator that returns a valid but empty result."""

    async def validate(self, campaign, plan, results):
        del campaign, plan, results
        return []


class ValidatorOnlyConfirmation:
    """Attempt to confirm a benign producer-owned observation through legacy output."""

    async def validate(self, campaign, plan, results):
        del campaign, plan
        result = results[0]
        return [
            Finding(
                finding_id="validator_only_bypass_attempt",
                title="Validator-only catalog claim",
                severity=FindingSeverity.HIGH,
                threat_class="M03",
                target=str(result.data["target"]),
                summary="The Validator claims a marker that the raw transcript does not contain.",
                reproduction=["Review the cited catalog execution."],
                evidence=result.evidence,
                confidence=1,
                validated=True,
            )
        ]


def test_ai_chat_probe_tool_prepares_only_fixed_post_contract() -> None:
    scenario = next(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.model.system-prompt-disclosure"
    )
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class="M03",
        session_id="pajin:test:prompt:1",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    tool = AIChatProbeTool()
    request = ToolRequest(
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )

    job = tool.prepare(request)

    assert job.command == ["ai-chat-probe"]
    assert job.network is NetworkMode.NONE
    assert json.loads(job.stdin) == {
        "target": request.target,
        "probe": probe.model_dump(mode="json"),
    }
    with pytest.raises(ValueError, match="require POST"):
        tool.prepare(request.model_copy(update={"method": "GET"}))


def test_kisa_planner_builds_six_unique_ai_probe_tasks() -> None:
    plan = asyncio.run(
        KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=2)).plan(_campaign())
    )

    assert len(plan.steps) == 6
    assert {step.scenario_id for step in plan.steps} == {
        "kisa.model.system-prompt-disclosure",
        "kisa.model.jailbreak-policy-bypass",
        "kisa.agent.memory-poisoning-persistence",
    }
    assert all(step.request.tool_id == "ai.chat-probe" for step in plan.steps)
    probes = [AIChatProbeInput.model_validate(step.request.arguments) for step in plan.steps]
    assert len({probe.session_id for probe in probes}) == 6
    assert {probe.threat_class for probe in probes} == {"M03", "M06", "A04"}


def test_independent_validator_rejects_claim_without_transcript_marker() -> None:
    scenario = next(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.model.system-prompt-disclosure"
    )
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class="M03",
        session_id="pajin:test:forged:1",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    request = ToolRequest(
        agent_id="agent:specialist",
        tool_id="ai.chat-probe",
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )
    plan = AgentPlan(
        summary="forged vulnerable flag test",
        steps=[
            PlannedStep(
                request=request,
                title="probe",
                rationale="validator must inspect the transcript",
                scenario_id=scenario.scenario_id,
                threat_classes={"M03"},
            )
        ],
    )
    now = datetime.now(UTC)
    result = ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        evidence=["evidence/forged.json"],
        data={
            "target": request.target,
            "scenarioId": probe.scenario_id,
            "threatClass": probe.threat_class,
            "sessionId": probe.session_id,
            "vulnerable": True,
            "turns": [
                {"response": {"message": {"role": "assistant", "content": "I cannot reveal that."}}}
            ],
            "checks": [{"matched": True}],
            "sensitiveExposureCount": 0,
        },
    )

    findings = asyncio.run(
        KISAValidatorRuntime(DeterministicAgentRuntime()).validate(_campaign(), plan, [result])
    )

    assert findings == []


def test_ai_chat_kisa_mode_runs_all_scenarios_and_deduplicates_findings(
    tmp_path: Path,
) -> None:
    thresholds = EvaluationThresholds(repetitions=2)
    registry = ToolRegistry()
    registry.register(AIChatProbeTool())
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=registry,
        policy=PolicyEngine(),
        worker=ContractAIWorker(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))
    mode_outcome = KISAModePack(thresholds=thresholds).evaluate(_campaign(), outcome)

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.tool_results) == 6
    assert {finding.threat_class for finding in outcome.findings} == {"M03", "M06", "A04"}
    assert all(len(finding.evidence) == 2 for finding in outcome.findings)
    assessment = mode_outcome.assessment
    assert assessment.coverage.executed == {"M03", "M06", "A04"}
    assert assessment.coverage.untested == set()
    assert assessment.coverage.coverage_rate == 1
    metrics = {metric.metric_id: metric for metric in assessment.metrics}
    assert metrics["attack-success-rate"].value == 1
    assert metrics["reproducibility-rate"].value == 1
    assert metrics["sensitive-exposure-count"].value == 2
    assert metrics["sensitive-exposure-count"].status is MetricStatus.FAIL
    assert metrics["mean-response-latency"].value == pytest.approx(0.01)
    assert metrics["mean-response-latency"].status is MetricStatus.PASS


def test_kisa_candidate_survives_validator_omission_without_confirmation(
    tmp_path: Path,
) -> None:
    thresholds = EvaluationThresholds(repetitions=2)
    registry = ToolRegistry()
    registry.register(AIChatProbeTool())
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=OmissionValidator(),
        candidate_producer=KISACandidateProducer(),
        tools=registry,
        policy=PolicyEngine(),
        worker=ContractAIWorker(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.findings == []
    assert len(outcome.validation.candidates) == 3
    assert all(
        candidate.claim.validated is False and candidate.source == "trusted-core:candidate-producer"
        for candidate in outcome.validation.candidates
    )
    assert all(
        decision.disposition is FindingDisposition.NEEDS_REVIEW
        and decision.reason_codes == [ValidationReasonCode.VALIDATOR_OMITTED]
        for decision in outcome.validation.decisions
    )
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    persisted = json.loads(
        (outcome.run_path / "candidate-findings.json").read_text(encoding="utf-8")
    )
    assert len(persisted) == 3


def test_validator_only_claim_cannot_bypass_kisa_candidate_authority(
    tmp_path: Path,
) -> None:
    thresholds = EvaluationThresholds(repetitions=2)
    registry = ToolRegistry()
    registry.register(AIChatProbeTool())
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=ValidatorOnlyConfirmation(),
        candidate_producer=KISACandidateProducer(),
        tools=registry,
        policy=PolicyEngine(),
        worker=ContractAIWorker(expose_markers=False),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.findings == []
    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.candidates[0].source == "legacy-validator-output"
    decision = outcome.validation.decisions[0]
    assert decision.disposition is FindingDisposition.NEEDS_REVIEW
    assert decision.reason_codes == [ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED]
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    produced = next(event for event in events if event["event_type"] == "candidate-set.produced")
    assert produced["payload"]["candidateCount"] == 0
    assert produced["payload"]["authoritativeRequestCount"] == 6
    assert produced["payload"]["authoritativeClaimCount"] == 3
