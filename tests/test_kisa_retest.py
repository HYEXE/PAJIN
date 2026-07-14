import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.orchestration import RunStatus
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import ChecklistStatus, EvaluationThresholds
from pajin.modes.ai_redteam.retest import (
    KISARetestService,
    RegressionStatus,
    RetestFindingStatus,
)
from pajin.modes.ai_redteam.runtime import (
    KISAPlannerRuntime,
    KISARetestPlannerRuntime,
    KISAValidatorRuntime,
)
from pajin.modes.ai_redteam.service import KISAModePack
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import RunIntegrityError
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeTool, AIChatRegressionTool
from pajin.tools.base import ToolRegistry
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


class ProfileAIWorker:
    def __init__(self, *, vulnerable: bool, regression_passed: bool = True) -> None:
        self._vulnerable = vulnerable
        self._regression_passed = regression_passed

    async def run(self, job: WorkerJob) -> WorkerResult:
        started_at = datetime.now(UTC)
        assert job.command == ["ai-chat-probe"]
        assert job.network is NetworkMode.EGRESS_PROXY
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        purpose = probe.get("purpose", "attack")
        checks_should_match = self._vulnerable if purpose == "attack" else self._regression_passed
        turns = []
        for index, turn in enumerate(probe["turns"]):
            markers = [
                check["value"]
                for check in probe["checks"]
                if checks_should_match
                and check["turn"] == index
                and check["kind"] == "response-contains"
            ]
            content = " ".join(["safe normal response", *markers])
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
                        "safety": {
                            "blocked": purpose == "attack" and not self._vulnerable,
                            "reason": "hardened" if not self._vulnerable else None,
                        },
                        "memoryWrites": [],
                    },
                    "responseLatencySeconds": 0.01,
                }
            )
        checks = [
            {
                "checkId": check["check_id"],
                "kind": check["kind"],
                "turn": check["turn"],
                "matched": checks_should_match,
                "sensitive": check["sensitive"],
            }
            for check in probe["checks"]
        ]
        output = {
            "target": payload["target"],
            "scenarioId": probe["scenario_id"],
            "threatClass": probe["threat_class"],
            "sessionId": probe["session_id"],
            "purpose": purpose,
            "vulnerable": checks_should_match if purpose == "attack" else False,
            "observation": "profile-controlled test observation",
            "turns": turns,
            "checks": checks,
            "sensitiveExposureCount": sum(
                check["matched"] and check["sensitive"] for check in checks
            ),
            "meanResponseLatencySeconds": 0.01,
            "regressionPassed": checks_should_match if purpose == "regression" else None,
            "networkPerformed": True,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="profile-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


def _campaign():
    return load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(AIChatProbeTool())
    registry.register(AIChatRegressionTool())
    return registry


def _run(
    tmp_path: Path,
    *,
    retest: bool,
    vulnerable: bool,
    regression_passed: bool = True,
):
    thresholds = EvaluationThresholds(repetitions=2)
    planner = (
        KISARetestPlannerRuntime(thresholds=thresholds)
        if retest
        else KISAPlannerRuntime(thresholds=thresholds)
    )
    runner = MultiAgentCampaignRunner(
        planner=planner,
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=_registry(),
        policy=PolicyEngine(),
        worker=ProfileAIWorker(
            vulnerable=vulnerable,
            regression_passed=regression_passed,
        ),
        output_root=tmp_path,
    )
    outcome = asyncio.run(runner.run(_campaign()))
    mode = KISAModePack(thresholds=thresholds).evaluate(_campaign(), outcome)
    return outcome, mode


def test_retest_planner_separates_attack_and_normal_function_tasks() -> None:
    plan = asyncio.run(KISARetestPlannerRuntime().plan(_campaign()))

    assert len(plan.steps) == 8
    assert sum(step.request.tool_id == "ai.chat-probe" for step in plan.steps) == 6
    assert sum(step.request.tool_id == "ai.normal-probe" for step in plan.steps) == 2
    assert all(
        step.scenario_id is None for step in plan.steps if step.request.tool_id == "ai.normal-probe"
    )


def test_retest_requires_remediation_plan_before_comparison(tmp_path: Path) -> None:
    baseline, _ = _run(tmp_path, retest=False, vulnerable=True)
    retest, _ = _run(tmp_path, retest=True, vulnerable=False)

    with pytest.raises(ValueError, match="must be created before"):
        KISARetestService().compare(baseline.run_path, retest.run_path)


def test_retest_closes_findings_and_emits_kisa_overlay(tmp_path: Path) -> None:
    baseline, _ = _run(tmp_path, retest=False, vulnerable=True)
    retest, retest_mode = _run(tmp_path, retest=True, vulnerable=False)

    service = KISARetestService()
    plan = service.create_remediation_plan(baseline.run_path)
    result = service.compare(baseline.run_path, retest.run_path)

    assert baseline.status is RunStatus.COMPLETED
    assert retest.status is RunStatus.COMPLETED
    assert len(baseline.findings) == 3
    assert len(plan.actions) == 3
    assert plan.path == baseline.run_path / "remediation-plan.json"
    assert retest.findings == []
    assert len(retest.tool_results) == 8
    assert result.assessment.summary.fixed == 3
    assert result.assessment.summary.still_vulnerable == 0
    assert result.assessment.summary.inconclusive == 0
    assert result.assessment.summary.new_findings == 0
    assert result.assessment.summary.regression is RegressionStatus.PASS
    assert all(
        item.status is RetestFindingStatus.FIXED for item in result.assessment.finding_results
    )
    assert all(len(item.retest_evidence) == 2 for item in result.assessment.finding_results)

    overlay = {item.item_id: item for item in result.assessment.checklist_overlay.items}
    assert overlay["report.mitigation"].status is ChecklistStatus.YES
    assert overlay["improve.tasks"].status is ChecklistStatus.NEEDS_REVIEW
    assert overlay["improve.retest"].status is ChecklistStatus.YES
    assert overlay["improve.normal"].status is ChecklistStatus.YES
    assert overlay["improve.regression"].status is ChecklistStatus.YES
    assert {
        "remediation-plan.json",
        "kisa-retest.json",
        "kisa-checklist-overlay.json",
        "kisa-retest-report.md",
    } <= {path.name for path in retest.run_path.iterdir()}

    metrics = {item.metric_id: item for item in retest_mode.assessment.metrics}
    assert metrics["attack-success-rate"].value == 0
    assert metrics["block-refusal-rate"].value == 1


def test_retest_keeps_validated_findings_open(tmp_path: Path) -> None:
    baseline, _ = _run(tmp_path, retest=False, vulnerable=True)
    retest, _ = _run(tmp_path, retest=True, vulnerable=True)

    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    result = service.compare(baseline.run_path, retest.run_path)

    assert result.assessment.summary.fixed == 0
    assert result.assessment.summary.still_vulnerable == 3
    assert all(
        item.status is RetestFindingStatus.STILL_VULNERABLE
        for item in result.assessment.finding_results
    )
    assert result.assessment.summary.regression is RegressionStatus.PASS


def test_retest_rejects_run_when_sealed_repeat_evidence_is_missing(
    tmp_path: Path,
) -> None:
    baseline, _ = _run(tmp_path, retest=False, vulnerable=True)
    retest, _ = _run(tmp_path, retest=True, vulnerable=False)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    m03_evidence = []
    for path in (retest.run_path / "evidence").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload["result"]["data"].get("threatClass") == "M03":
            m03_evidence.append(path)
    assert len(m03_evidence) == 2
    m03_evidence[0].unlink()

    with pytest.raises(RunIntegrityError, match="sealed Run artifact is missing"):
        service.compare(baseline.run_path, retest.run_path)
