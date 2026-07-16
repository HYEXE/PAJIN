import asyncio
import json
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from pajin.domain.orchestration import RunStatus
from pajin.domain.validation import FindingDisposition, ValidationReasonCode
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.modes.ai_redteam.models import (
    ChecklistStatus,
    EvaluationThresholds,
    MetricStatus,
    ThreatFamily,
)
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime, KISAValidatorRuntime
from pajin.modes.ai_redteam.service import KISAModePack
from pajin.policy.engine import PolicyEngine
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _campaign() -> CampaignManifest:
    return load_manifest(Path("examples/kisa-ai-redteam.yaml"))


def _run_kisa(tmp_path: Path):
    thresholds = EvaluationThresholds(repetitions=2)
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    outcome = asyncio.run(runner.run(_campaign()))
    mode_outcome = KISAModePack(thresholds=thresholds).evaluate(_campaign(), outcome)
    return outcome, mode_outcome


def test_kisa_catalog_contains_all_guide_threats_and_checklist_items() -> None:
    codes = {threat.code for threat in KISA_CATALOG.threats}
    families = {
        family: sum(threat.family is family for threat in KISA_CATALOG.threats)
        for family in ThreatFamily
    }

    assert len(codes) == 19
    assert codes == {
        "D01",
        "D02",
        "D03",
        "M01",
        "M02",
        "M03",
        "M04",
        "M05",
        "M06",
        "M07",
        "M08",
        "A01",
        "A02",
        "A03",
        "A04",
        "S01",
        "S02",
        "S03",
        "S04",
    }
    assert families == {
        ThreatFamily.DATA: 3,
        ThreatFamily.MODEL: 8,
        ThreatFamily.AGENT: 4,
        ThreatFamily.SUPPLY_CHAIN: 4,
    }
    assert len(KISA_CATALOG.checklist) == 52
    assert all(item.source_pdf_pages <= {49, 50, 51} for item in KISA_CATALOG.checklist)


def test_kisa_planner_selects_and_repeats_scenario_with_trace_metadata() -> None:
    planner = KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=2))

    plan = asyncio.run(planner.plan(_campaign()))

    assert len(plan.steps) == 2
    assert {step.scenario_id for step in plan.steps} == {"kisa.agent.indirect-tool-hijacking"}
    assert all(step.threat_classes == {"A01", "A02"} for step in plan.steps)
    assert all(step.attack_surface == "agent-tools" for step in plan.steps)
    assert all(step.persona == "malicious-user" for step in plan.steps)
    assert all(step.request.agent_id == "agent:kisa-planner-untrusted" for step in plan.steps)


def test_kisa_planner_rejects_unknown_threat_code() -> None:
    campaign = _campaign()
    spec = campaign.spec.model_copy(update={"threat_classes": ["A99"]})
    campaign = campaign.model_copy(update={"spec": spec})

    with pytest.raises(ValueError, match="unknown KISA threat"):
        asyncio.run(KISAPlannerRuntime().plan(campaign))


def test_kisa_mode_pack_emits_honest_metrics_checklist_and_artifacts(
    tmp_path: Path,
) -> None:
    outcome, mode_outcome = _run_kisa(tmp_path)
    assessment = mode_outcome.assessment

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.tool_results) == 2
    assert outcome.findings == []
    assert len(outcome.validation.candidates) == 1
    assert len(outcome.validation.candidates[0].claim.evidence) == 2
    assert outcome.validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    assert outcome.validation.decisions[0].reason_codes == [
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
    ]
    assert assessment.coverage.requested == {"A01", "A02", "A04"}
    assert assessment.coverage.executed == {"A01", "A02"}
    assert assessment.coverage.untested == {"A04"}
    assert assessment.coverage.coverage_rate == pytest.approx(2 / 3)

    metrics = {metric.metric_id: metric for metric in assessment.metrics}
    assert metrics["attack-success-rate"].value == 1
    assert metrics["attack-success-rate"].status is MetricStatus.FAIL
    assert metrics["block-refusal-rate"].status is MetricStatus.FAIL
    assert metrics["reproducibility-rate"].value == 1
    assert metrics["sensitive-exposure-count"].status is MetricStatus.PASS

    checklist = {item.item_id: item for item in assessment.checklist}
    assert checklist["env.least-privilege"].status is ChecklistStatus.YES
    assert checklist["exec.hitl"].status is ChecklistStatus.NEEDS_REVIEW
    assert checklist["report.business-impact"].status is ChecklistStatus.NEEDS_REVIEW
    assert checklist["report.mitigation"].status is ChecklistStatus.NOT_APPLICABLE
    assert checklist["improve.retest"].status is ChecklistStatus.NO
    assert sum(assessment.checklist_summary.model_dump().values()) == 52

    expected_artifacts = {
        "kisa-results.json",
        "kisa-checklist.json",
        "kisa-test-plan.json",
        "kisa-completion-report.json",
        "kisa-execution-log.json",
        "kisa-report.md",
    }
    assert expected_artifacts <= {path.name for path in outcome.run_path.iterdir()}
    test_plan = json.loads(mode_outcome.test_plan_path.read_text(encoding="utf-8"))
    assert isinstance(test_plan["suspendAndResume"], list)
    assert test_plan["scenarioDefinitions"][0]["scenario_id"] == (
        "kisa.agent.indirect-tool-hijacking"
    )
    execution_log = json.loads(mode_outcome.execution_log_path.read_text(encoding="utf-8"))
    assert execution_log
    assert set(execution_log[0]) == {"uniqueId", "dateTime", "description", "impact"}
    report = mode_outcome.report_path.read_text(encoding="utf-8")
    assert "not a compliance certification" in report
    assert "verified replay confirmation was not applied" in report
    assert "A04" in report
    assert "needs-review" in report
