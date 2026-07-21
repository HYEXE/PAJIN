import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

import pajin.workflow.validation_artifacts as validation_artifacts
from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult
from pajin.domain.orchestration import RunStatus
from pajin.domain.validation import (
    ConfirmationBasis,
    FindingDisposition,
    ValidationReasonCode,
)
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
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import load_verified_run_snapshot
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _campaign() -> CampaignManifest:
    return load_manifest(Path("examples/kisa-ai-redteam.yaml"))


class ForgedMockVerdictWorker(SimulatedWorkerBackend):
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        result = await super().run(job, secrets=secrets)
        payload = json.loads(result.stdout)
        payload["vulnerable"] = False
        payload["observation"] = "worker-authored summary was deliberately forged"
        return result.model_copy(update={"stdout": json.dumps(payload)})


class AmbiguousMockWorker(SimulatedWorkerBackend):
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        result = await super().run(job, secrets=secrets)
        return result.model_copy(
            update={"stdout": '{"vulnerable":false,' + result.stdout.lstrip()[1:]}
        )


class SummaryTrustingMockAgentProbe(MockAgentProbe):
    """Test adapter that deliberately forwards an untrusted Worker summary."""

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=json.loads(result.stdout),
        )


class FailingMockWorker(SimulatedWorkerBackend):
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        result = await super().run(job, secrets=secrets)
        return WorkerResult(
            execution_id=result.execution_id,
            backend="forced-failure",
            status=WorkerStatus.FAILED,
            exit_code=1,
            stderr="deterministic test failure",
            started_at=result.started_at,
            finished_at=result.finished_at,
        )


def _execute_kisa(
    tmp_path: Path,
    *,
    worker: SimulatedWorkerBackend | None = None,
    tool: MockAgentProbe | None = None,
    kill_after_tool_calls: int | None = None,
):
    thresholds = EvaluationThresholds(repetitions=2)
    registry = ToolRegistry()
    registry.register(tool or MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker or SimulatedWorkerBackend(),
        output_root=tmp_path,
        kill_after_tool_calls=kill_after_tool_calls,
    )
    return asyncio.run(runner.run(_campaign()))


def _run_kisa(tmp_path: Path):
    thresholds = EvaluationThresholds(repetitions=2)
    outcome = _execute_kisa(tmp_path)
    mode_outcome = KISAModePack(thresholds=thresholds).evaluate(_campaign(), outcome)
    return outcome, mode_outcome


def test_kisa_mode_rejects_validation_from_an_intermediate_run_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = _execute_kisa(tmp_path)
    authority = load_verified_run_snapshot(outcome.run_path)
    phase_b_verification = authority.verification.model_copy(update={"root_digest": "0" * 64})
    original_artifact_load = validation_artifacts.load_verified_run_artifacts
    phase_b_initial_loads = 0

    def phase_b_initial(*args, **kwargs):
        nonlocal phase_b_initial_loads
        phase_b_initial_loads += 1
        return replace(authority, verification=phase_b_verification)

    def phase_b_artifacts(*args, **kwargs):
        snapshot = original_artifact_load(*args, **kwargs)
        return replace(snapshot, verification=phase_b_verification)

    monkeypatch.setattr(
        validation_artifacts,
        "load_verified_run_snapshot",
        phase_b_initial,
    )
    monkeypatch.setattr(
        validation_artifacts,
        "load_verified_run_artifacts",
        phase_b_artifacts,
    )

    with pytest.raises(ValueError, match="validation Run changed"):
        KISAModePack(thresholds=EvaluationThresholds(repetitions=2)).evaluate(
            _campaign(),
            outcome,
        )
    assert phase_b_initial_loads == 0
    assert not (outcome.run_path / "kisa-results.json").exists()


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
    assert "verified replay evidence was not applied" in report
    assert "A04" in report
    assert "needs-review" in report


@pytest.mark.parametrize("field", ["plan", "agents", "task_graph", "tool_results"])
def test_kisa_mode_pack_rejects_cross_run_execution_components(
    tmp_path: Path,
    field: str,
) -> None:
    first = _execute_kisa(tmp_path / "first")
    second = _execute_kisa(tmp_path / "second")
    mixed = first.model_copy(update={field: getattr(second, field)})

    with pytest.raises(ValueError, match="differ"):
        KISAModePack(thresholds=EvaluationThresholds(repetitions=2)).evaluate(_campaign(), mixed)

    assert not (first.run_path / "kisa-results.json").exists()


def test_kisa_mode_pack_rejects_campaign_from_another_snapshot(tmp_path: Path) -> None:
    outcome = _execute_kisa(tmp_path)
    campaign = _campaign()
    metadata = campaign.metadata.model_copy(update={"description": "foreign snapshot"})
    foreign_campaign = campaign.model_copy(update={"metadata": metadata})

    with pytest.raises(ValueError, match="Campaign differs"):
        KISAModePack(thresholds=EvaluationThresholds(repetitions=2)).evaluate(
            foreign_campaign, outcome
        )


@pytest.mark.parametrize(
    ("worker", "kill_after_tool_calls", "expected_status"),
    [
        (FailingMockWorker(), None, RunStatus.FAILED),
        (SimulatedWorkerBackend(), 1, RunStatus.CANCELLED),
    ],
)
def test_kisa_mode_pack_does_not_upgrade_incomplete_runs_to_executed(
    tmp_path: Path,
    worker: SimulatedWorkerBackend,
    kill_after_tool_calls: int | None,
    expected_status: RunStatus,
) -> None:
    outcome = _execute_kisa(
        tmp_path,
        worker=worker,
        kill_after_tool_calls=kill_after_tool_calls,
    )

    mode_outcome = KISAModePack(thresholds=EvaluationThresholds(repetitions=2)).evaluate(
        _campaign(), outcome
    )
    assessment = mode_outcome.assessment

    assert outcome.status is expected_status
    assert assessment.scenario_ids == []
    assert assessment.coverage.executed == set()
    assert assessment.coverage.untested == {"A01", "A02", "A04"}
    metrics = {metric.metric_id: metric for metric in assessment.metrics}
    for metric_id in (
        "attack-success-rate",
        "block-refusal-rate",
        "reproducibility-rate",
        "sensitive-exposure-count",
        "mean-response-latency",
    ):
        assert metrics[metric_id].value is None
        assert metrics[metric_id].status is MetricStatus.NOT_MEASURED
    checklist = {item.item_id: item for item in assessment.checklist}
    for item_id in (
        "scenario.reproducibility",
        "env.tools",
        "exec.attack",
        "exec.automated",
        "exec.verdict",
        "exec.impact",
        "record.logs",
        "record.evidence",
    ):
        assert checklist[item_id].status is ChecklistStatus.NO
    test_plan = json.loads(mode_outcome.test_plan_path.read_text(encoding="utf-8"))
    assert test_plan["testItems"] == ["kisa.agent.indirect-tool-hijacking"]
    completion = json.loads(mode_outcome.completion_report_path.read_text(encoding="utf-8"))
    assert completion["performedTestSummary"] == []


def test_kisa_mode_pack_recomputes_mock_verdict_from_sealed_request(tmp_path: Path) -> None:
    outcome = _execute_kisa(
        tmp_path,
        worker=ForgedMockVerdictWorker(),
        tool=SummaryTrustingMockAgentProbe(),
    )
    assert all(result.data["vulnerable"] is False for result in outcome.tool_results)

    assessment = (
        KISAModePack(thresholds=EvaluationThresholds(repetitions=2))
        .evaluate(_campaign(), outcome)
        .assessment
    )
    metrics = {metric.metric_id: metric for metric in assessment.metrics}

    assert metrics["attack-success-rate"].value == 1
    assert metrics["block-refusal-rate"].value == 0
    assert metrics["reproducibility-rate"].value == 1


def test_kisa_mode_pack_rejects_duplicate_keys_in_sealed_worker_stdout(
    tmp_path: Path,
) -> None:
    outcome = _execute_kisa(
        tmp_path,
        worker=AmbiguousMockWorker(),
        tool=SummaryTrustingMockAgentProbe(),
    )
    assert all(result.success for result in outcome.tool_results)

    with pytest.raises(ValueError, match="sealed KISA mock observation is invalid"):
        KISAModePack(thresholds=EvaluationThresholds(repetitions=2)).evaluate(
            _campaign(),
            outcome,
        )


def test_kisa_report_neutralizes_list_table_heading_and_html_injection(
    tmp_path: Path,
) -> None:
    outcome, mode_outcome = _run_kisa(tmp_path)
    assessment = mode_outcome.assessment
    injected = "Visible\n\n## Forged KISA Section\n| forged | row |\n<script>x</script>\n```"
    coverage = assessment.coverage.model_copy(update={"untested_reasons": {"A04": injected}})
    metrics = [
        assessment.metrics[0].model_copy(
            update={"name": injected, "unit": injected, "threshold": injected}
        ),
        *assessment.metrics[1:],
    ]
    checklist = [
        assessment.checklist[0].model_copy(update={"category": injected, "rationale": injected}),
        *assessment.checklist[1:],
    ]
    injected_assessment = assessment.model_copy(
        update={
            "guide": injected,
            "confirmation_artifact": injected,
            "coverage": coverage,
            "metrics": metrics,
            "checklist": checklist,
            "residual_risks": [injected],
        }
    )
    candidate = outcome.validation.candidates[0]
    finding = candidate.claim.model_copy(
        update={
            "title": injected,
            "summary": injected,
            "target": injected,
            "evidence": [injected],
        }
    )
    injected_candidate = candidate.model_copy(update={"claim": finding})
    injected_decision = outcome.validation.decisions[0].model_copy(
        update={"confirmation_basis": ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY}
    )
    injected_validation = outcome.validation.model_copy(
        update={
            "candidates": [injected_candidate],
            "decisions": [injected_decision],
            "confirmed_findings": [finding],
        }
    )
    injected_outcome = outcome.model_copy(
        update={"validation": injected_validation, "findings": [finding]}
    )

    report = KISAModePack(thresholds=EvaluationThresholds(repetitions=2))._render_report(
        _campaign(), injected_outcome, injected_assessment
    )

    assert report.count("\n## Evaluation metrics\n") == 1
    assert report.count("\n## KISA checklist\n") == 1
    assert "\n## Forged KISA Section" not in report
    assert "\n| forged |" not in report
    assert "\n```" not in report
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "\\|" in report
