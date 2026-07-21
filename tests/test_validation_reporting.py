from datetime import UTC, datetime

from pajin.agents.base import AgentReportNarrative
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
)
from pajin.domain.orchestration import (
    AgentNode,
    AgentRole,
    AgentStatus,
    RunStatus,
    TaskGraph,
    TaskNode,
)
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    FindingValidationSet,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.reporting import (
    escape_markdown_text,
    markdown_code_span,
    render_markdown_report,
)
from pajin.runtime.control import BudgetController, KillSwitch
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _plan(target: str) -> AgentPlan:
    return AgentPlan(
        summary="Run one bounded reporting scenario.",
        steps=[
            PlannedStep(
                step_id="step_reporting",
                title="Collect bounded evidence",
                rationale="Exercise the reporting contract.",
                request=ToolRequest(
                    request_id="request_reporting",
                    agent_id="agent:specialist:1",
                    tool_id="http_probe",
                    target=target,
                ),
            )
        ],
    )


def _finding(
    finding_id: str,
    *,
    target: str,
    title: str,
    summary: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        severity=FindingSeverity.HIGH,
        threat_class="A02",
        target=target,
        summary=summary,
        reproduction=["Replay the authorized request."],
        evidence=[f"evidence/{finding_id}.json"],
        confidence=0.9,
        validated=True,
    )


def _candidate(index: int, finding: Finding) -> CandidateFinding:
    return CandidateFinding(
        candidate_id=f"candidate_{index}",
        claim=finding,
        source_agent_id="agent:legacy-validator:1",
        source_request_ids=["request_reporting"],
        created_at=datetime(2026, 7, 14, 12, index, tzinfo=UTC),
    )


def _decision(
    index: int,
    candidate: CandidateFinding,
    disposition: FindingDisposition,
) -> ValidationDecision:
    reason_code = (
        ValidationReasonCode.VALIDATOR_CONFIRMED
        if disposition is FindingDisposition.CONFIRMED
        else ValidationReasonCode.VALIDATOR_DISAGREED
    )
    return ValidationDecision(
        decision_id=f"decision_{index}",
        candidate_id=candidate.candidate_id,
        validator_id="agent:deterministic-gate:1",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=disposition,
        reason_codes=[reason_code],
        decision_summary="Classified by the validation boundary.",
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[],
        decided_at=datetime(2026, 7, 14, 13, index, tzinfo=UTC),
    )


def test_report_counts_all_dispositions_without_leaking_non_confirmed_claims(
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    dispositions = [
        FindingDisposition.CONFIRMED,
        FindingDisposition.NEEDS_REVIEW,
        FindingDisposition.INCONCLUSIVE,
        FindingDisposition.REJECTED_OBJECTIVE,
    ]
    findings = [
        _finding(
            "finding_confirmed",
            target=target,
            title="Confirmed report finding",
            summary="This confirmed finding is safe to include in the report.",
        ),
        _finding(
            "finding_review",
            target=target,
            title="SECRET NEEDS REVIEW TITLE",
            summary="SECRET NEEDS REVIEW SUMMARY",
        ),
        _finding(
            "finding_inconclusive",
            target=target,
            title="SECRET INCONCLUSIVE TITLE",
            summary="SECRET INCONCLUSIVE SUMMARY",
        ),
        _finding(
            "finding_rejected",
            target=target,
            title="SECRET REJECTED TITLE",
            summary="SECRET REJECTED SUMMARY",
        ),
    ]
    candidates = [_candidate(index, finding) for index, finding in enumerate(findings, start=1)]
    validation = FindingValidationSet(
        candidates=candidates,
        decisions=[
            _decision(index, candidate, disposition)
            for index, (candidate, disposition) in enumerate(
                zip(candidates, dispositions, strict=True),
                start=1,
            )
        ],
        confirmed_findings=[findings[0]],
    )

    report = render_markdown_report(
        sample_campaign,
        "run_validation_reporting",
        _plan(target),
        [],
        validation.confirmed_findings,
        validation=validation,
    )

    assert "- Candidate findings preserved: `4`" in report
    assert "- Confirmed: `1`" in report
    assert "- Needs review: `1`" in report
    assert "- Inconclusive: `1`" in report
    assert "- Rejected by objective gate: `1`" in report
    assert "### Confirmed report finding" in report
    assert findings[0].summary in report
    for non_confirmed in findings[1:]:
        assert non_confirmed.title not in report
        assert non_confirmed.summary not in report


def test_report_without_validation_keeps_legacy_call_compatible(
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    finding = _finding(
        "finding_legacy",
        target=target,
        title="Legacy validated finding",
        summary="The pre-ledger report call remains supported.",
    )

    report = render_markdown_report(
        sample_campaign,
        "run_legacy_reporting",
        _plan(target),
        [],
        [finding],
    )

    assert "### Legacy validated finding" in report
    assert "## Validation Summary" not in report
    assert "Candidate findings preserved" not in report


def test_report_neutralizes_markdown_structure_html_and_code_span_injection(
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    plan = _plan(target)
    malicious_step = plan.steps[0].model_copy(
        update={
            "title": "Normal title\n\n## Forged Plan Section",
            "rationale": '<img src="https://attacker.invalid/track">\n\n## Forged Scope',
        }
    )
    plan = plan.model_copy(
        update={
            "summary": "Trusted summary\n\n## Forged Authorization",
            "steps": [malicious_step],
        }
    )
    finding = _finding(
        "finding_injected",
        target=target,
        title="Legitimate title\n\n## Forged Validated Finding",
        summary='<script>alert("report")</script>\n\n## Forged Summary',
    ).model_copy(
        update={
            "reproduction": ["Replay safely.\n\n## Forged Reproduction"],
            "evidence": ["evidence/result.json`\n\n## Forged Evidence"],
            "remediation": ["Review.\n\n## Forged Remediation"],
        }
    )

    report = render_markdown_report(
        sample_campaign,
        "run_injection_reporting",
        plan,
        [],
        [finding],
    )

    assert "<img" not in report
    assert "<script" not in report
    assert "&lt;img" in report
    assert "&lt;script&gt;" in report
    assert "\n## Forged" not in report
    assert report.count("\n## Authorization and Scope\n") == 1
    assert report.count("\n## Validated Findings\n") == 1
    evidence_line = next(line for line in report.splitlines() if "Forged Evidence" in line)
    assert evidence_line.startswith("- ``")


def test_multi_agent_report_neutralizes_model_table_list_and_heading_injection(
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    injected = "Visible\udfff\n\n## Forged Section\n| forged | row |\n<script>x</script>\n```"
    agent = AgentNode(
        agent_id=f"agent|table{injected}",
        role=AgentRole.SUPERVISOR,
        depth=0,
        capability_grant_id="grant_reporting",
        status=AgentStatus.COMPLETED,
    )
    task = TaskNode(
        task_id=f"task`code{injected}",
        title=injected,
        assigned_agent_id=agent.agent_id,
    )
    graph = TaskGraph()
    graph.add(task)
    narrative = AgentReportNarrative(
        summary=injected,
        risk_overview=injected,
        recommendations=[f"- nested item{injected}"],
        limitations=[injected],
    )

    report = MultiAgentCampaignRunner._render_report(
        sample_campaign,
        "run_multi_agent_reporting",
        _plan(target),
        [],
        [],
        {agent.agent_id: agent},
        graph,
        BudgetController(sample_campaign.spec.budgets),
        RunStatus.COMPLETED,
        narrative=narrative,
    )

    assert report.count("\n## Multi-Agent Execution\n") == 1
    assert report.count("\n## Model-generated Narrative\n") == 1
    assert "\n## Forged Section" not in report
    assert "\n| forged |" not in report
    assert "\n```" not in report
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "\\|" in report
    assert "\udfff" not in report
    report.encode("utf-8")


def test_public_markdown_helpers_remove_non_encodable_surrogates() -> None:
    injected = "safe\udffftext"

    assert escape_markdown_text(injected) == "safetext"
    assert markdown_code_span(injected) == "`safetext`"


def test_planless_cancellation_report_neutralizes_reason_and_identifier_injection(
    sample_campaign: CampaignManifest,
) -> None:
    injected = "Visible\n\n## Forged Cancellation\n<script>x</script>\n```"
    runner = object.__new__(MultiAgentCampaignRunner)
    runner._kill_switch = KillSwitch()
    runner._kill_switch.activate(injected)

    report = runner._render_cancelled_report(
        sample_campaign,
        f"run`{injected}",
        RunStatus.CANCELLED,
        None,
        [],
        [],
        FindingValidationSet(candidates=[], decisions=[], confirmed_findings=[]),
        {},
        TaskGraph(),
        BudgetController(sample_campaign.spec.budgets),
    )

    assert "\n## Forged Cancellation\n" not in report
    assert "\n```" not in report
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    report.encode("utf-8")
