from datetime import UTC, datetime

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
)
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    FindingValidationSet,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.reporting.markdown import render_markdown_report


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
