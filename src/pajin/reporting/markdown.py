"""Markdown report renderer for validated campaign results."""

import re
import unicodedata
from html import escape

from pajin.domain.models import AgentPlan, CampaignManifest, CampaignMode, Finding, ToolResult
from pajin.domain.validation import FindingDisposition, FindingValidationSet
from pajin.runtime.execution_context import (
    SIMULATED_EVIDENCE_LABEL,
    WorkerExecutionContext,
)


def _single_line(value: str) -> str:
    without_controls = "".join(
        " " if character.isspace() else character
        for character in value
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs"} or character.isspace()
    )
    return " ".join(without_controls.split())


def escape_markdown_text(value: str) -> str:
    """Render untrusted text as one non-structural Markdown line."""

    rendered = escape(_single_line(value), quote=False)
    for marker in "\\`*_{}[]()#+!|~":
        rendered = rendered.replace(marker, f"\\{marker}")
    if rendered.startswith("- "):
        rendered = "\\" + rendered
    numbered = re.match(r"^(\d{1,9})([.)])(?=\s)", rendered)
    if numbered is not None:
        punctuation = numbered.group(2)
        start = numbered.start(2)
        rendered = rendered[:start] + "\\" + punctuation + rendered[start + 1 :]
    return rendered


def markdown_code_span(value: str) -> str:
    """Render untrusted text in a single-line, delimiter-safe code span."""

    rendered = escape(_single_line(value), quote=False)
    longest = max((len(run) for run in re.findall(r"`+", rendered)), default=0)
    delimiter = "`" * (longest + 1)
    padding = " " if rendered.startswith("`") or rendered.endswith("`") else ""
    return f"{delimiter}{padding}{rendered}{padding}{delimiter}"


# Local aliases keep the canonical report compact while the named helpers above
# form the public escaping boundary shared by every Markdown renderer.
_text = escape_markdown_text
_code = markdown_code_span


def _append_report_header(
    lines: list[str],
    campaign: CampaignManifest,
    run_id: str,
    findings: list[Finding],
    validation: FindingValidationSet | None,
    execution_context: WorkerExecutionContext | None,
) -> None:
    lines.append(f"# PAJIN Campaign Report: {_text(campaign.metadata.name)}")
    if execution_context is not None and execution_context.simulated:
        lines.extend(
            [
                "",
                f"> **{SIMULATED_EVIDENCE_LABEL}.** "
                + _text(execution_context.warning or "Development-only simulated execution."),
            ]
        )
    lines.extend(
        [
            "",
            f"- Run ID: {_code(run_id)}",
            f"- Mode: {_code(campaign.spec.mode.value)}",
            f"- Autonomy: {_code(campaign.spec.autonomy.value)}",
            f"- Access profile: {_code(campaign.spec.access_profile)}",
            f"- Confirmed findings: {_code(str(len(findings)))}",
        ]
    )
    if execution_context is not None:
        lines.extend(
            [
                f"- Worker backend: {_code(execution_context.backend)}",
                f"- Backend implementation: {_code(execution_context.implementation)}",
                f"- Evidence scope: {_code(execution_context.evidence_scope.value)}",
            ]
        )
    if validation is not None:
        lines.append(f"- Candidate findings preserved: {_code(str(len(validation.candidates)))}")


def _append_authorization_and_scope(lines: list[str], campaign: CampaignManifest) -> None:
    lines.extend(
        [
            "",
            "## Authorization and Scope",
            "",
            f"- Approved by: {_code(campaign.spec.authorization.approved_by)}",
            f"- Approval evidence: {_code(campaign.spec.authorization.evidence)}",
            f"- Authorization expires: {_code(campaign.spec.authorization.expires_at.isoformat())}",
            "- Allowed targets:",
        ]
    )
    lines.extend(f"  - {_code(item)}" for item in campaign.spec.scope.allow)
    lines.append("- Denied targets:")
    lines.extend(f"  - {_code(item)}" for item in campaign.spec.scope.deny)
    if not campaign.spec.scope.deny:
        lines.append("  - None")


def _append_objectives_and_plan(
    lines: list[str],
    campaign: CampaignManifest,
    plan: AgentPlan,
) -> None:
    lines.extend(["", "## Objectives", ""])
    lines.extend(f"- {_text(objective)}" for objective in campaign.spec.objectives)
    lines.extend(["", "## Agent Plan", "", _text(plan.summary), ""])
    for index, step in enumerate(plan.steps, start=1):
        lines.extend(
            [
                f"### {index}. {_text(step.title)}",
                "",
                _text(step.rationale),
                "",
                f"- Tool: {_code(step.request.tool_id)}",
                f"- Target: {_code(step.request.target)}",
                f"- Method: {_code(step.request.method)}",
                "",
            ]
        )


def _append_execution_summary(lines: list[str], results: list[ToolResult]) -> None:
    lines.extend(["## Execution Summary", ""])
    for result in results:
        status = "SUCCESS" if result.success else "FAILED"
        lines.extend(
            [
                f"- {_code(result.request_id)} / {_code(result.tool_id)}: **{status}**",
                f"  - Started: {_code(result.started_at.isoformat())}",
                f"  - Finished: {_code(result.finished_at.isoformat())}",
            ]
        )
        if result.error:
            lines.append(f"  - Error: {_code(result.error)}")
        lines.extend(f"  - Evidence: {_code(evidence)}" for evidence in result.evidence)


def _append_validation_summary(lines: list[str], validation: FindingValidationSet) -> None:
    disposition_counts = {
        disposition: sum(decision.disposition is disposition for decision in validation.decisions)
        for disposition in FindingDisposition
    }
    lines.extend(
        [
            "",
            "## Validation Summary",
            "",
            f"- Confirmed: {_code(str(disposition_counts[FindingDisposition.CONFIRMED]))}",
            f"- Needs review: {_code(str(disposition_counts[FindingDisposition.NEEDS_REVIEW]))}",
            f"- Inconclusive: {_code(str(disposition_counts[FindingDisposition.INCONCLUSIVE]))}",
            "- Rejected by objective gate: "
            f"{_code(str(disposition_counts[FindingDisposition.REJECTED_OBJECTIVE]))}",
            "",
            "Non-confirmed candidates remain internal to the validation ledger and are not "
            "presented as validated findings.",
        ]
    )


def _append_validated_findings(
    lines: list[str],
    campaign: CampaignManifest,
    findings: list[Finding],
) -> None:
    lines.extend(["", "## Validated Findings", ""])
    if not findings:
        lines.append("No validated findings were produced by this campaign.")
    classification_label = (
        "KISA threat class"
        if campaign.spec.mode is CampaignMode.AI_REDTEAM
        else "Vulnerability class"
    )
    for finding in findings:
        lines.extend(
            [
                f"### {_text(finding.title)}",
                "",
                f"- ID: {_code(finding.finding_id)}",
                f"- Severity: **{finding.severity.value.upper()}**",
                f"- {classification_label}: {_code(finding.threat_class)}",
                f"- Target: {_code(finding.target)}",
                f"- Affected component: {_code(finding.affected_component or 'Not specified')}",
                f"- Root cause: {_code(finding.root_cause or 'Not specified')}",
                f"- Confidence: {_code(f'{finding.confidence:.2f}')}",
                f"- Independently validated: {_code(str(finding.validated))}",
                "",
                _text(finding.summary),
                "",
            ]
        )
        if finding.impact:
            lines.extend(["#### Impact", "", _text(finding.impact), ""])
        lines.extend(["#### Reproduction", ""])
        lines.extend(
            f"{index}. {_text(step)}" for index, step in enumerate(finding.reproduction, start=1)
        )
        lines.extend(["", "#### Evidence", ""])
        lines.extend(f"- {_code(evidence)}" for evidence in finding.evidence)
        if finding.remediation:
            lines.extend(["", "#### Remediation", ""])
            lines.extend(f"- {_text(item)}" for item in finding.remediation)


def _append_limitations(lines: list[str]) -> None:
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "This report contains only evidence captured by the selected Worker and Tool adapters. "
            "It does not by itself prove target ownership, complete test coverage, or the absence "
            "of vulnerabilities.",
        ]
    )


def render_markdown_report(
    campaign: CampaignManifest,
    run_id: str,
    plan: AgentPlan,
    results: list[ToolResult],
    findings: list[Finding],
    validation: FindingValidationSet | None = None,
    execution_context: WorkerExecutionContext | None = None,
) -> str:
    """Render a reproducible technical report from typed run data."""

    lines: list[str] = []
    _append_report_header(lines, campaign, run_id, findings, validation, execution_context)
    _append_authorization_and_scope(lines, campaign)
    _append_objectives_and_plan(lines, campaign, plan)
    _append_execution_summary(lines, results)
    if validation is not None:
        _append_validation_summary(lines, validation)
    _append_validated_findings(lines, campaign, findings)
    _append_limitations(lines)
    return "\n".join(lines) + "\n"
