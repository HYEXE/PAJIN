"""Markdown report renderer for validated campaign results."""

from pajin.domain.models import AgentPlan, CampaignManifest, CampaignMode, Finding, ToolResult
from pajin.domain.validation import FindingDisposition, FindingValidationSet


def render_markdown_report(
    campaign: CampaignManifest,
    run_id: str,
    plan: AgentPlan,
    results: list[ToolResult],
    findings: list[Finding],
    validation: FindingValidationSet | None = None,
) -> str:
    """Render a reproducible technical report from typed run data."""

    lines = [
        f"# PAJIN Campaign Report: {campaign.metadata.name}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Mode: `{campaign.spec.mode.value}`",
        f"- Autonomy: `{campaign.spec.autonomy.value}`",
        f"- Access profile: `{campaign.spec.access_profile}`",
        f"- Confirmed findings: `{len(findings)}`",
    ]
    if validation is not None:
        lines.append(f"- Candidate findings preserved: `{len(validation.candidates)}`")
    lines.extend(
        [
            "",
            "## Authorization and Scope",
            "",
            f"- Approved by: `{campaign.spec.authorization.approved_by}`",
            f"- Approval evidence: `{campaign.spec.authorization.evidence}`",
            f"- Authorization expires: `{campaign.spec.authorization.expires_at.isoformat()}`",
            "- Allowed targets:",
        ]
    )
    lines.extend(f"  - `{item}`" for item in campaign.spec.scope.allow)
    lines.append("- Denied targets:")
    lines.extend(f"  - `{item}`" for item in campaign.spec.scope.deny)
    if not campaign.spec.scope.deny:
        lines.append("  - None")

    lines.extend(["", "## Objectives", ""])
    lines.extend(f"- {objective}" for objective in campaign.spec.objectives)
    lines.extend(["", "## Agent Plan", "", plan.summary, ""])
    for index, step in enumerate(plan.steps, start=1):
        lines.extend(
            [
                f"### {index}. {step.title}",
                "",
                step.rationale,
                "",
                f"- Tool: `{step.request.tool_id}`",
                f"- Target: `{step.request.target}`",
                f"- Method: `{step.request.method}`",
                "",
            ]
        )

    lines.extend(["## Execution Summary", ""])
    for result in results:
        status = "SUCCESS" if result.success else "FAILED"
        lines.extend(
            [
                f"- `{result.request_id}` / `{result.tool_id}`: **{status}**",
                f"  - Started: `{result.started_at.isoformat()}`",
                f"  - Finished: `{result.finished_at.isoformat()}`",
            ]
        )
        if result.error:
            lines.append(f"  - Error: `{result.error}`")
        lines.extend(f"  - Evidence: `{evidence}`" for evidence in result.evidence)

    if validation is not None:
        disposition_counts = {
            disposition: sum(
                decision.disposition is disposition for decision in validation.decisions
            )
            for disposition in FindingDisposition
        }
        lines.extend(
            [
                "",
                "## Validation Summary",
                "",
                f"- Confirmed: `{disposition_counts[FindingDisposition.CONFIRMED]}`",
                f"- Needs review: `{disposition_counts[FindingDisposition.NEEDS_REVIEW]}`",
                f"- Inconclusive: `{disposition_counts[FindingDisposition.INCONCLUSIVE]}`",
                "- Rejected by objective gate: "
                f"`{disposition_counts[FindingDisposition.REJECTED_OBJECTIVE]}`",
                "",
                "Non-confirmed candidates remain internal to the validation ledger and are not "
                "presented as validated findings.",
            ]
        )

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
                f"### {finding.title}",
                "",
                f"- ID: `{finding.finding_id}`",
                f"- Severity: **{finding.severity.value.upper()}**",
                f"- {classification_label}: `{finding.threat_class}`",
                f"- Target: `{finding.target}`",
                f"- Affected component: `{finding.affected_component or 'Not specified'}`",
                f"- Root cause: `{finding.root_cause or 'Not specified'}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                f"- Independently validated: `{finding.validated}`",
                "",
                finding.summary,
                "",
            ]
        )
        if finding.impact:
            lines.extend(["#### Impact", "", finding.impact, ""])
        lines.extend(["#### Reproduction", ""])
        lines.extend(f"{index}. {step}" for index, step in enumerate(finding.reproduction, start=1))
        lines.extend(["", "#### Evidence", ""])
        lines.extend(f"- `{evidence}`" for evidence in finding.evidence)
        if finding.remediation:
            lines.extend(["", "#### Remediation", ""])
            lines.extend(f"- {item}" for item in finding.remediation)

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
    return "\n".join(lines) + "\n"
