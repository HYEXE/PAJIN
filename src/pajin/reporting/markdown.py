"""Markdown report renderer for validated campaign results."""

from pajin.domain.models import AgentPlan, CampaignManifest, Finding, ToolResult


def render_markdown_report(
    campaign: CampaignManifest,
    run_id: str,
    plan: AgentPlan,
    results: list[ToolResult],
    findings: list[Finding],
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
        "",
        "## Authorization and Scope",
        "",
        f"- Approved by: `{campaign.spec.authorization.approved_by}`",
        f"- Approval evidence: `{campaign.spec.authorization.evidence}`",
        f"- Authorization expires: `{campaign.spec.authorization.expires_at.isoformat()}`",
        "- Allowed targets:",
    ]
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

    lines.extend(["", "## Validated Findings", ""])
    if not findings:
        lines.append("No validated findings were produced by this campaign.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- ID: `{finding.finding_id}`",
                f"- Severity: **{finding.severity.value.upper()}**",
                f"- KISA threat class: `{finding.threat_class}`",
                f"- Target: `{finding.target}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                f"- Independently validated: `{finding.validated}`",
                "",
                finding.summary,
                "",
                "#### Reproduction",
                "",
            ]
        )
        lines.extend(f"{index}. {step}" for index, step in enumerate(finding.reproduction, start=1))
        lines.extend(["", "#### Evidence", ""])
        lines.extend(f"- `{evidence}`" for evidence in finding.evidence)

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "This MVP run used a deterministic mock tool and did not contact a real target. "
            "The report validates PAJIN's policy, evidence, validation, and reporting path.",
        ]
    )
    return "\n".join(lines) + "\n"
