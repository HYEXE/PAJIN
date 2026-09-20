"""Safe Markdown rendering for sealed local Web assessment results."""

from __future__ import annotations

from pajin.reporting import escape_markdown_text, markdown_code_span
from pajin.web_assessment.discovery_evidence import AuthenticatedDiscoveryEvidence
from pajin.web_assessment.models import (
    AssessmentIssue,
    AttackPath,
    LocalWebAssessmentResult,
    request_evidence_sequence,
)


def _issue_lines(issue: AssessmentIssue) -> list[str]:
    lines = [
        f"## {escape_markdown_text(issue.title)}",
        "",
        f"- Check: {markdown_code_span(issue.check)}",
        f"- CWE: {markdown_code_span(issue.cwe)}",
        f"- Status: {markdown_code_span(issue.status)}",
        f"- Severity: {markdown_code_span(issue.severity)}",
        f"- Issue ID: {markdown_code_span(issue.issue_id)}",
        "- PAJIN Finding authority: `false`",
        "",
        "### Observed local impact",
        "",
        escape_markdown_text(issue.observed_impact),
        "",
        "### Potential impact",
        "",
        escape_markdown_text(issue.potential_impact),
        "",
        "### Remediation",
        "",
        escape_markdown_text(issue.remediation),
        "",
        "### Controlled trials",
        "",
    ]
    for trial in issue.trials:
        lines.append(
            "- "
            + markdown_code_span(trial.repetition)
            + f": reproduced={markdown_code_span(str(trial.reproduced).lower())}, "
            + f"controls={markdown_code_span(str(trial.controls_passed).lower())}, "
            + f"evidence={markdown_code_span(str(len(trial.evidence_ids)))}"
        )
    return lines


def _attack_path_lines(path: AttackPath) -> list[str]:
    lines = [
        f"## {escape_markdown_text(path.title)}",
        "",
        f"- Status: {markdown_code_span(path.status)}",
        f"- Path ID: {markdown_code_span(path.path_id)}",
        "- PAJIN Finding authority: `false`",
        "",
    ]
    for stage in path.stages:
        lines.extend(
            [
                f"### {stage.ordinal}. {escape_markdown_text(stage.stage_id)}",
                "",
                f"- State: {markdown_code_span(stage.state)}",
                f"- Summary: {escape_markdown_text(stage.summary)}",
                f"- Evidence records: {markdown_code_span(str(len(stage.evidence_ids)))}",
            ]
        )
        if stage.issue_id is not None:
            lines.append(f"- Issue: {markdown_code_span(stage.issue_id)}")
        lines.append("")
    lines.extend(
        [
            "### Observed local impact",
            "",
            escape_markdown_text(path.observed_impact),
            "",
            "### Potential impact",
            "",
            escape_markdown_text(path.potential_impact),
        ]
    )
    return lines


def render_local_web_assessment_report(
    result: LocalWebAssessmentResult,
    *,
    discovery_evidence: AuthenticatedDiscoveryEvidence | None = None,
) -> str:
    """Render only validated, secret-free result fields as one local report."""

    result = LocalWebAssessmentResult.model_validate(result.model_dump(mode="json"))
    if (result.discovery_evidence_reference is None) != (discovery_evidence is None):
        raise ValueError("local Web report requires the discovery Evidence named by the result")
    if discovery_evidence is not None:
        if result.discovery_evidence_reference != "discovery-evidence.json":
            raise ValueError("local Web report discovery Evidence reference is absent")
        discovery_reference = "discovery-evidence.json"
        discovery_evidence = AuthenticatedDiscoveryEvidence.model_validate(
            discovery_evidence.model_dump(mode="json", by_alias=True)
        )
        passive_requests = tuple(
            sorted(
                (
                    request
                    for request in result.requests
                    if request.phase == "browser-passive-discovery"
                ),
                key=request_evidence_sequence,
            )
        )
        if (
            result.discovery_evidence_digest != discovery_evidence.evidence_digest
            or result.origin != discovery_evidence.discovery_plan.origin
            or passive_requests != discovery_evidence.request_evidence
        ):
            raise ValueError("local Web report discovery Evidence differs from the result")
    reproduced = sum(issue.status == "locally-reproduced" for issue in result.issues)
    validated_paths = sum(path.status == "locally-validated" for path in result.attack_paths)
    lines = [
        "# PAJIN Local Web Assessment",
        "",
        "> This is an operator-approved diagnostic result from an exact numeric loopback origin. "
        "It is not a confirmed PAJIN Finding and was not delivered externally.",
        "",
        "## Run summary",
        "",
        f"- Run ID: {markdown_code_span(result.run_id)}",
        f"- Plan: {markdown_code_span(result.plan_name)}",
        f"- Origin: {markdown_code_span(result.origin)}",
        f"- Target: {escape_markdown_text(result.target_product)} "
        f"{markdown_code_span(result.target_version)}",
        f"- Browser authenticated: {markdown_code_span(str(result.browser.authenticated).lower())}",
        f"- Dynamic pages captured: {markdown_code_span(str(len(result.browser.pages)))}",
        f"- HTTP evidence records: {markdown_code_span(str(len(result.requests)))}",
        f"- Locally reproduced issues: {markdown_code_span(str(reproduced))}",
        f"- Locally validated attack paths: {markdown_code_span(str(validated_paths))}",
        f"- Result digest: {markdown_code_span(result.result_digest)}",
        "- Disposable account state retained in local lab: `true`",
        "- Credentials persisted: `false`",
        "- External delivery performed: `false`",
        "- PAJIN Finding authority: `false`",
        "",
        "# Diagnostic issues",
        "",
    ]
    if discovery_evidence is not None:
        discovery_lines = [
            f"- Passive routes discovered: "
            f"{markdown_code_span(str(len(discovery_evidence.discovery_result.routes)))}",
            f"- Passive forms described: "
            f"{markdown_code_span(str(len(discovery_evidence.discovery_result.forms)))}",
            f"- Passive discovery requests: "
            f"{markdown_code_span(str(len(discovery_evidence.request_evidence)))}",
            f"- Discovery Evidence: {markdown_code_span(discovery_reference)}",
            f"- Discovery Evidence digest: "
            f"{markdown_code_span(discovery_evidence.evidence_digest)}",
        ]
        diagnostic_heading = lines.index("# Diagnostic issues")
        lines[diagnostic_heading:diagnostic_heading] = [*discovery_lines, ""]
    for issue in result.issues:
        lines.extend(_issue_lines(issue))
        lines.append("")
    lines.extend(["# Attack paths", ""])
    for path in result.attack_paths:
        lines.extend(_attack_path_lines(path))
        lines.append("")
    lines.extend(
        [
            "# Evidence notes",
            "",
            "Browser artifacts contain screenshots plus DOM hashes, not raw DOM snapshots. "
            "Request evidence stores keyed request fingerprints, response hashes, sizes, statuses, "
            "and origin-relative paths. Test passwords and session tokens are intentionally "
            "absent.",
        ]
    )
    if discovery_evidence is not None:
        lines.extend(
            [
                "",
                "For `browser-passive-discovery` RequestEvidence records, `response_sha256` "
                "is the SHA-256 of intentionally retained empty bytes and `response_bytes` is "
                "`0`. These values are empty-retention sentinels, not measurements of the "
                "observed response body. The observed encoded response-body byte metric is "
                "bound as `observedResponseBodyBytes` in `discovery-evidence.json`. Non-passive "
                "RequestEvidence records retain their normal response-body hash and byte-size "
                "meaning.",
            ]
        )
    lines.extend(
        [
            "",
            "The disposable account remains in the user-provided local lab because account "
            "deletion "
            "was outside this assessment's approved methods and paths.",
        ]
    )
    return "\n".join(lines) + "\n"
