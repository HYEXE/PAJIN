"""Markdown projection for KISA remediation and retest assessments."""

from __future__ import annotations

from typing import Any, Protocol

from pajin.reporting import escape_markdown_text, markdown_code_span


class _RetestAssessmentView(Protocol):
    @property
    def baseline_run_id(self) -> str: ...

    @property
    def retest_run_id(self) -> str: ...

    @property
    def summary(self) -> Any: ...

    @property
    def finding_results(self) -> Any: ...

    @property
    def regression(self) -> Any: ...

    @property
    def remediation_actions(self) -> Any: ...

    @property
    def checklist_overlay(self) -> Any: ...


def render_retest_report(assessment: _RetestAssessmentView) -> str:
    """Render an already-validated retest assessment without loading Run state."""

    summary = assessment.summary
    lines = [
        "# KISA Remediation and Retest Report",
        "",
        f"- Baseline run: {markdown_code_span(assessment.baseline_run_id)}",
        f"- Retest run: {markdown_code_span(assessment.retest_run_id)}",
        f"- Fixed: {markdown_code_span(str(summary.fixed))}",
        f"- Still vulnerable: {markdown_code_span(str(summary.still_vulnerable))}",
        f"- Inconclusive: {markdown_code_span(str(summary.inconclusive))}",
        *(
            [
                "- Unexpected new confirmed findings observed in scoped parent Run: "
                f"{markdown_code_span(str(summary.new_findings))}"
            ]
            if summary.new_findings
            else []
        ),
        "- New threat discovery: **not assessed**; run a fresh `pajin kisa-run` "
        "as a separate discovery Gate for currently supported scenarios.",
        f"- Normal-function regression: {markdown_code_span(summary.regression.value)}",
        "",
        "## Finding outcomes",
        "",
        "| Threat | Baseline candidate | Status | Oracle | ReplayOutcome | Receipt seal |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for result in assessment.finding_results:
        lineage = result.replay_lineage
        oracle_verdict = result.oracle_verdict.value if result.oracle_verdict else "-"
        lines.append(
            f"| {escape_markdown_text(result.threat_class)} | "
            f"{escape_markdown_text(result.baseline_candidate_id)} | "
            f"**{escape_markdown_text(result.status.value)}** | "
            f"{escape_markdown_text(oracle_verdict)} | "
            f"{escape_markdown_text(lineage.replay_outcome_id if lineage else '-')} | "
            f"{escape_markdown_text(lineage.receipt_seal_root_digest if lineage else '-')} |"
        )
        lines.extend(
            [
                "",
                f"- Baseline Decision: {markdown_code_span(result.baseline_decision_id)}",
                f"- Baseline Finding: {markdown_code_span(result.baseline_finding_id)}",
            ]
        )
        if lineage is not None:
            lines.extend(
                [
                    f"- Replay Run: {markdown_code_span(lineage.replay_run_id)}",
                    f"- ReplayOutcome: {markdown_code_span(lineage.replay_outcome_id)}",
                    "- Replay requests: "
                    + ", ".join(
                        markdown_code_span(request_id) for request_id in lineage.replay_request_ids
                    ),
                    "- OracleResult: " + markdown_code_span(lineage.oracle_result_id or "-"),
                    "- Replay evidence: "
                    + ", ".join(markdown_code_span(path) for path in lineage.replay_evidence),
                    "- Replay artifact seal: "
                    + markdown_code_span(lineage.artifact_seal_root_digest),
                    "- Verification receipt seal: "
                    + markdown_code_span(lineage.receipt_seal_root_digest),
                ]
            )
        if result.replay_context is not None:
            lines.append(
                "- Parent Retest source root: "
                f"{markdown_code_span(result.replay_context.retest_source_root_digest)}"
            )
    lines.extend(
        [
            "",
            "## Normal-function regression evidence",
            "",
            "- Expected targets: "
            + ", ".join(
                markdown_code_span(target) for target in assessment.regression.expected_targets
            ),
            "- Expected repetitions per target: "
            f"{markdown_code_span(str(assessment.regression.expected_repetitions))}",
            "",
            "| Target | Planned request | Terminal request | Attempt | Trusted result |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for evidence in assessment.regression.evidence:
        trusted_result = (
            "not measured"
            if evidence.trusted_passed is None
            else "pass"
            if evidence.trusted_passed
            else "fail"
        )
        lines.append(
            f"| {escape_markdown_text(evidence.target)} | "
            f"{escape_markdown_text(evidence.planned_request_id)} | "
            f"{escape_markdown_text(evidence.request_id)} | {evidence.attempt} | "
            f"{escape_markdown_text(trusted_result)} |"
        )
    lines.extend(["", "## Remediation plan", ""])
    for action in assessment.remediation_actions:
        lines.extend(
            [
                f"### {escape_markdown_text(action.threat_class)}: "
                f"{escape_markdown_text(action.title)}",
                "",
                f"- Baseline Candidate: {markdown_code_span(action.baseline_candidate_id)}",
                f"- Baseline Decision: {markdown_code_span(action.baseline_decision_id)}",
                f"- Baseline Finding: {markdown_code_span(action.baseline_finding_id)}",
                f"- Display fingerprint: {markdown_code_span(action.finding_fingerprint)}",
                "- Owner: " + markdown_code_span(action.owner or "needs human assignment"),
                "- Controls:",
            ]
        )
        lines.extend(f"  - {escape_markdown_text(control)}" for control in action.controls)
        lines.append("- Acceptance criteria:")
        lines.extend(
            f"  - {escape_markdown_text(criterion)}" for criterion in action.acceptance_criteria
        )
    lines.extend(
        [
            "",
            "## Checklist overlay",
            "",
            "This append-only overlay updates only the listed KISA lifecycle items. "
            "It is evidence support, not a compliance certification.",
            "",
        ]
    )
    for overlay in assessment.checklist_overlay.items:
        lines.append(
            f"- {markdown_code_span(overlay.item_id)}: "
            f"**{escape_markdown_text(overlay.status.value)}** — "
            f"{escape_markdown_text(overlay.rationale)}"
        )
    return "\n".join(lines) + "\n"
