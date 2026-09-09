"""Local human-review reports that preserve bounded source authority."""

from __future__ import annotations

import json
from collections.abc import Sequence

from pajin.control_plane.measured_reviews.models import ReviewEvidence, ReviewRevision
from pajin.control_plane.measured_reviews.state import rebuild_review


def _block(value: str) -> str:
    # Indented code keeps arbitrary human text and embedded Markdown inert.
    return "\n".join("    " + line for line in value.splitlines()) + "\n"


def _evidence(evidence: ReviewEvidence) -> str:
    return "\n".join(
        (
            f"- Domain: {evidence.domain}",
            f"- Evidence digest: `{evidence.evidence_digest}`",
            f"- Source identity: `{evidence.source_identity}`",
            f"- Verified at: {evidence.verified_at.isoformat()}",
            "- Historical verification receipt; this download does not reverify the source.",
            "- Verified controlled benchmark summary; raw content is not included.",
            "",
            "### Measured summary",
            "",
            _block(
                json.dumps(
                    evidence.projection.model_dump(mode="json", by_alias=True),
                    indent=2,
                    ensure_ascii=False,
                )
            ),
        )
    )


def render_review_report(history: Sequence[ReviewRevision]) -> str:
    view = rebuild_review(history)
    lines = [
        "# PAJIN human review report",
        "",
        f"Status: {'ACCEPTED' if view.state == 'accepted' else 'DRAFT'} ({view.state})",
        f"Review: `{view.review_id}`; revision: {view.revision}",
        f"Revision digest: `{view.record_digest}`",
        "",
        "This report records attributed human judgments about controlled benchmark evidence. "
        "It does not confirm a generic vulnerability, authorize execution or external delivery, "
        "or make the source eligible for SARIF. Production impact remains unverified.",
        "",
        "## Review title",
        "",
        _block(view.title),
        "## Baseline evidence",
        "",
        _evidence(view.evidence),
        "## Human assessment",
        "",
    ]
    assessment = view.assessment
    if assessment is None:
        lines.append("No assessment has been submitted.")
    else:
        lines.extend(
            [
                f"Author: `{view.assessment_author}`",
                "",
                f"Human-assigned severity: **{assessment.severity.value}**",
                "",
                "Severity is a human assessment of this bounded evidence, "
                "including when marked safe.",
                "",
                "### Impact",
                "",
                _block(assessment.impact),
                "### Severity rationale",
                "",
                _block(assessment.severity_rationale),
                "### Known limitations",
                "",
                _block(assessment.limitations),
                "### Remediation",
                "",
            ]
        )
        for number, step in enumerate(assessment.remediation, 1):
            lines.extend(
                [
                    f"Step {number}",
                    "",
                    _block(step.action),
                    "Expected verification",
                    "",
                    _block(step.verification),
                ]
            )
        lines.extend(["### Retest plan", "", _block(assessment.retest_plan)])
    lines.extend(["## Retest", ""])
    if view.retest is None:
        lines.append("No separately verified retest evidence is attached to this assessment.")
    else:
        lines.extend(
            [
                f"Author: `{view.retest_author}`",
                "",
                f"Human conclusion: {view.retest.conclusion}",
                "",
                "Execution after remediation is not independently verified. A new benchmark result "
                "does not automatically prove that a production issue was fixed.",
                "",
                "Change reference",
                "",
                _block(view.retest.change_reference),
                "Rationale",
                "",
                _block(view.retest.rationale),
                _evidence(view.retest.evidence),
            ]
        )
    lines.extend(["## Human review decision", ""])
    if view.decision is None:
        lines.append("The current revision has no human review decision.")
    else:
        lines.extend(
            [
                f"Reviewer: `{view.reviewer}`",
                f"Decision: {view.decision.decision}",
                f"Decision applies to revision {view.revision} only.",
                "",
                _block(view.decision.reason),
            ]
        )
    lines.extend(
        [
            "## Retained revision history",
            "",
            "The following records preserve earlier assessments and decisions, including "
            "ones superseded by later edits. Their verification timestamps are historical.",
            "",
        ]
    )
    for revision in history:
        lines.extend(
            [
                f"### Revision {revision.revision}: {revision.command.action}",
                "",
                f"Actor: `{revision.actor}` ({revision.actor_role}); "
                f"recorded at: {revision.recorded_at.isoformat()}",
                "",
                f"Record digest: `{revision.record_digest}`",
                "",
                _block(
                    json.dumps(
                        revision.command.model_dump(mode="json", by_alias=True),
                        indent=2,
                        ensure_ascii=False,
                    )
                ),
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
