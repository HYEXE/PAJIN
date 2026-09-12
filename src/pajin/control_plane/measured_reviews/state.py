"""Rebuild human-review state from exact, append-only authenticated revisions."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from pajin.control_plane.measured_reviews.models import (
    MAX_REVIEW_REVISIONS,
    AcknowledgeReviewNotification,
    AssessReview,
    AssignReview,
    AttachRetest,
    DecideReview,
    HumanAssessment,
    MeasuredReviewView,
    OpenReview,
    ReviewHistoryItem,
    ReviewRevision,
)


@dataclass
class _AssignmentState:
    assignee: str | None = None
    revision: int = 0
    recipients: dict[int, set[str]] = field(default_factory=dict)
    acknowledgments: set[tuple[int, str]] = field(default_factory=set)

    def apply(self, revision: ReviewRevision) -> bool:
        command = revision.command
        if isinstance(command, AssignReview):
            if command.assignee == self.assignee:
                raise ValueError("assignment must change the current assignee")
            self.recipients[revision.revision] = {
                s for s in (self.assignee, command.assignee) if s is not None
            }
            self.assignee, self.revision = command.assignee, revision.revision
        elif isinstance(command, AcknowledgeReviewNotification):
            acknowledgment = (command.assignment_revision, revision.actor)
            if revision.actor not in self.recipients.get(command.assignment_revision, set()):
                raise ValueError("notification belongs to another recipient or does not exist")
            if acknowledgment in self.acknowledgments:
                raise ValueError("notification is already acknowledged")
            self.acknowledgments.add(acknowledgment)
        else:
            return False
        return True


def rebuild_review(revisions: Sequence[ReviewRevision]) -> MeasuredReviewView:
    """Reject gaps, edits, invalid transitions, and self-acceptance before projection."""
    if not revisions or len(revisions) > MAX_REVIEW_REVISIONS:
        raise ValueError("review history is empty or exceeds its revision limit")
    canonical = [ReviewRevision.model_validate_json(r.model_dump_json()) for r in revisions]
    first = canonical[0]
    opened = first.command
    if first.revision != 1 or not isinstance(opened, OpenReview):
        raise ValueError("review history requires its original evidence revision")
    if opened.evidence.verified_at > first.recorded_at:
        raise ValueError("review predates evidence verification")
    assessment: HumanAssessment | None = None
    assessment_author = None
    retest: AttachRetest | None = None
    retest_author = None
    decision: DecideReview | None = None
    reviewer = None
    decision_revision = None
    assignments = _AssignmentState()
    state = "open"
    previous = first
    request_keys = {(first.actor, first.request_key)}
    evidence_digests = {opened.evidence.evidence_digest}
    source_identities = {opened.evidence.source_identity}
    for expected_sequence, revision in enumerate(canonical[1:], 2):
        if (
            revision.review_id != first.review_id
            or revision.revision != expected_sequence
            or revision.previous_digest != previous.record_digest
            or revision.recorded_at < previous.recorded_at
            or (revision.actor, revision.request_key) in request_keys
        ):
            raise ValueError("review history identity, order, or predecessor differs")
        command = revision.command
        if isinstance(command, AssessReview):
            if command.assessment.evidence_digest != opened.evidence.evidence_digest:
                raise ValueError("assessment cites different baseline evidence")
            assessment = command.assessment
            assessment_author = revision.actor
            retest = None
            retest_author = None
            decision = None
            reviewer = None
            decision_revision = None
            state = "awaiting-review"
        elif isinstance(command, DecideReview):
            if state != "awaiting-review" or assessment is None:
                raise ValueError("review decision requires a pending complete assessment")
            if revision.actor in {assessment_author, retest_author}:
                raise ValueError("review contributors cannot accept or decide their own revision")
            decision = command
            reviewer = revision.actor
            decision_revision = revision.revision
            state = "accepted" if command.decision == "accept" else "changes-requested"
        elif isinstance(command, AttachRetest):
            if state != "accepted" or assessment is None:
                raise ValueError("retest requires an accepted baseline assessment")
            if (
                command.evidence.domain != opened.evidence.domain
                or command.evidence.case_contract_digest != opened.evidence.case_contract_digest
                or command.evidence.evidence_digest in evidence_digests
                or command.evidence.source_identity in source_identities
                or command.evidence.verified_at <= opened.evidence.verified_at
                or command.evidence.verified_at > revision.recorded_at
            ):
                raise ValueError("retest evidence is reused, incompatible, or not newly verified")
            retest = command
            retest_author = revision.actor
            decision = None
            reviewer = None
            decision_revision = None
            state = "awaiting-review"
            evidence_digests.add(command.evidence.evidence_digest)
            source_identities.add(command.evidence.source_identity)
        elif assignments.apply(revision):
            pass
        else:
            raise ValueError("review history cannot be reopened")
        request_keys.add((revision.actor, revision.request_key))
        previous = revision
    return MeasuredReviewView.model_validate(
        {
            "apiVersion": "pajin.dev/measured-human-review/v2"
            if assignments.revision
            else "pajin.dev/measured-human-review/v1",
            "review_id": first.review_id,
            "revision": previous.revision,
            "record_digest": previous.record_digest,
            "title": opened.title,
            "evidence": opened.evidence,
            "state": state,
            "assessment": assessment,
            "assessment_author": assessment_author,
            "retest": retest,
            "retest_author": retest_author,
            "decision": decision,
            "reviewer": reviewer,
            "assignee": assignments.assignee,
            "assignment_revision": assignments.revision,
            "decision_revision": decision_revision if assignments.revision else None,
            "history": tuple(
                ReviewHistoryItem(
                    revision=r.revision,
                    action=r.command.action,
                    actor=r.actor,
                    actorRole=r.actor_role,
                    recordedAt=r.recorded_at,
                    recordDigest=r.record_digest,
                )
                for r in canonical
            ),
        }
    )
