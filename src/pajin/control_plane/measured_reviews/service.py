"""Atomic review revisions and exact duplicate recovery in the existing database."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pajin.control_plane.database import ControlPlaneRepository, MeasuredReviewRevisionRecord
from pajin.control_plane.errors import AuthorizationDenied, ResourceNotFound, StateConflict
from pajin.control_plane.measured_reviews.evidence import MeasuredReviewEvidenceReader
from pajin.control_plane.measured_reviews.models import (
    MAX_REVIEW_HISTORY_BYTES,
    MAX_REVIEW_REVISIONS,
    AssessmentRequest,
    AssessReview,
    AttachRetest,
    DecideReview,
    DecisionRequest,
    MeasuredReviewView,
    OpenReview,
    OpenReviewRequest,
    RetestRequest,
    ReviewCommand,
    ReviewList,
    ReviewListItem,
    ReviewRevision,
    review_digest,
)
from pajin.control_plane.measured_reviews.state import rebuild_review
from pajin.control_plane.models import Principal, PrincipalRole

type MutationRequest = OpenReviewRequest | AssessmentRequest | DecisionRequest | RetestRequest
_READ_ROLES = frozenset({PrincipalRole.OPERATOR, PrincipalRole.APPROVER, PrincipalRole.AUDITOR})


def require_review_role(principal: Principal, *roles: PrincipalRole) -> None:
    if PrincipalRole.WORKER in principal.roles or principal.roles.isdisjoint(roles):
        raise AuthorizationDenied("Credential lacks the required human review role")


def _load(session: Session, review_id: str) -> list[ReviewRevision]:
    rows = session.scalars(
        select(MeasuredReviewRevisionRecord)
        .where(MeasuredReviewRevisionRecord.review_id == review_id)
        .order_by(MeasuredReviewRevisionRecord.revision)
        .limit(MAX_REVIEW_REVISIONS + 1)
    ).all()
    if not rows:
        raise ResourceNotFound("Measured review does not exist")
    try:
        history = []
        total_bytes = 0
        for row in rows:
            encoded = json.dumps(row.payload, ensure_ascii=False, allow_nan=False)
            total_bytes += len(encoded.encode("utf-8"))
            if total_bytes > MAX_REVIEW_HISTORY_BYTES:
                raise ValueError("review history exceeds its byte limit")
            revision = ReviewRevision.model_validate_json(encoded)
            recorded_at = row.recorded_at
            if recorded_at.tzinfo is None:
                recorded_at = recorded_at.replace(tzinfo=UTC)
            if (
                row.review_id != revision.review_id
                or row.revision != revision.revision
                or row.previous_digest != revision.previous_digest
                or row.actor != revision.actor
                or row.actor_role != revision.actor_role
                or recorded_at != revision.recorded_at
                or row.request_key != revision.request_key
                or row.request_digest != revision.request_digest
                or row.record_digest != revision.record_digest
            ):
                raise ValueError("review row differs from its canonical revision")
            history.append(revision)
        view = rebuild_review(history)
        if any(row.source_domain != view.evidence.domain for row in rows):
            raise ValueError("review row domain differs")
        return history
    except (ValueError, TypeError) as exc:
        raise StateConflict("Stored measured review history is not integrity-valid") from exc


def _duplicate(
    session: Session, *, actor: str, request_key: str, request_digest: str
) -> MeasuredReviewView | None:
    row = session.scalar(
        select(MeasuredReviewRevisionRecord).where(
            MeasuredReviewRevisionRecord.actor == actor,
            MeasuredReviewRevisionRecord.request_key == request_key,
        )
    )
    if row is None:
        return None
    history = _load(session, row.review_id)
    if row.request_digest != request_digest:
        raise StateConflict("Request key already belongs to a different review command")
    return rebuild_review(history[: row.revision])


class MeasuredReviewService:
    def __init__(
        self, repository: ControlPlaneRepository, evidence: MeasuredReviewEvidenceReader
    ) -> None:
        self._repository = repository
        self.evidence = evidence

    def history(self, review_id: str, *, principal: Principal) -> tuple[ReviewRevision, ...]:
        require_review_role(principal, *_READ_ROLES)
        with self._repository.read_transaction() as session:
            return tuple(_load(session, review_id))

    def get(self, review_id: str, *, principal: Principal) -> MeasuredReviewView:
        return rebuild_review(self.history(review_id, principal=principal))

    def list_reviews(self, *, principal: Principal, after: str | None = None) -> ReviewList:
        require_review_role(principal, *_READ_ROLES)
        with self._repository.read_transaction() as session:
            query = select(MeasuredReviewRevisionRecord.review_id).where(
                MeasuredReviewRevisionRecord.revision == 1
            )
            if after is not None:
                query = query.where(MeasuredReviewRevisionRecord.review_id > after)
            ids = session.scalars(
                query.order_by(MeasuredReviewRevisionRecord.review_id).limit(11)
            ).all()
            items = []
            for review_id in ids[:10]:
                view = rebuild_review(_load(session, review_id))
                items.append(
                    ReviewListItem.model_validate(
                        {
                            "review_id": view.review_id,
                            "title": view.title,
                            "domain": view.evidence.domain,
                            "state": view.state,
                            "revision": view.revision,
                        }
                    )
                )
            return ReviewList(items=tuple(items), nextAfter=ids[9] if len(ids) > 10 else None)

    def submit(
        self,
        payload: MutationRequest,
        *,
        principal: Principal,
        review_id: str | None = None,
    ) -> MeasuredReviewView:
        """Verify a source outside the writer transaction, then recheck and append atomically."""
        role = (
            PrincipalRole.APPROVER
            if isinstance(payload, DecisionRequest)
            else PrincipalRole.OPERATOR
        )
        require_review_role(principal, role)
        payload = type(payload).model_validate_json(payload.model_dump_json())
        if (review_id is None) != isinstance(payload, OpenReviewRequest):
            raise StateConflict("Review command and identity differ")
        digest = review_digest(
            "pajin.measured-review.request/v1",
            {
                "actor": principal.subject,
                "role": role.value,
                "action": type(payload).__name__,
                "reviewId": review_id,
                "request": payload.model_dump(mode="json", by_alias=True),
            },
        )
        with self._repository.read_transaction() as session:
            duplicate = _duplicate(
                session,
                actor=principal.subject,
                request_key=payload.request_key,
                request_digest=digest,
            )
            if duplicate is not None:
                return duplicate
            history = [] if review_id is None else _load(session, review_id)
        self._require_revision(payload, history)
        command = self._prepare(payload, history)
        identity = review_id or "review_" + uuid4().hex
        try:
            with self._repository.transaction() as session:
                duplicate = _duplicate(
                    session,
                    actor=principal.subject,
                    request_key=payload.request_key,
                    request_digest=digest,
                )
                if duplicate is not None:
                    return duplicate
                history = [] if review_id is None else _load(session, review_id)
                self._require_revision(payload, history)
                revision = ReviewRevision.model_validate(
                    {
                        "review_id": identity,
                        "revision": len(history) + 1,
                        "previous_digest": history[-1].record_digest if history else None,
                        "actor": principal.subject,
                        "actor_role": role.value,
                        "recorded_at": datetime.now(UTC),
                        "request_key": payload.request_key,
                        "request_digest": digest,
                        "command": command,
                    }
                )
                history.append(revision)
                if sum(len(r.model_dump_json().encode("utf-8")) for r in history) > (
                    MAX_REVIEW_HISTORY_BYTES
                ):
                    raise StateConflict("Review history is full; open a new review")
                view = rebuild_review(history)
                session.add(
                    MeasuredReviewRevisionRecord(
                        review_id=identity,
                        revision=revision.revision,
                        source_domain=view.evidence.domain,
                        previous_digest=revision.previous_digest,
                        actor=principal.subject,
                        actor_role=role.value,
                        recorded_at=revision.recorded_at,
                        request_key=payload.request_key,
                        request_digest=digest,
                        record_digest=revision.record_digest,
                        payload=revision.model_dump(mode="json", by_alias=True),
                    )
                )
                session.flush()
                return view
        except IntegrityError as exc:
            # Cross-process PostgreSQL uniqueness races roll back the entire append.
            with self._repository.read_transaction() as session:
                duplicate = _duplicate(
                    session,
                    actor=principal.subject,
                    request_key=payload.request_key,
                    request_digest=digest,
                )
                if duplicate is not None:
                    return duplicate
            raise StateConflict("Review changed concurrently; reload before editing") from exc
        except ValueError as exc:
            raise StateConflict(str(exc)) from exc

    @staticmethod
    def _require_revision(payload: MutationRequest, history: list[ReviewRevision]) -> None:
        if not isinstance(payload, OpenReviewRequest) and payload.expected_revision != len(history):
            raise StateConflict("Review changed; reload its current revision before editing")

    def _prepare(self, payload: MutationRequest, history: list[ReviewRevision]) -> ReviewCommand:
        if isinstance(payload, OpenReviewRequest):
            return OpenReview(
                title=payload.title,
                evidence=self.evidence.read_exact(payload.domain, payload.evidence_digest),
            )
        if isinstance(payload, AssessmentRequest):
            return AssessReview(assessment=payload.assessment)
        if isinstance(payload, DecisionRequest):
            return DecideReview(decision=payload.decision, reason=payload.reason)
        view = rebuild_review(history)
        return AttachRetest(
            evidence=self.evidence.read_exact(view.evidence.domain, payload.evidence_digest),
            changeReference=payload.change_reference,
            conclusion=payload.conclusion,
            rationale=payload.rationale,
        )
