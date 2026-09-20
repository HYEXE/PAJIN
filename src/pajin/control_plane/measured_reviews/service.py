"""Atomic review revisions and exact duplicate recovery in the existing database."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pajin.control_plane.database import (
    ControlPlaneRepository,
    MeasuredReviewRevisionRecord,
    ReviewNotificationReceiptRecord,
)
from pajin.control_plane.errors import AuthorizationDenied, ResourceNotFound, StateConflict
from pajin.control_plane.measured_reviews.evidence import MeasuredReviewEvidenceReader
from pajin.control_plane.measured_reviews.models import (
    MAX_REVIEW_HISTORY_BYTES,
    MAX_REVIEW_REVISIONS,
    AcknowledgeReviewNotification,
    AssessmentRequest,
    AssessReview,
    AssignmentRequest,
    AssignReview,
    AttachRetest,
    DecideReview,
    DecisionRequest,
    FollowupReviewRequest,
    MeasuredReviewView,
    NotificationAckRequest,
    NotificationReceipt,
    NotificationReceiptRequest,
    OpenReview,
    OpenReviewRequest,
    RetestRequest,
    ReviewCommand,
    ReviewInbox,
    ReviewList,
    ReviewListItem,
    ReviewNotification,
    ReviewPredecessor,
    ReviewRevision,
    review_digest,
)
from pajin.control_plane.measured_reviews.notifications import (
    assignment_state,
    load_receipts,
    receipt_request_digest,
)
from pajin.control_plane.measured_reviews.search import (
    FilteredReviewInbox,
    ReviewFilters,
    ReviewSearchCursor,
    ReviewSearchItem,
    ReviewSearchPage,
)
from pajin.control_plane.measured_reviews.state import rebuild_review
from pajin.control_plane.models import Principal, PrincipalRole

type MutationRequest = (
    OpenReviewRequest
    | AssessmentRequest
    | DecisionRequest
    | RetestRequest
    | AssignmentRequest
    | NotificationAckRequest
)
_READ_ROLES = frozenset({PrincipalRole.OPERATOR, PrincipalRole.APPROVER, PrincipalRole.AUDITOR})


def require_review_role(principal: Principal, *roles: PrincipalRole) -> None:
    if PrincipalRole.WORKER in principal.roles or principal.roles.isdisjoint(roles):
        raise AuthorizationDenied("Credential lacks the required human review role")


def _load(
    session: Session,
    review_id: str,
    *,
    validate_predecessor: bool = True,
) -> list[ReviewRevision]:
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
        if validate_predecessor and view.predecessor is not None:
            predecessor = view.predecessor
            try:
                parent = _load(session, predecessor.review_id, validate_predecessor=False)
            except ResourceNotFound as exc:
                raise ValueError("review predecessor is missing") from exc
            if (
                len(parent) != predecessor.revision
                or parent[-1].record_digest != predecessor.record_digest
                or rebuild_review(parent).evidence != view.evidence
                or history[0].recorded_at < parent[-1].recorded_at
            ):
                raise ValueError("review predecessor or historical evidence differs")
        return history
    except (ValueError, TypeError) as exc:
        raise StateConflict("Stored measured review history is not integrity-valid") from exc


def _lock_review(session: Session, review_id: str) -> None:
    row = session.scalar(
        select(MeasuredReviewRevisionRecord)
        .where(
            MeasuredReviewRevisionRecord.review_id == review_id,
            MeasuredReviewRevisionRecord.revision == 1,
        )
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFound("Measured review does not exist")


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


def _notices(
    history: list[ReviewRevision],
    receipts: list[NotificationReceipt],
    subject: str,
) -> tuple[ReviewNotification, ...]:
    state = assignment_state(history)
    acknowledged = state.acknowledgments | {(r.assignment_revision, r.actor) for r in receipts}
    return tuple(
        ReviewNotification(
            notificationId="review-notice_" + revision.record_digest,
            reviewId=revision.review_id,
            assignmentRevision=revision.revision,
            currentRevision=len(history),
            assignee=revision.command.assignee,
            actor=revision.actor,
            recordedAt=revision.recorded_at,
            acknowledged=(revision.revision, subject) in acknowledged,
        )
        for revision in history
        if isinstance(revision.command, AssignReview)
        and subject in state.recipients[revision.revision]
    )


class MeasuredReviewService:
    def __init__(
        self,
        repository: ControlPlaneRepository,
        evidence: MeasuredReviewEvidenceReader,
        *,
        principals: tuple[Principal, ...] = (),
    ) -> None:
        self._repository = repository
        self.evidence = evidence
        # Deployment-owned human identities only; request data cannot enroll an assignee.
        self.assignees = tuple(
            sorted(
                {
                    p.subject
                    for p in principals
                    if PrincipalRole.WORKER not in p.roles
                    and not p.roles.isdisjoint({PrincipalRole.OPERATOR, PrincipalRole.APPROVER})
                }
            )
        )

    def inbox(self, *, principal: Principal, after: str | None = None) -> ReviewInbox:
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
            notices: list[ReviewNotification] = []
            for review_id in ids[:10]:
                history = _load(session, review_id)
                notices.extend(
                    _notices(history, load_receipts(session, history), principal.subject)
                )
            return ReviewInbox(
                items=tuple(notices),
                scannedReviews=min(10, len(ids)),
                nextAfter=ids[9] if len(ids) > 10 else None,
            )

    def _search(
        self,
        *,
        principal: Principal,
        filters: ReviewFilters,
        cursor: str | None,
        kind: Literal["reviews", "inbox"],
    ) -> tuple[tuple[ReviewSearchItem, ...], tuple[ReviewNotification, ...], int, str | None]:
        require_review_role(principal, *_READ_ROLES)
        filters = ReviewFilters.model_validate_json(filters.model_dump_json())
        after = None
        if cursor is not None:
            decoded = ReviewSearchCursor.decode(cursor)
            if (
                decoded.kind != kind
                or decoded.subject != principal.subject
                or decoded.filters != filters
            ):
                raise ValueError("review cursor principal or filters differ")
            after = decoded.after
        with self._repository.read_transaction() as session:
            query = select(MeasuredReviewRevisionRecord.review_id).where(
                MeasuredReviewRevisionRecord.revision == 1
            )
            if after is not None:
                query = query.where(MeasuredReviewRevisionRecord.review_id > after)
            ids = session.scalars(
                query.order_by(MeasuredReviewRevisionRecord.review_id).limit(11)
            ).all()
            items: list[ReviewSearchItem] = []
            notifications: list[ReviewNotification] = []
            for review_id in ids[:10]:
                # Verify every scanned row, including those a filter will later exclude.
                history = _load(session, review_id)
                view = rebuild_review(history)
                notices = _notices(history, load_receipts(session, history), principal.subject)
                unread = sum(not notice.acknowledged for notice in notices)
                if filters.matches(view, unread):
                    items.append(
                        ReviewSearchItem.model_validate(
                            {
                                "reviewId": view.review_id,
                                "title": view.title,
                                "domain": view.evidence.domain,
                                "state": view.state,
                                "revision": view.revision,
                                "assignee": view.assignee,
                                "unreadNotifications": unread,
                                "historyFull": view.revision == 200,
                            }
                        )
                    )
                    notifications.extend(
                        n for n in notices if not filters.unread or not n.acknowledged
                    )
            next_cursor = (
                ReviewSearchCursor(
                    kind=kind, subject=principal.subject, filters=filters, after=ids[9]
                ).encode()
                if len(ids) > 10
                else None
            )
            return tuple(items), tuple(notifications), min(len(ids), 10), next_cursor

    def search_reviews(
        self,
        *,
        principal: Principal,
        filters: ReviewFilters,
        cursor: str | None = None,
    ) -> ReviewSearchPage:
        items, _, scanned, next_cursor = self._search(
            principal=principal,
            filters=filters,
            cursor=cursor,
            kind="reviews",
        )
        return ReviewSearchPage(
            items=items, filters=filters, scannedReviews=scanned, nextCursor=next_cursor
        )

    def search_inbox(
        self,
        *,
        principal: Principal,
        filters: ReviewFilters,
        cursor: str | None = None,
    ) -> FilteredReviewInbox:
        _, notices, scanned, next_cursor = self._search(
            principal=principal,
            filters=filters,
            cursor=cursor,
            kind="inbox",
        )
        return FilteredReviewInbox(
            items=notices, filters=filters, scannedReviews=scanned, nextCursor=next_cursor
        )

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
        if isinstance(payload, NotificationAckRequest):
            require_review_role(principal, PrincipalRole.OPERATOR, PrincipalRole.APPROVER)
            role = next(
                r for r in (PrincipalRole.OPERATOR, PrincipalRole.APPROVER) if r in principal.roles
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
                if review_id is not None:
                    _lock_review(session, review_id)
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
                if isinstance(payload, NotificationAckRequest) and any(
                    r.actor == principal.subject
                    and r.assignment_revision == payload.assignment_revision
                    for r in load_receipts(session, history)
                ):
                    raise StateConflict("Notification is already acknowledged")
                revision = ReviewRevision.model_validate(
                    {
                        "review_id": identity,
                        "apiVersion": "pajin.dev/measured-review-revision/v2"
                        if isinstance(command, AssignReview | AcknowledgeReviewNotification)
                        else "pajin.dev/measured-review-revision/v1",
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

    def report_inputs(
        self,
        review_id: str,
        *,
        principal: Principal,
    ) -> tuple[tuple[ReviewRevision, ...], tuple[NotificationReceipt, ...]]:
        require_review_role(principal, *_READ_ROLES)
        with self._repository.read_transaction() as session:
            history = _load(session, review_id)
            return tuple(history), tuple(load_receipts(session, history))

    def notification_receipts(
        self,
        review_id: str,
        *,
        principal: Principal,
    ) -> tuple[NotificationReceipt, ...]:
        require_review_role(principal, *_READ_ROLES)
        with self._repository.read_transaction() as session:
            return tuple(load_receipts(session, _load(session, review_id)))

    @staticmethod
    def _receipt_duplicate(
        session: Session,
        *,
        actor: str,
        request_key: str,
        request_digest: str,
    ) -> NotificationReceipt | None:
        row = session.scalar(
            select(ReviewNotificationReceiptRecord).where(
                ReviewNotificationReceiptRecord.actor == actor,
                ReviewNotificationReceiptRecord.request_key == request_key,
            )
        )
        if row is None:
            return None
        receipts = load_receipts(session, _load(session, row.review_id))
        if row.request_digest != request_digest:
            raise StateConflict("Receipt request key belongs to a different notification")
        return next(r for r in receipts if r.record_digest == row.record_digest)

    def acknowledge_notification(
        self,
        review_id: str,
        payload: NotificationReceiptRequest,
        *,
        principal: Principal,
    ) -> NotificationReceipt:
        require_review_role(principal, PrincipalRole.OPERATOR, PrincipalRole.APPROVER)
        payload = NotificationReceiptRequest.model_validate_json(payload.model_dump_json())
        role = next(
            r for r in (PrincipalRole.OPERATOR, PrincipalRole.APPROVER) if r in principal.roles
        )
        digest = receipt_request_digest(
            review_id, payload, actor=principal.subject, role=role.value
        )
        try:
            with self._repository.transaction() as session:
                _lock_review(session, review_id)
                duplicate = self._receipt_duplicate(
                    session,
                    actor=principal.subject,
                    request_key=payload.request_key,
                    request_digest=digest,
                )
                if duplicate is not None:
                    return duplicate
                history = _load(session, review_id)
                state = assignment_state(history)
                receipts = load_receipts(session, history)
                key = (payload.assignment_revision, principal.subject)
                if principal.subject not in state.recipients.get(
                    payload.assignment_revision, set()
                ):
                    raise StateConflict("Notification does not belong to this recipient")
                assignment = history[payload.assignment_revision - 1]
                if payload.notification_id != "review-notice_" + assignment.record_digest:
                    raise StateConflict(
                        "Notification identity differs from its immutable assignment"
                    )
                if key in state.acknowledgments or any(
                    (r.assignment_revision, r.actor) == key for r in receipts
                ):
                    raise StateConflict("Notification is already acknowledged")
                receipt = NotificationReceipt.model_validate(
                    {
                        "reviewId": review_id,
                        "assignmentRevision": payload.assignment_revision,
                        "assignmentDigest": assignment.record_digest,
                        "actor": principal.subject,
                        "actorRole": role.value,
                        "recordedAt": datetime.now(UTC),
                        "requestKey": payload.request_key,
                        "requestDigest": digest,
                    }
                )
                if receipt.recorded_at < assignment.recorded_at:
                    raise StateConflict("Current clock precedes the retained assignment")
                session.add(
                    ReviewNotificationReceiptRecord(
                        review_id=receipt.review_id,
                        assignment_revision=receipt.assignment_revision,
                        assignment_digest=receipt.assignment_digest,
                        actor=receipt.actor,
                        actor_role=receipt.actor_role,
                        recorded_at=receipt.recorded_at,
                        request_key=receipt.request_key,
                        request_digest=receipt.request_digest,
                        record_digest=receipt.record_digest,
                        payload=receipt.model_dump(mode="json", by_alias=True),
                    )
                )
                session.flush()
                return receipt
        except IntegrityError as exc:
            with self._repository.read_transaction() as session:
                duplicate = self._receipt_duplicate(
                    session,
                    actor=principal.subject,
                    request_key=payload.request_key,
                    request_digest=digest,
                )
                if duplicate is not None:
                    return duplicate
            raise StateConflict(
                "Notification changed concurrently; refresh its saved state"
            ) from exc

    def open_followup(
        self,
        review_id: str,
        payload: FollowupReviewRequest,
        *,
        principal: Principal,
    ) -> MeasuredReviewView:
        require_review_role(principal, PrincipalRole.OPERATOR)
        payload = FollowupReviewRequest.model_validate_json(payload.model_dump_json())
        digest = review_digest(
            "pajin.measured-review.request/v1",
            {
                "actor": principal.subject,
                "role": "operator",
                "action": "FollowupReviewRequest",
                "reviewId": review_id,
                "request": payload.model_dump(mode="json", by_alias=True),
            },
        )
        try:
            with self._repository.transaction() as session:
                _lock_review(session, review_id)
                duplicate = _duplicate(
                    session,
                    actor=principal.subject,
                    request_key=payload.request_key,
                    request_digest=digest,
                )
                if duplicate is not None:
                    return duplicate
                history = _load(session, review_id)
                if (
                    len(history) != payload.expected_revision
                    or history[-1].record_digest != payload.expected_digest
                ):
                    raise StateConflict(
                        "Full review identity changed; reload before opening a follow-up"
                    )
                view = rebuild_review(history)
                now = datetime.now(UTC)
                if now < history[-1].recorded_at:
                    raise StateConflict("Current clock precedes the retained predecessor")
                command = OpenReview(
                    title=payload.title,
                    evidence=view.evidence,
                    predecessor=ReviewPredecessor(
                        reviewId=review_id,
                        revision=view.revision,
                        recordDigest=view.record_digest,
                        reason=payload.reason,
                    ),
                )
                revision = ReviewRevision.model_validate(
                    {
                        "apiVersion": "pajin.dev/measured-review-revision/v3",
                        "reviewId": "review_" + uuid4().hex,
                        "revision": 1,
                        "previousDigest": None,
                        "actor": principal.subject,
                        "actorRole": "operator",
                        "recordedAt": now,
                        "requestKey": payload.request_key,
                        "requestDigest": digest,
                        "command": command,
                    }
                )
                session.add(
                    MeasuredReviewRevisionRecord(
                        review_id=revision.review_id,
                        revision=1,
                        source_domain=view.evidence.domain,
                        previous_digest=None,
                        actor=revision.actor,
                        actor_role=revision.actor_role,
                        recorded_at=revision.recorded_at,
                        request_key=revision.request_key,
                        request_digest=revision.request_digest,
                        record_digest=revision.record_digest,
                        payload=revision.model_dump(mode="json", by_alias=True),
                    )
                )
                session.flush()
                return rebuild_review([revision])
        except IntegrityError as exc:
            with self._repository.read_transaction() as session:
                duplicate = _duplicate(
                    session,
                    actor=principal.subject,
                    request_key=payload.request_key,
                    request_digest=digest,
                )
                if duplicate is not None:
                    return duplicate
            raise StateConflict("Follow-up creation conflicted; reload its saved state") from exc

    @staticmethod
    def _require_revision(payload: MutationRequest, history: list[ReviewRevision]) -> None:
        if not isinstance(payload, OpenReviewRequest) and payload.expected_revision != len(history):
            raise StateConflict("Review changed; reload its current revision before editing")

    def _prepare(self, payload: MutationRequest, history: list[ReviewRevision]) -> ReviewCommand:
        if isinstance(payload, AssignmentRequest):
            if payload.assignee is not None and payload.assignee not in self.assignees:
                raise AuthorizationDenied("Assignee is not a configured human reviewer")
            return AssignReview(assignee=payload.assignee, reason=payload.reason)
        if isinstance(payload, NotificationAckRequest):
            return AcknowledgeReviewNotification(assignmentRevision=payload.assignment_revision)
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
