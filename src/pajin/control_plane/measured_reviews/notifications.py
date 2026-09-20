"""Verify bounded immutable notification receipts independently of human review revisions."""

import json
from datetime import UTC

from sqlalchemy import LargeBinary, Text, cast, func, select
from sqlalchemy.orm import Session

from pajin.control_plane.database import ReviewNotificationReceiptRecord
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.measured_reviews.models import (
    MAX_NOTIFICATION_RECEIPTS,
    NotificationReceipt,
    NotificationReceiptRequest,
    ReviewRevision,
    review_digest,
)
from pajin.control_plane.measured_reviews.state import _AssignmentState


def assignment_state(history: list[ReviewRevision]) -> _AssignmentState:
    state = _AssignmentState()
    for revision in history:
        state.apply(revision)
    return state


def receipt_request_digest(
    review_id: str,
    payload: NotificationReceiptRequest,
    *,
    actor: str,
    role: str,
) -> str:
    return review_digest(
        "pajin.measured-review.notification-request/v1",
        {
            "reviewId": review_id,
            "actor": actor,
            "role": role,
            "request": payload.model_dump(mode="json", by_alias=True),
        },
    )


def load_receipts(session: Session, history: list[ReviewRevision]) -> list[NotificationReceipt]:
    review_id = history[0].review_id
    table = ReviewNotificationReceiptRecord
    predicate = table.review_id == review_id
    # Refuse oversized stored JSON before ORM hydration of the receipt set.
    length = (
        func.length(cast(table.payload, LargeBinary))
        if session.get_bind().dialect.name == "sqlite"
        else func.octet_length(cast(table.payload, Text))
    )
    count, size = session.execute(
        select(func.count(), func.coalesce(func.sum(length), 0)).where(predicate)
    ).one()
    if count > MAX_NOTIFICATION_RECEIPTS or size > MAX_NOTIFICATION_RECEIPTS * 4096:
        raise StateConflict("Stored notification receipts exceed their bounded history")
    rows = session.scalars(
        select(table)
        .where(predicate)
        .order_by(
            table.assignment_revision,
            table.actor,
        )
        .limit(MAX_NOTIFICATION_RECEIPTS + 1)
    ).all()
    state = assignment_state(history)
    receipts = []
    seen = set(state.acknowledgments)
    try:
        for row in rows:
            receipt = NotificationReceipt.model_validate_json(
                json.dumps(row.payload, ensure_ascii=False, allow_nan=False)
            )
            recorded_at = row.recorded_at
            if recorded_at.tzinfo is None:
                recorded_at = recorded_at.replace(tzinfo=UTC)
            if (
                row.review_id != receipt.review_id
                or row.assignment_revision != receipt.assignment_revision
                or row.assignment_digest != receipt.assignment_digest
                or row.actor != receipt.actor
                or row.actor_role != receipt.actor_role
                or row.request_key != receipt.request_key
                or row.request_digest != receipt.request_digest
                or row.record_digest != receipt.record_digest
                or recorded_at != receipt.recorded_at
                or receipt.assignment_revision > len(history)
            ):
                raise ValueError("notification receipt columns differ from its payload")
            assignment = history[receipt.assignment_revision - 1]
            key = (receipt.assignment_revision, receipt.actor)
            if (
                receipt.actor not in state.recipients.get(receipt.assignment_revision, set())
                or receipt.assignment_digest != assignment.record_digest
                or receipt.recorded_at < assignment.recorded_at
                or key in seen
            ):
                raise ValueError("notification receipt recipient or assignment differs")
            request = NotificationReceiptRequest(
                requestKey=receipt.request_key,
                notificationId="review-notice_" + receipt.assignment_digest,
                assignmentRevision=receipt.assignment_revision,
            )
            if receipt.request_digest != receipt_request_digest(
                review_id,
                request,
                actor=receipt.actor,
                role=receipt.actor_role,
            ):
                raise ValueError("notification receipt request binding differs")
            seen.add(key)
            receipts.append(receipt)
    except (ValueError, TypeError) as exc:
        raise StateConflict("Stored notification receipt is not integrity-valid") from exc
    return receipts
