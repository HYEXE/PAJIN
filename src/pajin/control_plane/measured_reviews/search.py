"""Principal- and filter-bound cursors for bounded scans of verified review state."""

import base64
from typing import Literal, Self

from pydantic import Field, model_validator

from pajin.control_plane.measured_reviews.models import (
    MeasuredReviewView,
    ReviewId,
    ReviewListItem,
    ReviewModel,
    ReviewNotification,
    ReviewState,
    Subject,
)
from pajin.runtime.safe_files import parse_strict_json_bytes


class ReviewFilters(ReviewModel):
    assignee: Subject | None = None
    unassigned: bool = False
    state: ReviewState | None = None
    unread: bool = False

    @model_validator(mode="after")
    def reject_conflicting_assignees(self) -> Self:
        if self.assignee is not None and self.unassigned:
            raise ValueError("choose a specific assignee or unassigned, not both")
        return self

    def matches(self, view: MeasuredReviewView, unread: int) -> bool:
        return (
            (self.assignee is None or view.assignee == self.assignee)
            and (not self.unassigned or view.assignee is None)
            and (self.state is None or view.state == self.state)
            and (not self.unread or unread > 0)
        )


class ReviewSearchCursor(ReviewModel):
    kind: Literal["reviews", "inbox"]
    subject: Subject
    filters: ReviewFilters
    after: ReviewId

    def encode(self) -> str:
        return base64.urlsafe_b64encode(self.model_dump_json().encode()).decode().rstrip("=")

    @classmethod
    def decode(cls, value: str) -> Self:
        if not value or len(value) > 2048:
            raise ValueError("invalid review search cursor")
        content = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        result = cls.model_validate(
            parse_strict_json_bytes(
                content,
                label="review search cursor",
                max_bytes=2048,
            )
        )
        if result.encode() != value:
            raise ValueError("noncanonical review search cursor")
        return result


class ReviewSearchItem(ReviewListItem):
    assignee: Subject | None
    unread_notifications: int = Field(alias="unreadNotifications", ge=0, le=199)
    history_full: bool = Field(alias="historyFull")


class ReviewSearchPage(ReviewModel):
    api_version: Literal["pajin.dev/review-search/v1"] = Field(
        default="pajin.dev/review-search/v1",
        alias="apiVersion",
    )
    items: tuple[ReviewSearchItem, ...] = Field(max_length=10)
    filters: ReviewFilters
    scanned_reviews: int = Field(alias="scannedReviews", ge=0, le=10)
    next_cursor: str | None = Field(alias="nextCursor", max_length=2048)


class FilteredReviewInbox(ReviewModel):
    api_version: Literal["pajin.dev/review-inbox/v2"] = Field(
        default="pajin.dev/review-inbox/v2",
        alias="apiVersion",
    )
    items: tuple[ReviewNotification, ...] = Field(max_length=2000)
    filters: ReviewFilters
    scanned_reviews: int = Field(alias="scannedReviews", ge=0, le=10)
    next_cursor: str | None = Field(alias="nextCursor", max_length=2048)
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
