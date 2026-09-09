"""Versioned human-review records; none of these models grants execution authority."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import FindingSeverity
from pajin.workflow.ai_measured_product_flow import AIMeasuredProduct
from pajin.workflow.network_measured_product_flow import NetworkMeasuredProduct
from pajin.workflow.web_measured_product_flow import WebMeasuredProductFlowProjection

type ReviewDomain = Literal["web", "network", "ai"]
type Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
type ReviewId = Annotated[str, Field(pattern=r"^review_[a-f0-9]{32}$")]
type Subject = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")]
type RequestKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
type ReviewProjection = Annotated[
    WebMeasuredProductFlowProjection | NetworkMeasuredProduct | AIMeasuredProduct,
    Field(discriminator="kind"),
]
MAX_REVIEW_REVISIONS = 200
MAX_REVIEW_BYTES = 512 * 1024
MAX_REVIEW_HISTORY_BYTES = 8 * 1024 * 1024


class ReviewModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        populate_by_name=True,
        revalidate_instances="always",
        allow_inf_nan=False,
        str_strip_whitespace=True,
    )

    @field_validator(
        "raw_content_included",
        "execution_after_remediation_verified",
        "historical_verification_only",
        "execution_authorized",
        "generic_finding_confirmed",
        "sarif_authorized",
        "external_delivery_authorized",
        mode="before",
        check_fields=False,
    )
    @classmethod
    def reject_non_boolean_markers(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("review boundary markers must be literal booleans")
        return value


def review_digest(domain: str, value: object) -> str:
    encoded = json.dumps(
        {"domain": domain, "value": value},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_REVIEW_BYTES:
        raise ValueError("measured review record exceeds its byte limit")
    return hashlib.sha256(encoded).hexdigest()


class ReviewEvidence(ReviewModel):
    """Server-verified public summary, distinct from raw or production evidence."""

    api_version: Literal["pajin.dev/measured-review-evidence/v1"] = Field(
        default="pajin.dev/measured-review-evidence/v1", alias="apiVersion"
    )
    domain: ReviewDomain
    projection: ReviewProjection
    verified_at: datetime = Field(alias="verifiedAt")
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    evidence_scope: Literal["verified-controlled-benchmark-summary"] = Field(
        default="verified-controlled-benchmark-summary", alias="evidenceScope"
    )
    raw_content_included: Literal[False] = Field(default=False, alias="rawContentIncluded")

    @field_validator("verified_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence verification time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def bind_projection(self) -> Self:
        expected_domain = {
            WebMeasuredProductFlowProjection: "web",
            NetworkMeasuredProduct: "network",
            AIMeasuredProduct: "ai",
        }.get(type(self.projection))
        if self.domain != expected_domain:
            raise ValueError("review evidence domain differs from its projection")
        canonical = type(self.projection).model_validate_json(
            self.projection.model_dump_json(by_alias=True)
        )
        object.__setattr__(self, "projection", canonical)
        digest = review_digest(
            "pajin.measured-review.evidence/v1",
            {
                "domain": self.domain,
                "projection": canonical.model_dump(mode="json", by_alias=True),
            },
        )
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("review evidence digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self

    @property
    def case_contract_digest(self) -> str:
        projection = self.projection
        material = (
            projection.scope.measured_case.model_dump(mode="json", by_alias=True)
            if isinstance(projection, WebMeasuredProductFlowProjection)
            else [item.case.model_dump(mode="json", by_alias=True) for item in projection.cases]
        )
        return review_digest(
            "pajin.measured-review.case/v1", {"domain": self.domain, "cases": material}
        )

    @property
    def source_identity(self) -> str:
        if isinstance(self.projection, WebMeasuredProductFlowProjection):
            return self.projection.source_authority_digest
        return self.projection.source_evaluation.evaluation_digest


class RemediationStep(ReviewModel):
    action: str = Field(min_length=1, max_length=2000)
    verification: str = Field(min_length=1, max_length=2000)


class HumanAssessment(ReviewModel):
    impact: str = Field(min_length=1, max_length=5000)
    severity: FindingSeverity
    severity_rationale: str = Field(alias="severityRationale", min_length=1, max_length=5000)
    evidence_digest: Digest = Field(alias="evidenceDigest")
    limitations: str = Field(min_length=1, max_length=5000)
    remediation: tuple[RemediationStep, ...] = Field(min_length=1, max_length=20)
    retest_plan: str = Field(alias="retestPlan", min_length=1, max_length=5000)
    judgment_scope: Literal["human-assessment-of-bounded-benchmark-evidence"] = Field(
        default="human-assessment-of-bounded-benchmark-evidence", alias="judgmentScope"
    )

    @field_validator("severity", mode="before")
    @classmethod
    def parse_severity(cls, value: object) -> object:
        return FindingSeverity(value) if type(value) is str else value

    @field_validator("remediation", mode="before")
    @classmethod
    def parse_steps(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value


class OpenReview(ReviewModel):
    action: Literal["opened"] = "opened"
    title: str = Field(min_length=1, max_length=180)
    evidence: ReviewEvidence


class AssessReview(ReviewModel):
    action: Literal["assessed"] = "assessed"
    assessment: HumanAssessment


class DecideReview(ReviewModel):
    action: Literal["decided"] = "decided"
    decision: Literal["accept", "request-changes"]
    reason: str = Field(min_length=1, max_length=5000)


class AttachRetest(ReviewModel):
    action: Literal["retested"] = "retested"
    evidence: ReviewEvidence
    change_reference: str = Field(alias="changeReference", min_length=1, max_length=1000)
    conclusion: Literal["reviewer-assessed-resolved", "persists", "inconclusive"]
    rationale: str = Field(min_length=1, max_length=5000)
    execution_after_remediation_verified: Literal[False] = Field(
        default=False, alias="executionAfterRemediationVerified"
    )


type ReviewCommand = Annotated[
    OpenReview | AssessReview | DecideReview | AttachRetest, Field(discriminator="action")
]


class ReviewRevision(ReviewModel):
    api_version: Literal["pajin.dev/measured-review-revision/v1"] = Field(
        default="pajin.dev/measured-review-revision/v1", alias="apiVersion"
    )
    review_id: ReviewId = Field(alias="reviewId")
    revision: int = Field(ge=1, le=MAX_REVIEW_REVISIONS)
    previous_digest: Digest | None = Field(alias="previousDigest")
    actor: Subject
    actor_role: Literal["operator", "approver"] = Field(alias="actorRole")
    recorded_at: datetime = Field(alias="recordedAt")
    request_key: RequestKey = Field(alias="requestKey")
    request_digest: Digest = Field(alias="requestDigest")
    command: ReviewCommand
    record_digest: str = Field(default="", alias="recordDigest", max_length=64)

    @field_validator("recorded_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("review revision time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        if (self.revision == 1) != (self.previous_digest is None):
            raise ValueError("review revision predecessor differs")
        if (self.revision == 1) != isinstance(self.command, OpenReview):
            raise ValueError("only the first review revision can open the review")
        expected_role = "approver" if isinstance(self.command, DecideReview) else "operator"
        if self.actor_role != expected_role:
            raise ValueError("review command actor role differs")
        digest = review_digest(
            "pajin.measured-review.revision/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"record_digest"}),
        )
        if self.record_digest and self.record_digest != digest:
            raise ValueError("review revision digest differs")
        object.__setattr__(self, "record_digest", digest)
        return self


class OpenReviewRequest(ReviewModel):
    request_key: RequestKey = Field(alias="requestKey")
    domain: ReviewDomain
    evidence_digest: Digest = Field(alias="evidenceDigest")
    title: str = Field(min_length=1, max_length=180)


class RevisionRequest(ReviewModel):
    request_key: RequestKey = Field(alias="requestKey")
    expected_revision: int = Field(alias="expectedRevision", ge=1, lt=MAX_REVIEW_REVISIONS)


class AssessmentRequest(RevisionRequest):
    assessment: HumanAssessment


class DecisionRequest(RevisionRequest):
    decision: Literal["accept", "request-changes"]
    reason: str = Field(min_length=1, max_length=5000)


class RetestRequest(RevisionRequest):
    evidence_digest: Digest = Field(alias="evidenceDigest")
    change_reference: str = Field(alias="changeReference", min_length=1, max_length=1000)
    conclusion: Literal["reviewer-assessed-resolved", "persists", "inconclusive"]
    rationale: str = Field(min_length=1, max_length=5000)


class ReviewHistoryItem(ReviewModel):
    revision: int
    action: Literal["opened", "assessed", "decided", "retested"]
    actor: Subject
    actor_role: Literal["operator", "approver"] = Field(alias="actorRole")
    recorded_at: datetime = Field(alias="recordedAt")
    record_digest: Digest = Field(alias="recordDigest")


class MeasuredReviewView(ReviewModel):
    api_version: Literal["pajin.dev/measured-human-review/v1"] = Field(
        default="pajin.dev/measured-human-review/v1", alias="apiVersion"
    )
    review_id: ReviewId = Field(alias="reviewId")
    revision: int
    record_digest: Digest = Field(alias="recordDigest")
    title: str
    evidence: ReviewEvidence
    state: Literal["open", "awaiting-review", "changes-requested", "accepted"]
    assessment: HumanAssessment | None
    assessment_author: Subject | None = Field(alias="assessmentAuthor")
    retest: AttachRetest | None
    retest_author: Subject | None = Field(alias="retestAuthor")
    decision: DecideReview | None
    reviewer: Subject | None
    history: tuple[ReviewHistoryItem, ...]
    historical_verification_only: Literal[True] = Field(
        default=True, alias="historicalVerificationOnly"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    generic_finding_confirmed: Literal[False] = Field(
        default=False, alias="genericFindingConfirmed"
    )
    sarif_authorized: Literal[False] = Field(default=False, alias="sarifAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False, alias="externalDeliveryAuthorized"
    )


class ReviewListItem(ReviewModel):
    review_id: ReviewId = Field(alias="reviewId")
    title: str
    domain: ReviewDomain
    state: Literal["open", "awaiting-review", "changes-requested", "accepted"]
    revision: int


class ReviewList(ReviewModel):
    items: tuple[ReviewListItem, ...]
    next_after: ReviewId | None = Field(alias="nextAfter")
