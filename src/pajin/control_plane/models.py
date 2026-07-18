"""Typed contracts for the PAJIN durable Control Plane."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import CampaignMode, StrictModel, ToolRiskTier
from pajin.domain.replay import ReplayPurpose


class RunState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting-approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobState(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DEAD_LETTER = "dead-letter"
    CANCELLED = "cancelled"


class JobKind(StrEnum):
    CAMPAIGN = "campaign"
    TOOL_LOOP = "tool-loop"


class InternalJobKind(StrEnum):
    """Job kinds that may only be created and claimed through trusted services."""

    REPLAY = "internal-replay"


class ReplayBatchState(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    GATING = "gating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReplayItemState(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    VERIFIED = "verified"
    GATED = "gated"
    RETRY_PENDING = "retry-pending"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReplayTicketState(StrEnum):
    ISSUED = "issued"
    CLAIMED = "claimed"
    FINALIZED = "finalized"
    ABANDONED = "abandoned"


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class PrincipalRole(StrEnum):
    OPERATOR = "operator"
    APPROVER = "approver"
    WORKER = "worker"
    AUDITOR = "auditor"


class ControlPlaneConflictCode(StrEnum):
    """Stable machine-readable causes for Control Plane HTTP 409 responses."""

    RUN_CANCELLED = "run_cancelled"
    LEASE_LOST = "lease_lost"


class ControlPlaneConflictResponse(StrictModel):
    """Shared JSON body for typed and legacy-compatible conflict responses."""

    detail: str = Field(min_length=1, max_length=500)
    code: ControlPlaneConflictCode | None = None


class Principal(StrictModel):
    subject: str = Field(min_length=1, max_length=200)
    roles: frozenset[PrincipalRole] = Field(min_length=1)


class ApprovalIntent(StrictModel):
    call_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=2_000)
    risk_tier: ToolRiskTier
    expires_at: datetime

    @model_validator(mode="after")
    def require_high_risk(self) -> ApprovalIntent:
        if self.risk_tier < ToolRiskTier.T3:
            raise ValueError("Control Plane approvals are reserved for T3/T4 intents")
        if self.expires_at.tzinfo is None:
            raise ValueError("approval expiry must be timezone-aware")
        return self


class SubmitRunRequest(StrictModel):
    campaign_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    input: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=8, max_length=200)
    max_attempts: int = Field(default=3, ge=1, le=20)
    job_kind: JobKind = JobKind.CAMPAIGN


class ClaimJobRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    kinds: list[JobKind] = Field(
        default_factory=lambda: [JobKind.CAMPAIGN], min_length=1, max_length=20
    )
    lease_seconds: int = Field(default=30, ge=5, le=300)
    wait_seconds: int = Field(default=0, ge=0, le=20)


class ArtifactLocator(StrictModel):
    """Opaque exact-version lookup key for one managed source artifact."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    artifact_id: str = Field(pattern=r"^artifact_[0-9a-f]{32}$")
    repository_version: int = Field(strict=True, ge=1, le=2_147_483_647)


class ArtifactRef(StrictModel):
    """Immutable repository identity for a sealed Run artifact."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    artifact_id: str = Field(pattern=r"^artifact_[0-9a-f]{32}$")
    repository_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    media_type: str = Field(
        min_length=3,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$",
    )
    schema_kind: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    byte_length: int = Field(strict=True, ge=1, le=2_147_483_647)
    content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    producer_run_id: str = Field(pattern=r"^run_[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    integrity_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_by: str = Field(min_length=1, max_length=200)


class AdmitSourceArtifactRequest(StrictModel):
    """Internal-only request to admit one producer-owned sealed Run snapshot."""

    staging_id: str = Field(
        strict=True,
        pattern=r"^stage_[0-9a-f]{32}$",
    )
    producer_run_id: str = Field(pattern=r"^run_[0-9a-f]{32}$")
    producer_job_id: str = Field(pattern=r"^job_[0-9a-f]{32}$")
    idempotency_key: str = Field(min_length=8, max_length=200)


class ReplayJobPayload(StrictModel):
    """Canonical, non-executable authority envelope for one internal Replay Job."""

    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    source: ArtifactRef
    mode: CampaignMode
    purpose: ReplayPurpose
    policy_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    contract_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    grant_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    attempt: int = Field(strict=True, ge=1, le=100)
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)


class CreateReplayBatchRequest(StrictModel):
    """Locator-only request for server-owned sealed-source Replay derivation."""

    source: ArtifactLocator
    idempotency_key: str = Field(min_length=8, max_length=200)


class ReplayClaimRequest(StrictModel):
    """Internal Replay claim parameters; the Worker principal comes from authentication."""

    executor_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_seconds: int = Field(default=30, strict=True, ge=5, le=300)


class ReplayLeaseRequest(StrictModel):
    """Heartbeat parameters bound to an already burned Replay ticket."""

    executor_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    lease_seconds: int = Field(default=30, strict=True, ge=5, le=300)
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)


class LeaseRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    lease_seconds: int = Field(default=30, ge=5, le=300)


class CompleteJobRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    result: dict[str, Any] = Field(default_factory=dict)


class FailJobRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    error: str = Field(min_length=1, max_length=2_000)
    retryable: bool = True


class CreateCheckpointRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    state: dict[str, Any]
    pending_intent: ApprovalIntent


class DecideApprovalRequest(StrictModel):
    approve: bool
    reason: str = Field(min_length=1, max_length=1_000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        reason = value.strip()
        if not reason:
            raise ValueError("approval decision reason must not be blank")
        return reason


class CancelRunRequest(StrictModel):
    reason: str = Field(min_length=1, max_length=1_000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        reason = value.strip()
        if not reason:
            raise ValueError("cancellation reason must not be blank")
        return reason


class ResumeCheckpointRequest(StrictModel):
    approval_id: str = Field(pattern=r"^approval_[0-9a-f]{32}$")


class RunView(StrictModel):
    run_id: str
    campaign_name: str
    state: RunState
    input: dict[str, Any]
    current_checkpoint_id: str | None
    created_at: datetime
    updated_at: datetime


class RunSummaryView(StrictModel):
    run_id: str
    campaign_name: str
    state: RunState
    current_checkpoint_id: str | None
    created_at: datetime
    updated_at: datetime


class RunListView(StrictModel):
    items: list[RunSummaryView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=10_000)


class JobView(StrictModel):
    job_id: str
    run_id: str
    kind: str
    state: JobState
    payload: dict[str, Any]
    priority: int = Field(strict=True, ge=-2_147_483_648, le=2_147_483_647)
    attempts: int = Field(strict=True, ge=0, le=2_147_483_647)
    max_attempts: int = Field(strict=True, ge=1, le=2_147_483_647)
    available_at: datetime
    lease_owner: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    result: dict[str, Any] | None
    error: str | None
    created_at: datetime
    updated_at: datetime


class ClaimedJob(StrictModel):
    job: JobView
    lease_token: str


class ReplayBatchView(StrictModel):
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    campaign_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    source: ArtifactRef
    mode: CampaignMode
    purpose: ReplayPurpose
    policy_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    state: ReplayBatchState
    cas_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    created_by: str = Field(min_length=1, max_length=200)
    created_at: datetime
    updated_at: datetime


class ReplayItemView(StrictModel):
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    state: ReplayItemState
    candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    contract_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    grant_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    required_attempts: int = Field(strict=True, ge=1, le=100)
    max_attempts: int = Field(strict=True, ge=1, le=100)
    attempts: int = Field(strict=True, ge=0, le=100)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def require_valid_attempt_counts(self) -> ReplayItemView:
        if self.max_attempts < self.required_attempts:
            raise ValueError("max_attempts must be greater than or equal to required_attempts")
        if self.attempts > self.max_attempts:
            raise ValueError("attempts must not exceed max_attempts")
        return self


class ReplayTicketView(StrictModel):
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    job_id: str = Field(pattern=r"^job_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    state: ReplayTicketState
    attempt: int = Field(strict=True, ge=1, le=100)
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    executor_profile: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
    )
    claimed_by: str | None = Field(default=None, min_length=1, max_length=200)
    lease_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def require_claim_binding(self) -> ReplayTicketView:
        claim_fields = (self.executor_profile, self.claimed_by, self.lease_expires_at)
        if self.state is ReplayTicketState.CLAIMED and any(value is None for value in claim_fields):
            raise ValueError("claimed Replay ticket requires principal, profile, and lease expiry")
        return self


class ReplayClaimView(StrictModel):
    job: JobView
    batch: ReplayBatchView
    item: ReplayItemView
    ticket: ReplayTicketView
    lease_token: str = Field(min_length=32, max_length=300)

    @model_validator(mode="before")
    @classmethod
    def require_strict_job_attempt_authority(cls, value: Any) -> Any:
        """Keep generic JobView coercion out of the Replay authority boundary."""

        if isinstance(value, Mapping):
            job = value.get("job")
            if isinstance(job, Mapping):
                for field_name in ("priority", "attempts", "max_attempts"):
                    field_value = job.get(field_name)
                    if not isinstance(field_value, int) or isinstance(field_value, bool):
                        raise ValueError(f"Replay claim Job {field_name} must be a strict integer")
        return value

    @model_validator(mode="after")
    def require_burned_ticket_binding(self) -> ReplayClaimView:
        if self.job.kind != InternalJobKind.REPLAY.value:
            raise ValueError("Replay claim must contain an internal Replay Job")
        if self.job.state is not JobState.LEASED:
            raise ValueError("Replay claim Job must be leased")
        if self.ticket.state is not ReplayTicketState.CLAIMED:
            raise ValueError("Replay claim ticket must be claimed")
        if self.batch.state is not ReplayBatchState.RUNNING:
            raise ValueError("Replay claim batch must be running")
        if self.item.state is not ReplayItemState.RUNNING:
            raise ValueError("Replay claim item must be running")
        job_integer_fields = {
            "priority": self.job.priority,
            "attempts": self.job.attempts,
            "max_attempts": self.job.max_attempts,
        }
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in job_integer_fields.values()
        ):
            raise ValueError("Replay claim Job authority fields must be strict integers")
        if not -2_147_483_648 <= self.job.priority <= 2_147_483_647:
            raise ValueError("Replay claim Job priority must fit PostgreSQL INT4")
        if self.job.lease_owner != self.ticket.claimed_by:
            raise ValueError("Replay claim Job and ticket principals must match")
        if self.job.lease_expires_at != self.ticket.lease_expires_at:
            raise ValueError("Replay claim Job and ticket lease deadlines must match")
        if self.job.attempts != 1:
            raise ValueError("Replay claim Job attempts must equal one")
        if self.job.max_attempts != 1:
            raise ValueError("Replay claim Job max attempts must equal one")
        if self.item.batch_id != self.batch.batch_id:
            raise ValueError("Replay claim item and batch IDs must match")
        if self.ticket.batch_id != self.batch.batch_id:
            raise ValueError("Replay claim ticket and batch IDs must match")
        if self.ticket.item_id != self.item.item_id:
            raise ValueError("Replay claim ticket and item IDs must match")
        if self.ticket.job_id != self.job.job_id:
            raise ValueError("Replay claim ticket and Job IDs must match")
        if self.job.run_id != self.item.replay_run_id:
            raise ValueError("Replay claim Job and item Replay Run IDs must match")
        if self.ticket.replay_run_id != self.item.replay_run_id:
            raise ValueError("Replay claim ticket and item Replay Run IDs must match")
        if self.ticket.attempt != self.item.attempts:
            raise ValueError("Replay claim ticket attempt must match the item attempt count")
        try:
            payload = ReplayJobPayload.model_validate(self.job.payload)
        except ValueError as exc:
            raise ValueError("Replay claim Job payload must be canonical") from exc
        if (
            payload.batch_id != self.batch.batch_id
            or payload.item_id != self.item.item_id
            or payload.ticket_id != self.ticket.ticket_id
            or payload.replay_run_id != self.job.run_id
            or payload.replay_run_id != self.item.replay_run_id
            or payload.source != self.batch.source
            or payload.mode is not self.batch.mode
            or payload.purpose is not self.batch.purpose
            or payload.policy_version != self.batch.policy_version
            or payload.candidate_id != self.item.candidate_id
            or payload.candidate_digest != self.item.candidate_digest
            or payload.contract_digest != self.item.contract_digest
            or payload.compilation_digest != self.item.compilation_digest
            or payload.grant_digest != self.item.grant_digest
            or payload.attempt != self.ticket.attempt
            or payload.fencing_value != self.ticket.fencing_value
        ):
            raise ValueError("Replay claim Job payload authority binding is inconsistent")
        return self


class CheckpointView(StrictModel):
    checkpoint_id: str
    run_id: str
    sequence: int
    schema_version: int
    state: dict[str, Any]
    pending_intent: ApprovalIntent
    payload_sha256: str
    signature: str
    key_id: str
    created_at: datetime
    claimed_at: datetime | None
    claimed_by: str | None
    continuation_job_id: str | None


class ApprovalView(StrictModel):
    approval_id: str
    run_id: str
    checkpoint_id: str
    intent: ApprovalIntent
    state: ApprovalState
    requested_by: str
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_reason: str | None
    consumed_by: str | None
    consumed_at: datetime | None


class SubmissionView(StrictModel):
    run: RunView
    job: JobView
    created: bool


class CancelRunView(StrictModel):
    run: RunView
    applied: bool
    cancelled_job_ids: list[str]
    revoked_approval_ids: list[str]


class CheckpointCreationView(StrictModel):
    checkpoint: CheckpointView
    approval: ApprovalView


class ResumeView(StrictModel):
    run: RunView
    job: JobView
    checkpoint: CheckpointView
    approval: ApprovalView


class AuditEventView(StrictModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    run_id: str
    sequence: int
    event_type: str
    actor: str
    payload: dict[str, Any]
    occurred_at: datetime
