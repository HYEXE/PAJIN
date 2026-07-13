"""Typed contracts for the PAJIN durable Control Plane."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import ConfigDict, Field, model_validator

from pajin.domain.models import StrictModel, ToolRiskTier


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


class JobKind(StrEnum):
    CAMPAIGN = "campaign"
    TOOL_LOOP = "tool-loop"


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class PrincipalRole(StrEnum):
    OPERATOR = "operator"
    APPROVER = "approver"
    WORKER = "worker"
    AUDITOR = "auditor"


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
    kinds: list[str] = Field(default_factory=lambda: ["campaign"], min_length=1, max_length=20)
    lease_seconds: int = Field(default=30, ge=5, le=300)
    wait_seconds: int = Field(default=0, ge=0, le=20)


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


class JobView(StrictModel):
    job_id: str
    run_id: str
    kind: str
    state: JobState
    payload: dict[str, Any]
    priority: int
    attempts: int
    max_attempts: int
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
