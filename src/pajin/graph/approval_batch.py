"""Bounded asynchronous coordination over existing single-action approvals."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import stat
import tempfile
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from inspect import iscoroutinefunction
from pathlib import Path
from re import fullmatch
from typing import Annotated, Any, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    GraphApprovedActionPermitAuthority,
)
from pajin.graph.approved_cleanup import (
    ApprovedReversibleActionPermitAuthorization,
    GraphApprovedReversibleActionPermitAuthority,
)
from pajin.graph.authority import ActionPermit
from pajin.graph.cleanup import ActionCleanupReservation, ActionCleanupReservationRequest
from pajin.graph.models import canonical_graph_json, graph_digest
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

ACTION_APPROVAL_BATCH_API_VERSION: Literal["pajin.dev/action-approval-batch/v1alpha1"] = (
    "pajin.dev/action-approval-batch/v1alpha1"
)
ACTION_APPROVAL_BATCH_COMPLETION_API_VERSION: Literal[
    "pajin.dev/action-approval-batch-completion/v1alpha1"
] = "pajin.dev/action-approval-batch-completion/v1alpha1"
ACTION_APPROVAL_BATCH_CANCELLATION_API_VERSION: Literal[
    "pajin.dev/action-approval-batch-cancellation/v1alpha1"
] = "pajin.dev/action-approval-batch-cancellation/v1alpha1"
ACTION_APPROVAL_BATCH_JOURNAL_BACKUP_MANIFEST_API_VERSION: Literal[
    "pajin.dev/action-approval-batch-journal-backup-manifest/v1alpha1"
] = "pajin.dev/action-approval-batch-journal-backup-manifest/v1alpha1"
ACTION_APPROVAL_BATCH_JOURNAL_RETENTION_API_VERSION: Literal[
    "pajin.dev/action-approval-batch-journal-retention/v1alpha1"
] = "pajin.dev/action-approval-batch-journal-retention/v1alpha1"

_MAX_BATCH_ACTIONS = 8
_MAX_BATCH_BYTES = 4 * 1024 * 1024
_MAX_JOURNAL_BACKUP_BYTES = 64 * 1024 * 1024
_MAX_JOURNAL_BACKUP_MANIFEST_BYTES = 128 * 1024
_MAX_JOURNAL_STATE_BYTES = 32 * 1024 * 1024
_SCHEMA_VERSION = 1
_APPLICATION_ID = 0x50414A42
_BUSY_TIMEOUT_MS = 5_000
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ActionApprovalBatchAuthorization = (
    ActionApprovalAuthorization | ApprovedReversibleActionPermitAuthorization
)


class ActionApprovalBatchError(RuntimeError):
    """Raised when bounded batch coordination cannot proceed safely."""


class ActionApprovalBatchItemState(StrEnum):
    """Durable state of one approval in a bounded asynchronous batch."""

    PENDING = "pending"
    CLAIM_STARTED = "claim-started"
    DISPATCH_STARTED_OUTCOME_UNKNOWN = "dispatch-started-outcome-unknown"
    TERMINAL_SUCCEEDED = "terminal-succeeded"
    TERMINAL_FAILED = "terminal-failed"
    CANCELLED_BEFORE_DISPATCH = "cancelled-before-dispatch"


class ActionApprovalBatchState(StrEnum):
    """Derived aggregate state; it never grants dispatch authority."""

    PENDING = "pending"
    ACTIVE = "active"
    MANUAL_REVIEW_REQUIRED = "manual-review-required"
    TERMINAL_SUCCEEDED = "terminal-succeeded"
    TERMINAL_PARTIAL = "terminal-partial"
    CANCELLED = "cancelled"


_MANUAL_REVIEW_STATES = frozenset(
    {
        ActionApprovalBatchItemState.CLAIM_STARTED,
        ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
    }
)


class ActionApprovalBatchEnvelope(StrictModel):
    """One authenticated, ordered, bounded set of existing single approvals."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-approval-batch/v1alpha1"] = Field(
        default=ACTION_APPROVAL_BATCH_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionApprovalBatchEnvelope"] = "ActionApprovalBatchEnvelope"
    batch_id: str = Field(default="", alias="batchId", max_length=96)
    batch_digest: str = Field(default="", alias="batchDigest", max_length=64)
    mode: Literal["batch"] = "batch"
    asynchronous: Literal[True] = True
    max_actions: Annotated[int, Field(ge=2, le=_MAX_BATCH_ACTIONS)] = Field(alias="maxActions")
    issuer: ActionApprovalIssuerAuthorityBinding
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    approvals: tuple[ActionApprovalEnvelope, ...]
    cleanup_requests: tuple[ActionCleanupReservationRequest | None, ...] = Field(
        default=(), alias="cleanupRequests", max_length=_MAX_BATCH_ACTIONS
    )
    approved_at: datetime = Field(alias="approvedAt")
    not_before: datetime = Field(alias="notBefore")
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("asynchronous", mode="before")
    @classmethod
    def require_exact_async_flag(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Action approval batch asynchronous must be the JSON boolean true")
        return value

    @field_validator("max_actions", mode="before")
    @classmethod
    def require_exact_bound(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Action approval batch maxActions must be a JSON integer")
        return value

    @field_validator("approved_at", "not_before", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Action approval batch time")

    @model_validator(mode="after")
    def bind_batch(self) -> Self:
        if len(self.approvals) != self.max_actions:
            raise ValueError("Action approval batch must contain exactly maxActions approvals")
        cleanup_requests = self.cleanup_requests
        if not cleanup_requests:
            cleanup_requests = tuple(None for _ in self.approvals)
            object.__setattr__(self, "cleanup_requests", cleanup_requests)
        if len(cleanup_requests) != len(self.approvals):
            raise ValueError("Action approval batch cleanup request count differs")
        if not self.approved_at <= self.not_before < self.expires_at:
            raise ValueError("Action approval batch window is invalid")
        approval_ids: set[str] = set()
        proposal_ids: set[str] = set()
        request_ids: set[str] = set()
        permit_ids: set[str] = set()
        cleanup_request_ids: set[str] = set()
        shared: tuple[object, ...] | None = None
        for approval, cleanup_request in zip(
            self.approvals,
            cleanup_requests,
            strict=True,
        ):
            current_shared = (
                approval.issuer,
                approval.requested_by,
                approval.approved_by,
                approval.campaign_id,
                approval.campaign_digest,
                approval.run_id,
                approval.mission_envelope,
                approval.activation_set_digest,
                approval.approved_at,
                approval.not_before,
                approval.expires_at,
            )
            if shared is None:
                shared = current_shared
            elif shared != current_shared:
                raise ValueError("Action approval batch items do not share one authority window")
            if (
                approval.issuer != self.issuer
                or approval.campaign_id != self.campaign_id
                or approval.campaign_digest != self.campaign_digest
                or approval.run_id != self.run_id
                or approval.approved_at != self.approved_at
                or approval.not_before != self.not_before
                or approval.expires_at != self.expires_at
            ):
                raise ValueError("Action approval batch item differs from its batch authority")
            cleanup_request_id = _validate_batch_item_scope(approval, cleanup_request)
            if cleanup_request_id is not None:
                if cleanup_request_id in cleanup_request_ids:
                    raise ValueError("Action approval batch reuses a cleanup request")
                cleanup_request_ids.add(cleanup_request_id)
            if (
                approval.approval_id in approval_ids
                or approval.proposal.proposal_id in proposal_ids
                or approval.proposal.request_id in request_ids
                or approval.expected_action_permit_id in permit_ids
            ):
                raise ValueError("Action approval batch contains a duplicate action")
            approval_ids.add(approval.approval_id)
            proposal_ids.add(approval.proposal.proposal_id)
            request_ids.add(approval.proposal.request_id)
            permit_ids.add(approval.expected_action_permit_id)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"batch_id", "batch_digest"},
        )
        digest = graph_digest(
            "pajin.action.approval-batch/v1",
            material,
            max_bytes=_MAX_BATCH_BYTES,
        )
        batch_id = f"action-approval-batch_{digest}"
        if self.batch_digest and self.batch_digest != digest:
            raise ValueError("Action approval batch digest differs")
        if self.batch_id and self.batch_id != batch_id:
            raise ValueError("Action approval batch ID differs")
        object.__setattr__(self, "batch_digest", digest)
        object.__setattr__(self, "batch_id", batch_id)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ActionApprovalBatchEnvelope",
            max_bytes=_MAX_BATCH_BYTES,
        )
        return self

    def approval_at(self, ordinal: int) -> ActionApprovalEnvelope:
        """Return a detached item by its one-based canonical ordinal."""

        if type(ordinal) is not int or not 1 <= ordinal <= len(self.approvals):
            raise ActionApprovalBatchError("Action approval batch ordinal is invalid")
        return self.approvals[ordinal - 1].model_copy(deep=True)

    def cleanup_request_at(self, ordinal: int) -> ActionCleanupReservationRequest | None:
        """Return the detached cleanup request paired with one reversible item."""

        if type(ordinal) is not int or not 1 <= ordinal <= len(self.approvals):
            raise ActionApprovalBatchError("Action approval batch ordinal is invalid")
        request = self.cleanup_requests[ordinal - 1]
        return request.model_copy(deep=True) if request is not None else None


class ActionApprovalBatchCompletion(StrictModel):
    """Authenticated terminal evidence for one claimed batch item."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-approval-batch-completion/v1alpha1"] = Field(
        default=ACTION_APPROVAL_BATCH_COMPLETION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["ActionApprovalBatchCompletion"] = "ActionApprovalBatchCompletion"
    completion_id: str = Field(default="", alias="completionId", max_length=128)
    completion_digest: str = Field(default="", alias="completionDigest", max_length=64)
    batch_id: str = Field(alias="batchId", pattern=r"^action-approval-batch_[a-f0-9]{64}$")
    batch_digest: _Sha256 = Field(alias="batchDigest")
    item_ordinal: Annotated[int, Field(ge=1, le=_MAX_BATCH_ACTIONS)] = Field(alias="itemOrdinal")
    approval_id: str = Field(alias="approvalId", pattern=r"^action-approval_[a-f0-9]{64}$")
    approval_digest: _Sha256 = Field(alias="approvalDigest")
    permit_id: str = Field(alias="permitId", pattern=r"^action-permit_[a-f0-9]{64}$")
    permit_digest: _Sha256 = Field(alias="permitDigest")
    receipt_id: str = Field(alias="receiptId", pattern=r"^action-approval-receipt_[a-f0-9]{64}$")
    receipt_digest: _Sha256 = Field(alias="receiptDigest")
    cleanup_reservation_id: (
        Annotated[
            str,
            Field(pattern=r"^action-cleanup-reservation_[a-f0-9]{64}$"),
        ]
        | None
    ) = Field(default=None, alias="cleanupReservationId")
    cleanup_reservation_digest: _Sha256 | None = Field(
        default=None, alias="cleanupReservationDigest"
    )
    restored_state_evidence_digest: _Sha256 | None = Field(
        default=None, alias="restoredStateEvidenceDigest"
    )
    outcome: Literal["succeeded", "failed"]
    source: Literal["worker-completion", "manual-reconciliation"]
    evidence_digest: _Sha256 = Field(alias="evidenceDigest")
    completed_at: datetime = Field(alias="completedAt")
    redispatch_authority: Literal[False] = Field(default=False, alias="redispatchAuthority")

    @field_validator("item_ordinal", mode="before")
    @classmethod
    def require_exact_ordinal(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Batch completion itemOrdinal must be a JSON integer")
        return value

    @field_validator("redispatch_authority", mode="before")
    @classmethod
    def require_no_redispatch(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Batch completion redispatchAuthority must be false")
        return value

    @field_validator("completed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Action approval batch completion time")

    @model_validator(mode="after")
    def bind_completion(self) -> Self:
        cleanup_evidence = (
            self.cleanup_reservation_id,
            self.cleanup_reservation_digest,
            self.restored_state_evidence_digest,
        )
        if any(value is not None for value in cleanup_evidence) is not all(
            value is not None for value in cleanup_evidence
        ):
            raise ValueError("Batch completion cleanup evidence is partial")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"completion_id", "completion_digest"},
        )
        digest = graph_digest(
            "pajin.action.approval-batch-completion/v1",
            material,
            max_bytes=_MAX_BATCH_BYTES,
        )
        completion_id = f"action-approval-batch-completion_{digest}"
        if self.completion_digest and self.completion_digest != digest:
            raise ValueError("Action approval batch completion digest differs")
        if self.completion_id and self.completion_id != completion_id:
            raise ValueError("Action approval batch completion ID differs")
        object.__setattr__(self, "completion_digest", digest)
        object.__setattr__(self, "completion_id", completion_id)
        return self


class ActionApprovalBatchCancellation(StrictModel):
    """Authenticated cancellation of still-pending batch items only."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-approval-batch-cancellation/v1alpha1"] = Field(
        default=ACTION_APPROVAL_BATCH_CANCELLATION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["ActionApprovalBatchCancellation"] = "ActionApprovalBatchCancellation"
    cancellation_id: str = Field(default="", alias="cancellationId", max_length=104)
    cancellation_digest: str = Field(default="", alias="cancellationDigest", max_length=64)
    batch_id: str = Field(alias="batchId", pattern=r"^action-approval-batch_[a-f0-9]{64}$")
    batch_digest: _Sha256 = Field(alias="batchDigest")
    item_ordinals: tuple[Annotated[int, Field(ge=1, le=_MAX_BATCH_ACTIONS)], ...] = Field(
        alias="itemOrdinals", min_length=1, max_length=_MAX_BATCH_ACTIONS
    )
    reason_digest: _Sha256 = Field(alias="reasonDigest")
    cancelled_at: datetime = Field(alias="cancelledAt")
    redispatch_authority: Literal[False] = Field(default=False, alias="redispatchAuthority")

    @field_validator("item_ordinals", mode="before")
    @classmethod
    def require_exact_ordinals(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)) or any(type(item) is not int for item in value):
            raise ValueError("Batch cancellation itemOrdinals must be JSON integers")
        return value

    @field_validator("cancelled_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Action approval batch cancellation time")

    @field_validator("redispatch_authority", mode="before")
    @classmethod
    def require_no_redispatch(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Batch cancellation redispatchAuthority must be false")
        return value

    @model_validator(mode="after")
    def bind_cancellation(self) -> Self:
        if tuple(sorted(set(self.item_ordinals))) != self.item_ordinals:
            raise ValueError("Batch cancellation ordinals must be unique and ordered")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"cancellation_id", "cancellation_digest"},
        )
        digest = graph_digest(
            "pajin.action.approval-batch-cancellation/v1",
            material,
            max_bytes=_MAX_BATCH_BYTES,
        )
        cancellation_id = f"action-approval-batch-cancellation_{digest}"
        if self.cancellation_digest and self.cancellation_digest != digest:
            raise ValueError("Action approval batch cancellation digest differs")
        if self.cancellation_id and self.cancellation_id != cancellation_id:
            raise ValueError("Action approval batch cancellation ID differs")
        object.__setattr__(self, "cancellation_digest", digest)
        object.__setattr__(self, "cancellation_id", cancellation_id)
        return self


class ActionApprovalBatchInputAuthority(Protocol):
    """Deployment-pinned authentication of one complete batch envelope."""

    def verify_action_approval_batch(self, batch: ActionApprovalBatchEnvelope) -> None:
        """Authenticate the exact canonical batch or raise."""


class ActionApprovalBatchCompletionAuthority(Protocol):
    """Deployment-pinned authentication of terminal item evidence."""

    def verify_action_approval_batch_completion(
        self,
        batch: ActionApprovalBatchEnvelope,
        approval: ActionApprovalEnvelope,
        authorization: ActionApprovalBatchAuthorization,
        completion: ActionApprovalBatchCompletion,
    ) -> None:
        """Authenticate the exact terminal evidence or raise."""


class ActionApprovalBatchCancellationAuthority(Protocol):
    """Deployment-pinned authentication of pending-item cancellation."""

    def verify_action_approval_batch_cancellation(
        self,
        batch: ActionApprovalBatchEnvelope,
        cancellation: ActionApprovalBatchCancellation,
    ) -> None:
        """Authenticate the exact cancellation or raise."""


class ActionApprovalBatchItemRecord(StrictModel):
    """Verified durable view of one batch item."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    batch_id: str = Field(alias="batchId", pattern=r"^action-approval-batch_[a-f0-9]{64}$")
    batch_digest: _Sha256 = Field(alias="batchDigest")
    item_ordinal: int = Field(alias="itemOrdinal", ge=1, le=_MAX_BATCH_ACTIONS)
    approval_id: str = Field(alias="approvalId", pattern=r"^action-approval_[a-f0-9]{64}$")
    approval_digest: _Sha256 = Field(alias="approvalDigest")
    state: ActionApprovalBatchItemState
    permit_id: (
        Annotated[
            str,
            Field(pattern=r"^action-permit_[a-f0-9]{64}$"),
        ]
        | None
    ) = Field(default=None, alias="permitId")
    permit_digest: _Sha256 | None = Field(default=None, alias="permitDigest")
    receipt_id: (
        Annotated[
            str,
            Field(pattern=r"^action-approval-receipt_[a-f0-9]{64}$"),
        ]
        | None
    ) = Field(default=None, alias="receiptId")
    receipt_digest: _Sha256 | None = Field(default=None, alias="receiptDigest")
    cleanup_reservation: ActionCleanupReservation | None = Field(
        default=None, alias="cleanupReservation"
    )
    completion: ActionApprovalBatchCompletion | None = None
    cancellation: ActionApprovalBatchCancellation | None = None
    event_digests: tuple[_Sha256, ...] = Field(alias="eventDigests", min_length=1, max_length=4)

    @model_validator(mode="after")
    def require_state_shape(self) -> Self:
        authority_fields = (
            self.permit_id,
            self.permit_digest,
            self.receipt_id,
            self.receipt_digest,
        )
        if any(value is not None for value in authority_fields) is not all(
            value is not None for value in authority_fields
        ):
            raise ValueError("Batch item durable authorization is partial")
        if self.state in {
            ActionApprovalBatchItemState.TERMINAL_SUCCEEDED,
            ActionApprovalBatchItemState.TERMINAL_FAILED,
        }:
            if self.completion is None or not all(value is not None for value in authority_fields):
                raise ValueError("Terminal batch item lacks its completion authority")
        elif self.completion is not None:
            raise ValueError("Non-terminal batch item contains a completion")
        if self.state is ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH:
            if self.cancellation is None or any(value is not None for value in authority_fields):
                raise ValueError("Cancelled batch item contains dispatch authority")
        elif self.cancellation is not None:
            raise ValueError("Non-cancelled batch item contains a cancellation")
        if self.cleanup_reservation is not None and not all(
            value is not None for value in authority_fields
        ):
            raise ValueError("Batch item cleanup reservation lacks dispatch authority")
        if len(set(self.event_digests)) != len(self.event_digests):
            raise ValueError("Batch item event chain contains a duplicate")
        return self


class ActionApprovalBatchPublication(StrictModel):
    """Derived batch state over fully verified item records."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    batch: ActionApprovalBatchEnvelope
    state: ActionApprovalBatchState
    items: tuple[ActionApprovalBatchItemRecord, ...]
    manual_review_required: bool = Field(alias="manualReviewRequired")
    redispatch_authority: Literal[False] = Field(default=False, alias="redispatchAuthority")

    @model_validator(mode="after")
    def derive_state(self) -> Self:
        if len(self.items) != len(self.batch.approvals):
            raise ValueError("Batch publication item count differs")
        expected = _batch_state(tuple(item.state for item in self.items))
        if self.state is not expected:
            raise ValueError("Batch publication state differs from its items")
        unknown = any(item.state in _MANUAL_REVIEW_STATES for item in self.items)
        if self.manual_review_required is not unknown:
            raise ValueError("Batch publication manual-review flag differs")
        return self


class ActionApprovalBatchJournalRetentionAssessment(StrictModel):
    """Verified eligibility evidence; it never deletes a journal or grants redispatch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-approval-batch-journal-retention/v1alpha1"] = Field(
        default=ACTION_APPROVAL_BATCH_JOURNAL_RETENTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionApprovalBatchJournalRetentionAssessment"] = (
        "ActionApprovalBatchJournalRetentionAssessment"
    )
    evaluated_at: datetime = Field(alias="evaluatedAt")
    minimum_retain_until: datetime = Field(alias="minimumRetainUntil")
    batch_count: int = Field(alias="batchCount", ge=0)
    terminal_batch_count: int = Field(alias="terminalBatchCount", ge=0)
    manual_review_required: bool = Field(alias="manualReviewRequired")
    deletion_eligible: bool = Field(alias="deletionEligible")
    journal_state_digest: _Sha256 = Field(alias="journalStateDigest")
    redispatch_authority: Literal[False] = Field(default=False, alias="redispatchAuthority")

    @field_validator("evaluated_at", "minimum_retain_until")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Action approval batch journal retention time")

    @model_validator(mode="after")
    def bind_retention(self) -> Self:
        if self.terminal_batch_count > self.batch_count:
            raise ValueError("Batch journal terminal count exceeds its batch count")
        expected = (
            self.batch_count > 0
            and self.terminal_batch_count == self.batch_count
            and not self.manual_review_required
            and self.evaluated_at >= self.minimum_retain_until
        )
        if self.deletion_eligible is not expected:
            raise ValueError("Batch journal deletion eligibility differs")
        return self


class SQLiteActionApprovalBatchJournalBackupManifest(StrictModel):
    """Content-addressed local backup and verified retention summary."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-approval-batch-journal-backup-manifest/v1alpha1"] = (
        Field(
            default=ACTION_APPROVAL_BATCH_JOURNAL_BACKUP_MANIFEST_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["SQLiteActionApprovalBatchJournalBackupManifest"] = (
        "SQLiteActionApprovalBatchJournalBackupManifest"
    )
    backup_id: str = Field(default="", alias="backupId", max_length=112)
    schema_version: Literal[1] = Field(default=1, alias="schemaVersion")
    schema_digest: _Sha256 = Field(default_factory=lambda: _SCHEMA_DIGEST, alias="schemaDigest")
    created_at: datetime = Field(alias="createdAt")
    database_sha256: _Sha256 = Field(alias="databaseSha256")
    database_bytes: int = Field(alias="databaseBytes", ge=1, le=_MAX_JOURNAL_BACKUP_BYTES)
    retention: ActionApprovalBatchJournalRetentionAssessment

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Action approval batch journal backup time")

    @model_validator(mode="after")
    def bind_backup(self) -> Self:
        if self.schema_digest != _SCHEMA_DIGEST:
            raise ValueError("Batch journal backup schema digest differs")
        if self.retention.evaluated_at != self.created_at:
            raise ValueError("Batch journal backup retention time differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"backup_id"})
        digest = graph_digest(
            "pajin.action.approval-batch-journal-backup/v1",
            material,
            max_bytes=_MAX_JOURNAL_BACKUP_MANIFEST_BYTES,
        )
        backup_id = f"action-approval-batch-journal-backup_{digest}"
        if self.backup_id and self.backup_id != backup_id:
            raise ValueError("Batch journal backup ID differs")
        object.__setattr__(self, "backup_id", backup_id)
        return self


class ActionApprovalBatchDispatchResult(StrictModel):
    """One dispatch attempt result without any retry authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    publication: ActionApprovalBatchPublication
    item: ActionApprovalBatchItemRecord
    authorization: ActionApprovalBatchAuthorization | None = None
    dispatched: bool

    @model_validator(mode="after")
    def bind_result(self) -> Self:
        stored = self.publication.items[self.item.item_ordinal - 1]
        if stored != self.item:
            raise ValueError("Batch dispatch result item differs from its publication")
        if self.dispatched and (
            self.authorization is None
            or not _authorization_newly_consumed(self.authorization)
            or self.item.state
            not in {
                ActionApprovalBatchItemState.TERMINAL_SUCCEEDED,
                ActionApprovalBatchItemState.TERMINAL_FAILED,
            }
        ):
            raise ValueError("Batch dispatch result overstates execution")
        return self


_METADATA_TABLE_SQL = """
CREATE TABLE action_approval_batch_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT
"""
_BATCHES_TABLE_SQL = """
CREATE TABLE action_approval_batches (
    batch_id TEXT PRIMARY KEY NOT NULL,
    batch_digest TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    max_actions INTEGER NOT NULL CHECK (max_actions BETWEEN 2 AND 8),
    canonical_batch BLOB NOT NULL
) STRICT
"""
_ITEMS_TABLE_SQL = """
CREATE TABLE action_approval_batch_items (
    batch_id TEXT NOT NULL REFERENCES action_approval_batches(batch_id),
    item_ordinal INTEGER NOT NULL CHECK (item_ordinal BETWEEN 1 AND 8),
    approval_id TEXT NOT NULL UNIQUE,
    approval_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'pending',
        'claim-started',
        'dispatch-started-outcome-unknown',
        'terminal-succeeded',
        'terminal-failed',
        'cancelled-before-dispatch'
    )),
    permit_id TEXT UNIQUE,
    permit_digest TEXT,
    receipt_id TEXT UNIQUE,
    receipt_digest TEXT,
    cleanup_request_digest TEXT,
    cleanup_reservation_id TEXT UNIQUE,
    cleanup_reservation_digest TEXT,
    cleanup_reservation_json BLOB,
    completion_json BLOB,
    cancellation_json BLOB,
    PRIMARY KEY (batch_id, item_ordinal),
    CHECK ((permit_id IS NULL AND permit_digest IS NULL
            AND receipt_id IS NULL AND receipt_digest IS NULL)
        OR (permit_id IS NOT NULL AND permit_digest IS NOT NULL
            AND receipt_id IS NOT NULL AND receipt_digest IS NOT NULL)),
    CHECK ((cleanup_reservation_id IS NULL AND cleanup_reservation_digest IS NULL
            AND cleanup_reservation_json IS NULL)
        OR (cleanup_reservation_id IS NOT NULL AND cleanup_reservation_digest IS NOT NULL
            AND cleanup_reservation_json IS NOT NULL)),
    CHECK ((state IN ('terminal-succeeded', 'terminal-failed') AND completion_json IS NOT NULL)
        OR (state NOT IN ('terminal-succeeded', 'terminal-failed') AND completion_json IS NULL)),
    CHECK ((state = 'cancelled-before-dispatch'
            AND cancellation_json IS NOT NULL AND permit_id IS NULL)
        OR (state <> 'cancelled-before-dispatch' AND cancellation_json IS NULL))
) STRICT
"""
_EVENTS_TABLE_SQL = """
CREATE TABLE action_approval_batch_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    item_ordinal INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 4),
    from_state TEXT,
    to_state TEXT NOT NULL,
    authority_digest TEXT,
    occurred_at TEXT NOT NULL,
    previous_event_digest TEXT,
    event_digest TEXT NOT NULL,
    FOREIGN KEY (batch_id, item_ordinal)
        REFERENCES action_approval_batch_items(batch_id, item_ordinal),
    UNIQUE (batch_id, item_ordinal, ordinal)
) STRICT
"""
_EVENTS_INDEX_SQL = (
    "CREATE INDEX action_approval_batch_events_item_idx "
    "ON action_approval_batch_events(batch_id, item_ordinal, ordinal)"
)
_BATCHES_IMMUTABLE_SQL = """
CREATE TRIGGER action_approval_batches_immutable
BEFORE UPDATE ON action_approval_batches
BEGIN
    SELECT RAISE(ABORT, 'Action approval batches are immutable');
END
"""
_BATCHES_NO_DELETE_SQL = """
CREATE TRIGGER action_approval_batches_no_delete
BEFORE DELETE ON action_approval_batches
BEGIN
    SELECT RAISE(ABORT, 'Action approval batches are append-only');
END
"""
_ITEMS_IDENTITY_IMMUTABLE_SQL = """
CREATE TRIGGER action_approval_batch_items_identity_immutable
BEFORE UPDATE OF batch_id, item_ordinal, approval_id, approval_digest, cleanup_request_digest
ON action_approval_batch_items
BEGIN
    SELECT RAISE(ABORT, 'Action approval batch item identity is immutable');
END
"""
_ITEMS_NO_DELETE_SQL = """
CREATE TRIGGER action_approval_batch_items_no_delete
BEFORE DELETE ON action_approval_batch_items
BEGIN
    SELECT RAISE(ABORT, 'Action approval batch items are append-only');
END
"""
_ITEMS_STATE_TRANSITION_SQL = """
CREATE TRIGGER action_approval_batch_items_state_transition
BEFORE UPDATE OF state ON action_approval_batch_items
WHEN NOT (
    (OLD.state = 'pending' AND NEW.state IN (
        'claim-started', 'cancelled-before-dispatch'
    ))
    OR
    (OLD.state = 'claim-started'
     AND NEW.state = 'dispatch-started-outcome-unknown')
    OR
    (OLD.state = 'dispatch-started-outcome-unknown'
     AND NEW.state IN ('terminal-succeeded', 'terminal-failed'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid Action approval batch state transition');
END
"""
_ITEMS_AUTHORIZATION_ONCE_SQL = """
CREATE TRIGGER action_approval_batch_items_authorization_once
BEFORE UPDATE OF permit_id, permit_digest, receipt_id, receipt_digest,
                 cleanup_reservation_id, cleanup_reservation_digest,
                 cleanup_reservation_json
ON action_approval_batch_items
WHEN NOT (
    OLD.state = 'claim-started'
    AND NEW.state = 'dispatch-started-outcome-unknown'
    AND OLD.permit_id IS NULL AND OLD.permit_digest IS NULL
    AND OLD.receipt_id IS NULL AND OLD.receipt_digest IS NULL
    AND NEW.permit_id IS NOT NULL AND NEW.permit_digest IS NOT NULL
    AND NEW.receipt_id IS NOT NULL AND NEW.receipt_digest IS NOT NULL
    AND OLD.cleanup_reservation_id IS NULL
    AND OLD.cleanup_reservation_digest IS NULL
    AND OLD.cleanup_reservation_json IS NULL
    AND (
        (NEW.cleanup_reservation_id IS NULL
         AND NEW.cleanup_reservation_digest IS NULL
         AND NEW.cleanup_reservation_json IS NULL)
        OR
        (NEW.cleanup_reservation_id IS NOT NULL
         AND NEW.cleanup_reservation_digest IS NOT NULL
         AND NEW.cleanup_reservation_json IS NOT NULL)
    )
)
BEGIN
    SELECT RAISE(ABORT, 'Action approval batch authorization is immutable');
END
"""
_EVENTS_IMMUTABLE_SQL = """
CREATE TRIGGER action_approval_batch_events_immutable
BEFORE UPDATE ON action_approval_batch_events
BEGIN
    SELECT RAISE(ABORT, 'Action approval batch events are append-only');
END
"""
_EVENTS_NO_DELETE_SQL = """
CREATE TRIGGER action_approval_batch_events_no_delete
BEFORE DELETE ON action_approval_batch_events
BEGIN
    SELECT RAISE(ABORT, 'Action approval batch events are append-only');
END
"""
_METADATA_IMMUTABLE_SQL = """
CREATE TRIGGER action_approval_batch_metadata_immutable
BEFORE UPDATE ON action_approval_batch_metadata
BEGIN
    SELECT RAISE(ABORT, 'Action approval batch metadata is immutable');
END
"""

_SCHEMA_OBJECT_SQL = {
    ("table", "action_approval_batch_metadata"): _METADATA_TABLE_SQL,
    ("table", "action_approval_batches"): _BATCHES_TABLE_SQL,
    ("table", "action_approval_batch_items"): _ITEMS_TABLE_SQL,
    ("table", "action_approval_batch_events"): _EVENTS_TABLE_SQL,
    ("index", "action_approval_batch_events_item_idx"): _EVENTS_INDEX_SQL,
    ("trigger", "action_approval_batches_immutable"): _BATCHES_IMMUTABLE_SQL,
    ("trigger", "action_approval_batches_no_delete"): _BATCHES_NO_DELETE_SQL,
    (
        "trigger",
        "action_approval_batch_items_identity_immutable",
    ): _ITEMS_IDENTITY_IMMUTABLE_SQL,
    ("trigger", "action_approval_batch_items_no_delete"): _ITEMS_NO_DELETE_SQL,
    (
        "trigger",
        "action_approval_batch_items_state_transition",
    ): _ITEMS_STATE_TRANSITION_SQL,
    (
        "trigger",
        "action_approval_batch_items_authorization_once",
    ): _ITEMS_AUTHORIZATION_ONCE_SQL,
    ("trigger", "action_approval_batch_events_immutable"): _EVENTS_IMMUTABLE_SQL,
    ("trigger", "action_approval_batch_events_no_delete"): _EVENTS_NO_DELETE_SQL,
    ("trigger", "action_approval_batch_metadata_immutable"): _METADATA_IMMUTABLE_SQL,
}
_TABLES = frozenset(
    {
        "action_approval_batch_metadata",
        "action_approval_batches",
        "action_approval_batch_items",
        "action_approval_batch_events",
    }
)


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split())


_SCHEMA_DIGEST: str = sha256(
    canonical_graph_json(
        {
            f"{kind}:{name}": _normalize_schema_sql(statement)
            for (kind, name), statement in sorted(_SCHEMA_OBJECT_SQL.items())
        },
        label="Action approval batch journal schema",
        max_bytes=_MAX_BATCH_BYTES,
    )
).hexdigest()


class SQLiteActionApprovalBatchJournal:
    """Host-local durable coordinator; it grants no ActionPermit or redispatch."""

    def __init__(
        self,
        path: Path,
        *,
        input_authority: ActionApprovalBatchInputAuthority,
        completion_authority: ActionApprovalBatchCompletionAuthority,
        cancellation_authority: ActionApprovalBatchCancellationAuthority,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(input_authority, "verify_action_approval_batch", None)):
            raise TypeError("Action approval batch input authority is invalid")
        if not callable(
            getattr(
                completion_authority,
                "verify_action_approval_batch_completion",
                None,
            )
        ):
            raise TypeError("Action approval batch completion authority is invalid")
        if not callable(
            getattr(
                cancellation_authority,
                "verify_action_approval_batch_cancellation",
                None,
            )
        ):
            raise TypeError("Action approval batch cancellation authority is invalid")
        self.path = Path(os.path.abspath(path))
        self._input_authority = input_authority
        self._completion_authority = completion_authority
        self._cancellation_authority = cancellation_authority
        self._clock = clock or (lambda: datetime.now(UTC))
        _initialize(self.path)

    def publications(self) -> tuple[ActionApprovalBatchPublication, ...]:
        """Read and authenticate every batch in canonical ID order."""

        try:
            with _readonly_connection(self.path) as connection:
                _validate_schema(connection)
                batch_ids = tuple(
                    _required_text(row, "batch_id")
                    for row in connection.execute(
                        "SELECT batch_id FROM action_approval_batches ORDER BY batch_id"
                    ).fetchall()
                )
            return tuple(self.publication(batch_id) for batch_id in batch_ids)
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError(
                "Action approval batch journal inventory read failed"
            ) from exc

    def assess_retention(
        self,
        *,
        minimum_retain_until: datetime,
        evaluated_at: datetime | None = None,
    ) -> ActionApprovalBatchJournalRetentionAssessment:
        """Verify all records and report whether an external deletion may be considered."""

        publications = self.publications()
        return _retention_assessment(
            publications,
            minimum_retain_until=minimum_retain_until,
            evaluated_at=evaluated_at or self._now(),
        )

    def create_backup(
        self,
        destination: Path,
        *,
        minimum_retain_until: datetime,
        created_at: datetime | None = None,
    ) -> SQLiteActionApprovalBatchJournalBackupManifest:
        """Create one verified local backup without changing retention or dispatch state."""

        return _create_journal_backup(
            self,
            destination,
            minimum_retain_until=minimum_retain_until,
            created_at=created_at or self._now(),
        )

    @classmethod
    def restore_backup(
        cls,
        backup: Path,
        *,
        destination: Path,
        input_authority: ActionApprovalBatchInputAuthority,
        completion_authority: ActionApprovalBatchCompletionAuthority,
        cancellation_authority: ActionApprovalBatchCancellationAuthority,
        clock: Callable[[], datetime] | None = None,
    ) -> SQLiteActionApprovalBatchJournal:
        """Verify one backup and restore only to a previously absent journal path."""

        return _restore_journal_backup(
            backup,
            destination=destination,
            input_authority=input_authority,
            completion_authority=completion_authority,
            cancellation_authority=cancellation_authority,
            clock=clock,
        )

    def register(self, batch: ActionApprovalBatchEnvelope) -> ActionApprovalBatchPublication:
        """Persist one exact batch and all pending items before any claim."""

        batch = _canonical(batch, ActionApprovalBatchEnvelope, label="batch")
        self._verify_batch(batch)
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                row = connection.execute(
                    "SELECT canonical_batch FROM action_approval_batches WHERE batch_id = ?",
                    (batch.batch_id,),
                ).fetchone()
                if row is not None:
                    stored = _batch_from_bytes(_required_bytes(row, "canonical_batch"))
                    if stored != batch:
                        raise ActionApprovalBatchError("Action approval batch ID equivocated")
                else:
                    collision = connection.execute(
                        "SELECT batch_id FROM action_approval_batches WHERE batch_digest = ?",
                        (batch.batch_digest,),
                    ).fetchone()
                    if collision is not None:
                        raise ActionApprovalBatchError("Action approval batch digest is reused")
                    connection.execute(
                        """
                        INSERT INTO action_approval_batches (
                            batch_id, batch_digest, campaign_id, run_id, max_actions,
                            canonical_batch
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            batch.batch_id,
                            batch.batch_digest,
                            batch.campaign_id,
                            batch.run_id,
                            batch.max_actions,
                            sqlite3.Binary(_batch_bytes(batch)),
                        ),
                    )
                    now = self._now()
                    for ordinal, (approval, cleanup_request) in enumerate(
                        zip(batch.approvals, batch.cleanup_requests, strict=True),
                        start=1,
                    ):
                        connection.execute(
                            """
                            INSERT INTO action_approval_batch_items (
                                batch_id, item_ordinal, approval_id, approval_digest,
                                cleanup_request_digest, state
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                batch.batch_id,
                                ordinal,
                                approval.approval_id,
                                approval.approval_digest,
                                (
                                    cleanup_request.reservation_request_digest
                                    if cleanup_request is not None
                                    else None
                                ),
                                ActionApprovalBatchItemState.PENDING.value,
                            ),
                        )
                        _insert_event(
                            connection,
                            batch=batch,
                            ordinal=ordinal,
                            from_state=None,
                            to_state=ActionApprovalBatchItemState.PENDING,
                            authority_digest=batch.batch_digest,
                            occurred_at=now,
                        )
                self._verify_batch(batch)
            return self.publication(batch.batch_id)
        except sqlite3.IntegrityError as exc:
            raise ActionApprovalBatchError("Action approval batch registration conflicted") from exc
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError("Action approval batch registration failed") from exc

    def claim(
        self,
        batch: ActionApprovalBatchEnvelope,
        ordinal: int,
    ) -> tuple[ActionApprovalBatchItemRecord, bool]:
        """Record claim intent before Graph Permit consumption or any dispatch."""

        batch = _canonical(batch, ActionApprovalBatchEnvelope, label="batch")
        approval = batch.approval_at(ordinal)
        self._verify_batch(batch)
        now = self._now()
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                _require_exact_batch(connection, batch)
                row = _item_row(connection, batch.batch_id, ordinal)
                current = _item_record(connection, batch, row)
                if current.state is ActionApprovalBatchItemState.PENDING:
                    if not batch.not_before <= now < batch.expires_at:
                        raise ActionApprovalBatchError(
                            "Action approval batch is not currently active"
                        )
                    connection.execute(
                        """
                        UPDATE action_approval_batch_items
                        SET state = ?
                        WHERE batch_id = ? AND item_ordinal = ? AND state = ?
                        """,
                        (
                            ActionApprovalBatchItemState.CLAIM_STARTED.value,
                            batch.batch_id,
                            ordinal,
                            ActionApprovalBatchItemState.PENDING.value,
                        ),
                    )
                    _insert_event(
                        connection,
                        batch=batch,
                        ordinal=ordinal,
                        from_state=ActionApprovalBatchItemState.PENDING,
                        to_state=ActionApprovalBatchItemState.CLAIM_STARTED,
                        authority_digest=approval.approval_digest,
                        occurred_at=now,
                    )
                    newly_claimed = True
                else:
                    newly_claimed = False
                self._verify_batch(batch)
            return self.item(batch.batch_id, ordinal), newly_claimed
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError("Action approval batch item claim failed") from exc

    def bind_authorization(
        self,
        batch: ActionApprovalBatchEnvelope,
        ordinal: int,
        authorization: ActionApprovalBatchAuthorization,
    ) -> ActionApprovalBatchItemRecord:
        """Bind the existing atomic Graph approval/Permit result to an unknown item."""

        batch = _canonical(batch, ActionApprovalBatchEnvelope, label="batch")
        approval = batch.approval_at(ordinal)
        authorization = _canonical_batch_authorization(authorization)
        _require_authorization_binding(batch, ordinal, approval, authorization)
        self._verify_batch(batch)
        permit, receipt, cleanup_reservation = _authorization_evidence(authorization)
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                _require_exact_batch(connection, batch)
                current = _item_record(
                    connection,
                    batch,
                    _item_row(connection, batch.batch_id, ordinal),
                )
                if current.state is ActionApprovalBatchItemState.CLAIM_STARTED:
                    connection.execute(
                        """
                        UPDATE action_approval_batch_items
                        SET state = ?, permit_id = ?, permit_digest = ?,
                            receipt_id = ?, receipt_digest = ?,
                            cleanup_reservation_id = ?, cleanup_reservation_digest = ?,
                            cleanup_reservation_json = ?
                        WHERE batch_id = ? AND item_ordinal = ?
                        """,
                        (
                            ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value,
                            permit.permit_id,
                            permit.permit_digest,
                            receipt.receipt_id,
                            receipt.receipt_digest,
                            (
                                cleanup_reservation.cleanup_reservation_id
                                if cleanup_reservation is not None
                                else None
                            ),
                            (
                                cleanup_reservation.cleanup_reservation_digest
                                if cleanup_reservation is not None
                                else None
                            ),
                            (
                                sqlite3.Binary(_cleanup_reservation_bytes(cleanup_reservation))
                                if cleanup_reservation is not None
                                else None
                            ),
                            batch.batch_id,
                            ordinal,
                        ),
                    )
                    _insert_event(
                        connection,
                        batch=batch,
                        ordinal=ordinal,
                        from_state=ActionApprovalBatchItemState.CLAIM_STARTED,
                        to_state=(ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN),
                        authority_digest=receipt.receipt_digest,
                        occurred_at=self._now(),
                    )
                elif (
                    current.state
                    is not ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                ):
                    raise ActionApprovalBatchError(
                        "Action approval batch item is not awaiting an outcome"
                    )
                elif (
                    current.permit_id != permit.permit_id
                    or current.permit_digest != permit.permit_digest
                    or current.receipt_id != receipt.receipt_id
                    or current.receipt_digest != receipt.receipt_digest
                    or current.cleanup_reservation != cleanup_reservation
                ):
                    raise ActionApprovalBatchError(
                        "Action approval batch item authorization equivocated"
                    )
                self._verify_batch(batch)
            return self.item(batch.batch_id, ordinal)
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError(
                "Action approval batch authorization binding failed"
            ) from exc

    def finalize(
        self,
        batch: ActionApprovalBatchEnvelope,
        ordinal: int,
        authorization: ActionApprovalBatchAuthorization,
        completion: ActionApprovalBatchCompletion,
    ) -> ActionApprovalBatchPublication:
        """Record authenticated terminal evidence; no terminal state can redispatch."""

        completion_authority = self._completion_authority
        batch = _canonical(batch, ActionApprovalBatchEnvelope, label="batch")
        approval = batch.approval_at(ordinal)
        authorization = _canonical_batch_authorization(authorization)
        completion = _canonical(
            completion,
            ActionApprovalBatchCompletion,
            label="completion",
        )
        _require_authorization_binding(batch, ordinal, approval, authorization)
        _require_completion_binding(batch, ordinal, approval, authorization, completion)
        self._verify_batch(batch)
        _verify_completion(
            completion_authority,
            batch,
            approval,
            authorization,
            completion,
        )
        terminal_state = (
            ActionApprovalBatchItemState.TERMINAL_SUCCEEDED
            if completion.outcome == "succeeded"
            else ActionApprovalBatchItemState.TERMINAL_FAILED
        )
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                _require_exact_batch(connection, batch)
                current = _item_record(
                    connection,
                    batch,
                    _item_row(connection, batch.batch_id, ordinal),
                )
                if current.state is terminal_state:
                    if current.completion != completion:
                        raise ActionApprovalBatchError(
                            "Action approval batch terminal evidence equivocated"
                        )
                elif current.state in {
                    ActionApprovalBatchItemState.TERMINAL_SUCCEEDED,
                    ActionApprovalBatchItemState.TERMINAL_FAILED,
                }:
                    raise ActionApprovalBatchError(
                        "Action approval batch terminal outcome equivocated"
                    )
                elif (
                    current.state
                    is not ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                ):
                    raise ActionApprovalBatchError("Action approval batch item is not reconcilable")
                else:
                    permit, receipt, cleanup_reservation = _authorization_evidence(authorization)
                    if (
                        current.permit_id != permit.permit_id
                        or current.permit_digest != permit.permit_digest
                        or current.receipt_id != receipt.receipt_id
                        or current.receipt_digest != receipt.receipt_digest
                        or current.cleanup_reservation != cleanup_reservation
                    ):
                        raise ActionApprovalBatchError(
                            "Action approval batch terminal authority differs"
                        )
                    connection.execute(
                        """
                        UPDATE action_approval_batch_items
                        SET state = ?, completion_json = ?
                        WHERE batch_id = ? AND item_ordinal = ?
                        """,
                        (
                            terminal_state.value,
                            sqlite3.Binary(_completion_bytes(completion)),
                            batch.batch_id,
                            ordinal,
                        ),
                    )
                    _insert_event(
                        connection,
                        batch=batch,
                        ordinal=ordinal,
                        from_state=(ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN),
                        to_state=terminal_state,
                        authority_digest=completion.completion_digest,
                        occurred_at=completion.completed_at,
                    )
                _verify_completion(
                    completion_authority,
                    batch,
                    approval,
                    authorization,
                    completion,
                )
                self._verify_batch(batch)
            return self.publication(batch.batch_id)
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError("Action approval batch finalization failed") from exc

    def cancel_pending(
        self,
        batch: ActionApprovalBatchEnvelope,
        cancellation: ActionApprovalBatchCancellation,
    ) -> ActionApprovalBatchPublication:
        """Cancel an exact set of pending items atomically; claimed items cannot be cancelled."""

        cancellation_authority = self._cancellation_authority
        batch = _canonical(batch, ActionApprovalBatchEnvelope, label="batch")
        cancellation = _canonical(
            cancellation,
            ActionApprovalBatchCancellation,
            label="cancellation",
        )
        if (
            cancellation.batch_id != batch.batch_id
            or cancellation.batch_digest != batch.batch_digest
            or cancellation.cancelled_at < batch.approved_at
            or cancellation.cancelled_at >= batch.expires_at
            or any(ordinal > len(batch.approvals) for ordinal in cancellation.item_ordinals)
        ):
            raise ActionApprovalBatchError("Action approval batch cancellation differs")
        self._verify_batch(batch)
        _verify_cancellation(cancellation_authority, batch, cancellation)
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                _require_exact_batch(connection, batch)
                records = [
                    _item_record(
                        connection,
                        batch,
                        _item_row(connection, batch.batch_id, ordinal),
                    )
                    for ordinal in cancellation.item_ordinals
                ]
                if any(
                    record.state is not ActionApprovalBatchItemState.PENDING for record in records
                ):
                    raise ActionApprovalBatchError(
                        "Action approval batch cancellation names a claimed item"
                    )
                for ordinal in cancellation.item_ordinals:
                    connection.execute(
                        """
                        UPDATE action_approval_batch_items
                        SET state = ?, cancellation_json = ?
                        WHERE batch_id = ? AND item_ordinal = ?
                        """,
                        (
                            ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH.value,
                            sqlite3.Binary(_cancellation_bytes(cancellation)),
                            batch.batch_id,
                            ordinal,
                        ),
                    )
                    _insert_event(
                        connection,
                        batch=batch,
                        ordinal=ordinal,
                        from_state=ActionApprovalBatchItemState.PENDING,
                        to_state=ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH,
                        authority_digest=cancellation.cancellation_digest,
                        occurred_at=cancellation.cancelled_at,
                    )
                _verify_cancellation(cancellation_authority, batch, cancellation)
                self._verify_batch(batch)
            return self.publication(batch.batch_id)
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError("Action approval batch cancellation failed") from exc

    def item(self, batch_id: str, ordinal: int) -> ActionApprovalBatchItemRecord:
        """Read and fully verify one durable item."""

        if fullmatch(r"^action-approval-batch_[a-f0-9]{64}$", batch_id) is None:
            raise ActionApprovalBatchError("Action approval batch ID is invalid")
        if type(ordinal) is not int or not 1 <= ordinal <= _MAX_BATCH_ACTIONS:
            raise ActionApprovalBatchError("Action approval batch ordinal is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                _validate_schema(connection)
                batch = _load_batch(connection, batch_id)
                return _item_record(
                    connection,
                    batch,
                    _item_row(connection, batch_id, ordinal),
                )
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError("Action approval batch item read failed") from exc

    def publication(self, batch_id: str) -> ActionApprovalBatchPublication:
        """Read and verify the aggregate state from every item."""

        if fullmatch(r"^action-approval-batch_[a-f0-9]{64}$", batch_id) is None:
            raise ActionApprovalBatchError("Action approval batch ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                _validate_schema(connection)
                batch = _load_batch(connection, batch_id)
                rows = connection.execute(
                    """
                    SELECT * FROM action_approval_batch_items
                    WHERE batch_id = ? ORDER BY item_ordinal
                    """,
                    (batch_id,),
                ).fetchall()
                if len(rows) != len(batch.approvals):
                    raise ActionApprovalBatchError(
                        "Action approval batch durable item set is incomplete"
                    )
                items = tuple(
                    _item_record(connection, batch, cast(sqlite3.Row, row)) for row in rows
                )
                states = tuple(item.state for item in items)
                derived = _batch_state(states)
                return ActionApprovalBatchPublication(
                    batch=batch,
                    state=derived,
                    items=items,
                    manualReviewRequired=any(state in _MANUAL_REVIEW_STATES for state in states),
                )
        except sqlite3.Error as exc:
            raise ActionApprovalBatchError("Action approval batch publication read failed") from exc

    def _verify_batch(self, batch: ActionApprovalBatchEnvelope) -> None:
        try:
            self._input_authority.verify_action_approval_batch(batch.model_copy(deep=True))
        except ActionApprovalBatchError:
            raise
        except Exception as exc:
            raise ActionApprovalBatchError(
                "Action approval batch input authority rejected the batch"
            ) from exc

    def _now(self) -> datetime:
        try:
            return _normalize_utc(self._clock(), label="Action approval batch clock")
        except Exception as exc:
            raise ActionApprovalBatchError("Action approval batch clock failed") from exc


class GraphApprovedActionBatchDispatcher:
    """Async coordinator over the existing single-action Graph authority."""

    def __init__(
        self,
        authority: GraphApprovedActionPermitAuthority | None,
        journal: SQLiteActionApprovalBatchJournal,
        *,
        reversible_authority: GraphApprovedReversibleActionPermitAuthority | None = None,
    ) -> None:
        if authority is not None and not isinstance(authority, GraphApprovedActionPermitAuthority):
            raise TypeError("Action approval batch Graph authority is invalid")
        if not isinstance(journal, SQLiteActionApprovalBatchJournal):
            raise TypeError("Action approval batch journal is invalid")
        if reversible_authority is not None and not isinstance(
            reversible_authority,
            GraphApprovedReversibleActionPermitAuthority,
        ):
            raise TypeError("Reversible Action approval batch authority is invalid")
        if authority is None and reversible_authority is None:
            raise TypeError("Action approval batch requires an execution authority")
        self._authority = authority
        self._reversible_authority = reversible_authority
        self._journal = journal

    async def dispatch_item_once(
        self,
        batch: ActionApprovalBatchEnvelope,
        ordinal: int,
        consumer: Callable[
            [ActionPermit, ActionApprovalConsumptionReceipt],
            Awaitable[ActionApprovalBatchCompletion],
        ],
    ) -> ActionApprovalBatchDispatchResult:
        """Claim one item before dispatch; exceptions remain outcome-unknown."""

        if not _is_async_callable(consumer):
            raise TypeError("Action approval batch consumer must be async")
        batch = _canonical(batch, ActionApprovalBatchEnvelope, label="batch")
        approval = batch.approval_at(ordinal)
        if batch.cleanup_request_at(ordinal) is not None:
            raise ActionApprovalBatchError(
                "Reversible batch item requires the cleanup-bound dispatcher"
            )
        authority = self._authority
        if authority is None:
            raise ActionApprovalBatchError("No-write Action approval batch authority is absent")
        self._journal.register(batch)
        item, newly_claimed = self._journal.claim(batch, ordinal)
        if not newly_claimed and item.state is not ActionApprovalBatchItemState.CLAIM_STARTED:
            return ActionApprovalBatchDispatchResult(
                publication=self._journal.publication(batch.batch_id),
                item=item,
                authorization=None,
                dispatched=False,
            )
        try:
            authorization = authority.authorize_for_dispatch(
                approval.mission_envelope,
                approval.proposal,
                approval.graph_decision,
                approval,
            )
            item = self._journal.bind_authorization(
                batch,
                ordinal,
                authorization,
            )
            if not authorization.action.newly_consumed:
                return ActionApprovalBatchDispatchResult(
                    publication=self._journal.publication(batch.batch_id),
                    item=item,
                    authorization=authorization,
                    dispatched=False,
                )
            completion = await consumer(
                authorization.action.permit.model_copy(deep=True),
                authorization.receipt.model_copy(deep=True),
            )
            completion = _canonical(
                completion,
                ActionApprovalBatchCompletion,
                label="completion",
            )
            if completion.source != "worker-completion":
                raise ActionApprovalBatchError(
                    "Action approval batch Worker returned a reconciliation record"
                )
            publication = self._journal.finalize(
                batch,
                ordinal,
                authorization,
                completion,
            )
            return ActionApprovalBatchDispatchResult(
                publication=publication,
                item=publication.items[ordinal - 1],
                authorization=authorization,
                dispatched=True,
            )
        except asyncio.CancelledError:
            raise
        except ActionApprovalBatchError:
            raise
        except Exception as exc:
            raise ActionApprovalBatchError("Action approval batch item outcome is unknown") from exc

    async def dispatch_reversible_item_once(
        self,
        batch: ActionApprovalBatchEnvelope,
        ordinal: int,
        consumer: Callable[
            [
                ActionPermit,
                ActionApprovalConsumptionReceipt,
                ActionCleanupReservation,
            ],
            Awaitable[ActionApprovalBatchCompletion],
        ],
    ) -> ActionApprovalBatchDispatchResult:
        """Consume approval and cleanup hold before one reversible async callback."""

        if not _is_async_callable(consumer):
            raise TypeError("Reversible Action approval batch consumer must be async")
        authority = self._reversible_authority
        if authority is None:
            raise ActionApprovalBatchError(
                "Reversible Action approval batch authority is not configured"
            )
        batch = _canonical(batch, ActionApprovalBatchEnvelope, label="batch")
        approval = batch.approval_at(ordinal)
        cleanup_request = batch.cleanup_request_at(ordinal)
        if cleanup_request is None:
            raise ActionApprovalBatchError(
                "No-write batch item cannot use the cleanup-bound dispatcher"
            )
        self._journal.register(batch)
        item, newly_claimed = self._journal.claim(batch, ordinal)
        if not newly_claimed and item.state is not ActionApprovalBatchItemState.CLAIM_STARTED:
            return ActionApprovalBatchDispatchResult(
                publication=self._journal.publication(batch.batch_id),
                item=item,
                authorization=None,
                dispatched=False,
            )
        try:
            authorization = authority.authorize_for_dispatch(
                approval.mission_envelope,
                approval.proposal,
                approval.graph_decision,
                approval,
                cleanup_request,
            )
            item = self._journal.bind_authorization(batch, ordinal, authorization)
            if not authorization.reversible.action.newly_consumed:
                return ActionApprovalBatchDispatchResult(
                    publication=self._journal.publication(batch.batch_id),
                    item=item,
                    authorization=authorization,
                    dispatched=False,
                )
            completion = await consumer(
                authorization.reversible.action.permit.model_copy(deep=True),
                authorization.receipt.model_copy(deep=True),
                authorization.reversible.cleanup_reservation.model_copy(deep=True),
            )
            completion = _canonical(
                completion,
                ActionApprovalBatchCompletion,
                label="completion",
            )
            if completion.source != "worker-completion":
                raise ActionApprovalBatchError(
                    "Reversible batch Worker returned a reconciliation record"
                )
            publication = self._journal.finalize(
                batch,
                ordinal,
                authorization,
                completion,
            )
            return ActionApprovalBatchDispatchResult(
                publication=publication,
                item=publication.items[ordinal - 1],
                authorization=authorization,
                dispatched=True,
            )
        except asyncio.CancelledError:
            raise
        except ActionApprovalBatchError:
            raise
        except Exception as exc:
            raise ActionApprovalBatchError(
                "Reversible Action approval batch item outcome is unknown"
            ) from exc


def _canonical_batch_authorization(
    authorization: ActionApprovalBatchAuthorization,
) -> ActionApprovalBatchAuthorization:
    if isinstance(authorization, ActionApprovalAuthorization):
        return _canonical(
            authorization,
            ActionApprovalAuthorization,
            label="authorization",
        )
    if isinstance(authorization, ApprovedReversibleActionPermitAuthorization):
        return _canonical(
            authorization,
            ApprovedReversibleActionPermitAuthorization,
            label="reversible authorization",
        )
    raise ActionApprovalBatchError("Action approval batch authorization type is invalid")


def _authorization_evidence(
    authorization: ActionApprovalBatchAuthorization,
) -> tuple[ActionPermit, ActionApprovalConsumptionReceipt, ActionCleanupReservation | None]:
    if isinstance(authorization, ActionApprovalAuthorization):
        return authorization.action.permit, authorization.receipt, None
    return (
        authorization.reversible.action.permit,
        authorization.receipt,
        authorization.reversible.cleanup_reservation,
    )


def _authorization_newly_consumed(authorization: ActionApprovalBatchAuthorization) -> bool:
    if isinstance(authorization, ActionApprovalAuthorization):
        return authorization.action.newly_consumed
    return authorization.reversible.action.newly_consumed


def _validate_batch_item_scope(
    approval: ActionApprovalEnvelope,
    cleanup_request: ActionCleanupReservationRequest | None,
) -> str | None:
    if approval.side_effect_class in {"none", "read-only"}:
        if approval.cleanup_required or cleanup_request is not None:
            raise ValueError("No-write batch approval cannot carry cleanup authority")
        return None
    if approval.side_effect_class != "reversible-write":
        raise ValueError("Action approval batch side effect is unsupported")
    if not approval.cleanup_required or cleanup_request is None:
        raise ValueError("Reversible batch approval requires one cleanup reservation request")
    _require_cleanup_request_binding(approval, cleanup_request)
    return cleanup_request.reservation_request_id


def _require_cleanup_request_binding(
    approval: ActionApprovalEnvelope,
    cleanup_request: ActionCleanupReservationRequest,
) -> None:
    envelope = approval.mission_envelope
    proposal = approval.proposal
    if (
        cleanup_request.campaign_id != approval.campaign_id
        or cleanup_request.run_id != approval.run_id
        or cleanup_request.envelope_id != envelope.envelope_id
        or cleanup_request.envelope_digest != envelope.envelope_digest
        or cleanup_request.source_action_proposal_id != proposal.proposal_id
        or cleanup_request.source_action_proposal_digest != proposal.proposal_digest
        or cleanup_request.target_digest != proposal.target_digest
    ):
        raise ValueError("Action approval batch cleanup request lineage differs")


def _require_cleanup_record_binding(
    approval: ActionApprovalEnvelope,
    cleanup_request: ActionCleanupReservationRequest | None,
    cleanup_reservation: ActionCleanupReservation | None,
    *,
    authorization_bound: bool,
) -> None:
    if cleanup_request is None:
        if (
            approval.side_effect_class not in {"none", "read-only"}
            or approval.cleanup_required
            or cleanup_reservation is not None
        ):
            raise ActionApprovalBatchError("No-write batch item gained cleanup authority")
        return
    if approval.side_effect_class != "reversible-write" or not approval.cleanup_required:
        raise ActionApprovalBatchError("Batch cleanup request belongs to a non-reversible item")
    _require_cleanup_request_binding(approval, cleanup_request)
    if cleanup_reservation is None:
        if authorization_bound:
            raise ActionApprovalBatchError("Reversible batch item lacks its cleanup reservation")
        return
    envelope = approval.mission_envelope
    if (
        cleanup_reservation.campaign_id != cleanup_request.campaign_id
        or cleanup_reservation.run_id != cleanup_request.run_id
        or cleanup_reservation.compiler_id != envelope.compiler_id
        or cleanup_reservation.compiler_version != envelope.compiler_version
        or cleanup_reservation.compiler_digest != envelope.compiler_digest
        or cleanup_reservation.envelope_id != cleanup_request.envelope_id
        or cleanup_reservation.envelope_digest != cleanup_request.envelope_digest
        or cleanup_reservation.reservation_request_id != cleanup_request.reservation_request_id
        or cleanup_reservation.reservation_request_digest
        != cleanup_request.reservation_request_digest
        or cleanup_reservation.cleanup_capability != cleanup_request.cleanup_capability
        or cleanup_reservation.target_digest != cleanup_request.target_digest
        or cleanup_reservation.cleanup_handler_id != cleanup_request.cleanup_handler_id
        or cleanup_reservation.cleanup_handler_version != cleanup_request.cleanup_handler_version
        or cleanup_reservation.cleanup_handler_digest != cleanup_request.cleanup_handler_digest
        or cleanup_reservation.cleanup_executor_id != cleanup_request.cleanup_executor_id
        or cleanup_reservation.cleanup_executor_version != cleanup_request.cleanup_executor_version
        or cleanup_reservation.cleanup_executor_digest != cleanup_request.cleanup_executor_digest
        or cleanup_reservation.reservation != cleanup_request.reservation
        or cleanup_reservation.claim_expires_at != cleanup_request.claim_expires_at
    ):
        raise ActionApprovalBatchError("Action approval batch cleanup reservation differs")


def _require_authorization_binding(
    batch: ActionApprovalBatchEnvelope,
    ordinal: int,
    approval: ActionApprovalEnvelope,
    authorization: ActionApprovalBatchAuthorization,
) -> None:
    permit, receipt, cleanup_reservation = _authorization_evidence(authorization)
    cleanup_request = batch.cleanup_request_at(ordinal)
    if (
        batch.approval_at(ordinal) != approval
        or authorization.approval != approval
        or receipt.approval != approval
        or receipt.action_permit != permit
    ):
        raise ActionApprovalBatchError("Action approval batch authorization differs")
    _require_cleanup_record_binding(
        approval,
        cleanup_request,
        cleanup_reservation,
        authorization_bound=True,
    )
    if cleanup_reservation is not None and (
        cleanup_reservation.source_action_permit_id != permit.permit_id
        or cleanup_reservation.source_action_permit_digest != permit.permit_digest
        or cleanup_reservation.source_action_dispatch_id != permit.dispatch_id
    ):
        raise ActionApprovalBatchError("Action approval batch cleanup authority differs")


def _require_completion_binding(
    batch: ActionApprovalBatchEnvelope,
    ordinal: int,
    approval: ActionApprovalEnvelope,
    authorization: ActionApprovalBatchAuthorization,
    completion: ActionApprovalBatchCompletion,
) -> None:
    permit, receipt, cleanup_reservation = _authorization_evidence(authorization)
    if (
        completion.batch_id != batch.batch_id
        or completion.batch_digest != batch.batch_digest
        or completion.item_ordinal != ordinal
        or completion.approval_id != approval.approval_id
        or completion.approval_digest != approval.approval_digest
        or completion.permit_id != permit.permit_id
        or completion.permit_digest != permit.permit_digest
        or completion.receipt_id != receipt.receipt_id
        or completion.receipt_digest != receipt.receipt_digest
        or completion.cleanup_reservation_id
        != (cleanup_reservation.cleanup_reservation_id if cleanup_reservation is not None else None)
        or completion.cleanup_reservation_digest
        != (
            cleanup_reservation.cleanup_reservation_digest
            if cleanup_reservation is not None
            else None
        )
        or (cleanup_reservation is not None)
        is not (completion.restored_state_evidence_digest is not None)
        or completion.completed_at < permit.consumed_at
    ):
        raise ActionApprovalBatchError("Action approval batch completion differs")


def _verify_completion(
    authority: ActionApprovalBatchCompletionAuthority,
    batch: ActionApprovalBatchEnvelope,
    approval: ActionApprovalEnvelope,
    authorization: ActionApprovalBatchAuthorization,
    completion: ActionApprovalBatchCompletion,
) -> None:
    try:
        authority.verify_action_approval_batch_completion(
            batch.model_copy(deep=True),
            approval.model_copy(deep=True),
            authorization.model_copy(deep=True),
            completion.model_copy(deep=True),
        )
    except ActionApprovalBatchError:
        raise
    except Exception as exc:
        raise ActionApprovalBatchError(
            "Action approval batch completion authority rejected terminal evidence"
        ) from exc


def _verify_cancellation(
    authority: ActionApprovalBatchCancellationAuthority,
    batch: ActionApprovalBatchEnvelope,
    cancellation: ActionApprovalBatchCancellation,
) -> None:
    try:
        authority.verify_action_approval_batch_cancellation(
            batch.model_copy(deep=True),
            cancellation.model_copy(deep=True),
        )
    except ActionApprovalBatchError:
        raise
    except Exception as exc:
        raise ActionApprovalBatchError(
            "Action approval batch cancellation authority rejected cancellation"
        ) from exc


def _batch_state(states: tuple[ActionApprovalBatchItemState, ...]) -> ActionApprovalBatchState:
    if not states:
        raise ValueError("Action approval batch contains no states")
    if all(state is ActionApprovalBatchItemState.PENDING for state in states):
        return ActionApprovalBatchState.PENDING
    if any(state in _MANUAL_REVIEW_STATES for state in states):
        return ActionApprovalBatchState.MANUAL_REVIEW_REQUIRED
    if all(state is ActionApprovalBatchItemState.TERMINAL_SUCCEEDED for state in states):
        return ActionApprovalBatchState.TERMINAL_SUCCEEDED
    if all(state is ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH for state in states):
        return ActionApprovalBatchState.CANCELLED
    terminal = {
        ActionApprovalBatchItemState.TERMINAL_SUCCEEDED,
        ActionApprovalBatchItemState.TERMINAL_FAILED,
        ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH,
    }
    if all(state in terminal for state in states):
        return ActionApprovalBatchState.TERMINAL_PARTIAL
    return ActionApprovalBatchState.ACTIVE


def _insert_event(
    connection: sqlite3.Connection,
    *,
    batch: ActionApprovalBatchEnvelope,
    ordinal: int,
    from_state: ActionApprovalBatchItemState | None,
    to_state: ActionApprovalBatchItemState,
    authority_digest: str | None,
    occurred_at: datetime,
) -> None:
    previous = connection.execute(
        """
        SELECT ordinal, event_digest FROM action_approval_batch_events
        WHERE batch_id = ? AND item_ordinal = ? ORDER BY ordinal DESC LIMIT 1
        """,
        (batch.batch_id, ordinal),
    ).fetchone()
    event_ordinal = 1 if previous is None else int(previous["ordinal"]) + 1
    previous_digest = None if previous is None else str(previous["event_digest"])
    event_digest = graph_digest(
        "pajin.action.approval-batch-event/v1",
        {
            "batchId": batch.batch_id,
            "batchDigest": batch.batch_digest,
            "itemOrdinal": ordinal,
            "ordinal": event_ordinal,
            "fromState": from_state.value if from_state is not None else None,
            "toState": to_state.value,
            "authorityDigest": authority_digest,
            "occurredAt": occurred_at.isoformat(),
            "previousEventDigest": previous_digest,
        },
        max_bytes=_MAX_BATCH_BYTES,
    )
    connection.execute(
        """
        INSERT INTO action_approval_batch_events (
            batch_id, item_ordinal, ordinal, from_state, to_state,
            authority_digest, occurred_at, previous_event_digest, event_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            batch.batch_id,
            ordinal,
            event_ordinal,
            from_state.value if from_state is not None else None,
            to_state.value,
            authority_digest,
            occurred_at.isoformat(),
            previous_digest,
            event_digest,
        ),
    )


def _item_record(
    connection: sqlite3.Connection,
    batch: ActionApprovalBatchEnvelope,
    row: sqlite3.Row,
) -> ActionApprovalBatchItemRecord:
    ordinal = _required_int(row, "item_ordinal")
    approval = batch.approval_at(ordinal)
    state = ActionApprovalBatchItemState(_required_text(row, "state"))
    completion_raw = _optional_bytes(row, "completion_json")
    cancellation_raw = _optional_bytes(row, "cancellation_json")
    cleanup_reservation_raw = _optional_bytes(row, "cleanup_reservation_json")
    completion = _completion_from_bytes(completion_raw) if completion_raw is not None else None
    cancellation = (
        _cancellation_from_bytes(cancellation_raw) if cancellation_raw is not None else None
    )
    cleanup_reservation = (
        _cleanup_reservation_from_bytes(cleanup_reservation_raw)
        if cleanup_reservation_raw is not None
        else None
    )
    event_rows = connection.execute(
        """
        SELECT * FROM action_approval_batch_events
        WHERE batch_id = ? AND item_ordinal = ? ORDER BY ordinal
        """,
        (batch.batch_id, ordinal),
    ).fetchall()
    if not event_rows or len(event_rows) > 4:
        raise ActionApprovalBatchError("Action approval batch item event count is invalid")
    previous_digest: str | None = None
    expected_from: str | None = None
    event_digests: list[str] = []
    event_authorities: list[str | None] = []
    for expected_ordinal, event in enumerate(event_rows, start=1):
        if _required_int(event, "ordinal") != expected_ordinal:
            raise ActionApprovalBatchError("Action approval batch event order differs")
        event_from = _optional_text(event, "from_state")
        event_to = _required_text(event, "to_state")
        if event_from != expected_from:
            raise ActionApprovalBatchError("Action approval batch event transition differs")
        occurred_at = _parse_timestamp(_required_text(event, "occurred_at"))
        authority_digest = _optional_text(event, "authority_digest")
        observed_previous = _optional_text(event, "previous_event_digest")
        observed_digest = _required_text(event, "event_digest")
        expected_digest = graph_digest(
            "pajin.action.approval-batch-event/v1",
            {
                "batchId": batch.batch_id,
                "batchDigest": batch.batch_digest,
                "itemOrdinal": ordinal,
                "ordinal": expected_ordinal,
                "fromState": event_from,
                "toState": event_to,
                "authorityDigest": authority_digest,
                "occurredAt": occurred_at.isoformat(),
                "previousEventDigest": previous_digest,
            },
            max_bytes=_MAX_BATCH_BYTES,
        )
        if observed_previous != previous_digest or observed_digest != expected_digest:
            raise ActionApprovalBatchError("Action approval batch event digest differs")
        previous_digest = observed_digest
        expected_from = event_to
        event_digests.append(observed_digest)
        event_authorities.append(authority_digest)
    if expected_from != state.value:
        raise ActionApprovalBatchError("Action approval batch item state differs from events")
    record = ActionApprovalBatchItemRecord(
        batchId=batch.batch_id,
        batchDigest=batch.batch_digest,
        itemOrdinal=ordinal,
        approvalId=_required_text(row, "approval_id"),
        approvalDigest=_required_text(row, "approval_digest"),
        state=state,
        permitId=_optional_text(row, "permit_id"),
        permitDigest=_optional_text(row, "permit_digest"),
        receiptId=_optional_text(row, "receipt_id"),
        receiptDigest=_optional_text(row, "receipt_digest"),
        cleanupReservation=cleanup_reservation,
        completion=completion,
        cancellation=cancellation,
        eventDigests=tuple(event_digests),
    )
    if (
        record.approval_id != approval.approval_id
        or record.approval_digest != approval.approval_digest
    ):
        raise ActionApprovalBatchError("Action approval batch item identity differs")
    cleanup_request = batch.cleanup_request_at(ordinal)
    expected_cleanup_digest = (
        cleanup_request.reservation_request_digest if cleanup_request is not None else None
    )
    if _optional_text(row, "cleanup_request_digest") != expected_cleanup_digest:
        raise ActionApprovalBatchError("Action approval batch cleanup request identity differs")
    _require_cleanup_record_binding(
        approval,
        cleanup_request,
        cleanup_reservation,
        authorization_bound=record.permit_id is not None,
    )
    _verify_item_event_authorities(
        batch=batch,
        approval=approval,
        record=record,
        completion=completion,
        cancellation=cancellation,
        event_authorities=event_authorities,
    )
    return record


def _verify_item_event_authorities(
    *,
    batch: ActionApprovalBatchEnvelope,
    approval: ActionApprovalEnvelope,
    record: ActionApprovalBatchItemRecord,
    completion: ActionApprovalBatchCompletion | None,
    cancellation: ActionApprovalBatchCancellation | None,
    event_authorities: list[str | None],
) -> None:
    if event_authorities[0] != batch.batch_digest:
        raise ActionApprovalBatchError("Action approval batch registration event differs")
    if record.state is ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH:
        if (
            cancellation is None
            or event_authorities != [batch.batch_digest, cancellation.cancellation_digest]
            or cancellation.batch_id != batch.batch_id
            or cancellation.batch_digest != batch.batch_digest
            or record.item_ordinal not in cancellation.item_ordinals
        ):
            raise ActionApprovalBatchError("Action approval batch cancellation event differs")
    elif record.state is not ActionApprovalBatchItemState.PENDING:
        if len(event_authorities) < 2 or event_authorities[1] != approval.approval_digest:
            raise ActionApprovalBatchError("Action approval batch claim event differs")
        if record.permit_id is not None and (
            len(event_authorities) < 3 or event_authorities[2] != record.receipt_digest
        ):
            raise ActionApprovalBatchError("Action approval batch authorization event differs")
        if completion is not None and (
            event_authorities[-1] != completion.completion_digest
            or completion.batch_id != batch.batch_id
            or completion.batch_digest != batch.batch_digest
            or completion.item_ordinal != record.item_ordinal
            or completion.approval_id != approval.approval_id
            or completion.approval_digest != approval.approval_digest
            or completion.permit_id != record.permit_id
            or completion.permit_digest != record.permit_digest
            or completion.receipt_id != record.receipt_id
            or completion.receipt_digest != record.receipt_digest
            or completion.cleanup_reservation_id
            != (
                record.cleanup_reservation.cleanup_reservation_id
                if record.cleanup_reservation is not None
                else None
            )
            or completion.cleanup_reservation_digest
            != (
                record.cleanup_reservation.cleanup_reservation_digest
                if record.cleanup_reservation is not None
                else None
            )
            or (record.cleanup_reservation is not None)
            is not (completion.restored_state_evidence_digest is not None)
            or (completion.outcome == "succeeded")
            is not (record.state is ActionApprovalBatchItemState.TERMINAL_SUCCEEDED)
        ):
            raise ActionApprovalBatchError("Action approval batch completion event differs")


def _require_exact_batch(
    connection: sqlite3.Connection,
    batch: ActionApprovalBatchEnvelope,
) -> None:
    if _load_batch(connection, batch.batch_id) != batch:
        raise ActionApprovalBatchError("Action approval batch durable authority differs")


def _load_batch(
    connection: sqlite3.Connection,
    batch_id: str,
) -> ActionApprovalBatchEnvelope:
    row = connection.execute(
        "SELECT * FROM action_approval_batches WHERE batch_id = ?",
        (batch_id,),
    ).fetchone()
    if row is None:
        raise ActionApprovalBatchError("Action approval batch is not registered")
    batch = _batch_from_bytes(_required_bytes(row, "canonical_batch"))
    if (
        batch.batch_id != _required_text(row, "batch_id")
        or batch.batch_digest != _required_text(row, "batch_digest")
        or batch.campaign_id != _required_text(row, "campaign_id")
        or batch.run_id != _required_text(row, "run_id")
        or batch.max_actions != _required_int(row, "max_actions")
    ):
        raise ActionApprovalBatchError("Stored Action approval batch index differs")
    return batch


def _item_row(connection: sqlite3.Connection, batch_id: str, ordinal: int) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT * FROM action_approval_batch_items
        WHERE batch_id = ? AND item_ordinal = ?
        """,
        (batch_id, ordinal),
    ).fetchone()
    if row is None:
        raise ActionApprovalBatchError("Action approval batch item is not registered")
    return cast(sqlite3.Row, row)


def _batch_bytes(batch: ActionApprovalBatchEnvelope) -> bytes:
    return canonical_graph_json(
        batch.model_dump(mode="json", by_alias=True),
        label="ActionApprovalBatchEnvelope",
        max_bytes=_MAX_BATCH_BYTES,
    )


def _completion_bytes(completion: ActionApprovalBatchCompletion) -> bytes:
    return canonical_graph_json(
        completion.model_dump(mode="json", by_alias=True),
        label="ActionApprovalBatchCompletion",
        max_bytes=_MAX_BATCH_BYTES,
    )


def _cancellation_bytes(cancellation: ActionApprovalBatchCancellation) -> bytes:
    return canonical_graph_json(
        cancellation.model_dump(mode="json", by_alias=True),
        label="ActionApprovalBatchCancellation",
        max_bytes=_MAX_BATCH_BYTES,
    )


def _cleanup_reservation_bytes(reservation: ActionCleanupReservation) -> bytes:
    return canonical_graph_json(
        reservation.model_dump(mode="json", by_alias=True),
        label="ActionCleanupReservation",
        max_bytes=_MAX_BATCH_BYTES,
    )


def _batch_from_bytes(raw: bytes) -> ActionApprovalBatchEnvelope:
    return _model_from_bytes(raw, ActionApprovalBatchEnvelope, label="batch")


def _completion_from_bytes(raw: bytes) -> ActionApprovalBatchCompletion:
    return _model_from_bytes(raw, ActionApprovalBatchCompletion, label="completion")


def _cancellation_from_bytes(raw: bytes) -> ActionApprovalBatchCancellation:
    return _model_from_bytes(raw, ActionApprovalBatchCancellation, label="cancellation")


def _cleanup_reservation_from_bytes(raw: bytes) -> ActionCleanupReservation:
    return _model_from_bytes(raw, ActionCleanupReservation, label="cleanup reservation")


def _model_from_bytes[ModelT: StrictModel](
    raw: bytes,
    model: type[ModelT],
    *,
    label: str,
) -> ModelT:
    import json

    try:
        parsed = json.loads(raw.decode("utf-8"))
        value = model.model_validate(parsed)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ActionApprovalBatchError(f"Stored Action approval {label} is invalid") from exc
    expected = canonical_graph_json(
        value.model_dump(mode="json", by_alias=True),
        label=f"Action approval {label}",
        max_bytes=_MAX_BATCH_BYTES,
    )
    if raw != expected:
        raise ActionApprovalBatchError(f"Stored Action approval {label} is not canonical")
    return value


def _canonical[ModelT: StrictModel](
    value: ModelT,
    model: type[ModelT],
    *,
    label: str,
) -> ModelT:
    try:
        return model.model_validate(value.model_dump(mode="json", by_alias=True))
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ActionApprovalBatchError(f"Action approval {label} is not canonical") from exc


def action_approval_batch_journal_backup_manifest_path(backup: Path) -> Path:
    """Return the fixed sidecar path for one batch journal backup."""

    backup_path = Path(os.path.abspath(backup))
    return Path(f"{backup_path}.manifest.json")


def _retention_assessment(
    publications: tuple[ActionApprovalBatchPublication, ...],
    *,
    minimum_retain_until: datetime,
    evaluated_at: datetime,
) -> ActionApprovalBatchJournalRetentionAssessment:
    retain_until = _normalize_utc(
        minimum_retain_until,
        label="Action approval batch journal minimum retention time",
    )
    evaluated = _normalize_utc(
        evaluated_at,
        label="Action approval batch journal retention evaluation time",
    )
    terminal_states = {
        ActionApprovalBatchState.TERMINAL_SUCCEEDED,
        ActionApprovalBatchState.TERMINAL_PARTIAL,
        ActionApprovalBatchState.CANCELLED,
    }
    terminal_count = sum(item.state in terminal_states for item in publications)
    manual_review_required = any(item.manual_review_required for item in publications)
    state_digest = graph_digest(
        "pajin.action.approval-batch-journal-state/v1",
        tuple(item.model_dump(mode="json", by_alias=True) for item in publications),
        max_bytes=_MAX_JOURNAL_STATE_BYTES,
    )
    deletion_eligible = (
        bool(publications)
        and terminal_count == len(publications)
        and not manual_review_required
        and evaluated >= retain_until
    )
    return ActionApprovalBatchJournalRetentionAssessment(
        evaluatedAt=evaluated,
        minimumRetainUntil=retain_until,
        batchCount=len(publications),
        terminalBatchCount=terminal_count,
        manualReviewRequired=manual_review_required,
        deletionEligible=deletion_eligible,
        journalStateDigest=state_digest,
    )


def _create_journal_backup(
    journal: SQLiteActionApprovalBatchJournal,
    destination: Path,
    *,
    minimum_retain_until: datetime,
    created_at: datetime,
) -> SQLiteActionApprovalBatchJournalBackupManifest:
    created = _normalize_utc(
        created_at,
        label="Action approval batch journal backup time",
    )
    retain_until = _normalize_utc(
        minimum_retain_until,
        label="Action approval batch journal minimum retention time",
    )
    if retain_until < created:
        raise ActionApprovalBatchError(
            "Action approval batch journal retention ends before backup creation"
        )
    backup_path = Path(os.path.abspath(destination))
    manifest_path = action_approval_batch_journal_backup_manifest_path(backup_path)
    if journal.path in {backup_path, manifest_path}:
        raise ActionApprovalBatchError(
            "Action approval batch journal backup overlaps the live journal"
        )
    _prepare_private_parent(backup_path.parent)
    _require_absent_leaf(backup_path, label="Action approval batch journal backup")
    _require_absent_leaf(
        manifest_path,
        label="Action approval batch journal backup manifest",
    )
    temporary_backup = _private_temporary_path(backup_path)
    temporary_manifest: Path | None = None
    backup_published = False
    try:
        _copy_journal_database(journal.path, temporary_backup)
        verified = SQLiteActionApprovalBatchJournal(
            temporary_backup,
            input_authority=journal._input_authority,
            completion_authority=journal._completion_authority,
            cancellation_authority=journal._cancellation_authority,
            clock=journal._clock,
        )
        publications = verified.publications()
        retention = _retention_assessment(
            publications,
            minimum_retain_until=retain_until,
            evaluated_at=created,
        )
        database = read_bounded_regular_bytes(
            temporary_backup,
            max_bytes=_MAX_JOURNAL_BACKUP_BYTES,
            label="Action approval batch journal backup database",
            require_single_link=True,
        )
        manifest = SQLiteActionApprovalBatchJournalBackupManifest(
            createdAt=created,
            databaseSha256=sha256(database).hexdigest(),
            databaseBytes=len(database),
            retention=retention,
        )
        temporary_manifest = _write_private_temporary(
            manifest_path,
            _journal_backup_manifest_bytes(manifest),
        )
        _publish_exclusive(
            temporary_backup,
            backup_path,
            label="Action approval batch journal backup",
        )
        backup_published = True
        _publish_exclusive(
            temporary_manifest,
            manifest_path,
            label="Action approval batch journal backup manifest",
        )
        temporary_manifest = None
        return manifest
    except (
        ActionApprovalBatchError,
        OSError,
        sqlite3.Error,
        ValidationError,
        ValueError,
    ) as exc:
        if backup_published:
            with suppress(OSError):
                backup_path.unlink()
                _fsync_directory(backup_path.parent)
        if isinstance(exc, ActionApprovalBatchError):
            raise
        raise ActionApprovalBatchError(
            "Action approval batch journal backup creation failed"
        ) from exc
    finally:
        with suppress(FileNotFoundError):
            temporary_backup.unlink()
        if temporary_manifest is not None:
            with suppress(FileNotFoundError):
                temporary_manifest.unlink()


def _restore_journal_backup(
    backup: Path,
    *,
    destination: Path,
    input_authority: ActionApprovalBatchInputAuthority,
    completion_authority: ActionApprovalBatchCompletionAuthority,
    cancellation_authority: ActionApprovalBatchCancellationAuthority,
    clock: Callable[[], datetime] | None,
) -> SQLiteActionApprovalBatchJournal:
    backup_path = Path(os.path.abspath(backup))
    manifest_path = action_approval_batch_journal_backup_manifest_path(backup_path)
    destination_path = Path(os.path.abspath(destination))
    if destination_path in {backup_path, manifest_path}:
        raise ActionApprovalBatchError("Action approval batch journal restore overlaps its backup")
    _prepare_private_parent(destination_path.parent)
    _require_absent_leaf(
        destination_path,
        label="Action approval batch journal restore destination",
    )
    temporary = _private_temporary_path(destination_path)
    published = False
    selected_clock = clock or (lambda: datetime.now(UTC))
    try:
        manifest_raw = read_bounded_regular_bytes(
            manifest_path,
            max_bytes=_MAX_JOURNAL_BACKUP_MANIFEST_BYTES,
            label="Action approval batch journal backup manifest",
            require_single_link=True,
        )
        manifest = _parse_journal_backup_manifest(manifest_raw)
        if manifest_raw != _journal_backup_manifest_bytes(manifest):
            raise ActionApprovalBatchError(
                "Action approval batch journal backup manifest is not canonical bytes"
            )
        database = read_bounded_regular_bytes(
            backup_path,
            max_bytes=_MAX_JOURNAL_BACKUP_BYTES,
            label="Action approval batch journal backup database",
            require_single_link=True,
        )
        if (
            len(database) != manifest.database_bytes
            or sha256(database).hexdigest() != manifest.database_sha256
        ):
            raise ActionApprovalBatchError(
                "Action approval batch journal backup database digest differs"
            )
        _write_existing_private_file(temporary, database)
        verified = SQLiteActionApprovalBatchJournal(
            temporary,
            input_authority=input_authority,
            completion_authority=completion_authority,
            cancellation_authority=cancellation_authority,
            clock=selected_clock,
        )
        observed = _retention_assessment(
            verified.publications(),
            minimum_retain_until=manifest.retention.minimum_retain_until,
            evaluated_at=manifest.created_at,
        )
        if observed != manifest.retention:
            raise ActionApprovalBatchError(
                "Action approval batch journal backup logical state differs"
            )
        _publish_exclusive(
            temporary,
            destination_path,
            label="Action approval batch journal restore destination",
        )
        published = True
        return SQLiteActionApprovalBatchJournal(
            destination_path,
            input_authority=input_authority,
            completion_authority=completion_authority,
            cancellation_authority=cancellation_authority,
            clock=selected_clock,
        )
    except (
        ActionApprovalBatchError,
        OSError,
        sqlite3.Error,
        ValidationError,
        ValueError,
    ) as exc:
        if published:
            with suppress(OSError):
                destination_path.unlink()
                _fsync_directory(destination_path.parent)
        if isinstance(exc, ActionApprovalBatchError):
            raise
        raise ActionApprovalBatchError("Action approval batch journal restore failed") from exc
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _parse_journal_backup_manifest(
    raw: bytes,
) -> SQLiteActionApprovalBatchJournalBackupManifest:
    try:
        parsed = parse_strict_json_bytes(
            raw,
            label="Action approval batch journal backup manifest",
            max_bytes=_MAX_JOURNAL_BACKUP_MANIFEST_BYTES,
            max_depth=16,
            max_nodes=128,
        )
        return SQLiteActionApprovalBatchJournalBackupManifest.model_validate(parsed)
    except (TypeError, ValidationError, ValueError) as exc:
        raise ActionApprovalBatchError(
            "Action approval batch journal backup manifest is invalid"
        ) from exc


def _journal_backup_manifest_bytes(
    manifest: SQLiteActionApprovalBatchJournalBackupManifest,
) -> bytes:
    return (
        canonical_graph_json(
            manifest.model_dump(mode="json", by_alias=True),
            label="SQLiteActionApprovalBatchJournalBackupManifest",
            max_bytes=_MAX_JOURNAL_BACKUP_MANIFEST_BYTES,
        )
        + b"\n"
    )


def _copy_journal_database(source: Path, destination: Path) -> None:
    destination_connection: sqlite3.Connection | None = None
    try:
        with _readonly_connection(source) as source_connection:
            destination_connection = sqlite3.connect(
                destination,
                isolation_level=None,
                timeout=_BUSY_TIMEOUT_MS / 1_000,
            )
            source_connection.backup(destination_connection)
        if destination_connection is not None:
            destination_connection.close()
            destination_connection = None
        if os.name == "posix":
            destination.chmod(0o600)
        _require_safe_path(destination)
        _require_safe_sidecars(destination)
    finally:
        if destination_connection is not None:
            destination_connection.close()


def _prepare_private_parent(parent: Path) -> None:
    probe = parent / ".approval-batch-path-probe"
    _require_safe_path(probe)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        parent.chmod(0o700)
    _require_safe_path(probe)


def _require_absent_leaf(path: Path, *, label: str) -> None:
    _require_safe_path(path)
    if path.exists() or path.is_symlink():
        raise ActionApprovalBatchError(f"{label} already exists")


def _private_temporary_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.close(descriptor)
    if os.name == "posix":
        Path(name).chmod(0o600)
    return Path(name)


def _write_private_temporary(destination: Path, content: bytes) -> Path:
    temporary = _private_temporary_path(destination)
    try:
        _write_existing_private_file(temporary, content)
        return temporary
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _write_existing_private_file(path: Path, content: bytes) -> None:
    _require_safe_path(path)
    with path.open("wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name == "posix":
        path.chmod(0o600)


def _publish_exclusive(source: Path, destination: Path, *, label: str) -> None:
    _require_absent_leaf(destination, label=label)
    try:
        os.link(source, destination)
    except FileExistsError as exc:
        raise ActionApprovalBatchError(f"{label} already exists") from exc
    except OSError as exc:
        raise ActionApprovalBatchError(f"{label} publication failed") from exc
    try:
        source.unlink()
    except OSError as exc:
        with suppress(OSError):
            destination.unlink()
        raise ActionApprovalBatchError(f"{label} publication finalization failed") from exc
    _fsync_directory(destination.parent)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _initialize(path: Path) -> None:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.parent.chmod(0o700)
    existing_size = path.stat().st_size if path.exists() else 0
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            path,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("BEGIN IMMEDIATE")
        tables = _application_tables(connection)
        if not tables:
            if existing_size != 0:
                raise ActionApprovalBatchError(
                    "Existing Action approval batch journal has no trusted schema"
                )
            mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise ActionApprovalBatchError(
                    "Action approval batch journal requires DELETE journal mode"
                )
            for statement in _SCHEMA_OBJECT_SQL.values():
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO action_approval_batch_metadata(key, value) VALUES (?, ?)",
                (
                    ("schema_version", str(_SCHEMA_VERSION)),
                    ("schema_digest", _SCHEMA_DIGEST),
                ),
            )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
        _validate_schema(connection)
        connection.execute("COMMIT")
        if os.name == "posix":
            path.chmod(0o600)
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        if connection is not None:
            connection.close()
    _require_safe_path(path)
    _require_safe_sidecars(path)


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    identity = _file_identity(path)
    connection = _open_connection(path, readonly=False)
    if _file_identity(path) != identity:
        connection.close()
        raise ActionApprovalBatchError("Action approval batch journal changed while opening")
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
        _require_safe_path(path)
        _require_safe_sidecars(path)


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    identity = _file_identity(path)
    connection = _open_connection(path, readonly=True)
    if _file_identity(path) != identity:
        connection.close()
        raise ActionApprovalBatchError("Action approval batch journal changed while opening")
    try:
        connection.execute("BEGIN")
        yield connection
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
        _require_safe_path(path)
        _require_safe_sidecars(path)


def _open_connection(path: Path, *, readonly: bool) -> sqlite3.Connection:
    target: str | Path = f"{path.as_uri()}?mode=ro" if readonly else path
    connection = sqlite3.connect(
        target,
        uri=readonly,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    if readonly:
        connection.execute("PRAGMA query_only = ON")
    else:
        connection.execute("PRAGMA synchronous = FULL")
    return connection


def _validate_schema(connection: sqlite3.Connection) -> None:
    if _application_tables(connection) != _TABLES:
        raise ActionApprovalBatchError("Action approval batch journal table set differs")
    metadata = {
        str(row["key"]): str(row["value"])
        for row in connection.execute(
            "SELECT key, value FROM action_approval_batch_metadata ORDER BY key"
        ).fetchall()
    }
    user_version = connection.execute("PRAGMA user_version").fetchone()
    application_id = connection.execute("PRAGMA application_id").fetchone()
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
    if (
        metadata != {"schema_digest": _SCHEMA_DIGEST, "schema_version": str(_SCHEMA_VERSION)}
        or user_version is None
        or user_version[0] != _SCHEMA_VERSION
        or application_id is None
        or application_id[0] != _APPLICATION_ID
        or journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
        or foreign_keys is None
        or foreign_keys[0] != 1
        or trusted_schema is None
        or trusted_schema[0] != 0
    ):
        raise ActionApprovalBatchError("Action approval batch journal metadata differs")
    placeholders = ", ".join("?" for _ in _TABLES)
    rows = connection.execute(
        f"""
        SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL AND type IN ('table', 'index', 'trigger')
          AND (name IN ({placeholders}) OR tbl_name IN ({placeholders}))
        """,
        (*sorted(_TABLES), *sorted(_TABLES)),
    ).fetchall()
    actual = {
        (str(row["type"]), str(row["name"])): _normalize_schema_sql(str(row["sql"])) for row in rows
    }
    expected = {key: _normalize_schema_sql(value) for key, value in _SCHEMA_OBJECT_SQL.items()}
    if actual != expected:
        raise ActionApprovalBatchError("Action approval batch journal schema differs")
    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if len(quick_check) != 1 or quick_check[0][0] != "ok":
        raise ActionApprovalBatchError("Action approval batch journal integrity check failed")


def _application_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }


def _require_safe_path(path: Path) -> None:
    parent = path.parent
    for ancestor in (parent, *parent.parents):
        if ancestor.exists() and (
            ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction())
        ):
            raise ActionApprovalBatchError("Action approval batch journal ancestor is unsafe")
    if parent.exists() and not parent.is_dir():
        raise ActionApprovalBatchError("Action approval batch journal parent is unsafe")
    if path.exists() or path.is_symlink():
        file_stat = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or path.is_symlink()
            or (hasattr(path, "is_junction") and path.is_junction())
            or file_stat.st_nlink != 1
        ):
            raise ActionApprovalBatchError(
                "Action approval batch journal is not a single-link regular file"
            )


def _require_safe_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not (sidecar.exists() or sidecar.is_symlink()):
            continue
        file_stat = sidecar.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or sidecar.is_symlink()
            or (hasattr(sidecar, "is_junction") and sidecar.is_junction())
            or file_stat.st_nlink != 1
        ):
            raise ActionApprovalBatchError("Action approval batch journal sidecar is unsafe")


def _file_identity(path: Path) -> tuple[tuple[int, int], tuple[int, int]]:
    parent_stat = path.parent.stat()
    file_stat = path.stat()
    return (
        (int(parent_stat.st_dev), int(parent_stat.st_ino)),
        (int(file_stat.st_dev), int(file_stat.st_ino)),
    )


def _required_text(row: sqlite3.Row, field: str) -> str:
    value = row[field]
    if type(value) is not str or not value:
        raise ActionApprovalBatchError(f"Action approval batch {field} is invalid")
    return value


def _optional_text(row: sqlite3.Row, field: str) -> str | None:
    value = row[field]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise ActionApprovalBatchError(f"Action approval batch {field} is invalid")
    return value


def _required_int(row: sqlite3.Row, field: str) -> int:
    value = row[field]
    if type(value) is not int:
        raise ActionApprovalBatchError(f"Action approval batch {field} is invalid")
    return value


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if type(value) is not bytes or not value:
        raise ActionApprovalBatchError(f"Action approval batch {field} is invalid")
    return value


def _optional_bytes(row: sqlite3.Row, field: str) -> bytes | None:
    value = row[field]
    if value is None:
        return None
    if type(value) is not bytes or not value:
        raise ActionApprovalBatchError(f"Action approval batch {field} is invalid")
    return value


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _parse_timestamp(value: str) -> datetime:
    try:
        return _normalize_utc(datetime.fromisoformat(value), label="Batch event time")
    except ValueError as exc:
        raise ActionApprovalBatchError("Action approval batch event time is invalid") from exc


def _is_async_callable(value: Any) -> bool:
    return iscoroutinefunction(value) or (callable(value) and iscoroutinefunction(value.__call__))
