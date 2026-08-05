"""Pre-reserved, consumed-on-issuance CleanupPermit authority contracts."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from re import fullmatch
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.authority import (
    ActionBudgetReservation,
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    ActionPermit,
    ActionPermitAuthorization,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
    validate_action_authority,
)
from pajin.graph.consistency import GraphDecision
from pajin.graph.models import canonical_graph_json, graph_digest
from pajin.graph.projection import GraphSnapshotRef

ACTION_CLEANUP_RESERVATION_REQUEST_API_VERSION: Literal[
    "pajin.dev/action-cleanup-reservation-request/v1alpha1"
] = "pajin.dev/action-cleanup-reservation-request/v1alpha1"
ACTION_CLEANUP_RESERVATION_API_VERSION: Literal[
    "pajin.dev/action-cleanup-reservation/v1alpha1"
] = "pajin.dev/action-cleanup-reservation/v1alpha1"
CLEANUP_REQUEST_API_VERSION: Literal["pajin.dev/cleanup-request/v1alpha1"] = (
    "pajin.dev/cleanup-request/v1alpha1"
)
CLEANUP_PERMIT_API_VERSION: Literal["pajin.dev/cleanup-permit/v1alpha1"] = (
    "pajin.dev/cleanup-permit/v1alpha1"
)

_MAX_CLEANUP_AUTHORITY_BYTES = 512 * 1024
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_PortableIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
]
_CampaignIdentifier = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]

_RESERVATION_REQUEST_ID_PATTERN = r"^cleanup-reservation-request_[a-f0-9]{64}$"
_RESERVATION_ID_PATTERN = r"^action-cleanup-reservation_[a-f0-9]{64}$"
_ACTION_PERMIT_ID_PATTERN = r"^action-permit_[a-f0-9]{64}$"
_ACTION_DISPATCH_ID_PATTERN = r"^action-dispatch_[a-f0-9]{64}$"
_MISSION_ENVELOPE_ID_PATTERN = r"^mission-envelope_[a-f0-9]{64}$"
_ACTION_PROPOSAL_ID_PATTERN = r"^action-proposal_[a-f0-9]{64}$"
_CLEANUP_REQUEST_ID_PATTERN = r"^cleanup-request_[a-f0-9]{64}$"
_CLEANUP_PERMIT_ID_PATTERN = r"^cleanup-permit_[a-f0-9]{64}$"
_CLEANUP_DISPATCH_ID_PATTERN = r"^cleanup-dispatch_[a-f0-9]{64}$"


class CleanupPermitError(RuntimeError):
    """Raised when cleanup authority cannot be established safely."""


class CleanupPermitConflict(CleanupPermitError):
    """Raised when a cleanup identity or exact retry equivocates."""


class CleanupPermitStaleDecision(CleanupPermitError):
    """Raised when the cleanup decision no longer names the latest Graph state."""


class CleanupPermitBudgetExceeded(CleanupPermitError):
    """Raised when an Action plus cleanup hold would exceed its Envelope."""


class ActionCleanupReservationRequest(StrictModel):
    """Non-executable cleanup capacity requested before a reversible Action."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/action-cleanup-reservation-request/v1alpha1"
    ] = Field(
        default=ACTION_CLEANUP_RESERVATION_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionCleanupReservationRequest"] = "ActionCleanupReservationRequest"
    executable: Literal[False] = False
    reservation_request_id: str = Field(
        default="",
        alias="reservationRequestId",
        max_length=92,
    )
    reservation_request_digest: str = Field(
        default="",
        alias="reservationRequestDigest",
        max_length=64,
    )
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    envelope_id: str = Field(alias="envelopeId", pattern=_MISSION_ENVELOPE_ID_PATTERN)
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    source_action_proposal_id: str = Field(
        alias="sourceActionProposalId",
        pattern=_ACTION_PROPOSAL_ID_PATTERN,
    )
    source_action_proposal_digest: _Sha256 = Field(alias="sourceActionProposalDigest")
    cleanup_capability: ActionCapabilityRef = Field(alias="cleanupCapability")
    target_digest: _Sha256 = Field(alias="targetDigest")
    cleanup_handler_id: _Identifier = Field(alias="cleanupHandlerId")
    cleanup_handler_version: _Identifier = Field(alias="cleanupHandlerVersion")
    cleanup_handler_digest: _Sha256 = Field(alias="cleanupHandlerDigest")
    cleanup_executor_id: _Identifier = Field(alias="cleanupExecutorId")
    cleanup_executor_version: _Identifier = Field(alias="cleanupExecutorVersion")
    cleanup_executor_digest: _Sha256 = Field(alias="cleanupExecutorDigest")
    reservation: ActionBudgetReservation
    created_at: datetime = Field(alias="createdAt")
    claim_expires_at: datetime = Field(alias="claimExpiresAt")

    @field_validator("created_at", "claim_expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="cleanup reservation request time")

    @field_validator("executable", mode="before")
    @classmethod
    def require_non_executable(cls, value: object) -> object:
        if type(value) is not bool or value:
            raise ValueError("cleanup reservation request must be literal non-executable")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if not self.created_at < self.claim_expires_at:
            raise ValueError("cleanup reservation request window is invalid")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reservation_request_id", "reservation_request_digest"},
        )
        digest = graph_digest(
            "pajin.cleanup.reservation-request/v1",
            material,
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        request_id = f"cleanup-reservation-request_{digest}"
        if self.reservation_request_digest and self.reservation_request_digest != digest:
            raise ValueError("cleanup reservation request digest differs")
        if self.reservation_request_id and self.reservation_request_id != request_id:
            raise ValueError("cleanup reservation request ID differs")
        object.__setattr__(self, "reservation_request_digest", digest)
        object.__setattr__(self, "reservation_request_id", request_id)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ActionCleanupReservationRequest",
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        return self


class ActionCleanupReservation(StrictModel):
    """Durable cleanup capacity held atomically with one ActionPermit."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-cleanup-reservation/v1alpha1"] = Field(
        default=ACTION_CLEANUP_RESERVATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionCleanupReservation"] = "ActionCleanupReservation"
    cleanup_reservation_id: str = Field(
        default="",
        alias="cleanupReservationId",
        max_length=91,
    )
    cleanup_reservation_digest: str = Field(
        default="",
        alias="cleanupReservationDigest",
        max_length=64,
    )
    status: Literal["reserved"] = "reserved"
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    compiler_id: _Identifier = Field(alias="compilerId")
    compiler_version: _Identifier = Field(alias="compilerVersion")
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    envelope_id: str = Field(alias="envelopeId", pattern=_MISSION_ENVELOPE_ID_PATTERN)
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    reservation_request_id: str = Field(
        alias="reservationRequestId",
        pattern=_RESERVATION_REQUEST_ID_PATTERN,
    )
    reservation_request_digest: _Sha256 = Field(alias="reservationRequestDigest")
    source_action_permit_id: str = Field(
        alias="sourceActionPermitId",
        pattern=_ACTION_PERMIT_ID_PATTERN,
    )
    source_action_permit_digest: _Sha256 = Field(alias="sourceActionPermitDigest")
    source_action_dispatch_id: str = Field(
        alias="sourceActionDispatchId",
        pattern=_ACTION_DISPATCH_ID_PATTERN,
    )
    cleanup_capability: ActionCapabilityRef = Field(alias="cleanupCapability")
    target_digest: _Sha256 = Field(alias="targetDigest")
    cleanup_handler_id: _Identifier = Field(alias="cleanupHandlerId")
    cleanup_handler_version: _Identifier = Field(alias="cleanupHandlerVersion")
    cleanup_handler_digest: _Sha256 = Field(alias="cleanupHandlerDigest")
    cleanup_executor_id: _Identifier = Field(alias="cleanupExecutorId")
    cleanup_executor_version: _Identifier = Field(alias="cleanupExecutorVersion")
    cleanup_executor_digest: _Sha256 = Field(alias="cleanupExecutorDigest")
    reservation: ActionBudgetReservation
    reserved_at: datetime = Field(alias="reservedAt")
    claim_expires_at: datetime = Field(alias="claimExpiresAt")

    @field_validator("reserved_at", "claim_expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="action cleanup reservation time")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if not self.reserved_at < self.claim_expires_at:
            raise ValueError("action cleanup reservation window is invalid")
        stable_material = {
            "campaignId": self.campaign_id,
            "runId": self.run_id,
            "compilerId": self.compiler_id,
            "compilerVersion": self.compiler_version,
            "compilerDigest": self.compiler_digest,
            "envelopeId": self.envelope_id,
            "envelopeDigest": self.envelope_digest,
            "reservationRequestId": self.reservation_request_id,
            "reservationRequestDigest": self.reservation_request_digest,
            "sourceActionPermitId": self.source_action_permit_id,
            "sourceActionPermitDigest": self.source_action_permit_digest,
        }
        identity = graph_digest(
            "pajin.cleanup.action-reservation-id/v1",
            stable_material,
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        reservation_id = f"action-cleanup-reservation_{identity}"
        if self.cleanup_reservation_id and self.cleanup_reservation_id != reservation_id:
            raise ValueError("action cleanup reservation ID differs")
        object.__setattr__(self, "cleanup_reservation_id", reservation_id)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"cleanup_reservation_digest"},
        )
        digest = graph_digest(
            "pajin.cleanup.action-reservation/v1",
            material,
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        if self.cleanup_reservation_digest and self.cleanup_reservation_digest != digest:
            raise ValueError("action cleanup reservation digest differs")
        object.__setattr__(self, "cleanup_reservation_digest", digest)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ActionCleanupReservation",
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        return self


class CleanupRequest(StrictModel):
    """Content-addressed caller proposal requiring an external input authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cleanup-request/v1alpha1"] = Field(
        default=CLEANUP_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CleanupRequest"] = "CleanupRequest"
    cleanup_request_id: str = Field(
        default="",
        alias="cleanupRequestId",
        max_length=80,
    )
    cleanup_request_digest: str = Field(
        default="",
        alias="cleanupRequestDigest",
        max_length=64,
    )
    executable: Literal[False] = False
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    original_action_permit_reusable: Literal[False] = Field(
        default=False,
        alias="originalActionPermitReusable",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    redispatch_allowed: Literal[False] = Field(default=False, alias="redispatchAllowed")
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    envelope_id: str = Field(alias="envelopeId", pattern=_MISSION_ENVELOPE_ID_PATTERN)
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    cleanup_reservation_id: str = Field(
        alias="cleanupReservationId",
        pattern=_RESERVATION_ID_PATTERN,
    )
    cleanup_reservation_digest: _Sha256 = Field(alias="cleanupReservationDigest")
    source_action_permit_id: str = Field(
        alias="sourceActionPermitId",
        pattern=_ACTION_PERMIT_ID_PATTERN,
    )
    source_action_permit_digest: _Sha256 = Field(alias="sourceActionPermitDigest")
    source_action_dispatch_id: str = Field(
        alias="sourceActionDispatchId",
        pattern=_ACTION_DISPATCH_ID_PATTERN,
    )
    source_outcome_id: _Identifier = Field(alias="sourceOutcomeId")
    source_outcome_digest: _Sha256 = Field(alias="sourceOutcomeDigest")
    source_run_root_digest: _Sha256 = Field(alias="sourceRunRootDigest")
    source_terminal_event_digest: _Sha256 = Field(alias="sourceTerminalEventDigest")
    source_gateway_outcome_digest: _Sha256 = Field(alias="sourceGatewayOutcomeDigest")
    source_worker_execution_id: _Identifier = Field(alias="sourceWorkerExecutionId")
    decision_id: _Identifier = Field(alias="decisionId")
    decision_digest: _Sha256 = Field(alias="decisionDigest")
    snapshot: GraphSnapshotRef
    cleanup_handler_id: _Identifier = Field(alias="cleanupHandlerId")
    cleanup_handler_version: _Identifier = Field(alias="cleanupHandlerVersion")
    cleanup_handler_digest: _Sha256 = Field(alias="cleanupHandlerDigest")
    cleanup_executor_id: _Identifier = Field(alias="cleanupExecutorId")
    cleanup_executor_version: _Identifier = Field(alias="cleanupExecutorVersion")
    cleanup_executor_digest: _Sha256 = Field(alias="cleanupExecutorDigest")
    cleanup_plan_digest: _Sha256 = Field(alias="cleanupPlanDigest")
    capability: ActionCapabilityRef
    target_digest: _Sha256 = Field(alias="targetDigest")
    request_id: _PortableIdentifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    reservation: ActionBudgetReservation
    created_at: datetime = Field(alias="createdAt")

    @field_validator("created_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="cleanup request time")

    @field_validator(
        "executable",
        "permit_granted",
        "original_action_permit_reusable",
        "scope_expansion_authorized",
        "redispatch_allowed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value:
            raise ValueError("CleanupRequest authority flags must be literal false")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.snapshot.campaign_id != self.campaign_id:
            raise ValueError("CleanupRequest Snapshot belongs to another Campaign")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"cleanup_request_id", "cleanup_request_digest"},
        )
        digest = graph_digest(
            "pajin.cleanup.request/v1",
            material,
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        request_id = f"cleanup-request_{digest}"
        if self.cleanup_request_digest and self.cleanup_request_digest != digest:
            raise ValueError("CleanupRequest digest differs")
        if self.cleanup_request_id and self.cleanup_request_id != request_id:
            raise ValueError("CleanupRequest ID differs")
        object.__setattr__(self, "cleanup_request_digest", digest)
        object.__setattr__(self, "cleanup_request_id", request_id)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="CleanupRequest",
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        return self


class CleanupPermit(StrictModel):
    """Consumed-on-issuance, non-bearer proof for one cleanup dispatch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cleanup-permit/v1alpha1"] = Field(
        default=CLEANUP_PERMIT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CleanupPermit"] = "CleanupPermit"
    cleanup_permit_id: str = Field(
        default="",
        alias="cleanupPermitId",
        max_length=79,
    )
    cleanup_permit_digest: str = Field(
        default="",
        alias="cleanupPermitDigest",
        max_length=64,
    )
    cleanup_dispatch_id: str = Field(
        default="",
        alias="cleanupDispatchId",
        max_length=81,
    )
    status: Literal["consumed"] = "consumed"
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    compiler_id: _Identifier = Field(alias="compilerId")
    compiler_version: _Identifier = Field(alias="compilerVersion")
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    envelope_id: str = Field(alias="envelopeId", pattern=_MISSION_ENVELOPE_ID_PATTERN)
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    cleanup_reservation_id: str = Field(
        alias="cleanupReservationId",
        pattern=_RESERVATION_ID_PATTERN,
    )
    cleanup_reservation_digest: _Sha256 = Field(alias="cleanupReservationDigest")
    cleanup_request_id: str = Field(
        alias="cleanupRequestId",
        pattern=_CLEANUP_REQUEST_ID_PATTERN,
    )
    cleanup_request_digest: _Sha256 = Field(alias="cleanupRequestDigest")
    source_action_permit_id: str = Field(
        alias="sourceActionPermitId",
        pattern=_ACTION_PERMIT_ID_PATTERN,
    )
    source_action_permit_digest: _Sha256 = Field(alias="sourceActionPermitDigest")
    source_action_dispatch_id: str = Field(
        alias="sourceActionDispatchId",
        pattern=_ACTION_DISPATCH_ID_PATTERN,
    )
    source_outcome_id: _Identifier = Field(alias="sourceOutcomeId")
    source_outcome_digest: _Sha256 = Field(alias="sourceOutcomeDigest")
    source_run_root_digest: _Sha256 = Field(alias="sourceRunRootDigest")
    source_terminal_event_digest: _Sha256 = Field(alias="sourceTerminalEventDigest")
    source_gateway_outcome_digest: _Sha256 = Field(alias="sourceGatewayOutcomeDigest")
    decision_id: _Identifier = Field(alias="decisionId")
    decision_digest: _Sha256 = Field(alias="decisionDigest")
    snapshot: GraphSnapshotRef
    cleanup_handler_digest: _Sha256 = Field(alias="cleanupHandlerDigest")
    cleanup_executor_digest: _Sha256 = Field(alias="cleanupExecutorDigest")
    cleanup_plan_digest: _Sha256 = Field(alias="cleanupPlanDigest")
    capability: ActionCapabilityRef
    target_digest: _Sha256 = Field(alias="targetDigest")
    request_id: _PortableIdentifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    reservation: ActionBudgetReservation
    issued_at: datetime = Field(alias="issuedAt")
    consumed_at: datetime = Field(alias="consumedAt")
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("issued_at", "consumed_at", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="CleanupPermit time")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.snapshot.campaign_id != self.campaign_id:
            raise ValueError("CleanupPermit Snapshot belongs to another Campaign")
        if not self.issued_at <= self.consumed_at < self.expires_at:
            raise ValueError("CleanupPermit issuance, consumption, or expiry is invalid")
        stable_material = {
            "campaignId": self.campaign_id,
            "runId": self.run_id,
            "compilerId": self.compiler_id,
            "compilerVersion": self.compiler_version,
            "compilerDigest": self.compiler_digest,
            "envelopeId": self.envelope_id,
            "envelopeDigest": self.envelope_digest,
            "cleanupReservationId": self.cleanup_reservation_id,
            "cleanupReservationDigest": self.cleanup_reservation_digest,
            "cleanupRequestId": self.cleanup_request_id,
            "cleanupRequestDigest": self.cleanup_request_digest,
            "sourceActionPermitId": self.source_action_permit_id,
            "sourceActionPermitDigest": self.source_action_permit_digest,
            "decisionId": self.decision_id,
            "decisionDigest": self.decision_digest,
            "snapshot": self.snapshot.model_dump(mode="json", by_alias=True),
            "requestId": self.request_id,
            "requestDigest": self.request_digest,
        }
        identity = graph_digest(
            "pajin.cleanup.permit-id/v1",
            stable_material,
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        permit_id = f"cleanup-permit_{identity}"
        dispatch_id = "cleanup-dispatch_" + graph_digest(
            "pajin.cleanup.dispatch-id/v1",
            {"cleanupPermitId": permit_id, "requestId": self.request_id},
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        if self.cleanup_permit_id and self.cleanup_permit_id != permit_id:
            raise ValueError("CleanupPermit ID differs")
        if self.cleanup_dispatch_id and self.cleanup_dispatch_id != dispatch_id:
            raise ValueError("CleanupPermit dispatch ID differs")
        object.__setattr__(self, "cleanup_permit_id", permit_id)
        object.__setattr__(self, "cleanup_dispatch_id", dispatch_id)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"cleanup_permit_digest"},
        )
        digest = graph_digest(
            "pajin.cleanup.permit/v1",
            material,
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        if self.cleanup_permit_digest and self.cleanup_permit_digest != digest:
            raise ValueError("CleanupPermit digest differs")
        object.__setattr__(self, "cleanup_permit_digest", digest)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="CleanupPermit",
            max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
        )
        return self


class ReversibleActionPermitAuthorization(StrictModel):
    """Atomic ActionPermit plus mandatory cleanup capacity result."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    action: ActionPermitAuthorization
    cleanup_reservation: ActionCleanupReservation = Field(alias="cleanupReservation")


class CleanupPermitAuthorization(StrictModel):
    """Result of one final cleanup authority transaction."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    permit: CleanupPermit
    newly_consumed: bool = Field(alias="newlyConsumed")


class GraphReversibleActionPermitStore(Protocol):
    """Storage-neutral atomic ActionPermit plus cleanup-hold transaction."""

    def claim_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
    ) -> object: ...

    def authorize_reversible_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        action_capability: RegisteredActionCapability,
        cleanup_request: ActionCleanupReservationRequest,
        cleanup_capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ReversibleActionPermitAuthorization: ...


class GraphCleanupPermitStore(Protocol):
    """Storage-neutral one-shot cleanup authority transaction."""

    def claim_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
    ) -> object: ...

    def authorize_cleanup_for_dispatch(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> CleanupPermitAuthorization: ...

    def cleanup_reservation(self, reservation_id: str) -> ActionCleanupReservation | None: ...

    def cleanup_reservations(self) -> tuple[ActionCleanupReservation, ...]: ...

    def cleanup_permit(self, permit_id: str) -> CleanupPermit | None: ...

    def cleanup_permits(self) -> tuple[CleanupPermit, ...]: ...


class ReversibleActionPermitInputAuthority(Protocol):
    """Authenticate reversible-write semantics before an Action plus hold claim.

    A production implementation must exact-rebuild the current signed Definition and code-owned
    source-to-cleanup mapping and require `reversible-write` plus `cleanupRequired=true`.
    """

    def verify_reversible_action(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> None: ...


class CleanupPermitInputAuthority(Protocol):
    """Authenticate sealed source outcome and current cleanup plan before claim.

    A production implementation must exact-rebuild managed Run evidence and the current Handler,
    Executor, Capability, Tool request, target, price, and pre-action hold bindings.
    """

    def verify_cleanup_request(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
    ) -> None: ...


class GraphReversibleActionPermitAuthority:
    """Atomically consume an ActionPermit and hold its cleanup capacity."""

    def __init__(
        self,
        *,
        campaign_id: str,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        capabilities: ActionCapabilityRegistry,
        permit_store: GraphReversibleActionPermitStore,
        input_authority: ReversibleActionPermitInputAuthority,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("reversible ActionPermit authority Campaign ID is invalid")
        _require_compiler_identity(compiler_id, compiler_version, compiler_digest)
        _require_permit_ttl(permit_ttl)
        self._campaign_id = campaign_id
        self._compiler_identity = (compiler_id, compiler_version, compiler_digest)
        self._capabilities = capabilities
        self._permit_store = permit_store
        self._input_authority = input_authority
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl
        self._writer = permit_store.claim_writer(*self._compiler_identity)

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> ReversibleActionPermitAuthorization:
        envelope = _canonical(MissionEnvelope, envelope, label="MissionEnvelope")
        proposal = _canonical(ActionProposal, proposal, label="ActionProposal")
        decision = _canonical(GraphDecision, decision, label="GraphDecision")
        cleanup_request = _canonical(
            ActionCleanupReservationRequest,
            cleanup_request,
            label="ActionCleanupReservationRequest",
        )
        if (
            envelope.campaign_id != self._campaign_id
            or proposal.campaign_id != self._campaign_id
            or decision.campaign_id != self._campaign_id
            or cleanup_request.campaign_id != self._campaign_id
        ):
            raise CleanupPermitError("reversible Action input belongs to another Campaign")
        if self._compiler_identity != (
            envelope.compiler_id,
            envelope.compiler_version,
            envelope.compiler_digest,
        ):
            raise CleanupPermitError("MissionEnvelope compiler identity differs")
        action_capability = self._capabilities.resolve(proposal.capability)
        cleanup_capability = self._capabilities.resolve(cleanup_request.cleanup_capability)
        evaluated_at = _normalize_utc(
            self._clock(),
            label="reversible ActionPermit evaluation time",
        )
        self._verify_input(envelope, proposal, decision, cleanup_request)
        authorization = self._permit_store.authorize_reversible_for_dispatch(
            envelope,
            proposal,
            decision,
            action_capability,
            cleanup_request,
            cleanup_capability,
            writer=self._writer,
            evaluated_at=evaluated_at,
            permit_ttl=self._permit_ttl,
        )
        self._verify_input(envelope, proposal, decision, cleanup_request)
        return authorization

    def _verify_input(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> None:
        try:
            self._input_authority.verify_reversible_action(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                cleanup_request.model_copy(deep=True),
            )
        except CleanupPermitError:
            raise
        except Exception as exc:
            raise CleanupPermitError(
                "reversible Action input authority rejected the claim"
            ) from exc


class GraphCleanupPermitAuthority:
    """Consume a hold only after the required external input-authority verification."""

    def __init__(
        self,
        *,
        campaign_id: str,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        capabilities: ActionCapabilityRegistry,
        permit_store: GraphCleanupPermitStore,
        input_authority: CleanupPermitInputAuthority,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("CleanupPermit authority Campaign ID is invalid")
        _require_compiler_identity(compiler_id, compiler_version, compiler_digest)
        _require_permit_ttl(permit_ttl)
        self._campaign_id = campaign_id
        self._compiler_identity = (compiler_id, compiler_version, compiler_digest)
        self._capabilities = capabilities
        self._permit_store = permit_store
        self._input_authority = input_authority
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl
        self._writer = permit_store.claim_writer(*self._compiler_identity)

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
    ) -> CleanupPermitAuthorization:
        envelope = _canonical(MissionEnvelope, envelope, label="MissionEnvelope")
        request = _canonical(CleanupRequest, request, label="CleanupRequest")
        decision = _canonical(GraphDecision, decision, label="GraphDecision")
        if (
            envelope.campaign_id != self._campaign_id
            or request.campaign_id != self._campaign_id
            or decision.campaign_id != self._campaign_id
        ):
            raise CleanupPermitError("CleanupPermit input belongs to another Campaign")
        if self._compiler_identity != (
            envelope.compiler_id,
            envelope.compiler_version,
            envelope.compiler_digest,
        ):
            raise CleanupPermitError("MissionEnvelope compiler identity differs")
        capability = self._capabilities.resolve(request.capability)
        evaluated_at = _normalize_utc(
            self._clock(),
            label="CleanupPermit evaluation time",
        )
        self._verify_input(envelope, request, decision)
        authorization = self._permit_store.authorize_cleanup_for_dispatch(
            envelope,
            request,
            decision,
            capability,
            writer=self._writer,
            evaluated_at=evaluated_at,
            permit_ttl=self._permit_ttl,
        )
        self._verify_input(envelope, request, decision)
        return authorization

    def _verify_input(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
    ) -> None:
        try:
            self._input_authority.verify_cleanup_request(
                envelope.model_copy(deep=True),
                request.model_copy(deep=True),
                decision.model_copy(deep=True),
            )
        except CleanupPermitError:
            raise
        except Exception as exc:
            raise CleanupPermitError("cleanup input authority rejected the claim") from exc


@dataclass(frozen=True)
class ReversibleActionDispatchResult[DispatchResultT]:
    """Observation of one reserved reversible Action dispatch attempt."""

    authorization: ReversibleActionPermitAuthorization
    dispatched: bool
    result: DispatchResultT | None = None


class GraphReversibleActionPermitDispatcher:
    """Invoke a reversible Action only after its cleanup capacity is durable."""

    def __init__(self, authority: GraphReversibleActionPermitAuthority) -> None:
        self._authority = authority

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
        dispatch: Callable[[ActionPermit], Awaitable[DispatchResultT]],
    ) -> ReversibleActionDispatchResult[DispatchResultT]:
        authorization = self._authority.authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            cleanup_request,
        )
        if not authorization.action.newly_consumed:
            return ReversibleActionDispatchResult(
                authorization=authorization,
                dispatched=False,
            )
        result = await dispatch(authorization.action.permit)
        return ReversibleActionDispatchResult(
            authorization=authorization,
            dispatched=True,
            result=result,
        )


@dataclass(frozen=True)
class CleanupDispatchResult[DispatchResultT]:
    """Observation of one one-shot cleanup dispatch attempt."""

    permit: CleanupPermit
    dispatched: bool
    result: DispatchResultT | None = None


class GraphCleanupPermitDispatcher:
    """Invoke cleanup only for the first durable CleanupPermit consumption."""

    def __init__(self, authority: GraphCleanupPermitAuthority) -> None:
        self._authority = authority

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
        dispatch: Callable[[CleanupPermit], Awaitable[DispatchResultT]],
    ) -> CleanupDispatchResult[DispatchResultT]:
        authorization = self._authority.authorize_for_dispatch(
            envelope,
            request,
            decision,
        )
        if not authorization.newly_consumed:
            return CleanupDispatchResult(
                permit=authorization.permit,
                dispatched=False,
            )
        result = await dispatch(authorization.permit)
        return CleanupDispatchResult(
            permit=authorization.permit,
            dispatched=True,
            result=result,
        )


def validate_action_cleanup_reservation_authority(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    action_capability: RegisteredActionCapability,
    request: ActionCleanupReservationRequest,
    cleanup_capability: RegisteredActionCapability,
    *,
    evaluated_at: datetime,
) -> None:
    """Validate a reversible Action and its pre-dispatch cleanup hold."""

    validate_action_authority(
        envelope,
        proposal,
        decision,
        action_capability,
        evaluated_at=evaluated_at,
    )
    if (
        request.campaign_id != envelope.campaign_id
        or request.run_id != envelope.run_id
        or request.envelope_id != envelope.envelope_id
        or request.envelope_digest != envelope.envelope_digest
    ):
        raise CleanupPermitError("cleanup reservation lineage differs from the Action")
    if (
        request.source_action_proposal_id != proposal.proposal_id
        or request.source_action_proposal_digest != proposal.proposal_digest
    ):
        raise CleanupPermitError("cleanup reservation binds another ActionProposal")
    if request.cleanup_capability != cleanup_capability.reference():
        raise CleanupPermitError("cleanup reservation Capability binding differs")
    if request.cleanup_capability not in envelope.allowed_capabilities:
        raise CleanupPermitError("cleanup Capability is outside the MissionEnvelope")
    if request.cleanup_capability == proposal.capability:
        raise CleanupPermitError("cleanup requires a distinct registered Capability")
    if request.cleanup_capability.risk_tier > envelope.max_risk_tier:
        raise CleanupPermitError("cleanup risk exceeds the MissionEnvelope")
    if request.target_digest != proposal.target_digest:
        raise CleanupPermitError("cleanup target differs from the source Action")
    if request.target_digest not in envelope.allowed_target_digests:
        raise CleanupPermitError("cleanup target is outside the MissionEnvelope")
    if (
        request.created_at < envelope.not_before
        or request.created_at > evaluated_at
        or evaluated_at >= request.claim_expires_at
        or request.claim_expires_at > envelope.expires_at
    ):
        raise CleanupPermitError("cleanup reservation is outside its authority timeline")
    if (
        request.reservation.tool_calls > envelope.budget.tool_call_limit
        or request.reservation.request_units > envelope.budget.request_unit_limit
        or request.reservation.cost_microusd > envelope.budget.cost_limit_microusd
    ):
        raise CleanupPermitBudgetExceeded(
            "cleanup reservation exceeds the MissionEnvelope"
        )


def build_action_cleanup_reservation(
    envelope: MissionEnvelope,
    action_permit: ActionPermit,
    request: ActionCleanupReservationRequest,
    *,
    evaluated_at: datetime,
) -> ActionCleanupReservation:
    """Build the cleanup hold committed atomically with an ActionPermit."""

    return ActionCleanupReservation(
        campaignId=envelope.campaign_id,
        runId=envelope.run_id,
        compilerId=envelope.compiler_id,
        compilerVersion=envelope.compiler_version,
        compilerDigest=envelope.compiler_digest,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        reservationRequestId=request.reservation_request_id,
        reservationRequestDigest=request.reservation_request_digest,
        sourceActionPermitId=action_permit.permit_id,
        sourceActionPermitDigest=action_permit.permit_digest,
        sourceActionDispatchId=action_permit.dispatch_id,
        cleanupCapability=request.cleanup_capability,
        targetDigest=request.target_digest,
        cleanupHandlerId=request.cleanup_handler_id,
        cleanupHandlerVersion=request.cleanup_handler_version,
        cleanupHandlerDigest=request.cleanup_handler_digest,
        cleanupExecutorId=request.cleanup_executor_id,
        cleanupExecutorVersion=request.cleanup_executor_version,
        cleanupExecutorDigest=request.cleanup_executor_digest,
        reservation=request.reservation,
        reservedAt=evaluated_at,
        claimExpiresAt=request.claim_expires_at,
    )


def validate_cleanup_authority(
    envelope: MissionEnvelope,
    request: CleanupRequest,
    decision: GraphDecision,
    capability: RegisteredActionCapability,
    source_action_permit: ActionPermit,
    reservation: ActionCleanupReservation,
    *,
    evaluated_at: datetime,
) -> None:
    """Validate exact source, hold, plan, and fresh cleanup execution authority."""

    _validate_cleanup_source_lineage(
        envelope,
        request,
        source_action_permit,
        reservation,
    )
    _validate_cleanup_decision_timeline(
        envelope,
        request,
        decision,
        source_action_permit,
        reservation,
        evaluated_at=evaluated_at,
    )
    _validate_cleanup_execution_binding(
        envelope,
        request,
        capability,
        source_action_permit,
        reservation,
    )


def _validate_cleanup_source_lineage(
    envelope: MissionEnvelope,
    request: CleanupRequest,
    source_action_permit: ActionPermit,
    reservation: ActionCleanupReservation,
) -> None:
    if (
        request.campaign_id != envelope.campaign_id
        or request.run_id != envelope.run_id
        or source_action_permit.campaign_id != envelope.campaign_id
        or source_action_permit.run_id != envelope.run_id
        or reservation.campaign_id != envelope.campaign_id
        or reservation.run_id != envelope.run_id
    ):
        raise CleanupPermitError("cleanup authority lineage belongs to another Campaign or Run")
    if (
        request.envelope_id != envelope.envelope_id
        or request.envelope_digest != envelope.envelope_digest
        or source_action_permit.envelope_id != envelope.envelope_id
        or source_action_permit.envelope_digest != envelope.envelope_digest
        or reservation.envelope_id != envelope.envelope_id
        or reservation.envelope_digest != envelope.envelope_digest
    ):
        raise CleanupPermitError("cleanup MissionEnvelope binding differs")
    if (
        reservation.compiler_id != envelope.compiler_id
        or reservation.compiler_version != envelope.compiler_version
        or reservation.compiler_digest != envelope.compiler_digest
    ):
        raise CleanupPermitError("cleanup reservation compiler identity differs")
    if (
        request.cleanup_reservation_id != reservation.cleanup_reservation_id
        or request.cleanup_reservation_digest != reservation.cleanup_reservation_digest
        or request.source_action_permit_id != source_action_permit.permit_id
        or request.source_action_permit_digest != source_action_permit.permit_digest
        or request.source_action_dispatch_id != source_action_permit.dispatch_id
        or reservation.source_action_permit_id != source_action_permit.permit_id
        or reservation.source_action_permit_digest != source_action_permit.permit_digest
        or reservation.source_action_dispatch_id != source_action_permit.dispatch_id
    ):
        raise CleanupPermitError("cleanup source ActionPermit or reservation differs")


def _validate_cleanup_decision_timeline(
    envelope: MissionEnvelope,
    request: CleanupRequest,
    decision: GraphDecision,
    source_action_permit: ActionPermit,
    reservation: ActionCleanupReservation,
    *,
    evaluated_at: datetime,
) -> None:
    if decision.campaign_id != envelope.campaign_id:
        raise CleanupPermitError("cleanup decision belongs to another Campaign")
    if (
        request.decision_id != decision.decision_id
        or request.decision_digest != decision.decision_digest
        or request.snapshot != decision.snapshot
    ):
        raise CleanupPermitError("CleanupRequest Graph decision binding differs")
    if decision.decision_payload_digest != request.source_outcome_digest:
        raise CleanupPermitError("cleanup decision does not bind the declared source outcome")
    if request.created_at < decision.created_at or request.created_at > evaluated_at:
        raise CleanupPermitError("CleanupRequest is outside the evaluated authority timeline")
    if (
        request.created_at < source_action_permit.consumed_at
        or evaluated_at >= reservation.claim_expires_at
        or not envelope.not_before <= evaluated_at < envelope.expires_at
    ):
        raise CleanupPermitError("cleanup reservation or MissionEnvelope is not active")


def _validate_cleanup_execution_binding(
    envelope: MissionEnvelope,
    request: CleanupRequest,
    capability: RegisteredActionCapability,
    source_action_permit: ActionPermit,
    reservation: ActionCleanupReservation,
) -> None:
    if capability.reference() != request.capability:
        raise CleanupPermitError("CleanupRequest Capability binding differs")
    if request.capability != reservation.cleanup_capability:
        raise CleanupPermitError("CleanupRequest substitutes the reserved Capability")
    if request.capability not in envelope.allowed_capabilities:
        raise CleanupPermitError("cleanup Capability is outside the MissionEnvelope")
    if request.capability.risk_tier > envelope.max_risk_tier:
        raise CleanupPermitError("cleanup risk exceeds the MissionEnvelope")
    if (
        request.target_digest != reservation.target_digest
        or request.target_digest != source_action_permit.target_digest
        or request.target_digest not in envelope.allowed_target_digests
    ):
        raise CleanupPermitError("CleanupRequest target binding differs")
    if request.request_id == source_action_permit.request_id:
        raise CleanupPermitError("cleanup requires a fresh Tool request identity")
    if request.reservation != reservation.reservation:
        raise CleanupPermitError("CleanupRequest budget differs from the pre-reserved capacity")
    if (
        request.cleanup_handler_id != reservation.cleanup_handler_id
        or request.cleanup_handler_version != reservation.cleanup_handler_version
        or request.cleanup_handler_digest != reservation.cleanup_handler_digest
        or request.cleanup_executor_id != reservation.cleanup_executor_id
        or request.cleanup_executor_version != reservation.cleanup_executor_version
        or request.cleanup_executor_digest != reservation.cleanup_executor_digest
    ):
        raise CleanupPermitError("cleanup Handler or Executor authority differs")


def build_cleanup_permit(
    envelope: MissionEnvelope,
    request: CleanupRequest,
    reservation: ActionCleanupReservation,
    *,
    evaluated_at: datetime,
    permit_ttl: timedelta,
) -> CleanupPermit:
    """Build one canonical consumed CleanupPermit after all durable checks."""

    expires_at = min(
        envelope.expires_at,
        reservation.claim_expires_at,
        evaluated_at + permit_ttl,
    )
    return CleanupPermit(
        campaignId=envelope.campaign_id,
        runId=envelope.run_id,
        compilerId=envelope.compiler_id,
        compilerVersion=envelope.compiler_version,
        compilerDigest=envelope.compiler_digest,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        cleanupReservationId=reservation.cleanup_reservation_id,
        cleanupReservationDigest=reservation.cleanup_reservation_digest,
        cleanupRequestId=request.cleanup_request_id,
        cleanupRequestDigest=request.cleanup_request_digest,
        sourceActionPermitId=request.source_action_permit_id,
        sourceActionPermitDigest=request.source_action_permit_digest,
        sourceActionDispatchId=request.source_action_dispatch_id,
        sourceOutcomeId=request.source_outcome_id,
        sourceOutcomeDigest=request.source_outcome_digest,
        sourceRunRootDigest=request.source_run_root_digest,
        sourceTerminalEventDigest=request.source_terminal_event_digest,
        sourceGatewayOutcomeDigest=request.source_gateway_outcome_digest,
        decisionId=request.decision_id,
        decisionDigest=request.decision_digest,
        snapshot=request.snapshot,
        cleanupHandlerDigest=request.cleanup_handler_digest,
        cleanupExecutorDigest=request.cleanup_executor_digest,
        cleanupPlanDigest=request.cleanup_plan_digest,
        capability=request.capability,
        targetDigest=request.target_digest,
        requestId=request.request_id,
        requestDigest=request.request_digest,
        normalizedParametersDigest=request.normalized_parameters_digest,
        reservation=request.reservation,
        issuedAt=evaluated_at,
        consumedAt=evaluated_at,
        expiresAt=expires_at,
    )


def cleanup_permit_attempt_id(
    envelope: MissionEnvelope,
    request: CleanupRequest,
    decision: GraphDecision,
) -> str:
    """Return the deterministic CleanupPermit ID without a clock value."""

    material = {
        "campaignId": envelope.campaign_id,
        "runId": envelope.run_id,
        "compilerId": envelope.compiler_id,
        "compilerVersion": envelope.compiler_version,
        "compilerDigest": envelope.compiler_digest,
        "envelopeId": envelope.envelope_id,
        "envelopeDigest": envelope.envelope_digest,
        "cleanupReservationId": request.cleanup_reservation_id,
        "cleanupReservationDigest": request.cleanup_reservation_digest,
        "cleanupRequestId": request.cleanup_request_id,
        "cleanupRequestDigest": request.cleanup_request_digest,
        "sourceActionPermitId": request.source_action_permit_id,
        "sourceActionPermitDigest": request.source_action_permit_digest,
        "decisionId": decision.decision_id,
        "decisionDigest": decision.decision_digest,
        "snapshot": decision.snapshot.model_dump(mode="json", by_alias=True),
        "requestId": request.request_id,
        "requestDigest": request.request_digest,
    }
    return "cleanup-permit_" + graph_digest(
        "pajin.cleanup.permit-id/v1",
        material,
        max_bytes=_MAX_CLEANUP_AUTHORITY_BYTES,
    )


def _require_compiler_identity(
    compiler_id: str,
    compiler_version: str,
    compiler_digest: str,
) -> None:
    if (
        fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_id) is None
        or fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_version) is None
        or fullmatch(r"^[a-f0-9]{64}$", compiler_digest) is None
    ):
        raise ValueError("cleanup compiler identity is invalid")


def _require_permit_ttl(permit_ttl: timedelta) -> None:
    if not timedelta(seconds=1) <= permit_ttl <= timedelta(minutes=5):
        raise ValueError("CleanupPermit TTL must be from 1 second through 5 minutes")


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _canonical[ModelT: StrictModel](
    model_type: type[ModelT],
    value: ModelT,
    *,
    label: str,
) -> ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise CleanupPermitError(f"{label} is not canonical") from exc
