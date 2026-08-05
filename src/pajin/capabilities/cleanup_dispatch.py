"""Domain-separated CleanupPermit dispatch and sealed reconciliation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import (
    CapabilityDispatchAuditStore,
    ExistingModeCapabilityActivation,
    PreparedCapabilityAction,
    capability_gateway_outcome_digest,
    capability_grant_digest,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.models import CapabilityDefinition, capability_definition_digest
from pajin.capabilities.reconciliation import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityGraphRunAuditAnchor,
)
from pajin.domain.models import CampaignManifest, CapabilityGrant, StrictModel, ToolRequest
from pajin.graph.authority import MissionEnvelope
from pajin.graph.cleanup import (
    CleanupDispatchResult,
    CleanupPermit,
    CleanupRequest,
    GraphCleanupPermitDispatcher,
)
from pajin.graph.consistency import GraphDecision
from pajin.runtime.error_safety import audit_safe_exception_type
from pajin.runtime.store import AuditEvent, VerifiedRunSnapshot
from pajin.tools.gateway import GatewayOutcome

CLEANUP_CAPABILITY_DISPATCH_AUDIT_EVENT_API_VERSION: Literal[
    "pajin.dev/cleanup-capability-dispatch-audit-event/v1alpha1"
] = "pajin.dev/cleanup-capability-dispatch-audit-event/v1alpha1"
CLEANUP_CAPABILITY_DISPATCH_RECONCILIATION_API_VERSION: Literal[
    "pajin.dev/cleanup-capability-dispatch-reconciliation/v1alpha1"
] = "pajin.dev/cleanup-capability-dispatch-reconciliation/v1alpha1"
CLEANUP_CAPABILITY_DISPATCH_EVENT_PREFIX = "capability.cleanup-dispatch."
CLEANUP_CAPABILITY_DISPATCH_RECONCILIATION_EVENT_TYPE = (
    "capability.cleanup-dispatch-reconciliation.recorded"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class CleanupCapabilityDispatchError(ValueError):
    """Raised when cleanup dispatch authority or sealed evidence differs."""


class CleanupCapabilityDispatchStage(StrEnum):
    """Closed lifecycle stages for one consumed CleanupPermit."""

    CLAIMED = "claimed"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class CleanupCapabilityDispatchAuditEvent(StrictModel):
    """Content-addressed CleanupPermit-to-Gateway lifecycle record."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cleanup-capability-dispatch-audit-event/v1alpha1"] = Field(
        default=CLEANUP_CAPABILITY_DISPATCH_AUDIT_EVENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CleanupCapabilityDispatchAuditEvent"] = "CleanupCapabilityDispatchAuditEvent"
    event_id: str = Field(default="", alias="eventId", max_length=110)
    event_digest: str = Field(default="", alias="eventDigest", max_length=64)
    stage: CleanupCapabilityDispatchStage
    occurred_at: datetime = Field(alias="occurredAt")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    release: CapabilityReleaseRef
    cleanup_permit_id: str = Field(
        alias="cleanupPermitId",
        min_length=1,
        max_length=79,
    )
    cleanup_permit_digest: _Sha256 = Field(alias="cleanupPermitDigest")
    cleanup_dispatch_id: str = Field(
        alias="cleanupDispatchId",
        min_length=1,
        max_length=81,
    )
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    cleanup_request_id: str = Field(
        alias="cleanupRequestId",
        min_length=1,
        max_length=80,
    )
    cleanup_request_digest: _Sha256 = Field(alias="cleanupRequestDigest")
    source_action_permit_id: str = Field(
        alias="sourceActionPermitId",
        min_length=1,
        max_length=78,
    )
    source_action_permit_digest: _Sha256 = Field(alias="sourceActionPermitDigest")
    source_action_dispatch_id: str = Field(
        alias="sourceActionDispatchId",
        min_length=1,
        max_length=80,
    )
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    source_capability_grant_digest: _Sha256 = Field(alias="sourceCapabilityGrantDigest")
    capability_grant_digest: _Sha256 = Field(alias="capabilityGrantDigest")
    gateway_outcome_digest: _Sha256 | None = Field(
        default=None,
        alias="gatewayOutcomeDigest",
    )
    gateway_execution_id: str | None = Field(
        default=None,
        alias="gatewayExecutionId",
        min_length=1,
        max_length=200,
    )
    executed: bool | None = None
    policy_allowed: bool | None = Field(default=None, alias="policyAllowed")
    tool_success: bool | None = Field(default=None, alias="toolSuccess")
    evidence: tuple[str, ...] = Field(default=(), max_length=100)
    error_type: str | None = Field(
        default=None,
        alias="errorType",
        min_length=1,
        max_length=200,
    )

    @field_validator("occurred_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_time(value, label="cleanup dispatch event time")

    @field_validator("executed", "policy_allowed", "tool_success", mode="before")
    @classmethod
    def require_literal_optional_boolean(cls, value: object) -> object:
        if value is not None and type(value) is not bool:
            raise ValueError("cleanup dispatch outcome flags must use JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_lifecycle_and_identity(self) -> Self:
        if self.evidence != tuple(sorted(set(self.evidence))):
            raise ValueError("cleanup dispatch evidence must be unique and sorted")
        outcome_fields = (
            self.gateway_outcome_digest,
            self.executed,
            self.policy_allowed,
            self.tool_success,
        )
        if self.stage is CleanupCapabilityDispatchStage.COMPLETED:
            if any(value is None for value in outcome_fields) or self.error_type is not None:
                raise ValueError("completed cleanup dispatch requires only Gateway outcome fields")
        elif self.stage in {
            CleanupCapabilityDispatchStage.FAILED,
            CleanupCapabilityDispatchStage.CANCELLED,
        }:
            if any(value is not None for value in outcome_fields):
                raise ValueError("unsuccessful cleanup dispatch cannot claim a Gateway outcome")
            if self.gateway_execution_id is not None or self.evidence:
                raise ValueError("unsuccessful cleanup dispatch cannot claim Gateway evidence")
            if self.error_type is None:
                raise ValueError("unsuccessful cleanup dispatch requires an audit-safe error type")
        elif (
            any(value is not None for value in outcome_fields)
            or self.gateway_execution_id is not None
            or self.evidence
            or self.error_type is not None
        ):
            raise ValueError("non-terminal cleanup dispatch cannot claim Gateway result fields")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"event_id", "event_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cleanup-dispatch-audit-event/v1",
            material,
        )
        event_id = f"cleanup-capability-dispatch-event_{digest}"
        if self.event_digest and self.event_digest != digest:
            raise ValueError("cleanup dispatch event digest differs from canonical identity")
        if self.event_id and self.event_id != event_id:
            raise ValueError("cleanup dispatch event ID differs from canonical identity")
        object.__setattr__(self, "event_digest", digest)
        object.__setattr__(self, "event_id", event_id)
        return self


class CleanupCapabilityDispatchReconciliationStatus(StrEnum):
    """Closed classification of one consumed CleanupPermit and sealed audit."""

    CONSUMED_WITHOUT_CLAIM = "consumed-without-claim"
    CLAIMED_OUTCOME_UNKNOWN = "claimed-outcome-unknown"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


_TERMINAL_STATUS_STAGE = {
    CleanupCapabilityDispatchReconciliationStatus.COMPLETED: (
        CleanupCapabilityDispatchStage.COMPLETED
    ),
    CleanupCapabilityDispatchReconciliationStatus.FAILED: (CleanupCapabilityDispatchStage.FAILED),
    CleanupCapabilityDispatchReconciliationStatus.CANCELLED: (
        CleanupCapabilityDispatchStage.CANCELLED
    ),
    CleanupCapabilityDispatchReconciliationStatus.EXPIRED: (CleanupCapabilityDispatchStage.EXPIRED),
}


class CleanupCapabilityDispatchReconciliation(StrictModel):
    """Sealed classification that never grants cleanup redispatch authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cleanup-capability-dispatch-reconciliation/v1alpha1"] = Field(
        default=CLEANUP_CAPABILITY_DISPATCH_RECONCILIATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CleanupCapabilityDispatchReconciliation"] = (
        "CleanupCapabilityDispatchReconciliation"
    )
    reconciliation_id: str = Field(
        default="",
        alias="reconciliationId",
        max_length=120,
    )
    reconciliation_digest: str = Field(
        default="",
        alias="reconciliationDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    status: CleanupCapabilityDispatchReconciliationStatus
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    cleanup_permit_id: str = Field(
        alias="cleanupPermitId",
        min_length=1,
        max_length=79,
    )
    cleanup_permit_digest: _Sha256 = Field(alias="cleanupPermitDigest")
    cleanup_dispatch_id: str = Field(
        alias="cleanupDispatchId",
        min_length=1,
        max_length=81,
    )
    observed_audit_sequence: int = Field(alias="observedAuditSequence", ge=1)
    observed_audit_event_hash: _Sha256 = Field(alias="observedAuditEventHash")
    evidence_seal_root_digest: _Sha256 = Field(alias="evidenceSealRootDigest")
    dispatch_event_digests: tuple[_Sha256, ...] = Field(
        alias="dispatchEventDigests",
        max_length=2,
    )
    terminal_stage: CleanupCapabilityDispatchStage | None = Field(
        default=None,
        alias="terminalStage",
    )
    terminal_event_digest: _Sha256 | None = Field(
        default=None,
        alias="terminalEventDigest",
    )
    redispatch_allowed: Literal[False] = Field(default=False, alias="redispatchAllowed")
    manual_review_required: bool = Field(alias="manualReviewRequired")

    @field_validator("manual_review_required", mode="before")
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("cleanup reconciliation flags must use JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_and_identity(self) -> Self:
        if len(set(self.dispatch_event_digests)) != len(self.dispatch_event_digests):
            raise ValueError("cleanup reconciliation event digests must be unique")
        expected_terminal = _TERMINAL_STATUS_STAGE.get(self.status)
        incomplete = self.status in {
            CleanupCapabilityDispatchReconciliationStatus.CONSUMED_WITHOUT_CLAIM,
            CleanupCapabilityDispatchReconciliationStatus.CLAIMED_OUTCOME_UNKNOWN,
        }
        expected_event_count = (
            0
            if self.status is CleanupCapabilityDispatchReconciliationStatus.CONSUMED_WITHOUT_CLAIM
            else 1
            if self.status is CleanupCapabilityDispatchReconciliationStatus.CLAIMED_OUTCOME_UNKNOWN
            else 2
        )
        if len(self.dispatch_event_digests) != expected_event_count:
            raise ValueError("cleanup reconciliation event count differs from its status")
        if self.terminal_stage != expected_terminal or (self.terminal_event_digest is None) != (
            expected_terminal is None
        ):
            raise ValueError("cleanup reconciliation terminal evidence differs from its status")
        if self.manual_review_required is not incomplete:
            raise ValueError("cleanup reconciliation manual-review flag differs from its status")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reconciliation_id", "reconciliation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cleanup-dispatch-reconciliation/v1",
            material,
        )
        reconciliation_id = f"cleanup-capability-reconciliation_{digest}"
        if self.reconciliation_digest and self.reconciliation_digest != digest:
            raise ValueError("cleanup dispatch reconciliation digest differs")
        if self.reconciliation_id and self.reconciliation_id != reconciliation_id:
            raise ValueError("cleanup dispatch reconciliation ID differs")
        object.__setattr__(self, "reconciliation_digest", digest)
        object.__setattr__(self, "reconciliation_id", reconciliation_id)
        return self


class CleanupCapabilityDispatchReconciliationObservation(StrictModel):
    """Verified record and optional terminal cleanup lifecycle event."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True, frozen=True)

    record: CleanupCapabilityDispatchReconciliation
    terminal_event: CleanupCapabilityDispatchAuditEvent | None = None
    already_recorded: bool

    @field_validator("already_recorded", mode="before")
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("cleanup reconciliation observation flags must be literal")
        return value


class _CleanupPermitDispatcher(Protocol):
    async def dispatch_once(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
        dispatch: Callable[[CleanupPermit], Awaitable[GatewayOutcome]],
    ) -> CleanupDispatchResult[GatewayOutcome]: ...


class _Gateway(Protocol):
    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome: ...


class ExistingModeCleanupCapabilityGatewayDispatcher:
    """Bridge one consumed CleanupPermit into the unchanged Tool Gateway."""

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        permits: GraphCleanupPermitDispatcher | _CleanupPermitDispatcher,
        gateway: _Gateway,
        audit_store: CapabilityDispatchAuditStore,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(activation, "resolve_for_dispatch", None)) or not hasattr(
            activation,
            "activation_set",
        ):
            raise TypeError("cleanup dispatch requires a verified Capability activation")
        if not callable(getattr(permits, "dispatch_once", None)):
            raise TypeError("cleanup dispatch requires a CleanupPermit dispatcher")
        if not callable(getattr(gateway, "execute", None)):
            raise TypeError("cleanup dispatch requires the Tool Gateway")
        if not isinstance(getattr(audit_store, "run_id", None), str) or not callable(
            getattr(audit_store, "append_event", None)
        ):
            raise TypeError("cleanup dispatch requires an append-only Run audit store")
        self._activation = activation
        self._permits = permits
        self._gateway = gateway
        self._audit_store = audit_store
        self._clock = clock or (lambda: datetime.now(UTC))

    async def dispatch_once(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
        prepared: PreparedCapabilityAction,
        *,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        source_grant: CapabilityGrant,
        source_terminal_occurred_at: datetime,
        used_calls: int,
    ) -> CleanupDispatchResult[GatewayOutcome]:
        """Consume once and invoke Gateway only for exact fresh cleanup authority."""

        canonical_envelope = _canonical(MissionEnvelope, envelope, label="MissionEnvelope")
        canonical_request = _canonical(CleanupRequest, request, label="CleanupRequest")
        canonical_decision = _canonical(GraphDecision, decision, label="GraphDecision")
        canonical_prepared = _canonical(
            PreparedCapabilityAction,
            prepared,
            label="prepared cleanup Capability",
        )
        canonical_campaign = _canonical(
            CampaignManifest,
            campaign,
            label="Campaign",
        )
        canonical_grant = _canonical(
            CapabilityGrant,
            grant,
            label="cleanup Capability Grant",
        )
        canonical_source_grant = _canonical(
            CapabilityGrant,
            source_grant,
            label="source Capability Grant",
        )
        source_terminal = _normalize_time(
            source_terminal_occurred_at,
            label="source terminal event time",
        )
        if type(used_calls) is not int or used_calls != 0:
            raise CleanupCapabilityDispatchError(
                "fresh cleanup Capability Grant requires zero used calls"
            )
        definition = self._validate_current_authority(
            canonical_request,
            canonical_prepared,
        )
        self._validate_campaign_and_grants(
            canonical_envelope,
            canonical_request,
            canonical_campaign,
            canonical_prepared,
            canonical_grant,
            canonical_source_grant,
            source_terminal=source_terminal,
        )
        if canonical_request.reservation.request_units != definition.request_unit_cost:
            raise CleanupCapabilityDispatchError(
                "cleanup reservation differs from Capability request-unit cost"
            )

        async def dispatch(permit: CleanupPermit) -> GatewayOutcome:
            canonical_permit = _canonical(CleanupPermit, permit, label="CleanupPermit")
            self._validate_permit(canonical_permit, canonical_request, canonical_prepared)
            if self._audit_store.run_id != canonical_permit.run_id:
                raise CleanupCapabilityDispatchError(
                    "cleanup dispatch audit Run differs from CleanupPermit"
                )
            claimed_at = self._dispatch_time()
            self._append_dispatch_event(
                permit=canonical_permit,
                prepared=canonical_prepared,
                grant=canonical_grant,
                source_grant=canonical_source_grant,
                stage=CleanupCapabilityDispatchStage.CLAIMED,
                occurred_at=claimed_at,
            )
            if claimed_at >= canonical_permit.expires_at:
                self._append_dispatch_event(
                    permit=canonical_permit,
                    prepared=canonical_prepared,
                    grant=canonical_grant,
                    source_grant=canonical_source_grant,
                    stage=CleanupCapabilityDispatchStage.EXPIRED,
                    occurred_at=self._dispatch_time(),
                )
                raise CleanupCapabilityDispatchError(
                    "consumed CleanupPermit expired before Tool Gateway dispatch"
                )
            try:
                if (
                    canonical_grant.issued_at > canonical_permit.issued_at
                    or canonical_grant.expires_at > canonical_permit.expires_at
                ):
                    raise CleanupCapabilityDispatchError(
                        "cleanup Capability Grant exceeds the CleanupPermit window"
                    )
                self._validate_current_authority(
                    canonical_request,
                    canonical_prepared,
                )
                outcome = await self._gateway.execute(
                    canonical_campaign,
                    canonical_grant,
                    canonical_prepared.request,
                    used_calls=used_calls,
                )
            except asyncio.CancelledError as exc:
                self._append_dispatch_event(
                    permit=canonical_permit,
                    prepared=canonical_prepared,
                    grant=canonical_grant,
                    source_grant=canonical_source_grant,
                    stage=CleanupCapabilityDispatchStage.CANCELLED,
                    occurred_at=self._dispatch_time(),
                    error_type=audit_safe_exception_type(exc),
                )
                raise
            except Exception as exc:
                self._append_dispatch_event(
                    permit=canonical_permit,
                    prepared=canonical_prepared,
                    grant=canonical_grant,
                    source_grant=canonical_source_grant,
                    stage=CleanupCapabilityDispatchStage.FAILED,
                    occurred_at=self._dispatch_time(),
                    error_type=audit_safe_exception_type(exc),
                )
                raise
            self._append_dispatch_event(
                permit=canonical_permit,
                prepared=canonical_prepared,
                grant=canonical_grant,
                source_grant=canonical_source_grant,
                stage=CleanupCapabilityDispatchStage.COMPLETED,
                occurred_at=self._dispatch_time(),
                outcome=outcome,
            )
            return outcome

        return await self._permits.dispatch_once(
            canonical_envelope,
            canonical_request,
            canonical_decision,
            dispatch,
        )

    def _validate_current_authority(
        self,
        request: CleanupRequest,
        prepared: PreparedCapabilityAction,
    ) -> CapabilityDefinition:
        try:
            if prepared.activation_set_digest != (
                self._activation.activation_set.activation_set_digest
            ):
                raise CleanupCapabilityDispatchError(
                    "prepared cleanup belongs to another activation set"
                )
            resolved = self._activation.resolve_for_dispatch(prepared.capability)
            if resolved.release != prepared.release:
                raise CleanupCapabilityDispatchError(
                    "prepared cleanup release differs from current signed authority"
                )
            definition = self._activation.rollout.bundle.definitions.resolve(
                resolved.capability.capability
            )
        except CleanupCapabilityDispatchError:
            raise
        except Exception as exc:
            raise CleanupCapabilityDispatchError(
                "cleanup Capability activation failed closed"
            ) from exc
        if (
            request.capability != prepared.capability
            or request.request_id != prepared.request.request_id
            or request.request_digest != prepared.request_digest
            or request.normalized_parameters_digest != prepared.normalized_parameters_digest
        ):
            raise CleanupCapabilityDispatchError(
                "CleanupRequest differs from prepared Capability dispatch"
            )
        if definition.reference() != resolved.capability.capability:
            raise CleanupCapabilityDispatchError(
                "cleanup Capability definition differs from current release"
            )
        return definition

    @staticmethod
    def _validate_campaign_and_grants(
        envelope: MissionEnvelope,
        request: CleanupRequest,
        campaign: CampaignManifest,
        prepared: PreparedCapabilityAction,
        grant: CapabilityGrant,
        source_grant: CapabilityGrant,
        *,
        source_terminal: datetime,
    ) -> None:
        if (
            envelope.campaign_id != request.campaign_id
            or campaign.metadata.name != request.campaign_id
            or grant.campaign != request.campaign_id
            or source_grant.campaign != request.campaign_id
        ):
            raise CleanupCapabilityDispatchError(
                "cleanup Gateway authority belongs to another Campaign"
            )
        if grant.grant_id == source_grant.grant_id or capability_grant_digest(
            grant
        ) == capability_grant_digest(source_grant):
            raise CleanupCapabilityDispatchError(
                "cleanup requires a distinct fresh Capability Grant"
            )
        if (
            grant.subject != prepared.request.agent_id
            or grant.tools != {prepared.request.tool_id}
            or grant.targets != {prepared.request.target}
            or grant.max_risk_tier != prepared.capability.risk_tier
            or grant.max_calls != 1
            or grant.delegable
        ):
            raise CleanupCapabilityDispatchError(
                "cleanup Capability Grant is not exact least authority"
            )
        if grant.issued_at <= source_terminal or grant.expires_at > envelope.expires_at:
            raise CleanupCapabilityDispatchError(
                "cleanup Capability Grant is not fresh or exceeds the Envelope"
            )

    @staticmethod
    def _validate_permit(
        permit: CleanupPermit,
        request: CleanupRequest,
        prepared: PreparedCapabilityAction,
    ) -> None:
        if (
            permit.campaign_id != request.campaign_id
            or permit.run_id != request.run_id
            or permit.envelope_id != request.envelope_id
            or permit.envelope_digest != request.envelope_digest
            or permit.cleanup_reservation_id != request.cleanup_reservation_id
            or permit.cleanup_reservation_digest != request.cleanup_reservation_digest
            or permit.cleanup_request_id != request.cleanup_request_id
            or permit.cleanup_request_digest != request.cleanup_request_digest
            or permit.source_action_permit_id != request.source_action_permit_id
            or permit.source_action_permit_digest != request.source_action_permit_digest
            or permit.source_action_dispatch_id != request.source_action_dispatch_id
            or permit.source_outcome_id != request.source_outcome_id
            or permit.source_outcome_digest != request.source_outcome_digest
            or permit.source_run_root_digest != request.source_run_root_digest
            or permit.source_terminal_event_digest != request.source_terminal_event_digest
            or permit.source_gateway_outcome_digest != request.source_gateway_outcome_digest
            or permit.decision_id != request.decision_id
            or permit.decision_digest != request.decision_digest
            or permit.snapshot != request.snapshot
            or permit.cleanup_handler_digest != request.cleanup_handler_digest
            or permit.cleanup_executor_digest != request.cleanup_executor_digest
            or permit.cleanup_plan_digest != request.cleanup_plan_digest
            or permit.capability != prepared.capability
            or permit.target_digest != request.target_digest
            or permit.request_id != prepared.request.request_id
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
            or permit.reservation != request.reservation
        ):
            raise CleanupCapabilityDispatchError(
                "consumed CleanupPermit differs from prepared cleanup dispatch"
            )

    def _append_dispatch_event(
        self,
        *,
        permit: CleanupPermit,
        prepared: PreparedCapabilityAction,
        grant: CapabilityGrant,
        source_grant: CapabilityGrant,
        stage: CleanupCapabilityDispatchStage,
        occurred_at: datetime,
        outcome: GatewayOutcome | None = None,
        error_type: str | None = None,
    ) -> CleanupCapabilityDispatchAuditEvent:
        event = CleanupCapabilityDispatchAuditEvent(
            stage=stage,
            occurredAt=occurred_at,
            activationSetDigest=prepared.activation_set_digest,
            release=prepared.release,
            cleanupPermitId=permit.cleanup_permit_id,
            cleanupPermitDigest=permit.cleanup_permit_digest,
            cleanupDispatchId=permit.cleanup_dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            cleanupRequestId=permit.cleanup_request_id,
            cleanupRequestDigest=permit.cleanup_request_digest,
            sourceActionPermitId=permit.source_action_permit_id,
            sourceActionPermitDigest=permit.source_action_permit_digest,
            sourceActionDispatchId=permit.source_action_dispatch_id,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            sourceCapabilityGrantDigest=capability_grant_digest(source_grant),
            capabilityGrantDigest=capability_grant_digest(grant),
            gatewayOutcomeDigest=(
                capability_gateway_outcome_digest(outcome) if outcome is not None else None
            ),
            gatewayExecutionId=(
                outcome.worker_result.execution_id
                if outcome is not None and outcome.worker_result is not None
                else None
            ),
            executed=outcome.executed if outcome is not None else None,
            policyAllowed=outcome.decision.allowed if outcome is not None else None,
            toolSuccess=outcome.result.success if outcome is not None else None,
            evidence=(tuple(sorted(set(outcome.result.evidence))) if outcome is not None else ()),
            errorType=error_type,
        )
        self._audit_store.append_event(
            f"{CLEANUP_CAPABILITY_DISPATCH_EVENT_PREFIX}{event.stage.value}",
            event.model_dump(mode="json", by_alias=True),
            occurred_at=event.occurred_at,
        )
        return event

    def _dispatch_time(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise CleanupCapabilityDispatchError("cleanup dispatch audit clock failed") from exc
        return _normalize_time(value, label="cleanup dispatch audit clock")


def reconcile_cleanup_capability_dispatch(
    snapshot: VerifiedRunSnapshot,
    permit: CleanupPermit,
) -> CleanupCapabilityDispatchReconciliationObservation:
    """Classify one consumed CleanupPermit without granting redispatch authority."""

    if not isinstance(snapshot, VerifiedRunSnapshot):
        raise TypeError("cleanup reconciliation requires a verified Run snapshot")
    canonical_permit = _canonical(CleanupPermit, permit, label="CleanupPermit")
    if snapshot.verification.run_id != canonical_permit.run_id or any(
        event.run_id != canonical_permit.run_id for event in snapshot.events
    ):
        raise CleanupCapabilityDispatchError(
            "cleanup reconciliation Run differs from CleanupPermit"
        )
    if not any(
        seal.root_digest == canonical_permit.source_run_root_digest for seal in snapshot.seals
    ):
        raise CleanupCapabilityDispatchError(
            "cleanup reconciliation is missing the sealed source Run root"
        )
    anchors, dispatch_events, existing_records = _scan_snapshot(
        snapshot,
        canonical_permit,
    )
    if (
        not dispatch_events
        and len(anchors) == 1
        and anchors[0][0].occurred_at > canonical_permit.consumed_at
    ):
        raise CleanupCapabilityDispatchError(
            "consumed CleanupPermit Run anchor was not established before its claim"
        )
    lifecycle = tuple(event for _, event in dispatch_events)
    _validate_lifecycle(canonical_permit, lifecycle)
    observed_event, status, terminal_event = _classify_lifecycle(
        anchors,
        dispatch_events,
    )
    seal_root = _evidence_seal_root_digest(snapshot, observed_event)
    record = CleanupCapabilityDispatchReconciliation(
        status=status,
        campaignId=canonical_permit.campaign_id,
        runId=canonical_permit.run_id,
        cleanupPermitId=canonical_permit.cleanup_permit_id,
        cleanupPermitDigest=canonical_permit.cleanup_permit_digest,
        cleanupDispatchId=canonical_permit.cleanup_dispatch_id,
        observedAuditSequence=observed_event.sequence,
        observedAuditEventHash=observed_event.event_hash,
        evidenceSealRootDigest=seal_root,
        dispatchEventDigests=tuple(event.event_digest for event in lifecycle),
        terminalStage=terminal_event.stage if terminal_event is not None else None,
        terminalEventDigest=(terminal_event.event_digest if terminal_event is not None else None),
        manualReviewRequired=terminal_event is None,
    )
    if len(existing_records) > 1 or any(item != record for item in existing_records):
        raise CleanupCapabilityDispatchError(
            "sealed cleanup reconciliation record differs or is duplicated"
        )
    return CleanupCapabilityDispatchReconciliationObservation(
        record=record,
        terminal_event=terminal_event,
        already_recorded=bool(existing_records),
    )


def _scan_snapshot(
    snapshot: VerifiedRunSnapshot,
    permit: CleanupPermit,
) -> tuple[
    list[tuple[AuditEvent, CapabilityGraphRunAuditAnchor]],
    list[tuple[AuditEvent, CleanupCapabilityDispatchAuditEvent]],
    list[CleanupCapabilityDispatchReconciliation],
]:
    anchors: list[tuple[AuditEvent, CapabilityGraphRunAuditAnchor]] = []
    dispatch_events: list[tuple[AuditEvent, CleanupCapabilityDispatchAuditEvent]] = []
    existing_records: list[CleanupCapabilityDispatchReconciliation] = []
    for audit_event in snapshot.events:
        if audit_event.event_type == CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE:
            try:
                anchor = CapabilityGraphRunAuditAnchor.model_validate(audit_event.payload)
            except ValidationError as exc:
                raise CleanupCapabilityDispatchError(
                    "Capability Graph Run anchor is invalid"
                ) from exc
            if anchor.run_id == permit.run_id and anchor.campaign_id == permit.campaign_id:
                anchors.append((audit_event, anchor))
        elif audit_event.event_type.startswith(CLEANUP_CAPABILITY_DISPATCH_EVENT_PREFIX):
            event = _parse_dispatch_event(audit_event)
            if event.cleanup_permit_id == permit.cleanup_permit_id:
                dispatch_events.append((audit_event, event))
        elif audit_event.event_type == CLEANUP_CAPABILITY_DISPATCH_RECONCILIATION_EVENT_TYPE:
            try:
                record = CleanupCapabilityDispatchReconciliation.model_validate(audit_event.payload)
            except ValidationError as exc:
                raise CleanupCapabilityDispatchError(
                    "cleanup dispatch reconciliation record is invalid"
                ) from exc
            if record.cleanup_permit_id == permit.cleanup_permit_id:
                existing_records.append(record)
    return anchors, dispatch_events, existing_records


def _parse_dispatch_event(
    audit_event: AuditEvent,
) -> CleanupCapabilityDispatchAuditEvent:
    try:
        event = CleanupCapabilityDispatchAuditEvent.model_validate(audit_event.payload)
    except ValidationError as exc:
        raise CleanupCapabilityDispatchError("cleanup dispatch audit event is invalid") from exc
    if audit_event.event_type != (f"{CLEANUP_CAPABILITY_DISPATCH_EVENT_PREFIX}{event.stage.value}"):
        raise CleanupCapabilityDispatchError(
            "cleanup dispatch outer event type differs from its stage"
        )
    return event


def _validate_lifecycle(
    permit: CleanupPermit,
    lifecycle: tuple[CleanupCapabilityDispatchAuditEvent, ...],
) -> None:
    if len(lifecycle) > 2:
        raise CleanupCapabilityDispatchError("cleanup dispatch lifecycle is duplicated")
    if lifecycle and lifecycle[0].stage is not CleanupCapabilityDispatchStage.CLAIMED:
        raise CleanupCapabilityDispatchError(
            "cleanup dispatch terminal audit is missing its claimed event"
        )
    if len(lifecycle) == 2 and lifecycle[1].stage not in {
        CleanupCapabilityDispatchStage.COMPLETED,
        CleanupCapabilityDispatchStage.FAILED,
        CleanupCapabilityDispatchStage.CANCELLED,
        CleanupCapabilityDispatchStage.EXPIRED,
    }:
        raise CleanupCapabilityDispatchError(
            "cleanup dispatch lifecycle has no valid terminal stage"
        )
    if len(lifecycle) == 2 and lifecycle[1].occurred_at < lifecycle[0].occurred_at:
        raise CleanupCapabilityDispatchError(
            "cleanup dispatch terminal audit predates its claimed event"
        )
    if lifecycle and lifecycle[0].occurred_at < permit.consumed_at:
        raise CleanupCapabilityDispatchError(
            "cleanup dispatch claimed audit predates CleanupPermit consumption"
        )
    for event in lifecycle:
        if (
            event.cleanup_permit_digest != permit.cleanup_permit_digest
            or event.cleanup_dispatch_id != permit.cleanup_dispatch_id
            or event.campaign_id != permit.campaign_id
            or event.run_id != permit.run_id
            or event.cleanup_request_id != permit.cleanup_request_id
            or event.cleanup_request_digest != permit.cleanup_request_digest
            or event.source_action_permit_id != permit.source_action_permit_id
            or event.source_action_permit_digest != permit.source_action_permit_digest
            or event.source_action_dispatch_id != permit.source_action_dispatch_id
            or event.request_id != permit.request_id
            or event.request_digest != permit.request_digest
            or event.normalized_parameters_digest != permit.normalized_parameters_digest
        ):
            raise CleanupCapabilityDispatchError(
                "cleanup dispatch audit differs from CleanupPermit"
            )
    if len(lifecycle) == 2 and (
        lifecycle[0].activation_set_digest != lifecycle[1].activation_set_digest
        or lifecycle[0].release != lifecycle[1].release
        or lifecycle[0].source_capability_grant_digest
        != lifecycle[1].source_capability_grant_digest
        or lifecycle[0].capability_grant_digest != lifecycle[1].capability_grant_digest
    ):
        raise CleanupCapabilityDispatchError(
            "cleanup terminal authority differs from its claimed event"
        )


def _classify_lifecycle(
    anchors: list[tuple[AuditEvent, CapabilityGraphRunAuditAnchor]],
    dispatch_events: list[tuple[AuditEvent, CleanupCapabilityDispatchAuditEvent]],
) -> tuple[
    AuditEvent,
    CleanupCapabilityDispatchReconciliationStatus,
    CleanupCapabilityDispatchAuditEvent | None,
]:
    lifecycle = tuple(event for _, event in dispatch_events)
    if not lifecycle:
        if len(anchors) != 1:
            raise CleanupCapabilityDispatchError(
                "consumed CleanupPermit without audit requires one sealed Run anchor"
            )
        return (
            anchors[0][0],
            CleanupCapabilityDispatchReconciliationStatus.CONSUMED_WITHOUT_CLAIM,
            None,
        )
    if len(lifecycle) == 1:
        return (
            dispatch_events[0][0],
            CleanupCapabilityDispatchReconciliationStatus.CLAIMED_OUTCOME_UNKNOWN,
            None,
        )
    terminal_event = lifecycle[-1]
    return (
        dispatch_events[-1][0],
        CleanupCapabilityDispatchReconciliationStatus(terminal_event.stage.value),
        terminal_event,
    )


def _evidence_seal_root_digest(
    snapshot: VerifiedRunSnapshot,
    observed_event: AuditEvent,
) -> str:
    seal = next(
        (item for item in snapshot.seals if item.event_count >= observed_event.sequence),
        None,
    )
    if seal is None:
        raise CleanupCapabilityDispatchError(
            "cleanup reconciliation evidence is not covered by a Run seal"
        )
    return seal.root_digest


def _canonical[ModelT: StrictModel](
    model: type[ModelT],
    value: ModelT,
    *,
    label: str,
) -> ModelT:
    try:
        return model.model_validate(value.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise CleanupCapabilityDispatchError(f"{label} is not canonical") from exc


def _normalize_time(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise CleanupCapabilityDispatchError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise CleanupCapabilityDispatchError(f"{label} must include a UTC offset or Z")
    return value.astimezone(UTC)
