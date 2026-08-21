"""Opt-in activation and GRAPH-006 Tool Gateway dispatch for verified Capabilities."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Any, Literal, Protocol, Self, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.capabilities.adapters import registered_action_capability
from pajin.capabilities.authorities import (
    CapabilityAuthorityError,
    CapabilityAuthorityRole,
    CodeBackedCapabilityRef,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityReleaseRef,
    CapabilityUseProfile,
    ResolvedCapabilityRelease,
)
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    capability_definition_digest,
)
from pajin.capabilities.rollout import (
    EXISTING_MODE_CAPABILITY_RELEASE_SET_API_VERSION,
    ExistingModeCapabilityRollout,
    ExistingModeCapabilityRolloutError,
)
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
)
from pajin.graph.authority import (
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    ActionDispatchResult,
    ActionPermit,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
)
from pajin.graph.consistency import GraphDecision
from pajin.runtime.error_safety import audit_safe_exception_type
from pajin.tools.gateway import GatewayOutcome, canonical_tool_request_digest

EXISTING_MODE_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/existing-mode-capability-activation-set/v1alpha1"
] = "pajin.dev/existing-mode-capability-activation-set/v1alpha1"
EXISTING_MODE_CAPABILITY_MCP_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/existing-mode-capability-activation-set/v1alpha2"
] = "pajin.dev/existing-mode-capability-activation-set/v1alpha2"
PREPARED_CAPABILITY_ACTION_API_VERSION: Literal["pajin.dev/prepared-capability-action/v1alpha1"] = (
    "pajin.dev/prepared-capability-action/v1alpha1"
)
CAPABILITY_DISPATCH_AUDIT_EVENT_API_VERSION: Literal[
    "pajin.dev/capability-dispatch-audit-event/v1alpha1"
] = "pajin.dev/capability-dispatch-audit-event/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_ACTIVATED_CAPABILITIES = 8
_MAX_GATEWAY_OUTCOME_BYTES = 32 * 1024 * 1024


class ExistingModeCapabilityActivationError(ValueError):
    """Raised when signed runtime activation or dispatch authority differs."""


class CapabilityDispatchStage(StrEnum):
    """Closed lifecycle stages emitted after an ActionPermit is consumed."""

    CLAIMED = "claimed"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class CapabilityDispatchAuditEvent(StrictModel):
    """Content-addressed Permit-to-Gateway lifecycle record."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-dispatch-audit-event/v1alpha1"] = Field(
        default=CAPABILITY_DISPATCH_AUDIT_EVENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityDispatchAuditEvent"] = "CapabilityDispatchAuditEvent"
    event_id: str = Field(default="", alias="eventId", max_length=100)
    event_digest: str = Field(default="", alias="eventDigest", max_length=64)
    stage: CapabilityDispatchStage
    occurred_at: datetime = Field(alias="occurredAt")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    release: CapabilityReleaseRef
    permit_id: str = Field(alias="permitId", min_length=1, max_length=78)
    permit_digest: _Sha256 = Field(alias="permitDigest")
    dispatch_id: str = Field(alias="dispatchId", min_length=1, max_length=80)
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    proposal_id: str = Field(alias="proposalId", min_length=1, max_length=80)
    proposal_digest: _Sha256 = Field(alias="proposalDigest")
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    capability_grant_digest: _Sha256 | None = Field(
        default=None,
        alias="capabilityGrantDigest",
    )
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
        return _normalize_dispatch_time(value, label="Capability dispatch event time")

    @model_validator(mode="after")
    def bind_lifecycle_and_identity(self) -> Self:
        if self.evidence != tuple(sorted(set(self.evidence))):
            raise ValueError("Capability dispatch evidence must be unique and sorted")
        outcome_fields = (
            self.gateway_outcome_digest,
            self.executed,
            self.policy_allowed,
            self.tool_success,
        )
        if self.stage is CapabilityDispatchStage.COMPLETED:
            if any(value is None for value in outcome_fields) or self.error_type is not None:
                raise ValueError(
                    "completed Capability dispatch requires only Gateway outcome fields"
                )
        elif self.stage in {
            CapabilityDispatchStage.FAILED,
            CapabilityDispatchStage.CANCELLED,
        }:
            if any(value is not None for value in outcome_fields):
                raise ValueError("unsuccessful Capability dispatch cannot claim a Gateway outcome")
            if self.gateway_execution_id is not None or self.evidence:
                raise ValueError("unsuccessful Capability dispatch cannot claim Gateway evidence")
            if self.error_type is None:
                raise ValueError(
                    "unsuccessful Capability dispatch requires an audit-safe error type"
                )
        elif (
            any(value is not None for value in outcome_fields)
            or self.gateway_execution_id is not None
            or self.evidence
            or self.error_type is not None
        ):
            raise ValueError("non-terminal Capability dispatch cannot claim Gateway result fields")
        excluded_digest_fields = {"event_id", "event_digest"}
        if self.capability_grant_digest is None:
            excluded_digest_fields.add("capability_grant_digest")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude=excluded_digest_fields,
        )
        digest = capability_definition_digest(
            "pajin.capability.dispatch-audit-event/v1",
            material,
        )
        event_id = f"capability-dispatch-event_{digest}"
        if self.event_digest and self.event_digest != digest:
            raise ValueError("Capability dispatch event digest differs from canonical identity")
        if self.event_id and self.event_id != event_id:
            raise ValueError("Capability dispatch event ID differs from canonical identity")
        object.__setattr__(self, "event_digest", digest)
        object.__setattr__(self, "event_id", event_id)
        return self


class CapabilityDispatchAuditStore(Protocol):
    """Append-only Run audit boundary used by the Capability dispatch bridge."""

    run_id: str

    def append_event(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        occurred_at: datetime | None = None,
    ) -> object: ...


class ExistingModeCapabilityActivationBinding(StrictModel):
    """One signed release admitted into the opt-in GRAPH-006 registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: CapabilityReleaseRef
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")
    domain: str = Field(min_length=1, max_length=200)
    supported_surface_types: tuple[str, ...] = Field(
        alias="supportedSurfaceTypes",
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def bind_definition_identity(self) -> Self:
        definition = self.capability.capability
        action = self.action_capability
        if (
            action.capability_id != definition.capability_id
            or action.capability_version != definition.capability_version
            or action.definition_digest != definition.capability_digest
        ):
            raise ValueError("activated GRAPH Capability differs from its released definition")
        if self.supported_surface_types != tuple(sorted(set(self.supported_surface_types))):
            raise ValueError("activated Capability surface types must be unique and sorted")
        return self


class ExistingModeCapabilityActivationSet(StrictModel):
    """Content-addressed explicit subset of one verified CAP-005 release set."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/existing-mode-capability-activation-set/v1alpha1",
        "pajin.dev/existing-mode-capability-activation-set/v1alpha2",
    ] = Field(
        default=EXISTING_MODE_CAPABILITY_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExistingModeCapabilityActivationSet"] = "ExistingModeCapabilityActivationSet"
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=120)
    activation_set_digest: str = Field(
        default="",
        alias="activationSetDigest",
        max_length=64,
    )
    release_set_digest: _Sha256 = Field(alias="releaseSetDigest")
    profile: CapabilityUseProfile
    bindings: tuple[ExistingModeCapabilityActivationBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_ACTIVATED_CAPABILITIES,
    )

    @model_validator(mode="after")
    def bind_activation_set_identity(self) -> Self:
        keys = [_activation_binding_key(item) for item in self.bindings]
        if keys != sorted(set(keys)):
            raise ValueError("activated Capability bindings must be unique and canonically sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.existing-mode-activation-set/v1",
            material,
        )
        activation_set_id = f"existing-mode-capability-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("Capability activation-set digest differs from canonical identity")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("Capability activation-set ID differs from canonical identity")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


class PreparedCapabilityAction(StrictModel):
    """Exact CAP-002 request material bound into a later GRAPH-006 proposal."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/prepared-capability-action/v1alpha1"] = Field(
        default=PREPARED_CAPABILITY_ACTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["PreparedCapabilityAction"] = "PreparedCapabilityAction"
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    release: CapabilityReleaseRef
    capability: ActionCapabilityRef
    request: ToolRequest
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")

    @model_validator(mode="after")
    def bind_request_identity(self) -> Self:
        if self.request.tool_id != self.capability.tool_id:
            raise ValueError("prepared Capability action Tool differs from GRAPH authority")
        if capability_tool_request_digest(self.request) != self.request_digest:
            raise ValueError("prepared Capability action request digest differs")
        parameters = cast(Mapping[str, JsonValue], self.request.arguments)
        if capability_normalized_parameters_digest(parameters) != self.normalized_parameters_digest:
            raise ValueError("prepared Capability action parameter digest differs")
        return self


@dataclass(frozen=True, slots=True)
class ExistingModeCapabilityActivation:
    """Verified runtime activation that rechecks signed release authority on use."""

    rollout: ExistingModeCapabilityRollout
    activation_set: ExistingModeCapabilityActivationSet

    def __post_init__(self) -> None:
        _verify_activation(self)

    def action_registry(self) -> ActionCapabilityRegistry:
        """Return the exact immutable registry consumed by GRAPH-006."""

        _verify_activation(self)
        return ActionCapabilityRegistry(
            binding.action_capability for binding in self.activation_set.bindings
        )

    def resolve_for_dispatch(
        self,
        reference: ActionCapabilityRef,
    ) -> ResolvedCapabilityRelease:
        """Revalidate an activated signed release immediately before dispatch."""

        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise ExistingModeCapabilityActivationError(
                "GRAPH Capability reference is not canonical"
            ) from exc
        binding = next(
            (
                item
                for item in self.activation_set.bindings
                if item.action_capability.reference() == canonical
            ),
            None,
        )
        if binding is None:
            raise ExistingModeCapabilityActivationError(
                "GRAPH Capability is not in the opt-in activation set"
            )
        return _resolve_activation_binding(
            self.rollout,
            self.activation_set.profile,
            binding,
        )

    def prepare_action(
        self,
        *,
        release: CapabilityReleaseRef,
        request: ToolRequest,
        parameters: Mapping[str, JsonValue],
    ) -> PreparedCapabilityAction:
        """Materialize and compile one exact request through CAP-002 authorities."""

        canonical_release = _canonical_release_ref(release)
        binding = next(
            (item for item in self.activation_set.bindings if item.release == canonical_release),
            None,
        )
        if binding is None:
            raise ExistingModeCapabilityActivationError(
                "Capability release is not in the opt-in activation set"
            )
        resolved = self.resolve_for_dispatch(binding.action_capability.reference())
        canonical_request = _canonical_tool_request(request)
        try:
            materializer = self.rollout.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.MATERIALIZER,
            )
            compiler = self.rollout.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.ACTION_COMPILER,
            )
            materialized = materializer.materialize(parameters)
            compiled = compiler.compile(canonical_request, materialized)
        except CapabilityAuthorityError as exc:
            raise ExistingModeCapabilityActivationError(
                "CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _PermitDispatcher(Protocol):
    async def dispatch_once(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        dispatch: Callable[[ActionPermit], Awaitable[GatewayOutcome]],
    ) -> ActionDispatchResult[GatewayOutcome]: ...


class _Gateway(Protocol):
    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome: ...


class ExistingModeCapabilityGatewayDispatcher:
    """Bridge activated GRAPH-006 permits into the existing Tool Gateway."""

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        permits: _PermitDispatcher,
        gateway: _Gateway,
        audit_store: CapabilityDispatchAuditStore,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("Capability Gateway dispatch requires a verified activation")
        if not isinstance(getattr(audit_store, "run_id", None), str) or not callable(
            getattr(audit_store, "append_event", None)
        ):
            raise TypeError("Capability Gateway dispatch requires an append-only audit store")
        self._activation = activation
        self._permits = permits
        self._gateway = gateway
        self._audit_store = audit_store
        self._clock = clock or (lambda: datetime.now(UTC))

    async def dispatch_once(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        prepared: PreparedCapabilityAction,
        *,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        used_calls: int,
    ) -> ActionDispatchResult[GatewayOutcome]:
        """Consume the Permit once, then invoke Tool Gateway for the exact request."""

        if isinstance(used_calls, bool) or not isinstance(used_calls, int) or used_calls < 0:
            raise ExistingModeCapabilityActivationError(
                "Capability Gateway used-call count must be a non-negative integer"
            )
        canonical_prepared = _canonical_prepared_action(prepared)
        canonical_campaign = _canonical_model(
            campaign,
            CampaignManifest,
            label="Campaign",
        )
        canonical_grant = _canonical_model(
            grant,
            CapabilityGrant,
            label="Capability Grant",
        )
        if (
            canonical_campaign.metadata.name != proposal.campaign_id
            or canonical_grant.campaign != proposal.campaign_id
        ):
            raise ExistingModeCapabilityActivationError(
                "Tool Gateway authority belongs to another GRAPH Campaign"
            )
        definition = self._validate_proposal(proposal, canonical_prepared)

        async def dispatch(permit: ActionPermit) -> GatewayOutcome:
            self._validate_permit(permit, proposal, canonical_prepared)
            if self._audit_store.run_id != permit.run_id:
                raise ExistingModeCapabilityActivationError(
                    "Capability dispatch audit Run differs from the consumed ActionPermit"
                )
            claimed_at = self._dispatch_time()
            self._append_dispatch_event(
                permit=permit,
                prepared=canonical_prepared,
                grant=canonical_grant,
                stage=CapabilityDispatchStage.CLAIMED,
                occurred_at=claimed_at,
            )
            if claimed_at >= permit.expires_at:
                self._append_dispatch_event(
                    permit=permit,
                    prepared=canonical_prepared,
                    grant=canonical_grant,
                    stage=CapabilityDispatchStage.EXPIRED,
                    occurred_at=self._dispatch_time(),
                )
                raise ExistingModeCapabilityActivationError(
                    "consumed ActionPermit expired before Tool Gateway dispatch"
                )
            try:
                self._activation.resolve_for_dispatch(canonical_prepared.capability)
                outcome = await self._gateway.execute(
                    canonical_campaign,
                    canonical_grant,
                    canonical_prepared.request,
                    used_calls=used_calls,
                )
            except asyncio.CancelledError as exc:
                self._append_dispatch_event(
                    permit=permit,
                    prepared=canonical_prepared,
                    grant=canonical_grant,
                    stage=CapabilityDispatchStage.CANCELLED,
                    occurred_at=self._dispatch_time(),
                    error_type=audit_safe_exception_type(exc),
                )
                raise
            except Exception as exc:
                self._append_dispatch_event(
                    permit=permit,
                    prepared=canonical_prepared,
                    grant=canonical_grant,
                    stage=CapabilityDispatchStage.FAILED,
                    occurred_at=self._dispatch_time(),
                    error_type=audit_safe_exception_type(exc),
                )
                raise
            self._append_dispatch_event(
                permit=permit,
                prepared=canonical_prepared,
                grant=canonical_grant,
                stage=CapabilityDispatchStage.COMPLETED,
                occurred_at=self._dispatch_time(),
                outcome=outcome,
            )
            return outcome

        if proposal.reservation.request_units != definition.request_unit_cost:
            raise ExistingModeCapabilityActivationError(
                "GRAPH reservation understates or overstates Capability request-unit cost"
            )
        return await self._permits.dispatch_once(
            envelope,
            proposal,
            decision,
            dispatch,
        )

    def _validate_proposal(
        self,
        proposal: ActionProposal,
        prepared: PreparedCapabilityAction,
    ) -> CapabilityDefinition:
        if prepared.activation_set_digest != (
            self._activation.activation_set.activation_set_digest
        ):
            raise ExistingModeCapabilityActivationError(
                "prepared action belongs to another Capability activation set"
            )
        resolved = self._activation.resolve_for_dispatch(prepared.capability)
        if (
            proposal.capability != prepared.capability
            or proposal.request_id != prepared.request.request_id
            or proposal.request_digest != prepared.request_digest
            or proposal.normalized_parameters_digest != prepared.normalized_parameters_digest
        ):
            raise ExistingModeCapabilityActivationError(
                "GRAPH ActionProposal differs from the prepared Capability action"
            )
        if resolved.release != prepared.release:
            raise ExistingModeCapabilityActivationError(
                "prepared Capability release differs from current signed authority"
            )
        try:
            return self._activation.rollout.bundle.definitions.resolve(
                resolved.capability.capability
            )
        except CapabilityDefinitionError as exc:
            raise ExistingModeCapabilityActivationError(
                "activated Capability definition drifted before dispatch"
            ) from exc

    @staticmethod
    def _validate_permit(
        permit: ActionPermit,
        proposal: ActionProposal,
        prepared: PreparedCapabilityAction,
    ) -> None:
        if (
            permit.campaign_id != proposal.campaign_id
            or permit.run_id != proposal.run_id
            or permit.proposal_id != proposal.proposal_id
            or permit.proposal_digest != proposal.proposal_digest
            or permit.capability != prepared.capability
            or permit.request_id != prepared.request.request_id
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
        ):
            raise ExistingModeCapabilityActivationError(
                "consumed ActionPermit differs from the prepared Capability action"
            )

    def _append_dispatch_event(
        self,
        *,
        permit: ActionPermit,
        prepared: PreparedCapabilityAction,
        grant: CapabilityGrant,
        stage: CapabilityDispatchStage,
        occurred_at: datetime,
        outcome: GatewayOutcome | None = None,
        error_type: str | None = None,
    ) -> CapabilityDispatchAuditEvent:
        event = CapabilityDispatchAuditEvent(
            stage=stage,
            occurredAt=occurred_at,
            activationSetDigest=prepared.activation_set_digest,
            release=prepared.release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
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
            f"capability.dispatch.{event.stage.value}",
            event.model_dump(mode="json", by_alias=True),
            occurred_at=event.occurred_at,
        )
        return event

    def _dispatch_time(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise ExistingModeCapabilityActivationError(
                "Capability dispatch audit clock failed"
            ) from exc
        return _normalize_dispatch_time(value, label="Capability dispatch audit clock")


def activate_existing_mode_capabilities(
    *,
    rollout: ExistingModeCapabilityRollout,
    releases: Iterable[CapabilityReleaseRef],
    profile: CapabilityUseProfile,
) -> ExistingModeCapabilityActivation:
    """Activate an explicit signed release subset for one allowed usage profile."""

    if not isinstance(rollout, ExistingModeCapabilityRollout):
        raise TypeError("existing Mode activation requires a verified rollout")
    _canonical_rollout(rollout)
    try:
        requested_profile = CapabilityUseProfile(profile)
    except ValueError as exc:
        raise ExistingModeCapabilityActivationError(
            "Capability activation profile is unsupported"
        ) from exc
    canonical_releases = tuple(_canonical_release_ref(item) for item in releases)
    release_keys = [_release_key(item) for item in canonical_releases]
    if not canonical_releases:
        raise ExistingModeCapabilityActivationError(
            "Capability activation requires at least one explicit release"
        )
    if len(release_keys) != len(set(release_keys)):
        raise ExistingModeCapabilityActivationError(
            "Capability activation contains a duplicate release"
        )
    rollout_bindings = {_release_key(item.release): item for item in rollout.release_set.bindings}
    bindings: list[ExistingModeCapabilityActivationBinding] = []
    for release in canonical_releases:
        try:
            release_binding = rollout_bindings[_release_key(release)]
            resolved = rollout.lifecycle.resolve_for_use(release, requested_profile)
            definition = rollout.bundle.definitions.resolve(resolved.capability.capability)
        except (
            CapabilityDefinitionError,
            CapabilityLifecycleError,
            KeyError,
        ) as exc:
            raise ExistingModeCapabilityActivationError(
                "Capability release is not an executable member of the verified rollout"
            ) from exc
        if resolved.capability.reference() != release_binding.capability:
            raise ExistingModeCapabilityActivationError(
                "Capability release authority differs from the rollout binding"
            )
        bindings.append(
            ExistingModeCapabilityActivationBinding(
                release=release,
                capability=resolved.capability.reference(),
                actionCapability=registered_action_capability(definition),
                domain=definition.domain,
                supportedSurfaceTypes=definition.supported_surface_types,
            )
        )
    activation_set = ExistingModeCapabilityActivationSet(
        apiVersion=(
            EXISTING_MODE_CAPABILITY_ACTIVATION_SET_API_VERSION
            if rollout.release_set.api_version == EXISTING_MODE_CAPABILITY_RELEASE_SET_API_VERSION
            else EXISTING_MODE_CAPABILITY_MCP_ACTIVATION_SET_API_VERSION
        ),
        releaseSetDigest=rollout.release_set.release_set_digest,
        profile=requested_profile,
        bindings=tuple(sorted(bindings, key=_activation_binding_key)),
    )
    return ExistingModeCapabilityActivation(
        rollout=rollout,
        activation_set=activation_set,
    )


def capability_tool_request_digest(request: ToolRequest) -> str:
    """Return the exact canonical digest also persisted by Tool Gateway."""

    try:
        return canonical_tool_request_digest(request)
    except ValueError as exc:
        raise ExistingModeCapabilityActivationError(
            "Capability Tool request is not strict canonical JSON"
        ) from exc


def capability_grant_digest(grant: CapabilityGrant) -> str:
    """Bind the exact canonical Gateway grant with deterministic set ordering."""

    canonical = _canonical_model(grant, CapabilityGrant, label="Capability Grant")
    material = canonical.model_dump(mode="json")
    material["tools"] = sorted(canonical.tools)
    material["targets"] = sorted(canonical.targets)
    return capability_definition_digest(
        "pajin.capability.runtime-grant/v1",
        material,
    )


def capability_gateway_outcome_digest(outcome: GatewayOutcome) -> str:
    """Bind the exact Gateway outcome without copying result data into audit events."""

    try:
        canonical = GatewayOutcome.model_validate(outcome.model_dump(mode="json"))
        encoded = json.dumps(
            canonical.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (
        AttributeError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise ExistingModeCapabilityActivationError(
            "Capability Gateway outcome is not strict canonical JSON"
        ) from exc
    if len(encoded) > _MAX_GATEWAY_OUTCOME_BYTES:
        raise ExistingModeCapabilityActivationError(
            "Capability Gateway outcome exceeds the audit digest byte limit"
        )
    domain = b"pajin.capability.gateway-outcome/v1"
    return sha256(
        b"PAJIN-CAPABILITY\0"
        + len(domain).to_bytes(4, "big")
        + domain
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).hexdigest()


def capability_normalized_parameters_digest(
    parameters: Mapping[str, JsonValue],
) -> str:
    """Bind the exact CAP-002 materialized arguments used by GRAPH-006."""

    try:
        return capability_definition_digest(
            "pajin.capability.normalized-parameters/v1",
            dict(parameters),
        )
    except (OverflowError, TypeError, UnicodeError, ValueError) as exc:
        raise ExistingModeCapabilityActivationError(
            "Capability materialized parameters are not canonical JSON"
        ) from exc


def _verify_activation(activation: ExistingModeCapabilityActivation) -> None:
    rollout = _canonical_rollout(activation.rollout)
    try:
        activation_set = ExistingModeCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise ExistingModeCapabilityActivationError(
            "Capability activation set is not canonical"
        ) from exc
    if activation_set.release_set_digest != rollout.release_set.release_set_digest:
        raise ExistingModeCapabilityActivationError(
            "Capability activation references another signed release set"
        )
    expected_api_version = (
        EXISTING_MODE_CAPABILITY_ACTIVATION_SET_API_VERSION
        if rollout.release_set.api_version == EXISTING_MODE_CAPABILITY_RELEASE_SET_API_VERSION
        else EXISTING_MODE_CAPABILITY_MCP_ACTIVATION_SET_API_VERSION
    )
    if activation_set.api_version != expected_api_version:
        raise ExistingModeCapabilityActivationError(
            "Capability activation-set version differs from its signed release inventory"
        )
    release_bindings = {_release_key(item.release): item for item in rollout.release_set.bindings}
    for binding in activation_set.bindings:
        try:
            release_binding = release_bindings[_release_key(binding.release)]
        except KeyError as exc:
            raise ExistingModeCapabilityActivationError(
                "activated release is absent from the verified rollout"
            ) from exc
        if release_binding.capability != binding.capability:
            raise ExistingModeCapabilityActivationError(
                "activated release differs from its rollout authority"
            )
        _resolve_activation_binding(rollout, activation_set.profile, binding)


def _resolve_activation_binding(
    rollout: ExistingModeCapabilityRollout,
    profile: CapabilityUseProfile,
    binding: ExistingModeCapabilityActivationBinding,
) -> ResolvedCapabilityRelease:
    try:
        resolved = rollout.lifecycle.resolve_for_use(binding.release, profile)
        definition = rollout.bundle.definitions.resolve(resolved.capability.capability)
        expected_action = registered_action_capability(definition)
    except (
        CapabilityDefinitionError,
        CapabilityLifecycleError,
    ) as exc:
        raise ExistingModeCapabilityActivationError(
            "activated Capability failed signed release revalidation"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or expected_action != binding.action_capability
        or definition.domain != binding.domain
        or definition.supported_surface_types != binding.supported_surface_types
    ):
        raise ExistingModeCapabilityActivationError("activated Capability registration drifted")
    return resolved


def _canonical_rollout(
    rollout: ExistingModeCapabilityRollout,
) -> ExistingModeCapabilityRollout:
    try:
        return ExistingModeCapabilityRollout(
            bundle=rollout.bundle,
            lifecycle=rollout.lifecycle,
            release_set=rollout.release_set,
            benchmark_mappings=rollout.benchmark_mappings,
        )
    except (AttributeError, ExistingModeCapabilityRolloutError, TypeError) as exc:
        raise ExistingModeCapabilityActivationError(
            "existing Mode rollout failed activation revalidation"
        ) from exc


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise ExistingModeCapabilityActivationError(
            "Capability release reference is not canonical"
        ) from exc


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    try:
        return ToolRequest.model_validate(
            request.model_dump(
                mode="python",
                include=set(ToolRequest.model_fields),
            )
        )
    except (AttributeError, ValidationError) as exc:
        raise ExistingModeCapabilityActivationError(
            "Capability Tool request is not canonical"
        ) from exc


def _canonical_prepared_action(
    prepared: PreparedCapabilityAction,
) -> PreparedCapabilityAction:
    try:
        return PreparedCapabilityAction.model_validate(
            prepared.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise ExistingModeCapabilityActivationError(
            "prepared Capability action is not canonical"
        ) from exc


def _canonical_model[ModelT: StrictModel](
    value: ModelT,
    model_type: type[ModelT],
    *,
    label: str,
) -> ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise ExistingModeCapabilityActivationError(
            f"Capability Gateway {label} is not canonical"
        ) from exc


def _normalize_dispatch_time(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise ExistingModeCapabilityActivationError(f"{label} must be a datetime")
    try:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ExistingModeCapabilityActivationError(f"{label} must include a UTC offset or Z")
        return value.astimezone(UTC)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ExistingModeCapabilityActivationError(f"{label} is invalid") from exc


def _release_key(reference: CapabilityReleaseRef) -> tuple[str, str]:
    return reference.release_id, reference.release_digest


def _activation_binding_key(
    binding: ExistingModeCapabilityActivationBinding,
) -> tuple[str, str, str, str]:
    action = binding.action_capability
    return (
        action.capability_id,
        action.capability_version,
        binding.release.release_id,
        binding.release.release_digest,
    )
