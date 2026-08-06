"""ENG-002C2 explicit opt-in Common Engine execution gate."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.capabilities.activation import (
    CapabilityDispatchAuditStore,
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationError,
    ExistingModeCapabilityActivationSet,
    ExistingModeCapabilityGatewayDispatcher,
    PreparedCapabilityAction,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.models import CapabilitySideEffectClass
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolRiskTier,
)
from pajin.graph.approval import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
)
from pajin.graph.authority import (
    ActionBudgetReservation,
    ActionCapabilityRef,
    ActionDispatchResult,
    ActionProposal,
    GraphActionPermitAuthority,
    GraphActionPermitDispatcher,
    GraphActionPermitStore,
    MissionEnvelope,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.tools.gateway import GatewayOutcome
from pajin.workflow.common_engine import _common_engine_digest
from pajin.workflow.engine_mission_envelope import (
    CommonEngineMissionCapabilityBinding,
    CommonEngineMissionEnvelopeCompilationAuthority,
)

COMMON_ENGINE_ACTION_INTENT_API_VERSION: Literal[
    "pajin.dev/common-engine-action-intent/v1alpha1"
] = "pajin.dev/common-engine-action-intent/v1alpha1"
COMMON_ENGINE_EXECUTION_GATE_COMPILER_API_VERSION: Literal[
    "pajin.dev/common-engine-execution-gate-compiler/v1alpha1"
] = "pajin.dev/common-engine-execution-gate-compiler/v1alpha1"
COMMON_ENGINE_EXECUTION_GATE_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/common-engine-execution-gate-authority/v1alpha1"
] = "pajin.dev/common-engine-execution-gate-authority/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_INTENT_BYTES = 1024 * 1024
_MAX_COMPILER_BYTES = 256 * 1024
_MAX_GATE_AUTHORITY_BYTES = 32 * 1024 * 1024


class CommonEngineExecutionGateError(RuntimeError):
    """Raised when C1 authority cannot enter the explicit Common execution gate."""


class CommonEngineExecutionGateCompiler(StrictModel):
    """Code-owned compiler identity authorized only through the explicit C2 gate."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-execution-gate-compiler/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_EXECUTION_GATE_COMPILER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineExecutionGateCompiler"] = (
        "CommonEngineExecutionGateCompiler"
    )
    compiler_id: Literal["pajin.common-engine.execution-gate-compiler"] = Field(
        default="pajin.common-engine.execution-gate-compiler",
        alias="compilerId",
    )
    compiler_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="compilerVersion",
    )
    compiler_digest: str = Field(default="", alias="compilerDigest", max_length=64)
    source_envelope_scope_mutation_allowed: Literal[False] = Field(
        default=False,
        alias="sourceEnvelopeScopeMutationAllowed",
    )
    action_permit_issuance_authorized: Literal[True] = Field(
        default=True,
        alias="actionPermitIssuanceAuthorized",
    )
    common_runtime_dispatch_authorized: Literal[True] = Field(
        default=True,
        alias="commonRuntimeDispatchAuthorized",
    )
    legacy_default_path_selection_authorized: Literal[False] = Field(
        default=False,
        alias="legacyDefaultPathSelectionAuthorized",
    )

    @model_validator(mode="after")
    def bind_compiler(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"compiler_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-execution-gate-compiler/v1",
            material,
            max_bytes=_MAX_COMPILER_BYTES,
        )
        if self.compiler_digest and self.compiler_digest != digest:
            raise ValueError("Common Engine Execution Gate Compiler Digest differs")
        object.__setattr__(self, "compiler_digest", digest)
        return self


class CommonEngineExecutionGateAuthority(StrictModel):
    """Explicit activation that attenuates C1 into an executable compiler identity."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-execution-gate-authority/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_EXECUTION_GATE_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineExecutionGateAuthority"] = (
        "CommonEngineExecutionGateAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    compiler: CommonEngineExecutionGateCompiler
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    mission_compilation: CommonEngineMissionEnvelopeCompilationAuthority = Field(
        alias="missionCompilation"
    )
    mission_compilation_digest: _Sha256 = Field(alias="missionCompilationDigest")
    source_envelope_digest: _Sha256 = Field(alias="sourceEnvelopeDigest")
    activation_set: ExistingModeCapabilityActivationSet = Field(alias="activationSet")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    envelope: MissionEnvelope
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    gate_state: Literal["explicit-opt-in-ready"] = Field(
        default="explicit-opt-in-ready",
        alias="gateState",
    )
    action_permit_issuance_authorized: Literal[True] = Field(
        default=True,
        alias="actionPermitIssuanceAuthorized",
    )
    common_runtime_dispatch_authorized: Literal[True] = Field(
        default=True,
        alias="commonRuntimeDispatchAuthorized",
    )
    legacy_default_path_changed: Literal[False] = Field(
        default=False,
        alias="legacyDefaultPathChanged",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        compiler = registered_common_engine_execution_gate_compiler()
        compilation = CommonEngineMissionEnvelopeCompilationAuthority.model_validate(
            self.mission_compilation.model_dump(mode="json", by_alias=True)
        )
        activation_set = ExistingModeCapabilityActivationSet.model_validate(
            self.activation_set.model_dump(mode="json", by_alias=True)
        )
        expected_envelope = _execution_envelope(compiler, compilation)
        if (
            self.compiler != compiler
            or self.compiler_digest != compiler.compiler_digest
            or self.mission_compilation != compilation
            or self.mission_compilation_digest != compilation.authority_digest
            or self.source_envelope_digest != compilation.envelope.envelope_digest
            or self.activation_set != activation_set
            or self.activation_set_digest != activation_set.activation_set_digest
            or activation_set != compilation.activation_set
            or self.envelope != expected_envelope
            or self.envelope_digest != expected_envelope.envelope_digest
        ):
            raise ValueError("Common Engine Execution Gate Authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "authority_id",
                "authority_digest",
                "mission_compilation",
                "activation_set",
            },
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-execution-gate-authority/v1",
            material,
            max_bytes=_MAX_GATE_AUTHORITY_BYTES,
        )
        authority_id = f"common-engine-execution-gate:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Common Engine Execution Gate Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Common Engine Execution Gate Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


class CommonEngineActionIntent(StrictModel):
    """Non-executable intent derived from one exact C1 request binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/common-engine-action-intent/v1alpha1"] = Field(
        default=COMMON_ENGINE_ACTION_INTENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineActionIntent"] = "CommonEngineActionIntent"
    intent_id: str = Field(default="", alias="intentId", max_length=92)
    intent_digest: str = Field(default="", alias="intentDigest", max_length=64)
    execution_gate_authority_digest: _Sha256 = Field(
        alias="executionGateAuthorityDigest"
    )
    mission_authority_digest: _Sha256 = Field(alias="missionAuthorityDigest")
    envelope_id: str = Field(alias="envelopeId", min_length=1, max_length=81)
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    campaign_id: _Identifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    binding_ordinal: int = Field(alias="bindingOrdinal", ge=0, le=99)
    binding_digest: _Sha256 = Field(alias="bindingDigest")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    release: CapabilityReleaseRef
    capability: ActionCapabilityRef
    measured_request_digest: _Sha256 = Field(alias="measuredRequestDigest")
    request: ToolRequest
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    target_digest: _Sha256 = Field(alias="targetDigest")
    reservation: ActionBudgetReservation
    intent_state: Literal["requested-not-permitted"] = Field(
        default="requested-not-permitted",
        alias="intentState",
    )
    explicit_opt_in: Literal[True] = Field(default=True, alias="explicitOptIn")
    action_permit_issued: Literal[False] = Field(default=False, alias="actionPermitIssued")
    common_runtime_dispatched: Literal[False] = Field(
        default=False,
        alias="commonRuntimeDispatched",
    )

    @model_validator(mode="after")
    def bind_intent(self) -> Self:
        if self.request.request_id != _execution_request_id(
            self.run_id,
            self.binding_digest,
        ):
            raise ValueError("Common Engine execution request identity differs")
        if self.request.tool_id != self.capability.tool_id:
            raise ValueError("Common Engine intent Tool differs from Capability")
        if self.request_digest != capability_tool_request_digest(self.request):
            raise ValueError("Common Engine intent request digest differs")
        if self.normalized_parameters_digest != capability_normalized_parameters_digest(
            self.request.arguments
        ):
            raise ValueError("Common Engine intent parameter digest differs")
        if self.target_digest != sha256(self.request.target.encode("utf-8")).hexdigest():
            raise ValueError("Common Engine intent target digest differs")
        if self.reservation.tool_calls != 1:
            raise ValueError("Common Engine intent must reserve one Tool call")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"intent_id", "intent_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-action-intent/v1",
            material,
            max_bytes=_MAX_INTENT_BYTES,
        )
        intent_id = f"common-engine-action-intent:{digest}"
        if self.intent_digest and self.intent_digest != digest:
            raise ValueError("Common Engine Action Intent Digest differs")
        if self.intent_id and self.intent_id != intent_id:
            raise ValueError("Common Engine Action Intent ID differs")
        object.__setattr__(self, "intent_digest", digest)
        object.__setattr__(self, "intent_id", intent_id)
        return self


@dataclass(frozen=True, slots=True)
class CommonEngineExecutionGateResult:
    """Runtime result whose durable authorities remain Permit and Run audit events."""

    intent: CommonEngineActionIntent
    proposal: ActionProposal
    dispatch: ActionDispatchResult[GatewayOutcome]


class _Gateway(Protocol):
    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome: ...


def registered_common_engine_execution_gate_compiler(
) -> CommonEngineExecutionGateCompiler:
    """Return the exact ENG-002C2 execution-gate compiler identity."""

    return CommonEngineExecutionGateCompiler()


def compile_common_engine_execution_gate_authority(
    compilation: CommonEngineMissionEnvelopeCompilationAuthority,
    activation: ExistingModeCapabilityActivation,
) -> CommonEngineExecutionGateAuthority:
    """Activate a C1 ceiling for explicit C2 use without widening its authority."""

    try:
        canonical = CommonEngineMissionEnvelopeCompilationAuthority.model_validate(
            compilation.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise CommonEngineExecutionGateError(
            "Common execution activation requires canonical C1 authority"
        ) from exc
    if not isinstance(activation, ExistingModeCapabilityActivation):
        raise CommonEngineExecutionGateError(
            "Common execution activation requires a verified Capability activation"
        )
    try:
        if activation.activation_set != canonical.activation_set:
            raise ValueError("Capability activation differs from C1 authority")
        for binding in canonical.capability_bindings:
            resolved = activation.resolve_for_dispatch(binding.capability)
            if resolved.release != binding.release:
                raise ValueError("Capability release differs from C1 authority")
        compiler = registered_common_engine_execution_gate_compiler()
        envelope = _execution_envelope(compiler, canonical)
        return CommonEngineExecutionGateAuthority(
            compiler=compiler,
            compilerDigest=compiler.compiler_digest,
            missionCompilation=canonical,
            missionCompilationDigest=canonical.authority_digest,
            sourceEnvelopeDigest=canonical.envelope.envelope_digest,
            activationSet=canonical.activation_set,
            activationSetDigest=canonical.activation_set_digest,
            envelope=envelope,
            envelopeDigest=envelope.envelope_digest,
        )
    except (
        ExistingModeCapabilityActivationError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CommonEngineExecutionGateError(
            "Common execution activation failed closed"
        ) from exc


def compile_common_engine_action_intent(
    authority: CommonEngineExecutionGateAuthority,
    binding_ordinal: int,
    *,
    cost_microusd: int,
) -> CommonEngineActionIntent:
    """Compile one non-executable fresh-request intent from exact C2 authority."""

    try:
        canonical = CommonEngineExecutionGateAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise CommonEngineExecutionGateError(
            "Common Engine action intent requires canonical C2 gate authority"
        ) from exc
    return _compile_common_engine_action_intent_from_canonical(
        canonical,
        binding_ordinal,
        cost_microusd=cost_microusd,
    )


def _compile_common_engine_action_intent_from_canonical(
    canonical: CommonEngineExecutionGateAuthority,
    binding_ordinal: int,
    *,
    cost_microusd: int,
) -> CommonEngineActionIntent:
    if (
        isinstance(binding_ordinal, bool)
        or not isinstance(binding_ordinal, int)
        or binding_ordinal < 0
        or binding_ordinal >= len(
            canonical.mission_compilation.capability_bindings
        )
    ):
        raise CommonEngineExecutionGateError(
            "Common Engine action intent binding ordinal is invalid"
        )
    if (
        isinstance(cost_microusd, bool)
        or not isinstance(cost_microusd, int)
        or cost_microusd < 0
        or cost_microusd > canonical.envelope.budget.cost_limit_microusd
    ):
        raise CommonEngineExecutionGateError(
            "Common Engine action intent cost reservation exceeds C2 authority"
        )
    binding = canonical.mission_compilation.capability_bindings[binding_ordinal]
    request = _execution_request(binding, canonical.envelope.run_id)
    return CommonEngineActionIntent(
        executionGateAuthorityDigest=canonical.authority_digest,
        missionAuthorityDigest=canonical.mission_compilation.authority_digest,
        envelopeId=canonical.envelope.envelope_id,
        envelopeDigest=canonical.envelope.envelope_digest,
        campaignId=canonical.envelope.campaign_id,
        runId=canonical.envelope.run_id,
        bindingOrdinal=binding_ordinal,
        bindingDigest=binding.binding_digest,
        activationSetDigest=binding.activation_set_digest,
        release=binding.release,
        capability=binding.capability,
        measuredRequestDigest=binding.request_digest,
        request=request,
        requestDigest=capability_tool_request_digest(request),
        normalizedParametersDigest=binding.normalized_parameters_digest,
        targetDigest=binding.target_digest,
        reservation=ActionBudgetReservation(
            requestUnits=binding.request_units,
            costMicrousd=cost_microusd,
        ),
    )


class CommonEngineExecutionGate:
    """Explicitly opt one C2 intent into existing Permit and Gateway authorities."""

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        permit_store: GraphActionPermitStore,
        gateway: _Gateway,
        audit_store: CapabilityDispatchAuditStore,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("Common execution gate requires a verified Capability activation")
        if not isinstance(getattr(audit_store, "run_id", None), str) or not callable(
            getattr(audit_store, "append_event", None)
        ):
            raise TypeError("Common execution gate requires an append-only audit store")
        self._activation = activation
        self._policies = ActionApprovalCapabilityPolicyRegistry(
            tuple(
                ActionApprovalCapabilityPolicy(
                    capability=item.action_capability.reference(),
                    sideEffectClass=definition.side_effect_class.value,
                    approvalRequired=definition.approval_required,
                    cleanupRequired=definition.cleanup_required,
                )
                for item in activation.activation_set.bindings
                for definition in (
                    activation.rollout.bundle.definitions.resolve(
                        item.capability.capability
                    ),
                )
            )
        )
        self._permit_store = permit_store
        self._gateway = gateway
        self._audit_store = audit_store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl
        self._gate_authority_digest: str | None = None
        self._dispatcher: ExistingModeCapabilityGatewayDispatcher | None = None

    async def dispatch_once(
        self,
        authority: CommonEngineExecutionGateAuthority,
        intent: CommonEngineActionIntent,
        decision: GraphDecision,
        *,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
    ) -> CommonEngineExecutionGateResult:
        """Revalidate every predecessor, atomically consume a Permit, and dispatch once."""

        canonical_authority, canonical_intent, canonical_decision = _canonical_gate_inputs(
            authority,
            intent,
            decision,
        )
        expected_intent = _compile_common_engine_action_intent_from_canonical(
            canonical_authority,
            canonical_intent.binding_ordinal,
            cost_microusd=canonical_intent.reservation.cost_microusd,
        )
        if canonical_intent != expected_intent:
            raise CommonEngineExecutionGateError(
                "Common Engine Action Intent differs from C2 authority"
            )
        binding = canonical_authority.mission_compilation.capability_bindings[
            canonical_intent.binding_ordinal
        ]
        canonical_campaign = _canonical_campaign(campaign)
        canonical_grant = _canonical_grant(grant)
        evaluated_at = self._evaluated_at()
        self._validate_gate_authority(
            canonical_authority,
            canonical_intent,
            canonical_decision,
            canonical_campaign,
            canonical_grant,
            evaluated_at,
        )
        prepared = self._prepare_current_action(binding, canonical_intent)
        self._require_plain_definition_policy(binding)
        if prepared.capability.risk_tier >= ToolRiskTier.T2:
            raise CommonEngineExecutionGateError(
                "T2 or higher Common action requires an approval-aware execution gate"
            )
        proposal = ActionProposal(
            campaignId=canonical_intent.campaign_id,
            runId=canonical_intent.run_id,
            envelopeId=canonical_intent.envelope_id,
            envelopeDigest=canonical_intent.envelope_digest,
            decisionId=canonical_decision.decision_id,
            decisionDigest=canonical_decision.decision_digest,
            snapshot=canonical_decision.snapshot,
            proposerId=canonical_decision.actor_id,
            proposerDigest=canonical_decision.actor_digest,
            capability=canonical_intent.capability,
            targetDigest=canonical_intent.target_digest,
            requestId=canonical_intent.request.request_id,
            requestDigest=canonical_intent.request_digest,
            normalizedParametersDigest=canonical_intent.normalized_parameters_digest,
            riskTier=canonical_intent.capability.risk_tier,
            reservation=canonical_intent.reservation,
            createdAt=canonical_decision.created_at,
        )
        dispatcher = self._bound_dispatcher(canonical_authority)
        used_calls = sum(
            permit.run_id == canonical_intent.run_id
            for permit in self._permit_store.permits()
        )
        dispatch = await dispatcher.dispatch_once(
            canonical_authority.envelope,
            proposal,
            canonical_decision,
            prepared,
            campaign=canonical_campaign,
            grant=canonical_grant,
            used_calls=used_calls,
        )
        return CommonEngineExecutionGateResult(
            intent=canonical_intent,
            proposal=proposal,
            dispatch=dispatch,
        )

    def _bound_dispatcher(
        self,
        authority: CommonEngineExecutionGateAuthority,
    ) -> ExistingModeCapabilityGatewayDispatcher:
        if self._dispatcher is not None:
            if self._gate_authority_digest != authority.authority_digest:
                raise CommonEngineExecutionGateError(
                    "Common execution gate is pinned to another C2 authority"
                )
            return self._dispatcher
        permit_authority = GraphActionPermitAuthority(
            campaign_id=authority.envelope.campaign_id,
            compiler_id=authority.envelope.compiler_id,
            compiler_version=authority.envelope.compiler_version,
            compiler_digest=authority.envelope.compiler_digest,
            capabilities=self._activation.action_registry(),
            policies=self._policies,
            permit_store=self._permit_store,
            clock=self._evaluated_at,
            permit_ttl=self._permit_ttl,
        )
        self._dispatcher = ExistingModeCapabilityGatewayDispatcher(
            activation=self._activation,
            permits=GraphActionPermitDispatcher(permit_authority),
            gateway=self._gateway,
            audit_store=self._audit_store,
            clock=self._evaluated_at,
        )
        self._gate_authority_digest = authority.authority_digest
        return self._dispatcher

    def _validate_gate_authority(
        self,
        authority: CommonEngineExecutionGateAuthority,
        intent: CommonEngineActionIntent,
        decision: GraphDecision,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        evaluated_at: datetime,
    ) -> None:
        if (
            self._activation.activation_set != authority.activation_set
            or self._activation.activation_set.activation_set_digest
            != authority.activation_set_digest
        ):
            raise CommonEngineExecutionGateError(
                "current Capability activation differs from C1 authority"
            )
        if campaign != authority.mission_compilation.profile_compilation.source_campaign:
            raise CommonEngineExecutionGateError(
                "Common execution Campaign differs from C2 authority"
            )
        if self._audit_store.run_id != intent.run_id:
            raise CommonEngineExecutionGateError(
                "Common execution audit Run differs from C1 authority"
            )
        if (
            decision.campaign_id != intent.campaign_id
            or decision.decision_kind is not GraphDecisionKind.ACTION_PROPOSAL
            or decision.decision_payload_digest != intent.intent_digest
            or decision.snapshot.campaign_id != intent.campaign_id
        ):
            raise CommonEngineExecutionGateError(
                "Graph Decision does not authorize the exact Common action intent"
            )
        if not authority.envelope.not_before <= decision.created_at <= evaluated_at:
            raise CommonEngineExecutionGateError(
                "Common action decision is outside the Envelope timeline"
            )
        request = intent.request
        if (
            grant.campaign != intent.campaign_id
            or grant.subject != request.agent_id
            or request.tool_id not in grant.tools
            or request.target not in grant.targets
            or grant.max_risk_tier < intent.capability.risk_tier
            or grant.max_calls < authority.envelope.budget.tool_call_limit
            or not grant.issued_at <= evaluated_at < grant.expires_at
        ):
            raise CommonEngineExecutionGateError(
                "Capability Grant does not cover the exact Common action authority"
            )

    def _prepare_current_action(
        self,
        binding: CommonEngineMissionCapabilityBinding,
        intent: CommonEngineActionIntent,
    ) -> PreparedCapabilityAction:
        try:
            prepared = self._activation.prepare_action(
                release=binding.release,
                request=intent.request,
                parameters=intent.request.arguments,
            )
        except ExistingModeCapabilityActivationError:
            raise
        if (
            prepared.activation_set_digest != intent.activation_set_digest
            or prepared.release != intent.release
            or prepared.capability != intent.capability
            or prepared.request != intent.request
            or prepared.request_digest != intent.request_digest
            or prepared.normalized_parameters_digest
            != intent.normalized_parameters_digest
            or not _same_request_semantics(binding.request, intent.request)
        ):
            raise CommonEngineExecutionGateError(
                "current Capability materialization differs from C1 action intent"
            )
        return prepared

    @staticmethod
    def _require_plain_definition_policy(
        binding: CommonEngineMissionCapabilityBinding,
    ) -> None:
        definition = binding.definition
        if definition.approval_required:
            raise CommonEngineExecutionGateError(
                "approval-required Common action requires an approval-aware execution gate"
            )
        if (
            definition.cleanup_required
            or definition.side_effect_class
            not in {
                CapabilitySideEffectClass.NONE,
                CapabilitySideEffectClass.READ_ONLY,
            }
        ):
            raise CommonEngineExecutionGateError(
                "write or cleanup Common action requires a cleanup-aware execution gate"
            )

    def _evaluated_at(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise CommonEngineExecutionGateError(
                "Common execution gate clock failed"
            ) from exc
        if value.tzinfo is None or value.utcoffset() is None:
            raise CommonEngineExecutionGateError(
                "Common execution gate clock requires a UTC offset or Z"
            )
        return value.astimezone(UTC)


def _canonical_gate_inputs(
    authority: CommonEngineExecutionGateAuthority,
    intent: CommonEngineActionIntent,
    decision: GraphDecision,
) -> tuple[
    CommonEngineExecutionGateAuthority,
    CommonEngineActionIntent,
    GraphDecision,
]:
    try:
        return (
            CommonEngineExecutionGateAuthority.model_validate(
                authority.model_dump(mode="json", by_alias=True)
            ),
            CommonEngineActionIntent.model_validate(
                intent.model_dump(mode="json", by_alias=True)
            ),
            GraphDecision.model_validate(
                decision.model_dump(mode="json", by_alias=True)
            ),
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise CommonEngineExecutionGateError(
            "Common execution gate input is not canonical"
        ) from exc


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    try:
        return CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise CommonEngineExecutionGateError(
            "Common execution Campaign is not canonical"
        ) from exc


def _canonical_grant(grant: CapabilityGrant) -> CapabilityGrant:
    try:
        return CapabilityGrant.model_validate(
            grant.model_dump(mode="json")
        )
    except (AttributeError, ValidationError) as exc:
        raise CommonEngineExecutionGateError(
            "Common execution Capability Grant is not canonical"
        ) from exc


def _execution_envelope(
    compiler: CommonEngineExecutionGateCompiler,
    compilation: CommonEngineMissionEnvelopeCompilationAuthority,
) -> MissionEnvelope:
    payload = compilation.envelope.model_dump(mode="json", by_alias=True)
    payload.update(
        {
            "envelopeId": "",
            "envelopeDigest": "",
            "compilerId": compiler.compiler_id,
            "compilerVersion": compiler.compiler_version,
            "compilerDigest": compiler.compiler_digest,
        }
    )
    return MissionEnvelope.model_validate(payload)


def _execution_request(
    binding: CommonEngineMissionCapabilityBinding,
    run_id: str,
) -> ToolRequest:
    payload = binding.request.model_dump(mode="python")
    payload["request_id"] = _execution_request_id(run_id, binding.binding_digest)
    return ToolRequest.model_validate(payload)


def _execution_request_id(run_id: str, binding_digest: str) -> str:
    digest = sha256(
        f"pajin.common-engine.execution-request/v1\0{run_id}\0{binding_digest}".encode()
    ).hexdigest()
    return f"common_engine_{digest}"


def _same_request_semantics(measured: ToolRequest, execution: ToolRequest) -> bool:
    return measured.model_dump(mode="python", exclude={"request_id"}) == (
        execution.model_dump(mode="python", exclude={"request_id"})
    )
