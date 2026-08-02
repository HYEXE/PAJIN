"""ENG-002C1 parity-bound, non-expanding MissionEnvelope compilation."""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
from decimal import ROUND_FLOOR, Decimal
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import (
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationBinding,
    ExistingModeCapabilityActivationError,
    ExistingModeCapabilityActivationSet,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.adapters import tool_spec_digest
from pajin.capabilities.lifecycle import CapabilityReleaseBundle, CapabilityReleaseRef
from pajin.capabilities.models import CapabilityDefinition
from pajin.domain.models import AgentPlan, CampaignManifest, StrictModel, ToolRequest
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionCapabilityRef,
    MissionEnvelope,
)
from pajin.policy.scope import scope_matches
from pajin.tools.base import ToolSpec
from pajin.workflow.common_engine import _common_engine_digest
from pajin.workflow.engine_behavioral_parity import (
    COMMON_ENGINE_BEHAVIORAL_PARITY_API_VERSION,
    CommonEngineBehavioralParityAuthority,
)
from pajin.workflow.profile_compatibility import (
    LEGACY_CAMPAIGN_PROFILE_COMPILATION_API_VERSION,
    LegacyCampaignProfileCompilationAuthority,
)

COMMON_ENGINE_MISSION_ENVELOPE_COMPILER_API_VERSION: Literal[
    "pajin.dev/common-engine-mission-envelope-compiler/v1alpha1"
] = "pajin.dev/common-engine-mission-envelope-compiler/v1alpha1"
COMMON_ENGINE_MISSION_CAPABILITY_BINDING_API_VERSION: Literal[
    "pajin.dev/common-engine-mission-capability-binding/v1alpha1"
] = "pajin.dev/common-engine-mission-capability-binding/v1alpha1"
COMMON_ENGINE_MISSION_ENVELOPE_COMPILATION_API_VERSION: Literal[
    "pajin.dev/common-engine-mission-envelope-compilation/v1alpha1"
] = "pajin.dev/common-engine-mission-envelope-compilation/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_COMPILER_BYTES = 256 * 1024
_MAX_BINDING_BYTES = 512 * 1024
_MAX_AUTHORITY_BYTES = 128 * 1024 * 1024
_INTERSECTION_CONSTRAINTS = (
    "campaign-authorization-window",
    "campaign-budget-ceiling",
    "campaign-risk-ceiling",
    "campaign-scope-intersection",
    "registered-capability-subset",
    "sealed-behavioral-parity",
)


class CommonEngineMissionEnvelopeCompilationError(RuntimeError):
    """Raised when predecessor authority cannot compile a non-expanding Envelope."""


class CommonEngineMissionEnvelopeCompiler(StrictModel):
    """Code-owned compiler identity that cannot issue a Permit or dispatch runtime work."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-mission-envelope-compiler/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_MISSION_ENVELOPE_COMPILER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineMissionEnvelopeCompiler"] = (
        "CommonEngineMissionEnvelopeCompiler"
    )
    compiler_id: Literal["pajin.common-engine.mission-envelope-compiler"] = Field(
        default="pajin.common-engine.mission-envelope-compiler",
        alias="compilerId",
    )
    compiler_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="compilerVersion",
    )
    compiler_digest: str = Field(default="", alias="compilerDigest", max_length=64)
    accepted_profile_compilation_api_version: Literal[
        "pajin.dev/legacy-campaign-profile-compilation/v1alpha1"
    ] = Field(
        default=LEGACY_CAMPAIGN_PROFILE_COMPILATION_API_VERSION,
        alias="acceptedProfileCompilationApiVersion",
    )
    accepted_behavioral_parity_api_version: Literal[
        "pajin.dev/common-engine-behavioral-parity/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_BEHAVIORAL_PARITY_API_VERSION,
        alias="acceptedBehavioralParityApiVersion",
    )
    intersection_constraints: tuple[str, ...] = Field(
        default=_INTERSECTION_CONSTRAINTS,
        alias="intersectionConstraints",
        min_length=6,
        max_length=6,
    )
    campaign_mutation_allowed: Literal[False] = Field(
        default=False,
        alias="campaignMutationAllowed",
    )
    roe_defaults_application_authorized: Literal[False] = Field(
        default=False,
        alias="roeDefaultsApplicationAuthorized",
    )
    action_permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="actionPermitIssuanceAuthorized",
    )
    common_runtime_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="commonRuntimeDispatchAuthorized",
    )

    @model_validator(mode="after")
    def bind_compiler(self) -> Self:
        if self.intersection_constraints != _INTERSECTION_CONSTRAINTS:
            raise ValueError("MissionEnvelope compiler intersection constraints differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"compiler_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-mission-envelope-compiler/v1",
            material,
            max_bytes=_MAX_COMPILER_BYTES,
        )
        if self.compiler_digest and self.compiler_digest != digest:
            raise ValueError("Common Engine MissionEnvelope Compiler Digest differs")
        object.__setattr__(self, "compiler_digest", digest)
        return self


class CommonEngineMissionCapabilityBinding(StrictModel):
    """Bind one measured Plan request to one exact signed activated Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-mission-capability-binding/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_MISSION_CAPABILITY_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineMissionCapabilityBinding"] = (
        "CommonEngineMissionCapabilityBinding"
    )
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    request_ordinal: int = Field(alias="requestOrdinal", ge=0, le=99)
    request: ToolRequest
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    target_digest: _Sha256 = Field(alias="targetDigest")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    release: CapabilityReleaseRef
    release_bundle: CapabilityReleaseBundle = Field(alias="releaseBundle")
    definition: CapabilityDefinition
    capability: ActionCapabilityRef
    request_units: int = Field(alias="requestUnits", ge=1, le=100)
    authority_not_before: datetime = Field(alias="authorityNotBefore")
    authority_expires_at: datetime = Field(alias="authorityExpiresAt")

    @field_validator("authority_not_before", "authority_expires_at")
    @classmethod
    def normalize_authority_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Capability authority time must include a UTC offset or Z")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_request(self) -> Self:
        if self.request.tool_id != self.capability.tool_id:
            raise ValueError("Mission Capability binding Tool differs")
        if (
            self.release_bundle.release.statement.reference() != self.release
            or self.release_bundle.release.statement.capability.capability
            != self.definition.reference()
            or self.definition.reference().capability_id
            != self.capability.capability_id
            or self.definition.reference().capability_version
            != self.capability.capability_version
            or self.definition.capability_digest != self.capability.definition_digest
            or self.definition.tool.tool_id != self.capability.tool_id
            or self.definition.tool.tool_version != self.capability.tool_version
            or self.definition.tool.tool_digest != self.capability.tool_digest
            or self.definition.risk_tier != self.capability.risk_tier
            or self.definition.request_unit_cost != self.request_units
        ):
            raise ValueError("Mission Capability binding definition differs")
        release_not_before, release_expires_at = _release_authority_window(
            self.release_bundle
        )
        if (
            self.authority_not_before != release_not_before
            or self.authority_expires_at != release_expires_at
        ):
            raise ValueError("Mission Capability binding release window differs")
        if self.request_digest != capability_tool_request_digest(self.request):
            raise ValueError("Mission Capability binding request digest differs")
        if self.normalized_parameters_digest != capability_normalized_parameters_digest(
            self.request.arguments
        ):
            raise ValueError("Mission Capability binding parameter digest differs")
        if self.target_digest != sha256(self.request.target.encode("utf-8")).hexdigest():
            raise ValueError("Mission Capability binding target digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-mission-capability-binding/v1",
            material,
            max_bytes=_MAX_BINDING_BYTES,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Mission Capability Binding Digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


class CommonEngineMissionEnvelopeCompilationAuthority(StrictModel):
    """Content-addressed Envelope compilation with execution authority still disabled."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-mission-envelope-compilation/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_MISSION_ENVELOPE_COMPILATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineMissionEnvelopeCompilationAuthority"] = (
        "CommonEngineMissionEnvelopeCompilationAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    compiler: CommonEngineMissionEnvelopeCompiler
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    profile_compilation: LegacyCampaignProfileCompilationAuthority = Field(
        alias="profileCompilation"
    )
    profile_compilation_digest: _Sha256 = Field(alias="profileCompilationDigest")
    behavioral_parity: CommonEngineBehavioralParityAuthority = Field(
        alias="behavioralParity"
    )
    behavioral_parity_digest: _Sha256 = Field(alias="behavioralParityDigest")
    semantic_behavior_digest: _Sha256 = Field(alias="semanticBehaviorDigest")
    activation_set: ExistingModeCapabilityActivationSet = Field(alias="activationSet")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    run_id: _Identifier = Field(alias="runId")
    requested_not_before: datetime = Field(alias="requestedNotBefore")
    capability_bindings: tuple[CommonEngineMissionCapabilityBinding, ...] = Field(
        alias="capabilityBindings",
        min_length=1,
        max_length=100,
    )
    envelope: MissionEnvelope
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    compilation_state: Literal["mission-envelope-compiled-not-executable"] = Field(
        default="mission-envelope-compiled-not-executable",
        alias="compilationState",
    )
    authority_intersection_enforced: Literal[True] = Field(
        default=True,
        alias="authorityIntersectionEnforced",
    )
    mission_envelope_compiled: Literal[True] = Field(
        default=True,
        alias="missionEnvelopeCompiled",
    )
    action_permit_issued: Literal[False] = Field(default=False, alias="actionPermitIssued")
    common_runtime_dispatched: Literal[False] = Field(
        default=False,
        alias="commonRuntimeDispatched",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @field_validator("requested_not_before")
    @classmethod
    def normalize_requested_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("MissionEnvelope requested start must include a UTC offset or Z")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        compiler = registered_common_engine_mission_envelope_compiler()
        compilation = LegacyCampaignProfileCompilationAuthority.model_validate(
            self.profile_compilation.model_dump(mode="json", by_alias=True)
        )
        parity = CommonEngineBehavioralParityAuthority.model_validate(
            self.behavioral_parity.model_dump(mode="json", by_alias=True)
        )
        activation_set = ExistingModeCapabilityActivationSet.model_validate(
            self.activation_set.model_dump(mode="json", by_alias=True)
        )
        bindings = tuple(
            CommonEngineMissionCapabilityBinding.model_validate(
                item.model_dump(mode="json", by_alias=True)
            )
            for item in self.capability_bindings
        )
        _validate_predecessors(compilation, parity)
        _validate_bindings(compilation.source_campaign, parity, activation_set, bindings)
        expected_envelope = _build_envelope(
            compiler,
            compilation,
            parity,
            self.run_id,
            self.requested_not_before,
            bindings,
        )
        if (
            self.compiler != compiler
            or self.compiler_digest != compiler.compiler_digest
            or self.profile_compilation != compilation
            or self.profile_compilation_digest != compilation.authority_digest
            or self.behavioral_parity != parity
            or self.behavioral_parity_digest != parity.authority_digest
            or self.semantic_behavior_digest != parity.semantic_behavior_digest
            or self.activation_set != activation_set
            or self.activation_set_digest != activation_set.activation_set_digest
            or self.capability_bindings != bindings
            or self.envelope != expected_envelope
            or self.envelope_digest != expected_envelope.envelope_digest
        ):
            raise ValueError("Common Engine MissionEnvelope compilation authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "authority_id",
                "authority_digest",
                "profile_compilation",
                "behavioral_parity",
                "activation_set",
            },
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-mission-envelope-compilation/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"common-engine-mission-envelope:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("MissionEnvelope Compilation Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("MissionEnvelope Compilation Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_common_engine_mission_envelope_compiler(
) -> CommonEngineMissionEnvelopeCompiler:
    """Return the exact ENG-002C1 compiler identity."""

    return CommonEngineMissionEnvelopeCompiler()


def compile_common_engine_mission_envelope(
    compilation: LegacyCampaignProfileCompilationAuthority,
    parity: CommonEngineBehavioralParityAuthority,
    activation: ExistingModeCapabilityActivation,
    *,
    run_id: str,
    not_before: datetime,
) -> CommonEngineMissionEnvelopeCompilationAuthority:
    """Compile a non-expanding Envelope without issuing a Permit or dispatching work."""

    try:
        canonical_compilation = LegacyCampaignProfileCompilationAuthority.model_validate(
            compilation.model_dump(mode="json", by_alias=True)
        )
        canonical_parity = CommonEngineBehavioralParityAuthority.model_validate(
            parity.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise CommonEngineMissionEnvelopeCompilationError(
            "MissionEnvelope predecessor authority is not canonical"
        ) from exc
    try:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise ValueError(
                "MissionEnvelope compilation requires a verified Capability activation"
            )
        _validate_predecessors(canonical_compilation, canonical_parity)
        activation_set = ExistingModeCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
        plan = _normalized_plan(canonical_parity)
        bindings = tuple(
            _resolve_request_capability(
                activation,
                activation_set,
                canonical_parity,
                ordinal,
                request,
            )
            for ordinal, request in enumerate(step.request for step in plan.steps)
        )
        compiler = registered_common_engine_mission_envelope_compiler()
        envelope = _build_envelope(
            compiler,
            canonical_compilation,
            canonical_parity,
            run_id,
            not_before,
            bindings,
        )
        return CommonEngineMissionEnvelopeCompilationAuthority(
            compiler=compiler,
            compilerDigest=compiler.compiler_digest,
            profileCompilation=canonical_compilation,
            profileCompilationDigest=canonical_compilation.authority_digest,
            behavioralParity=canonical_parity,
            behavioralParityDigest=canonical_parity.authority_digest,
            semanticBehaviorDigest=canonical_parity.semantic_behavior_digest,
            activationSet=activation_set,
            activationSetDigest=activation_set.activation_set_digest,
            runId=run_id,
            requestedNotBefore=not_before,
            capabilityBindings=bindings,
            envelope=envelope,
            envelopeDigest=envelope.envelope_digest,
        )
    except (
        AttributeError,
        ExistingModeCapabilityActivationError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CommonEngineMissionEnvelopeCompilationError(
            "MissionEnvelope authority intersection failed closed"
        ) from exc


def _validate_predecessors(
    compilation: LegacyCampaignProfileCompilationAuthority,
    parity: CommonEngineBehavioralParityAuthority,
) -> None:
    measured_compilation = (
        parity.dual_runtime.planner_parity.adapter_selection.compilation
    )
    if (
        compilation != measured_compilation
        or compilation.authority_digest != measured_compilation.authority_digest
        or compilation.source_mode is not parity.legacy_observation.source_mode
        or not parity.profile_adapter_parity_admitted
        or not parity.fixture_parity_proven
        or parity.mission_envelope_compiled
        or parity.common_execution_authorized
    ):
        raise ValueError("Profile compilation differs from complete behavioral parity")


def _normalized_plan(parity: CommonEngineBehavioralParityAuthority) -> AgentPlan:
    try:
        return AgentPlan.model_validate(
            parity.dual_runtime.planner_parity.adapter_plan.normalized_plan
        )
    except ValidationError as exc:
        raise ValueError("behavioral parity normalized Plan is invalid") from exc


def _resolve_request_capability(
    activation: ExistingModeCapabilityActivation,
    activation_set: ExistingModeCapabilityActivationSet,
    parity: CommonEngineBehavioralParityAuthority,
    ordinal: int,
    request: ToolRequest,
) -> CommonEngineMissionCapabilityBinding:
    coordinate = parity.dual_runtime.adapter_execution.coordinate
    tool_binding = next(
        (item for item in coordinate.tool_bindings if item.tool_id == request.tool_id),
        None,
    )
    if tool_binding is None:
        raise ValueError(
            "Plan request Tool is outside the measured runtime coordinate"
        )
    spec = ToolSpec.model_validate(tool_binding.spec)
    matches: list[
        tuple[ExistingModeCapabilityActivationBinding, CapabilityDefinition, str]
    ] = []
    for binding in activation_set.bindings:
        action = binding.action_capability
        definition = activation.rollout.bundle.definitions.resolve(
            binding.capability.capability
        )
        if (
            action.tool_id != request.tool_id
            or action.tool_version != spec.version
            or action.tool_digest != tool_spec_digest(spec)
        ):
            continue
        try:
            prepared = activation.prepare_action(
                release=binding.release,
                request=request,
                parameters=request.arguments,
            )
        except ExistingModeCapabilityActivationError:
            continue
        if prepared.request == request and prepared.capability == action.reference():
            matches.append(
                (
                    binding,
                    definition,
                    prepared.normalized_parameters_digest,
                )
            )
    if len(matches) != 1:
        raise ValueError(
            "measured Plan request does not resolve to one exact activated Capability"
        )
    binding, definition, parameters_digest = matches[0]
    release_bundle = activation.rollout.lifecycle.resolve_release(binding.release)
    authority_not_before, authority_expires_at = _release_authority_window(
        release_bundle
    )
    return CommonEngineMissionCapabilityBinding(
        requestOrdinal=ordinal,
        request=request,
        requestDigest=capability_tool_request_digest(request),
        normalizedParametersDigest=parameters_digest,
        targetDigest=sha256(request.target.encode("utf-8")).hexdigest(),
        activationSetDigest=activation_set.activation_set_digest,
        release=binding.release,
        releaseBundle=release_bundle,
        definition=definition,
        capability=binding.action_capability.reference(),
        requestUnits=definition.request_unit_cost,
        authorityNotBefore=authority_not_before,
        authorityExpiresAt=authority_expires_at,
    )


def _validate_bindings(
    campaign: CampaignManifest,
    parity: CommonEngineBehavioralParityAuthority,
    activation_set: ExistingModeCapabilityActivationSet,
    bindings: tuple[CommonEngineMissionCapabilityBinding, ...],
) -> None:
    plan = _normalized_plan(parity)
    rules = campaign.spec.rules_of_engagement
    if len(bindings) != len(plan.steps):
        raise ValueError("Mission Capability binding count differs from measured Plan")
    activation_by_release = {
        item.release.release_digest: item for item in activation_set.bindings
    }
    coordinate_tools = {
        item.tool_id: ToolSpec.model_validate(item.spec)
        for item in parity.dual_runtime.adapter_execution.coordinate.tool_bindings
    }
    for ordinal, (step, binding) in enumerate(zip(plan.steps, bindings, strict=True)):
        activated = activation_by_release.get(binding.release.release_digest)
        spec = coordinate_tools.get(binding.request.tool_id)
        if (
            binding.request_ordinal != ordinal
            or binding.request != step.request
            or binding.activation_set_digest != activation_set.activation_set_digest
            or activated is None
            or binding.release_bundle.release.statement.reference() != binding.release
            or activated.action_capability.reference() != binding.capability
            or activated.capability.capability != binding.definition.reference()
            or activated.action_capability.definition_digest
            != binding.definition.capability_digest
            or binding.definition.request_unit_cost != binding.request_units
            or spec is None
            or binding.capability.tool_version != spec.version
            or binding.capability.tool_digest != tool_spec_digest(spec)
            or binding.request.method not in rules.allowed_methods
            or binding.capability.risk_tier
            > rules.max_tool_risk_tier
            or (
                bool(rules.allowed_tool_categories)
                and not spec.categories <= rules.allowed_tool_categories
            )
            or bool(spec.categories & rules.prohibit)
        ):
            raise ValueError("Mission Capability binding expands predecessor authority")
        try:
            target_denied = any(
                scope_matches(rule, binding.request.target)
                for rule in campaign.spec.scope.deny
            )
            target_allowed = any(
                scope_matches(rule, binding.request.target)
                for rule in campaign.spec.scope.allow
            )
        except ValueError as exc:
            raise ValueError("Mission Capability target scope is not canonical") from exc
        if target_denied or not target_allowed:
            raise ValueError("Mission Capability target expands Campaign scope")
    _require_successful_receipts(parity, len(bindings))


def _require_successful_receipts(
    parity: CommonEngineBehavioralParityAuthority,
    expected_count: int,
) -> None:
    evidence = parity.adapter_observation.normalized_receipt.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != expected_count:
        raise ValueError("MissionEnvelope requires complete measured receipts")
    for receipt in evidence:
        if not isinstance(receipt, dict):
            raise ValueError("MissionEnvelope measured receipt is invalid")
        policy = receipt.get("policyDecision")
        result = receipt.get("result")
        worker = receipt.get("workerResult")
        if (
            receipt.get("networkLogTrusted") is not True
            or not isinstance(policy, dict)
            or policy.get("allowed") is not True
            or not isinstance(result, dict)
            or result.get("success") is not True
            or not isinstance(worker, dict)
            or worker.get("status") != "succeeded"
            or worker.get("exit_code") != 0
        ):
            raise ValueError("MissionEnvelope requires successful trusted measured receipts")


def _build_envelope(
    compiler: CommonEngineMissionEnvelopeCompiler,
    compilation: LegacyCampaignProfileCompilationAuthority,
    parity: CommonEngineBehavioralParityAuthority,
    run_id: str,
    not_before: datetime,
    bindings: tuple[CommonEngineMissionCapabilityBinding, ...],
) -> MissionEnvelope:
    campaign = compilation.source_campaign
    requested_start = _canonical_not_before(campaign, parity, run_id, not_before)
    canonical_start = max(
        requested_start,
        *(binding.authority_not_before for binding in bindings),
    )
    windows = campaign.spec.rules_of_engagement.testing_windows
    if windows and not all(
        len(window.days) == 7
        and window.start_time == time(0, 0)
        and window.end_time == time(0, 0)
        for window in windows
    ):
        raise ValueError("MissionEnvelope cannot safely encode recurring Campaign testing windows")
    if len(bindings) > campaign.spec.budgets.max_tool_calls:
        raise ValueError("measured Plan exceeds the Campaign Tool-call budget")
    capabilities = tuple(
        sorted(
            {binding.capability for binding in bindings},
            key=lambda item: (
                item.capability_id,
                item.capability_version,
                item.capability_digest,
            ),
        )
    )
    targets = tuple(sorted({binding.target_digest for binding in bindings}))
    max_risk = max(binding.capability.risk_tier for binding in bindings)
    request_units = sum(binding.request_units for binding in bindings)
    rpm = campaign.spec.rules_of_engagement.max_requests_per_minute
    cost_microusd = int(
        (Decimal(str(campaign.spec.budgets.max_cost_usd)) * Decimal(1_000_000)).to_integral_value(
            rounding=ROUND_FLOOR
        )
    )
    expires_at = min(
        campaign.spec.authorization.expires_at,
        canonical_start + timedelta(seconds=campaign.spec.budgets.duration_seconds),
        *(binding.authority_expires_at for binding in bindings),
    )
    return MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=run_id,
        profileId=compilation.profile.profile_id,
        profileVersion=compilation.profile.profile_version,
        profileDigest=compilation.profile.profile_digest,
        compilerId=compiler.compiler_id,
        compilerVersion=compiler.compiler_version,
        compilerDigest=compiler.compiler_digest,
        sourceCampaignDigest=compilation.input_digest,
        allowedCapabilities=capabilities,
        allowedTargetDigests=targets,
        maxRiskTier=max_risk,
        budget=ActionBudgetLimit(
            toolCallLimit=len(bindings),
            requestUnitLimit=request_units,
            costLimitMicrousd=cost_microusd,
            rollingWindowSeconds=60 if rpm is not None else None,
            rollingRequestUnitLimit=(min(rpm, request_units) if rpm is not None else None),
        ),
        autonomy=campaign.spec.autonomy,
        authorizedAt=campaign.spec.authorization.approved_at,
        notBefore=canonical_start,
        expiresAt=expires_at,
    )


def _canonical_not_before(
    campaign: CampaignManifest,
    parity: CommonEngineBehavioralParityAuthority,
    run_id: str,
    value: datetime,
) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("MissionEnvelope start must include a UTC offset or Z")
    normalized = value.astimezone(UTC)
    authorization = campaign.spec.authorization
    if not authorization.approved_at <= normalized < authorization.expires_at:
        raise ValueError("MissionEnvelope start is outside Campaign authorization")
    source_run_ids = {
        parity.dual_runtime.legacy_execution.run_id,
        parity.dual_runtime.adapter_execution.run_id,
    }
    if run_id in source_run_ids:
        raise ValueError("MissionEnvelope Run must be fresh from parity fixture Runs")
    return normalized


def _release_authority_window(
    bundle: CapabilityReleaseBundle,
) -> tuple[datetime, datetime]:
    release = bundle.release.statement
    if not bundle.reviews:
        raise ValueError("Capability release has no signed review authority")
    not_before = max(
        release.issued_at.astimezone(UTC),
        *(review.statement.issued_at.astimezone(UTC) for review in bundle.reviews),
    )
    expires_at = min(
        review.statement.expires_at.astimezone(UTC) for review in bundle.reviews
    )
    if expires_at <= not_before:
        raise ValueError("Capability release authority window is empty")
    return not_before, expires_at
