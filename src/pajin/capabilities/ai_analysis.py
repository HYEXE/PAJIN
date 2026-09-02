"""AI-001B provider/model/Tool-bound read-only analysis preparation."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import (
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationError,
    PreparedCapabilityAction,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.adapters import registered_action_capability
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.domain_projection import (
    CapabilityDomainClassificationRef,
    RegisteredCapabilityDomainClassification,
)
from pajin.capabilities.existing import (
    REGISTERED_MCP_CAPABILITY_ID,
    REGISTERED_MCP_CAPABILITY_VERSION,
    REGISTERED_MCP_TARGET,
    ExistingModeCapabilityBundle,
    existing_mode_capability_bundle,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    RegisteredDomainWorkerBoundaryProfile,
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    registered_domain_worker_boundary_profiles,
)
from pajin.control_plane.redteam_profiles import (
    REDTEAM_LLM_PROFILE,
    REDTEAM_LLM_PROFILE_DIGEST,
    REDTEAM_LLM_PROFILE_VERSION,
    REDTEAM_LLM_RAG_CAPABILITY_ID,
    REDTEAM_LLM_RAG_CAPABILITY_VERSION,
    REDTEAM_LLM_RAG_PROFILE,
    REDTEAM_LLM_RAG_PROFILE_DIGEST,
    REDTEAM_LLM_RAG_PROFILE_VERSION,
    REDTEAM_LLM_RAG_REQUEST_UNITS,
    REDTEAM_LLM_RAG_SCENARIO_ID,
    REDTEAM_LLM_RAG_THREAT_CLASS,
    REDTEAM_MCP_PROFILE,
    REDTEAM_MCP_PROFILE_DIGEST,
    REDTEAM_MCP_PROFILE_VERSION,
    REDTEAM_MCP_REQUEST_UNITS,
    REDTEAM_MCP_THREAT_CLASS,
)
from pajin.discovery.ai_surfaces import (
    AIModelSurfaceLocator,
    AISecuritySurface,
    AISurfaceClass,
    typed_ai_security_surface,
)
from pajin.discovery.models import (
    HTTPRAGSurfaceLocator,
    MCPServerSurfaceLocator,
    ToolInterfaceSurfaceLocator,
    http_route_scope_url,
)
from pajin.domain.models import StrictModel, ToolRequest
from pajin.domain.security_domain import SecurityDomain
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.providers.models import ProviderRegistration
from pajin.runtime.secrets import SecretBroker
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mcp import (
    MCP_INSTRUCTION_HIJACKING_PROBE_TEXT,
    MCPInstructionHijackingProbeInput,
    demo_mcp_tool,
)
from pajin.tools.mock import MockAgentProbe

AI_READ_ONLY_ANALYSIS_CAPABILITY_BINDING_API_VERSION: Literal[
    "pajin.dev/ai-read-only-analysis-capability-binding/v1alpha1"
] = "pajin.dev/ai-read-only-analysis-capability-binding/v1alpha1"
AI_PROVIDER_MODEL_BINDING_API_VERSION: Literal["pajin.dev/ai-provider-model-binding/v1alpha1"] = (
    "pajin.dev/ai-provider-model-binding/v1alpha1"
)
AI_ANALYSIS_BUDGET_CEILING_API_VERSION: Literal["pajin.dev/ai-analysis-budget-ceiling/v1alpha1"] = (
    "pajin.dev/ai-analysis-budget-ceiling/v1alpha1"
)
AI_READ_ONLY_ANALYSIS_BINDING_API_VERSION: Literal[
    "pajin.dev/ai-read-only-analysis-binding/v1alpha1"
] = "pajin.dev/ai-read-only-analysis-binding/v1alpha1"
AI_READ_ONLY_ANALYSIS_PREPARATION_API_VERSION: Literal[
    "pajin.dev/ai-read-only-analysis-preparation/v1alpha1"
] = "pajin.dev/ai-read-only-analysis-preparation/v1alpha1"
AI_MEASUREMENT_OPERATION_PREPARATION_API_VERSION: Literal[
    "pajin.dev/ai-measurement-operation-preparation/v1alpha1"
] = "pajin.dev/ai-measurement-operation-preparation/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Fingerprint = Annotated[str, Field(pattern=r"^[a-f0-9]{16}$")]
_CapabilityBindingId = Annotated[
    str,
    Field(pattern=r"^ai-analysis-capability-binding_[a-f0-9]{64}$"),
]
_ProviderModelBindingId = Annotated[
    str,
    Field(pattern=r"^ai-provider-model-binding_[a-f0-9]{64}$"),
]
_AnalysisBindingId = Annotated[
    str,
    Field(pattern=r"^ai-read-only-analysis-binding_[a-f0-9]{64}$"),
]
_PreparationId = Annotated[
    str,
    Field(pattern=r"^ai-analysis-preparation_[a-f0-9]{64}$"),
]
_MeasurementPreparationId = Annotated[
    str,
    Field(pattern=r"^ai-measurement-operation-preparation_[a-f0-9]{64}$"),
]


class AIReadOnlyAnalysisError(ValueError):
    """Raised when an AI-001B identity, activation, or preparation drifts."""


class AIAnalysisProfileRef(StrictModel):
    """Exact REDTEAM compatibility profile identity; it grants no Profile authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    profile_id: _Identifier = Field(alias="profileId")
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")


@dataclass(frozen=True, slots=True)
class _AIAnalysisCapabilitySpec:
    capability_id: str
    capability_version: str
    profile_id: str
    profile_version: str
    profile_digest: str
    scenario_id: str
    threat_class: str
    request_units: int
    required_surface_classes: tuple[AISurfaceClass, ...]
    provider_model_required: bool
    credential_lease_required: bool
    network_access: bool

    def profile_reference(self) -> AIAnalysisProfileRef:
        if self.profile_version != "1.0.0":
            raise ValueError("AI analysis Profile version differs from code authority")
        return AIAnalysisProfileRef(
            profileId=self.profile_id,
            profileVersion="1.0.0",
            profileDigest=self.profile_digest,
        )


_AI_ANALYSIS_CAPABILITY_SPECS = (
    _AIAnalysisCapabilitySpec(
        "pajin.ai.kisa.system-prompt-disclosure",
        "1.0.0",
        REDTEAM_LLM_PROFILE,
        REDTEAM_LLM_PROFILE_VERSION,
        REDTEAM_LLM_PROFILE_DIGEST,
        "kisa.model.system-prompt-disclosure",
        "M03",
        1,
        (AISurfaceClass.MODEL, AISurfaceClass.TOOL),
        True,
        True,
        True,
    ),
    _AIAnalysisCapabilitySpec(
        "pajin.ai.kisa.jailbreak-policy-bypass",
        "1.0.0",
        REDTEAM_LLM_PROFILE,
        REDTEAM_LLM_PROFILE_VERSION,
        REDTEAM_LLM_PROFILE_DIGEST,
        "kisa.model.jailbreak-policy-bypass",
        "M06",
        1,
        (AISurfaceClass.MODEL, AISurfaceClass.TOOL),
        True,
        True,
        True,
    ),
    _AIAnalysisCapabilitySpec(
        REDTEAM_LLM_RAG_CAPABILITY_ID,
        REDTEAM_LLM_RAG_CAPABILITY_VERSION,
        REDTEAM_LLM_RAG_PROFILE,
        REDTEAM_LLM_RAG_PROFILE_VERSION,
        REDTEAM_LLM_RAG_PROFILE_DIGEST,
        REDTEAM_LLM_RAG_SCENARIO_ID,
        REDTEAM_LLM_RAG_THREAT_CLASS,
        REDTEAM_LLM_RAG_REQUEST_UNITS,
        (AISurfaceClass.MODEL, AISurfaceClass.RAG, AISurfaceClass.TOOL),
        True,
        True,
        True,
    ),
    _AIAnalysisCapabilitySpec(
        REGISTERED_MCP_CAPABILITY_ID,
        REGISTERED_MCP_CAPABILITY_VERSION,
        REDTEAM_MCP_PROFILE,
        REDTEAM_MCP_PROFILE_VERSION,
        REDTEAM_MCP_PROFILE_DIGEST,
        "redteam.mcp.instruction-hijacking-inspection",
        REDTEAM_MCP_THREAT_CLASS,
        REDTEAM_MCP_REQUEST_UNITS,
        (AISurfaceClass.MCP, AISurfaceClass.TOOL),
        False,
        False,
        False,
    ),
)


class AIReadOnlyAnalysisCapabilityBindingRef(StrictModel):
    """Exact reference to one code-owned REDTEAM/CAP-002 analysis binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: _CapabilityBindingId = Field(alias="bindingId")
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")
    capability: CodeBackedCapabilityRef


class AIReadOnlyAnalysisCapabilityBinding(StrictModel):
    """Code-owned Capability/Profile/Tool/Worker requirements without runtime authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-read-only-analysis-capability-binding/v1alpha1"] = Field(
        default=AI_READ_ONLY_ANALYSIS_CAPABILITY_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIReadOnlyAnalysisCapabilityBinding"] = "AIReadOnlyAnalysisCapabilityBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=95)
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    profile: AIAnalysisProfileRef
    capability: CodeBackedCapabilityRef
    capability_domain_classification: CapabilityDomainClassificationRef = Field(
        alias="capabilityDomainClassification"
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    tool_surface: AISecuritySurface = Field(alias="toolSurface")
    scenario_id: _Identifier = Field(alias="scenarioId")
    threat_class: _Identifier = Field(alias="threatClass")
    request_units: int = Field(alias="requestUnits", ge=1, le=100)
    required_surface_classes: tuple[AISurfaceClass, ...] = Field(
        alias="requiredSurfaceClasses",
        min_length=2,
        max_length=3,
    )
    side_effect_class: Literal[CapabilitySideEffectClass.READ_ONLY] = Field(
        default=CapabilitySideEffectClass.READ_ONLY,
        alias="sideEffectClass",
    )
    provider_model_required: bool = Field(alias="providerModelRequired")
    credential_lease_required: bool = Field(alias="credentialLeaseRequired")
    network_access_required: bool = Field(alias="networkAccessRequired")
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    complete_cap_002_verified: Literal[True] = Field(
        default=True,
        alias="completeCAP002Verified",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_product_profile_required: Literal[True] = Field(
        default=True,
        alias="currentProductProfileRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    action_permit_required: Literal[True] = Field(
        default=True,
        alias="actionPermitRequired",
    )
    gateway_policy_reentry_required: Literal[True] = Field(
        default=True,
        alias="gatewayPolicyReentryRequired",
    )
    worker_deployment_binding_required: Literal[True] = Field(
        default=True,
        alias="workerDeploymentBindingRequired",
    )
    request_budget_required: Literal[True] = Field(
        default=True,
        alias="requestBudgetRequired",
    )
    provider_usage_budget_required: bool = Field(alias="providerUsageBudgetRequired")
    profile_metadata_authority: Literal[False] = Field(
        default=False,
        alias="profileMetadataAuthority",
    )
    domain_metadata_authority: Literal[False] = Field(
        default=False,
        alias="domainMetadataAuthority",
    )
    surface_metadata_authority: Literal[False] = Field(
        default=False,
        alias="surfaceMetadataAuthority",
    )
    tool_metadata_authority: Literal[False] = Field(
        default=False,
        alias="toolMetadataAuthority",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    runtime_support_asserted_by_binding: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAssertedByBinding",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("request_units", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("AI analysis request units must be an integer")
        return value

    @field_validator(
        "provider_model_required",
        "credential_lease_required",
        "network_access_required",
        "binding_only",
        "complete_cap_002_verified",
        "current_capability_activation_required",
        "current_product_profile_required",
        "current_campaign_scope_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "worker_deployment_binding_required",
        "request_budget_required",
        "provider_usage_budget_required",
        "profile_metadata_authority",
        "domain_metadata_authority",
        "surface_metadata_authority",
        "tool_metadata_authority",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "credential_access_authorized",
        "graph_admission_authorized",
        "finding_confirmation_authorized",
        "runtime_support_asserted_by_binding",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI analysis Capability binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_code_authority(self) -> Self:
        spec = _analysis_spec(
            self.capability.capability.capability_id,
            self.capability.capability.capability_version,
        )
        definition, capability = _registered_definition_and_capability(spec)
        worker = _ai_worker_boundary_profile()
        classification = _capability_domain_classification(definition, capability, worker)
        tool_surface = _tool_surface(definition)
        tool_locator = tool_surface.locator
        if not isinstance(tool_locator, ToolInterfaceSurfaceLocator):
            raise ValueError("AI analysis Capability Tool Surface differs from code authority")
        if (
            self.profile != spec.profile_reference()
            or self.capability != capability
            or self.capability_domain_classification != classification
            or self.worker_profile != worker.reference()
            or self.tool_surface != tool_surface
            or self.scenario_id != spec.scenario_id
            or self.threat_class != spec.threat_class
            or self.request_units != spec.request_units
            or self.required_surface_classes != spec.required_surface_classes
            or self.provider_model_required is not spec.provider_model_required
            or self.credential_lease_required is not spec.credential_lease_required
            or self.network_access_required is not spec.network_access
            or self.provider_usage_budget_required is not spec.provider_model_required
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.request_unit_cost != spec.request_units
            or definition.network_access is not spec.network_access
            or definition.tool.tool_id != tool_locator.tool_id
            or definition.tool.tool_version != tool_locator.tool_version
            or definition.parameter_schema_digest != tool_locator.input_schema_digest
            or worker.network_boundary is not WorkerNetworkBoundary.BOUNDED_EGRESS
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.NO_HOST_ACCESS
            or worker.credential_boundary is not WorkerCredentialBoundary.EPHEMERAL_LEASE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.ISOLATED_NON_ROOT
        ):
            raise ValueError("AI analysis Capability binding differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.ai-read-only-analysis-capability-binding/v1",
            material,
        )
        binding_id: _CapabilityBindingId = f"ai-analysis-capability-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI analysis Capability binding digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("AI analysis Capability binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self

    def reference(self) -> AIReadOnlyAnalysisCapabilityBindingRef:
        """Return the exact detached code-owned binding identity."""

        return AIReadOnlyAnalysisCapabilityBindingRef(
            bindingId=self.binding_id,
            bindingVersion=self.binding_version,
            bindingDigest=self.binding_digest,
            capability=self.capability,
        )


class AIProviderModelBinding(StrictModel):
    """Secret-free exact provider/model identity that remains non-invocable."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-provider-model-binding/v1alpha1"] = Field(
        default=AI_PROVIDER_MODEL_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIProviderModelBinding"] = "AIProviderModelBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=91)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    provider_id: str = Field(
        alias="providerId",
        pattern=r"^[a-z0-9][a-z0-9-]{1,30}$",
    )
    endpoint: str = Field(min_length=1, max_length=2_000)
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    model_revision: str = Field(alias="modelRevision", min_length=1, max_length=200)
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    secret_ref_fingerprint: _Fingerprint = Field(alias="secretRefFingerprint")
    model_surface: AISecuritySurface = Field(alias="modelSurface")
    provider_registration_recheck_required: Literal[True] = Field(
        default=True,
        alias="providerRegistrationRecheckRequired",
    )
    ephemeral_credential_lease_required: Literal[True] = Field(
        default=True,
        alias="ephemeralCredentialLeaseRequired",
    )
    secret_reference_embedded: Literal[False] = Field(
        default=False,
        alias="secretReferenceEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="providerInvocationAuthorized",
    )

    @field_validator(
        "provider_registration_recheck_required",
        "ephemeral_credential_lease_required",
        "secret_reference_embedded",
        "credential_material_embedded",
        "credential_access_authorized",
        "provider_invocation_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI provider/model binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        locator = self.model_surface.locator
        if (
            self.model_surface.surface_class is not AISurfaceClass.MODEL
            or not isinstance(locator, AIModelSurfaceLocator)
            or locator.provider_id != self.provider_id
            or locator.model_id != self.model_id
            or locator.model_revision != self.model_revision
            or locator.provider_registration_digest != self.provider_registration_digest
        ):
            raise ValueError("AI provider/model binding differs from its typed model Surface")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.ai-provider-model-binding/v1",
            material,
        )
        binding_id: _ProviderModelBindingId = f"ai-provider-model-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI provider/model binding digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("AI provider/model binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


class AIAnalysisBudgetCeiling(StrictModel):
    """Exact attenuating request/token/cost ceiling; it is not a reservation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-analysis-budget-ceiling/v1alpha1"] = Field(
        default=AI_ANALYSIS_BUDGET_CEILING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIAnalysisBudgetCeiling"] = "AIAnalysisBudgetCeiling"
    request_units: int = Field(alias="requestUnits", ge=1, le=100)
    max_input_tokens: int = Field(alias="maxInputTokens", ge=0, le=10_000_000)
    max_output_tokens: int = Field(alias="maxOutputTokens", ge=0, le=10_000_000)
    max_total_tokens: int = Field(alias="maxTotalTokens", ge=0, le=20_000_000)
    max_cost_micro_usd: int = Field(alias="maxCostMicroUsd", ge=0, le=10**15)
    provider_usage_applicable: bool = Field(alias="providerUsageApplicable")
    attenuation_only: Literal[True] = Field(default=True, alias="attenuationOnly")
    reservation_created: Literal[False] = Field(default=False, alias="reservationCreated")

    @field_validator(
        "request_units",
        "max_input_tokens",
        "max_output_tokens",
        "max_total_tokens",
        "max_cost_micro_usd",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("AI analysis budget values must be integers")
        return value

    @field_validator(
        "provider_usage_applicable",
        "attenuation_only",
        "reservation_created",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI analysis budget markers must be booleans")
        return value

    @model_validator(mode="after")
    def require_exact_total(self) -> Self:
        if self.max_total_tokens != self.max_input_tokens + self.max_output_tokens:
            raise ValueError("AI analysis total-token ceiling must equal input plus output")
        if self.provider_usage_applicable:
            if self.max_input_tokens == 0 or self.max_output_tokens == 0:
                raise ValueError("provider-backed AI analysis requires positive token ceilings")
        elif any(
            value != 0
            for value in (
                self.max_input_tokens,
                self.max_output_tokens,
                self.max_total_tokens,
                self.max_cost_micro_usd,
            )
        ):
            raise ValueError("non-provider AI analysis cannot claim token or cost ceilings")
        return self


class AIReadOnlyAnalysisBindingRef(StrictModel):
    """Exact content-addressed reference to one provider/model/Tool binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: _AnalysisBindingId = Field(alias="bindingId")
    binding_digest: _Sha256 = Field(alias="bindingDigest")
    capability_binding: AIReadOnlyAnalysisCapabilityBindingRef = Field(alias="capabilityBinding")


class AIReadOnlyAnalysisBinding(StrictModel):
    """Exact AI Surface and budget composition that still cannot dispatch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-read-only-analysis-binding/v1alpha1"] = Field(
        default=AI_READ_ONLY_ANALYSIS_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIReadOnlyAnalysisBinding"] = "AIReadOnlyAnalysisBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=94)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    capability_binding: AIReadOnlyAnalysisCapabilityBinding = Field(alias="capabilityBinding")
    provider_model: AIProviderModelBinding | None = Field(
        default=None,
        alias="providerModel",
    )
    surfaces: tuple[AISecuritySurface, ...] = Field(min_length=2, max_length=3)
    budget: AIAnalysisBudgetCeiling
    state: Literal["bound-not-authorized"] = "bound-not-authorized"
    exact_surface_set_bound: Literal[True] = Field(
        default=True,
        alias="exactSurfaceSetBound",
    )
    provider_registration_recheck_required: bool = Field(
        alias="providerRegistrationRecheckRequired"
    )
    current_product_profile_required: Literal[True] = Field(
        default=True,
        alias="currentProductProfileRequired",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    budget_reserved: Literal[False] = Field(default=False, alias="budgetReserved")
    credential_lease_materialized: Literal[False] = Field(
        default=False,
        alias="credentialLeaseMaterialized",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    gateway_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayDispatchAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "exact_surface_set_bound",
        "provider_registration_recheck_required",
        "current_product_profile_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "approval_satisfied",
        "permit_issuance_authorized",
        "budget_reserved",
        "credential_lease_materialized",
        "worker_job_materialized",
        "gateway_dispatch_authorized",
        "graph_admission_authorized",
        "finding_confirmation_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI analysis binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_surfaces_and_budget(self) -> Self:
        expected_capability = resolve_ai_read_only_analysis_capability_binding(
            self.capability_binding.reference()
        )
        spec = _analysis_spec_for_binding(expected_capability)
        if self.capability_binding != expected_capability:
            raise ValueError("AI analysis binding Capability identity differs")
        if tuple(surface.surface_class for surface in self.surfaces) != (
            spec.required_surface_classes
        ):
            raise ValueError("AI analysis binding Surface classes differ from code authority")
        if self.surfaces[-1] != expected_capability.tool_surface:
            raise ValueError("AI analysis binding Tool Surface differs from code authority")
        if (
            self.budget.request_units != spec.request_units
            or self.budget.provider_usage_applicable is not spec.provider_model_required
            or self.provider_registration_recheck_required is not spec.provider_model_required
        ):
            raise ValueError("AI analysis binding budget differs from Capability authority")
        if spec.provider_model_required:
            if self.provider_model is None or self.surfaces[0] != self.provider_model.model_surface:
                raise ValueError("AI analysis binding requires the exact provider/model Surface")
            if AISurfaceClass.RAG in spec.required_surface_classes:
                _require_rag_surface_matches_provider(self.surfaces[1], self.provider_model)
        else:
            if self.provider_model is not None:
                raise ValueError("MCP-only analysis cannot import provider/model authority")
            _require_mcp_surface_matches_capability(self.surfaces[0])
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.ai-read-only-analysis-binding/v1",
            material,
        )
        binding_id: _AnalysisBindingId = f"ai-read-only-analysis-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI read-only analysis binding digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("AI read-only analysis binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self

    def reference(self) -> AIReadOnlyAnalysisBindingRef:
        """Return the exact detached dynamic binding identity."""

        return AIReadOnlyAnalysisBindingRef(
            bindingId=self.binding_id,
            bindingDigest=self.binding_digest,
            capabilityBinding=self.capability_binding.reference(),
        )


class AIReadOnlyAnalysisPreparation(StrictModel):
    """Exact CAP-002 preparation that still requires every dispatch authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-read-only-analysis-preparation/v1alpha1"] = Field(
        default=AI_READ_ONLY_ANALYSIS_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIReadOnlyAnalysisPreparation"] = "AIReadOnlyAnalysisPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=88)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: AIReadOnlyAnalysisBinding
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    capability_prepared: Literal[True] = Field(default=True, alias="capabilityPrepared")
    provider_registration_reverified: bool = Field(alias="providerRegistrationReverified")
    product_profile_recheck_required: Literal[True] = Field(
        default=True,
        alias="productProfileRecheckRequired",
    )
    campaign_scope_recheck_required: Literal[True] = Field(
        default=True,
        alias="campaignScopeRecheckRequired",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    budget_reserved: Literal[False] = Field(default=False, alias="budgetReserved")
    credential_lease_materialized: Literal[False] = Field(
        default=False,
        alias="credentialLeaseMaterialized",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    observation_produced: Literal[False] = Field(
        default=False,
        alias="observationProduced",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    gateway_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayDispatchAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "capability_prepared",
        "provider_registration_reverified",
        "product_profile_recheck_required",
        "campaign_scope_recheck_required",
        "approval_satisfied",
        "permit_issuance_authorized",
        "budget_reserved",
        "credential_lease_materialized",
        "worker_job_materialized",
        "observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "gateway_dispatch_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI analysis preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        static = self.binding.capability_binding
        spec = _analysis_spec_for_binding(static)
        definition, _capability = _registered_definition_and_capability(spec)
        expected_action = registered_action_capability(definition).reference()
        request = self.prepared_action.request
        if (
            self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != definition.tool.tool_id
            or request.method != "POST"
            or self.provider_registration_reverified is not spec.provider_model_required
        ):
            raise ValueError("AI analysis preparation differs from Capability authority")
        _validate_prepared_request(spec, request, self.binding)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.ai-read-only-analysis-preparation/v1",
            material,
        )
        preparation_id: _PreparationId = f"ai-analysis-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("AI analysis preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("AI analysis preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


class AIMeasurementOperationPreparation(StrictModel):
    """Additive preparation for one code-owned AI-002C Replay or Control request."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-measurement-operation-preparation/v1alpha1"] = Field(
        default=AI_MEASUREMENT_OPERATION_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIMeasurementOperationPreparation"] = "AIMeasurementOperationPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=110)
    preparation_digest: str = Field(
        default="",
        alias="preparationDigest",
        max_length=64,
    )
    binding: AIReadOnlyAnalysisBinding
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    registered_operation_digest: _Sha256 = Field(alias="registeredOperationDigest")
    operation_key: Literal[
        "replay-1",
        "replay-2",
        "control-baseline",
        "control-negative",
        "control-counterfactual",
    ] = Field(alias="operationKey")
    operation_ordinal: Literal[2, 3, 4, 5, 6] = Field(alias="operationOrdinal")
    operation_stage: Literal["replay", "control"] = Field(alias="operationStage")
    materializer_id: Literal["pajin.ai002c.fixed-m03-operation"] = Field(
        default="pajin.ai002c.fixed-m03-operation",
        alias="materializerId",
    )
    materializer_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="materializerVersion",
    )
    state: Literal["prepared-measurement-operation-not-authorized"] = (
        "prepared-measurement-operation-not-authorized"
    )
    capability_prepared: Literal[True] = Field(
        default=True,
        alias="capabilityPrepared",
    )
    provider_registration_reverified: Literal[True] = Field(
        default=True,
        alias="providerRegistrationReverified",
    )
    approval_satisfied: Literal[False] = Field(
        default=False,
        alias="approvalSatisfied",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    gateway_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayDispatchAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("operation_ordinal", mode="before")
    @classmethod
    def require_exact_ordinal(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("AI measurement operation ordinal must be exact")
        return value

    @field_validator(
        "capability_prepared",
        "provider_registration_reverified",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI measurement preparation completion markers must be true")
        return value

    @field_validator(
        "approval_satisfied",
        "permit_issuance_authorized",
        "worker_job_materialized",
        "gateway_dispatch_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI measurement preparation authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        matches = tuple(
            item
            for item in registered_ai_read_only_analysis_capability_bindings()
            if item.scenario_id == "kisa.model.system-prompt-disclosure"
            and item.threat_class == "M03"
        )
        provider_model = self.binding.provider_model
        request = self.prepared_action.request
        probe = AIChatProbeInput.model_validate(request.arguments)
        expected_action = None
        if len(matches) == 1:
            spec = _analysis_spec_for_binding(matches[0])
            definition, _capability = _registered_definition_and_capability(spec)
            expected_action = registered_action_capability(definition).reference()
        shapes = {
            "replay-1": (2, "replay"),
            "replay-2": (3, "replay"),
            "control-baseline": (4, "control"),
            "control-negative": (5, "control"),
            "control-counterfactual": (6, "control"),
        }
        if (
            len(matches) != 1
            or self.binding.capability_binding != matches[0]
            or provider_model is None
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != AIChatProbeTool.spec.tool_id
            or request.target != provider_model.endpoint
            or request.method != "POST"
            or probe.scenario_id != "kisa.model.system-prompt-disclosure"
            or probe.threat_class != "M03"
            or len(probe.turns) != 1
            or len(probe.checks) != 1
            or shapes[self.operation_key] != (self.operation_ordinal, self.operation_stage)
            or not request.request_id.startswith(
                f"tool_ai002c_operation_{self.operation_ordinal:02d}_"
            )
        ):
            raise ValueError("AI measurement preparation differs from its fixed M03 operation")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.ai-measurement-operation-preparation/v1",
            material,
        )
        preparation_id: _MeasurementPreparationId = f"ai-measurement-operation-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("AI measurement preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("AI measurement preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def registered_ai_read_only_analysis_capability_bindings() -> tuple[
    AIReadOnlyAnalysisCapabilityBinding, ...
]:
    """Return the exact REDTEAM-001A/B/D read-only CAP-002 binding inventory."""

    return tuple(item.model_copy(deep=True) for item in _registered_capability_bindings())


@cache
def _registered_capability_bindings() -> tuple[AIReadOnlyAnalysisCapabilityBinding, ...]:
    """Build the internal immutable inventory once per process."""

    worker = _ai_worker_boundary_profile()
    bindings: list[AIReadOnlyAnalysisCapabilityBinding] = []
    for spec in _AI_ANALYSIS_CAPABILITY_SPECS:
        definition, capability = _registered_definition_and_capability(spec)
        bindings.append(
            AIReadOnlyAnalysisCapabilityBinding(
                profile=spec.profile_reference(),
                capability=capability,
                capabilityDomainClassification=_capability_domain_classification(
                    definition,
                    capability,
                    worker,
                ),
                workerProfile=worker.reference(),
                toolSurface=_tool_surface(definition),
                scenarioId=spec.scenario_id,
                threatClass=spec.threat_class,
                requestUnits=spec.request_units,
                requiredSurfaceClasses=spec.required_surface_classes,
                providerModelRequired=spec.provider_model_required,
                credentialLeaseRequired=spec.credential_lease_required,
                networkAccessRequired=spec.network_access,
                providerUsageBudgetRequired=spec.provider_model_required,
            )
        )
    return tuple(bindings)


def resolve_ai_read_only_analysis_capability_binding(
    reference: AIReadOnlyAnalysisCapabilityBindingRef,
) -> AIReadOnlyAnalysisCapabilityBinding:
    """Resolve one exact binding without Profile, activation, or execution authority."""

    for binding in registered_ai_read_only_analysis_capability_bindings():
        if binding.reference() == reference:
            return binding.model_copy(deep=True)
    raise AIReadOnlyAnalysisError(
        "AI read-only analysis Capability binding is not registered exactly"
    )


def ai_provider_registration_digest(registration: ProviderRegistration) -> str:
    """Fingerprint one canonical Provider registration without returning its secret reference."""

    canonical = _canonical_provider_registration(registration)
    material = canonical.model_dump(mode="json", by_alias=True)
    material["allowed_function_tools"] = sorted(canonical.allowed_function_tools)
    return capability_definition_digest(
        "pajin.capability.ai-provider-registration/v1",
        material,
    )


def bind_ai_provider_model(
    registration: ProviderRegistration,
    *,
    model_revision: str,
) -> AIProviderModelBinding:
    """Create a secret-free provider/model binding that grants no invocation right."""

    canonical = _canonical_provider_registration(registration)
    registration_digest = ai_provider_registration_digest(canonical)
    surface = typed_ai_security_surface(
        locator=AIModelSurfaceLocator(
            providerId=canonical.provider_id,
            modelId=canonical.model,
            modelRevision=model_revision,
            providerRegistrationDigest=registration_digest,
        )
    )
    return AIProviderModelBinding(
        providerId=canonical.provider_id,
        endpoint=str(canonical.endpoint),
        modelId=canonical.model,
        modelRevision=model_revision,
        providerRegistrationDigest=registration_digest,
        secretRefFingerprint=SecretBroker.fingerprint(canonical.secret_ref),
        modelSurface=surface,
    )


def bind_ai_read_only_analysis(
    *,
    capability: AIReadOnlyAnalysisCapabilityBindingRef,
    budget: AIAnalysisBudgetCeiling,
    provider_registration: ProviderRegistration | None = None,
    model_revision: str | None = None,
    rag_surface: AISecuritySurface | None = None,
    mcp_surface: AISecuritySurface | None = None,
) -> AIReadOnlyAnalysisBinding:
    """Bind exact AI Surfaces and ceilings without preparing or authorizing an action."""

    static = resolve_ai_read_only_analysis_capability_binding(capability)
    spec = _analysis_spec_for_binding(static)
    canonical_budget = _canonical_budget(budget)
    if spec.provider_model_required:
        if provider_registration is None or model_revision is None or mcp_surface is not None:
            raise AIReadOnlyAnalysisError(
                "provider-backed AI analysis requires only exact provider/model inputs"
            )
        provider_model = bind_ai_provider_model(
            provider_registration,
            model_revision=model_revision,
        )
        surfaces: tuple[AISecuritySurface, ...]
        if AISurfaceClass.RAG in spec.required_surface_classes:
            if rag_surface is None:
                raise AIReadOnlyAnalysisError("RAG analysis requires one exact RAG Surface")
            surfaces = (
                provider_model.model_surface,
                _canonical_ai_surface(rag_surface),
                static.tool_surface,
            )
        else:
            if rag_surface is not None:
                raise AIReadOnlyAnalysisError("model-only analysis cannot import a RAG Surface")
            surfaces = (provider_model.model_surface, static.tool_surface)
    else:
        if (
            provider_registration is not None
            or model_revision is not None
            or rag_surface is not None
            or mcp_surface is None
        ):
            raise AIReadOnlyAnalysisError(
                "MCP-only analysis requires one MCP Surface and no provider/model inputs"
            )
        provider_model = None
        surfaces = (_canonical_ai_surface(mcp_surface), static.tool_surface)
    try:
        return AIReadOnlyAnalysisBinding(
            capabilityBinding=static,
            providerModel=provider_model,
            surfaces=surfaces,
            budget=canonical_budget,
            providerRegistrationRecheckRequired=spec.provider_model_required,
        )
    except ValidationError as exc:
        raise AIReadOnlyAnalysisError("AI read-only analysis binding failed closed") from exc


def prepare_ai_read_only_analysis(
    *,
    activation: ExistingModeCapabilityActivation,
    release: CapabilityReleaseRef,
    binding: AIReadOnlyAnalysisBinding,
    request: ToolRequest,
    provider_registration: ProviderRegistration | None = None,
) -> AIReadOnlyAnalysisPreparation:
    """Compile one exact existing action; Policy, Permit, Gateway, and Worker remain required."""

    if not isinstance(activation, ExistingModeCapabilityActivation):
        raise TypeError("AI analysis preparation requires an existing Mode activation")
    canonical_binding = _canonical_analysis_binding(binding)
    static = canonical_binding.capability_binding
    spec = _analysis_spec_for_binding(static)
    canonical_request = _canonical_tool_request(request)
    if spec.provider_model_required:
        if provider_registration is None or canonical_binding.provider_model is None:
            raise AIReadOnlyAnalysisError(
                "provider-backed AI preparation requires current Provider registration"
            )
        expected_provider = bind_ai_provider_model(
            provider_registration,
            model_revision=canonical_binding.provider_model.model_revision,
        )
        if expected_provider != canonical_binding.provider_model:
            raise AIReadOnlyAnalysisError(
                "AI preparation Provider registration differs from its binding"
            )
    elif provider_registration is not None:
        raise AIReadOnlyAnalysisError("MCP-only preparation cannot import Provider authority")
    try:
        definition = activation.rollout.bundle.definitions.resolve(static.capability.capability)
        manifest = next(
            item
            for item in activation.rollout.bundle.capabilities()
            if item.capability == definition.reference()
        )
        if manifest.reference() != static.capability:
            raise AIReadOnlyAnalysisError(
                "AI preparation activation differs from the registered CAP-002 authority"
            )
        prepared = activation.prepare_action(
            release=release,
            request=canonical_request,
            parameters=canonical_request.arguments,
        )
        return AIReadOnlyAnalysisPreparation(
            binding=canonical_binding,
            release=release,
            preparedAction=prepared,
            providerRegistrationReverified=spec.provider_model_required,
        )
    except (
        ExistingModeCapabilityActivationError,
        StopIteration,
        ValidationError,
        ValueError,
    ) as exc:
        if isinstance(exc, AIReadOnlyAnalysisError):
            raise
        raise AIReadOnlyAnalysisError(
            "AI read-only analysis CAP-002 preparation failed closed"
        ) from exc


def prepare_ai_measurement_operation(
    *,
    activation: ExistingModeCapabilityActivation,
    release: CapabilityReleaseRef,
    binding: AIReadOnlyAnalysisBinding,
    request: ToolRequest,
    provider_registration: ProviderRegistration,
    registered_operation_digest: str,
    operation_key: Literal[
        "replay-1",
        "replay-2",
        "control-baseline",
        "control-negative",
        "control-counterfactual",
    ],
    operation_ordinal: Literal[2, 3, 4, 5, 6],
    operation_stage: Literal["replay", "control"],
) -> AIMeasurementOperationPreparation:
    """Prepare one already code-materialized AI-002C request under current CAP-002."""

    if not isinstance(activation, ExistingModeCapabilityActivation):
        raise TypeError("AI measurement preparation requires current activation")
    try:
        canonical_release = CapabilityReleaseRef.model_validate(
            release.model_dump(mode="json", by_alias=True)
        )
        canonical_binding = _canonical_analysis_binding(binding)
        canonical_request = _canonical_tool_request(request)
        provider = _canonical_provider_registration(provider_registration)
        static = canonical_binding.capability_binding
        expected_provider = canonical_binding.provider_model
        if expected_provider is None or expected_provider != bind_ai_provider_model(
            provider,
            model_revision=expected_provider.model_revision,
        ):
            raise AIReadOnlyAnalysisError(
                "AI measurement Provider registration differs from its binding"
            )
        candidates = tuple(
            item
            for item in activation.activation_set.bindings
            if item.release == canonical_release and item.capability == static.capability
        )
        if len(candidates) != 1:
            raise AIReadOnlyAnalysisError(
                "AI measurement Capability release is not currently activated"
            )
        active = candidates[0]
        resolved = activation.resolve_for_dispatch(active.action_capability.reference())
        if (
            resolved.release != canonical_release
            or resolved.capability.reference() != static.capability
        ):
            raise AIReadOnlyAnalysisError(
                "AI measurement current signed Capability resolution differs"
            )
        prepared = PreparedCapabilityAction(
            activationSetDigest=activation.activation_set.activation_set_digest,
            release=canonical_release,
            capability=active.action_capability.reference(),
            request=canonical_request,
            requestDigest=capability_tool_request_digest(canonical_request),
            normalizedParametersDigest=(
                capability_normalized_parameters_digest(canonical_request.arguments)
            ),
        )
        return AIMeasurementOperationPreparation(
            binding=canonical_binding,
            release=canonical_release,
            preparedAction=prepared,
            registeredOperationDigest=registered_operation_digest,
            operationKey=operation_key,
            operationOrdinal=operation_ordinal,
            operationStage=operation_stage,
        )
    except (
        AIReadOnlyAnalysisError,
        ExistingModeCapabilityActivationError,
        ValidationError,
        ValueError,
    ) as exc:
        if isinstance(exc, AIReadOnlyAnalysisError):
            raise
        raise AIReadOnlyAnalysisError("AI measurement operation preparation failed closed") from exc


def _analysis_spec(capability_id: str, capability_version: str) -> _AIAnalysisCapabilitySpec:
    for spec in _AI_ANALYSIS_CAPABILITY_SPECS:
        if (spec.capability_id, spec.capability_version) == (
            capability_id,
            capability_version,
        ):
            return spec
    raise ValueError("AI read-only analysis Capability is not code registered")


def _analysis_spec_for_binding(
    binding: AIReadOnlyAnalysisCapabilityBinding,
) -> _AIAnalysisCapabilitySpec:
    capability = binding.capability.capability
    return _analysis_spec(capability.capability_id, capability.capability_version)


@cache
def _registered_definition_and_capability(
    spec: _AIAnalysisCapabilitySpec,
) -> tuple[CapabilityDefinition, CodeBackedCapabilityRef]:
    bundle = _existing_ai_capability_bundle()
    definition = next(
        item
        for item in bundle.definitions.definitions()
        if (item.capability_id, item.capability_version)
        == (spec.capability_id, spec.capability_version)
    )
    capability = next(
        item.reference()
        for item in bundle.capabilities()
        if item.capability == definition.reference()
    )
    return definition, capability


@cache
def _existing_ai_capability_bundle() -> ExistingModeCapabilityBundle:
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
        demo_mcp_tool(),
    ):
        tools.register(tool)
    return existing_mode_capability_bundle(tools, include_registered_mcp=True)


@cache
def _capability_domain_classification(
    definition: CapabilityDefinition,
    capability: CodeBackedCapabilityRef,
    worker: RegisteredDomainWorkerBoundaryProfile,
) -> CapabilityDomainClassificationRef:
    return RegisteredCapabilityDomainClassification(
        capability=definition.reference(),
        codeBackedCapability=capability,
        domainClassification=worker.domain_classification,
        reviewedSurfaceTypes=definition.supported_surface_types,
    ).reference()


@cache
def _ai_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.AI
    )


@cache
def _tool_surface(definition: CapabilityDefinition) -> AISecuritySurface:
    return typed_ai_security_surface(
        locator=ToolInterfaceSurfaceLocator(
            registry_id="pajin.capability-tools.existing-mode",
            tool_id=definition.tool.tool_id,
            tool_version=definition.tool.tool_version,
            input_schema_digest=definition.parameter_schema_digest,
        )
    )


def _canonical_provider_registration(
    registration: ProviderRegistration,
) -> ProviderRegistration:
    try:
        return ProviderRegistration.model_validate(registration.model_dump(mode="python"))
    except (AttributeError, ValidationError, ValueError) as exc:
        raise AIReadOnlyAnalysisError("AI Provider registration is not canonical") from exc


def _canonical_ai_surface(surface: AISecuritySurface) -> AISecuritySurface:
    try:
        return AISecuritySurface.model_validate(surface.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise AIReadOnlyAnalysisError("AI analysis Surface is not canonical") from exc


def _canonical_budget(budget: AIAnalysisBudgetCeiling) -> AIAnalysisBudgetCeiling:
    try:
        return AIAnalysisBudgetCeiling.model_validate(budget.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise AIReadOnlyAnalysisError("AI analysis budget is not canonical") from exc


def _canonical_analysis_binding(
    binding: AIReadOnlyAnalysisBinding,
) -> AIReadOnlyAnalysisBinding:
    try:
        return AIReadOnlyAnalysisBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise AIReadOnlyAnalysisError("AI read-only analysis binding is not canonical") from exc


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    try:
        return ToolRequest.model_validate(request.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise AIReadOnlyAnalysisError("AI analysis Tool request is not canonical") from exc


def _require_rag_surface_matches_provider(
    surface: AISecuritySurface,
    provider_model: AIProviderModelBinding,
) -> None:
    locator = surface.locator
    if (
        surface.surface_class is not AISurfaceClass.RAG
        or not isinstance(locator, HTTPRAGSurfaceLocator)
        or locator.boundary != "retrieval"
        or locator.route.method != "POST"
        or "{" in locator.route.path_template
        or http_route_scope_url(locator.route) != provider_model.endpoint
    ):
        raise ValueError("AI RAG Surface differs from the exact provider endpoint")


def _require_mcp_surface_matches_capability(surface: AISecuritySurface) -> None:
    locator = surface.locator
    if (
        surface.surface_class is not AISurfaceClass.MCP
        or not isinstance(locator, MCPServerSurfaceLocator)
        or locator.server_id != "demo-security"
        or "tools" not in locator.capabilities
    ):
        raise ValueError("AI MCP Surface differs from the registered MCP Capability")


def _validate_prepared_request(
    spec: _AIAnalysisCapabilitySpec,
    request: ToolRequest,
    binding: AIReadOnlyAnalysisBinding,
) -> None:
    if spec.provider_model_required:
        if binding.provider_model is None or request.target != binding.provider_model.endpoint:
            raise ValueError("AI provider request target differs from the exact provider binding")
        probe = AIChatProbeInput.model_validate(request.arguments)
        scenario = next(
            item for item in KISA_CATALOG.scenarios if item.scenario_id == spec.scenario_id
        )
        if (
            request.tool_id != AIChatProbeTool.spec.tool_id
            or probe.scenario_id != spec.scenario_id
            or probe.threat_class != spec.threat_class
            or len(probe.turns) != spec.request_units
            or scenario.probe is None
            or probe.turns != scenario.probe.turns
            or probe.checks != scenario.probe.checks
        ):
            raise ValueError("AI provider request differs from the exact REDTEAM scenario")
        return
    parsed = MCPInstructionHijackingProbeInput.model_validate(request.arguments)
    if (
        request.target != REGISTERED_MCP_TARGET
        or request.arguments != parsed.model_dump(mode="json", by_alias=True)
        or parsed.text != MCP_INSTRUCTION_HIJACKING_PROBE_TEXT
    ):
        raise ValueError("AI MCP request differs from the exact registered Tool contract")


__all__ = [
    "AI_ANALYSIS_BUDGET_CEILING_API_VERSION",
    "AI_MEASUREMENT_OPERATION_PREPARATION_API_VERSION",
    "AI_PROVIDER_MODEL_BINDING_API_VERSION",
    "AI_READ_ONLY_ANALYSIS_BINDING_API_VERSION",
    "AI_READ_ONLY_ANALYSIS_CAPABILITY_BINDING_API_VERSION",
    "AI_READ_ONLY_ANALYSIS_PREPARATION_API_VERSION",
    "AIAnalysisBudgetCeiling",
    "AIAnalysisProfileRef",
    "AIMeasurementOperationPreparation",
    "AIProviderModelBinding",
    "AIReadOnlyAnalysisBinding",
    "AIReadOnlyAnalysisBindingRef",
    "AIReadOnlyAnalysisCapabilityBinding",
    "AIReadOnlyAnalysisCapabilityBindingRef",
    "AIReadOnlyAnalysisError",
    "AIReadOnlyAnalysisPreparation",
    "ai_provider_registration_digest",
    "bind_ai_provider_model",
    "bind_ai_read_only_analysis",
    "prepare_ai_measurement_operation",
    "prepare_ai_read_only_analysis",
    "registered_ai_read_only_analysis_capability_bindings",
    "resolve_ai_read_only_analysis_capability_binding",
]
