"""SYS-001B read-only System inspection and host-agent preparation boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, ClassVar, Literal, Self, cast

from pydantic import ConfigDict, Field, JsonValue, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import (
    PreparedCapabilityAction,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.adapters import (
    ToolCapabilityRegistration,
    capability_definition_from_tool,
    registered_action_capability,
)
from pajin.capabilities.authorities import (
    CapabilityAuthorityAdapter,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapabilityRef,
    RegisteredCapabilityAuthority,
)
from pajin.capabilities.domain_projection import CapabilityDomainClassificationRef
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecycleRegistry,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityUseProfile,
    ResolvedCapabilityRelease,
)
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.capabilities.scaffold import capability_parameter_schema_digest
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    RegisteredDomainWorkerBoundaryProfile,
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    registered_domain_worker_boundary_profiles,
)
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSTrustPolicy,
)
from pajin.discovery.system_surfaces import (
    SystemConfigurationSurfaceLocator,
    SystemFilesystemSurfaceLocator,
    SystemHostResourceLocatorRef,
    SystemHostResourceLocatorRegistryRef,
    SystemHostResourceSurface,
    SystemHostSurfaceLocator,
    SystemProcessSurfaceLocator,
    SystemServiceSurfaceLocator,
    SystemSurfaceClass,
    SystemSurfaceLocatorKind,
    registered_system_host_resource_locator_registry,
)
from pajin.domain.models import (
    CampaignManifest,
    Scope,
    StrictModel,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.domain.security_domain import SecurityDomain, SecurityDomainClassificationRef
from pajin.graph.authority import (
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    RegisteredActionCapability,
)
from pajin.policy.scope import (
    InvalidScopeURL,
    normalize_scope_pattern,
    normalize_target_url,
    scope_matches,
)
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import Tool, ToolRegistry, ToolSpec

SYSTEM_READ_ONLY_CAPABILITY_ADAPTER_VERSION = "pajin.system-read-only-capability-adapter/v1"
SYSTEM_READ_ONLY_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/system-read-only-capability-activation-set/v1alpha1"
] = "pajin.dev/system-read-only-capability-activation-set/v1alpha1"
SYSTEM_READ_ONLY_BINDING_API_VERSION: Literal[
    "pajin.dev/system-read-only-inspection-binding/v1alpha1"
] = "pajin.dev/system-read-only-inspection-binding/v1alpha1"
SYSTEM_READ_ONLY_PREPARATION_API_VERSION: Literal[
    "pajin.dev/system-read-only-inspection-preparation/v1alpha1"
] = "pajin.dev/system-read-only-inspection-preparation/v1alpha1"
SYSTEM_CAMPAIGN_SCOPE_BINDING_API_VERSION: Literal[
    "pajin.dev/system-campaign-scope-binding/v1alpha1"
] = "pajin.dev/system-campaign-scope-binding/v1alpha1"
SYSTEM_HOST_AGENT_DEPLOYMENT_BINDING_API_VERSION: Literal[
    "pajin.dev/system-host-agent-deployment-binding/v1alpha1"
] = "pajin.dev/system-host-agent-deployment-binding/v1alpha1"
SYSTEM_HOST_AGENT_INSPECTION_REQUEST_API_VERSION: Literal[
    "pajin.dev/system-host-agent-inspection-request/v1alpha1"
] = "pajin.dev/system-host-agent-inspection-request/v1alpha1"
SYSTEM_READ_ONLY_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/system-read-only-capability-domain-classification/v1alpha1"
] = "pajin.dev/system-read-only-capability-domain-classification/v1alpha1"

SYSTEM_READ_ONLY_CAPABILITY_ID = "pajin.system.read-only-inspection"
SYSTEM_READ_ONLY_CAPABILITY_VERSION = "1.0.0"
SYSTEM_READ_ONLY_TOOL_ID = "system.read-only-inspection"
SYSTEM_SURFACE_SCOPE_ORIGIN = "https://system-scope.pajin.invalid"

_AUTHORITY_VERSION = "1.0.0"
_MAX_ARTIFACT_BYTES = 1_048_576
_MAX_RUNTIME_SECONDS = 60
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_HostId = Annotated[str, Field(pattern=r"^host-[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]


class SystemReadOnlyCapabilityError(ValueError):
    """Raised when SYS-001B Scope, trust, budget, or preparation drifts."""


class SystemReadOnlyOperation(StrEnum):
    """The metadata-only operations admitted by the first System slice."""

    HOST_METADATA = "host-metadata-read"
    PROCESS_METADATA = "process-metadata-read"
    FILESYSTEM_METADATA = "filesystem-metadata-read"
    SERVICE_STATUS = "service-status-read"
    CONFIGURATION_METADATA = "configuration-metadata-read"


_OPERATION_BY_SURFACE_CLASS = {
    SystemSurfaceClass.HOST: SystemReadOnlyOperation.HOST_METADATA,
    SystemSurfaceClass.PROCESS: SystemReadOnlyOperation.PROCESS_METADATA,
    SystemSurfaceClass.FILESYSTEM: SystemReadOnlyOperation.FILESYSTEM_METADATA,
    SystemSurfaceClass.SERVICE: SystemReadOnlyOperation.SERVICE_STATUS,
    SystemSurfaceClass.CONFIGURATION: SystemReadOnlyOperation.CONFIGURATION_METADATA,
}
_SUPPORTED_OPERATIONS = tuple(sorted(SystemReadOnlyOperation, key=lambda item: item.value))
_NON_ROOT_FORBIDDEN_IDENTITIES = frozenset(
    {
        "0",
        "administrator",
        "local-system",
        "localsystem",
        "nt-authority-system",
        "root",
        "s-1-5-18",
        "s-1-5-32-544",
        "system",
        "uid-0",
        "uid:0",
    }
)


class SystemHostAgentDeploymentRef(StrictModel):
    """Exact non-secret reference to one deployment-owned host-agent boundary."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    deployment_binding_id: str = Field(
        alias="deploymentBindingId",
        pattern=r"^system-host-agent-deployment_[a-f0-9]{64}$",
    )
    deployment_binding_version: Literal["1.0.0"] = Field(alias="deploymentBindingVersion")
    deployment_binding_digest: _Sha256 = Field(alias="deploymentBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    authorized_host_id: _HostId = Field(alias="authorizedHostId")
    principal_subject: _Identifier = Field(alias="principalSubject")
    certificate_spki_sha256: _Sha256 = Field(alias="certificateSPKISHA256")

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        expected_id = f"system-host-agent-deployment_{self.deployment_binding_digest}"
        if self.deployment_binding_id != expected_id:
            raise ValueError("System host agent deployment reference identity differs")
        return self


class SystemHostAgentDeploymentBinding(StrictModel):
    """Configuration-only mTLS/non-root boundary for one exact authorized host."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-host-agent-deployment-binding/v1alpha1"] = Field(
        default=SYSTEM_HOST_AGENT_DEPLOYMENT_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemHostAgentDeploymentBinding"] = "SystemHostAgentDeploymentBinding"
    deployment_binding_id: str = Field(
        default="",
        alias="deploymentBindingId",
        max_length=97,
    )
    deployment_binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="deploymentBindingVersion",
    )
    deployment_binding_digest: str = Field(
        default="",
        alias="deploymentBindingDigest",
        max_length=64,
    )
    deployment_id: _Identifier = Field(alias="deploymentId")
    authorized_host_id: _HostId = Field(alias="authorizedHostId")
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    worker_mtls_policy: WorkerMTLSTrustPolicy = Field(alias="workerMTLSPolicy")
    worker_mtls_policy_id: str = Field(
        alias="workerMTLSPolicyId",
        pattern=r"^worker-mtls-policy_[0-9a-f]{32}$",
    )
    worker_mtls_policy_digest: _Sha256 = Field(alias="workerMTLSPolicyDigest")
    certificate_binding: WorkerCertificateBinding = Field(alias="certificateBinding")
    agent_executable_sha256: _Sha256 = Field(alias="agentExecutableSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    allowed_operations: tuple[SystemReadOnlyOperation, ...] = Field(
        alias="allowedOperations",
        min_length=1,
        max_length=len(SystemReadOnlyOperation),
    )
    max_artifact_bytes: int = Field(
        alias="maxArtifactBytes",
        ge=1_024,
        le=_MAX_ARTIFACT_BYTES,
    )
    max_runtime_seconds: int = Field(
        alias="maxRuntimeSeconds",
        ge=1,
        le=_MAX_RUNTIME_SECONDS,
    )
    configuration_only: Literal[True] = Field(default=True, alias="configurationOnly")
    bearer_authentication_required: Literal[True] = Field(
        default=True,
        alias="bearerAuthenticationRequired",
    )
    direct_mtls_required: Literal[True] = Field(default=True, alias="directMTLSRequired")
    non_root_runtime_required: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeRequired",
    )
    runtime_attestation_required: Literal[True] = Field(
        default=True,
        alias="runtimeAttestationRequired",
    )
    metadata_only_operations: Literal[True] = Field(
        default=True,
        alias="metadataOnlyOperations",
    )
    bearer_authenticated: Literal[False] = Field(default=False, alias="bearerAuthenticated")
    live_direct_mtls_authenticated: Literal[False] = Field(
        default=False,
        alias="liveDirectMTLSAuthenticated",
    )
    non_root_runtime_verified: Literal[False] = Field(
        default=False,
        alias="nonRootRuntimeVerified",
    )
    agent_session_opened: Literal[False] = Field(default=False, alias="agentSessionOpened")
    host_connection_opened: Literal[False] = Field(
        default=False,
        alias="hostConnectionOpened",
    )
    host_access_authorized: Literal[False] = Field(
        default=False,
        alias="hostAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    root_authority_asserted: Literal[False] = Field(
        default=False,
        alias="rootAuthorityAsserted",
    )
    privilege_escalation_authorized: Literal[False] = Field(
        default=False,
        alias="privilegeEscalationAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("run_as_identity", mode="before")
    @classmethod
    def require_explicit_non_root_identity(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        if value != value.strip() or _is_forbidden_root_identity(value):
            raise ValueError("System host agent run-as identity must be explicit and non-root")
        return value

    @field_validator("allowed_operations")
    @classmethod
    def require_sorted_unique_operations(
        cls,
        value: tuple[SystemReadOnlyOperation, ...],
    ) -> tuple[SystemReadOnlyOperation, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("System host agent operations must be sorted and unique")
        return value

    @field_validator("max_artifact_bytes", "max_runtime_seconds", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("System host agent budgets must be integers")
        return value

    @field_validator(
        "configuration_only",
        "bearer_authentication_required",
        "direct_mtls_required",
        "non_root_runtime_required",
        "runtime_attestation_required",
        "metadata_only_operations",
        "bearer_authenticated",
        "live_direct_mtls_authenticated",
        "non_root_runtime_verified",
        "agent_session_opened",
        "host_connection_opened",
        "host_access_authorized",
        "credential_use_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "root_authority_asserted",
        "privilege_escalation_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System host agent deployment markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_deployment_identity(self) -> Self:
        worker = _system_worker_boundary_profile()
        if (
            self.worker_profile != worker.reference()
            or self.worker_mtls_policy_id != self.worker_mtls_policy.policy_id
            or self.worker_mtls_policy_digest
            != worker_mtls_trust_policy_digest(self.worker_mtls_policy)
            or self.certificate_binding not in self.worker_mtls_policy.bindings
        ):
            raise ValueError("System host agent deployment differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"deployment_binding_id", "deployment_binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.system-host-agent-deployment/v1",
            material,
        )
        binding_id = f"system-host-agent-deployment_{digest}"
        if self.deployment_binding_digest and self.deployment_binding_digest != digest:
            raise ValueError("System host agent deployment digest differs")
        if self.deployment_binding_id and self.deployment_binding_id != binding_id:
            raise ValueError("System host agent deployment ID differs")
        object.__setattr__(self, "deployment_binding_digest", digest)
        object.__setattr__(self, "deployment_binding_id", binding_id)
        return self

    def reference(self) -> SystemHostAgentDeploymentRef:
        return SystemHostAgentDeploymentRef(
            deploymentBindingId=self.deployment_binding_id,
            deploymentBindingVersion=self.deployment_binding_version,
            deploymentBindingDigest=self.deployment_binding_digest,
            deploymentId=self.deployment_id,
            authorizedHostId=self.authorized_host_id,
            principalSubject=self.certificate_binding.principal_subject,
            certificateSPKISHA256=self.certificate_binding.certificate_spki_sha256,
        )


class SystemInspectionBudget(StrictModel):
    """Attenuating request, artifact-byte, and runtime ceilings without reservation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    request_count: Literal[1] = Field(default=1, alias="requestCount")
    max_artifact_bytes: int = Field(
        alias="maxArtifactBytes",
        ge=1_024,
        le=_MAX_ARTIFACT_BYTES,
    )
    runtime_seconds: int = Field(alias="runtimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    filesystem_content_reads: Literal[0] = Field(default=0, alias="filesystemContentReads")
    configuration_value_reads: Literal[0] = Field(
        default=0,
        alias="configurationValueReads",
    )
    process_signals: Literal[0] = Field(default=0, alias="processSignals")
    service_control_operations: Literal[0] = Field(
        default=0,
        alias="serviceControlOperations",
    )
    host_write_operations: Literal[0] = Field(default=0, alias="hostWriteOperations")
    attenuation_only: Literal[True] = Field(default=True, alias="attenuationOnly")
    reservation_created: Literal[False] = Field(default=False, alias="reservationCreated")

    @field_validator(
        "request_count",
        "max_artifact_bytes",
        "runtime_seconds",
        "filesystem_content_reads",
        "configuration_value_reads",
        "process_signals",
        "service_control_operations",
        "host_write_operations",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("System inspection budget values must be integers")
        return value

    @field_validator("attenuation_only", "reservation_created", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System inspection budget markers must be booleans")
        return value


class SystemHostAgentInspectionRequest(StrictModel):
    """Secret-free request description; it neither connects to nor reads the host."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-host-agent-inspection-request/v1alpha1"] = Field(
        default=SYSTEM_HOST_AGENT_INSPECTION_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemHostAgentInspectionRequest"] = "SystemHostAgentInspectionRequest"
    deployment: SystemHostAgentDeploymentRef
    operation: SystemReadOnlyOperation
    surface: SystemHostResourceSurface
    target: str = Field(min_length=9, max_length=2_000)
    method: Literal["GET"] = "GET"
    budget: SystemInspectionBudget
    request_body_embedded: Literal[False] = Field(default=False, alias="requestBodyEmbedded")
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    live_authentication_performed: Literal[False] = Field(
        default=False,
        alias="liveAuthenticationPerformed",
    )
    agent_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="agentInvocationAuthorized",
    )
    host_read_authorized: Literal[False] = Field(default=False, alias="hostReadAuthorized")
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )

    @field_validator("target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        return _canonical_system_surface_target(value)

    @field_validator(
        "request_body_embedded",
        "credential_material_embedded",
        "live_authentication_performed",
        "agent_invocation_authorized",
        "host_read_authorized",
        "network_access_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System host agent request markers must be booleans")
        return value

    @model_validator(mode="after")
    def require_operation_surface(self) -> Self:
        if _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class] is not self.operation:
            raise ValueError("System inspection operation differs from the exact Surface class")
        if (
            self.surface.initial_state != "registered-not-authorized"
            or _surface_host(self.surface).host_id != self.deployment.authorized_host_id
        ):
            raise ValueError("System inspection Surface differs from the authorized host")
        if self.target != system_surface_scope_target(self.surface):
            raise ValueError("System inspection target differs from the exact Surface")
        return self


@dataclass(frozen=True, slots=True)
class BoundedSystemHostAgentAdapter:
    """Adapt exact typed Surfaces without authenticating or invoking a host agent."""

    _deployment: SystemHostAgentDeploymentBinding

    def __post_init__(self) -> None:
        try:
            canonical = SystemHostAgentDeploymentBinding.model_validate(
                self._deployment.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise SystemReadOnlyCapabilityError(
                "System host agent deployment is not canonical"
            ) from exc
        object.__setattr__(self, "_deployment", canonical)

    @property
    def deployment(self) -> SystemHostAgentDeploymentBinding:
        return self._deployment.model_copy(deep=True)

    def prepare_request(
        self,
        *,
        surface: SystemHostResourceSurface,
        operation: SystemReadOnlyOperation,
    ) -> SystemHostAgentInspectionRequest:
        """Return one bounded request description without host or network authority."""

        canonical_surface = _canonical_surface(surface)
        try:
            canonical_operation = SystemReadOnlyOperation(operation)
        except ValueError as exc:
            raise SystemReadOnlyCapabilityError(
                "System inspection operation is unsupported"
            ) from exc
        expected = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
        host = _surface_host(canonical_surface)
        if host.host_id != self._deployment.authorized_host_id:
            raise SystemReadOnlyCapabilityError(
                "System Surface host differs from the authorized host-agent deployment"
            )
        if canonical_operation is not expected:
            raise SystemReadOnlyCapabilityError(
                "System inspection operation differs from the exact Surface class"
            )
        if canonical_operation not in self._deployment.allowed_operations:
            raise SystemReadOnlyCapabilityError(
                "System inspection operation is outside the host-agent deployment"
            )
        return SystemHostAgentInspectionRequest(
            deployment=self._deployment.reference(),
            operation=canonical_operation,
            surface=canonical_surface,
            target=system_surface_scope_target(canonical_surface),
            budget=SystemInspectionBudget(
                maxArtifactBytes=self._deployment.max_artifact_bytes,
                runtimeSeconds=self._deployment.max_runtime_seconds,
            ),
        )


class SystemReadOnlyInspectionTool(Tool):
    """CAP-001 Tool identity whose authenticated host runtime remains unavailable."""

    spec = ToolSpec(
        tool_id=SYSTEM_READ_ONLY_TOOL_ID,
        version="1.0.0",
        description="Prepare one exact metadata-only System host-agent inspection",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"host-agent", "read-only", "system"}),
        evidence_types=frozenset({"json", "system-inspection-json"}),
        network_access=False,
        network_request_cost=1,
        parallel_safe=False,
    )

    def stable_execution_context(self) -> dict[str, object]:
        spec = self.spec.model_dump(mode="json")
        spec["categories"] = sorted(self.spec.categories)
        spec["evidence_types"] = sorted(self.spec.evidence_types)
        return {
            "implementationVersion": "pajin.tool-adapter/v1",
            "spec": spec,
            "liveHostAgentRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        _validate_system_tool_request(request)
        raise SystemReadOnlyCapabilityError(
            "SYS-001B does not materialize an authenticated host-agent Worker job"
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        _validate_system_tool_request(request)
        raise SystemReadOnlyCapabilityError(
            "SYS-001B has no authenticated host-agent runtime result to normalize"
        )


class SystemReadOnlyCapabilityDomainClassification(StrictModel):
    """Exact System classification for the additive SYS-001B CAP-002 bundle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-read-only-capability-domain-classification/v1alpha1"] = (
        Field(
            default=SYSTEM_READ_ONLY_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["SystemReadOnlyCapabilityDomainClassification"] = (
        "SystemReadOnlyCapabilityDomainClassification"
    )
    classification_id: str = Field(default="", alias="classificationId", max_length=97)
    classification_digest: str = Field(
        default="",
        alias="classificationDigest",
        max_length=64,
    )
    capability: CapabilityDefinitionRef
    code_backed_capability: CodeBackedCapabilityRef = Field(alias="codeBackedCapability")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    reviewed_surface_types: tuple[SystemSurfaceLocatorKind, ...] = Field(
        default=(
            "system-configuration",
            "system-filesystem",
            "system-host",
            "system-process",
            "system-service",
        ),
        alias="reviewedSurfaceTypes",
    )
    mapping_basis: Literal["sys-001b-explicit-code-reviewed-capability-and-surface-set"] = Field(
        default="sys-001b-explicit-code-reviewed-capability-and-surface-set",
        alias="mappingBasis",
    )
    projection_only: Literal[True] = Field(default=True, alias="projectionOnly")
    complete_code_authority_set_verified: Literal[True] = Field(
        default=True,
        alias="completeCodeAuthoritySetVerified",
    )
    global_domain_inventory_changed: Literal[False] = Field(
        default=False,
        alias="globalDomainInventoryChanged",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "projection_only",
        "complete_code_authority_set_verified",
        "global_domain_inventory_changed",
        "capability_activation_authorized",
        "worker_selection_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System Capability Domain markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        capability = _system_code_backed_capability()
        worker = _system_worker_boundary_profile()
        if (
            self.capability != capability.capability
            or self.code_backed_capability != capability
            or self.domain_classification != worker.domain_classification
            or self.reviewed_surface_types != _supported_locator_kinds()
        ):
            raise ValueError("System Capability Domain classification differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.system-domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("System Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("System Capability Domain classification ID differs")
        object.__setattr__(self, "classification_digest", digest)
        object.__setattr__(self, "classification_id", classification_id)
        return self

    def reference(self) -> CapabilityDomainClassificationRef:
        return CapabilityDomainClassificationRef(
            classificationId=self.classification_id,
            classificationDigest=self.classification_digest,
            capability=self.capability,
            domainClassification=self.domain_classification,
        )


class SystemCampaignScopeBinding(StrictModel):
    """Content-addressed current Campaign projection for exact System preparation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-campaign-scope-binding/v1alpha1"] = Field(
        default=SYSTEM_CAMPAIGN_SCOPE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemCampaignScopeBinding"] = "SystemCampaignScopeBinding"
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    campaign_name: str = Field(
        alias="campaignName",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    scope: Scope
    allowed_methods: tuple[str, ...] = Field(
        alias="allowedMethods",
        min_length=1,
        max_length=32,
    )
    allow_private_networks: bool = Field(alias="allowPrivateNetworks")
    projection_only: Literal[True] = Field(default=True, alias="projectionOnly")
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "allow_private_networks",
        "projection_only",
        "approval_satisfied",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System Campaign Scope markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_scope_projection(self) -> Self:
        if self.allowed_methods != tuple(sorted(set(self.allowed_methods))):
            raise ValueError("System Campaign allowed methods must be sorted and unique")
        if "GET" not in self.allowed_methods:
            raise ValueError("System Campaign Scope requires reviewed GET authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.system-campaign-scope-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("System Campaign Scope binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class SystemReadOnlyCapabilityBundle:
    """Frozen CAP-001/CAP-002 registries for one System read-only Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapabilityRef:
        manifests = self.authorities.capabilities()
        if len(manifests) != 1:
            raise SystemReadOnlyCapabilityError(
                "System read-only Capability authority inventory drifted"
            )
        return manifests[0].reference()


class SystemReadOnlyCapabilityActivationBinding(StrictModel):
    """One exact externally signed release admitted for Range-only use."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        definition = registered_system_read_only_capability_definition()
        action = self.action_capability
        if (
            self.capability != _system_code_backed_capability()
            or action != registered_action_capability(definition)
        ):
            raise ValueError("System read-only activation references another Capability")
        return self


class SystemReadOnlyCapabilityActivationSet(StrictModel):
    """Content-addressed activation of exactly one signed System release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-read-only-capability-activation-set/v1alpha1"] = Field(
        default=SYSTEM_READ_ONLY_CAPABILITY_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemReadOnlyCapabilityActivationSet"] = "SystemReadOnlyCapabilityActivationSet"
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(
        default="",
        alias="activationSetDigest",
        max_length=64,
    )
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: SystemReadOnlyCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.system-read-only-activation-set/v1",
            material,
        )
        activation_set_id = f"system-read-only-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("System read-only activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("System read-only activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class SystemReadOnlyCapabilityActivation:
    """Runtime activation that rechecks the signed current release on every use."""

    bundle: SystemReadOnlyCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: SystemReadOnlyCapabilityActivationSet

    def __post_init__(self) -> None:
        _verify_activation(self)

    def action_registry(self) -> ActionCapabilityRegistry:
        _verify_activation(self)
        return ActionCapabilityRegistry((self.activation_set.binding.action_capability,))

    def definition(self) -> CapabilityDefinition:
        _verify_activation(self)
        try:
            return self.bundle.definitions.resolve(
                self.activation_set.binding.capability.capability
            )
        except CapabilityDefinitionError as exc:
            raise SystemReadOnlyCapabilityError(
                "System read-only activated Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise SystemReadOnlyCapabilityError(
                "System read-only CAP-002 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(self, reference: ActionCapabilityRef) -> ResolvedCapabilityRelease:
        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise SystemReadOnlyCapabilityError(
                "System read-only GRAPH Capability reference is not canonical"
            ) from exc
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise SystemReadOnlyCapabilityError(
                "System read-only GRAPH Capability is outside the activation"
            )
        return _resolve_activation_binding(self, binding)

    def prepare_action(
        self,
        *,
        release: CapabilityReleaseRef,
        request: ToolRequest,
        parameters: Mapping[str, JsonValue],
    ) -> PreparedCapabilityAction:
        binding = self.activation_set.binding
        canonical_release = _canonical_release_ref(release)
        if binding.release != canonical_release:
            raise SystemReadOnlyCapabilityError(
                "System read-only release is outside the activation"
            )
        resolved = self.resolve_for_dispatch(binding.action_capability.reference())
        canonical_request = _canonical_tool_request(request)
        try:
            materializer = self.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.MATERIALIZER,
            )
            compiler = self.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.ACTION_COMPILER,
            )
            materialized = materializer.materialize(parameters)
            compiled = compiler.compile(canonical_request, materialized)
        except CapabilityAuthorityError as exc:
            raise SystemReadOnlyCapabilityError(
                "System read-only CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _SystemReadOnlyAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        definition: CapabilityDefinition,
        tool: SystemReadOnlyInspectionTool,
    ) -> None:
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{SYSTEM_READ_ONLY_CAPABILITY_ID}.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": SYSTEM_READ_ONLY_CAPABILITY_ADAPTER_VERSION,
            "method": "GET",
            "parameterSchemaDigest": self._definition.parameter_schema_digest,
            "hostAgentRequestAdaptationAvailable": True,
            "liveHostAgentRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
            "replayAuthorized": False,
            "cleanupAuthorized": False,
            "tool": {
                "type": f"{type(self._tool).__module__}.{type(self._tool).__qualname__}",
                "context": self._tool.stable_execution_context(),
            },
        }


class _SystemReadOnlyMaterializer(_SystemReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            request = SystemHostAgentInspectionRequest.model_validate(dict(parameters))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "System parameters differ from the bounded host-agent request"
            ) from exc
        return cast(Mapping[str, JsonValue], request.model_dump(mode="json", by_alias=True))


class _SystemReadOnlyActionCompiler(_SystemReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        try:
            inspection = SystemHostAgentInspectionRequest.model_validate(
                dict(materialized_arguments)
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "System materialized host-agent request is invalid"
            ) from exc
        if (
            request.tool_id != SYSTEM_READ_ONLY_TOOL_ID
            or request.method != "GET"
            or request.target != inspection.target
            or request.arguments
        ):
            raise CapabilityAuthorityError(
                "System compiler accepts only one exact empty GET request"
            )
        return request.model_copy(
            update={"arguments": inspection.model_dump(mode="json", by_alias=True)}
        )


class _SystemReadOnlyExecutorAdapter(_SystemReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _SystemReadOnlyResultNormalizer(_SystemReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _SystemReadOnlySuccessOracle(_SystemReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del request, result
        return CapabilityOracleDecision.INCONCLUSIVE


class _SystemReadOnlyReplayStrategy(_SystemReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        return None


class _SystemReadOnlyCleanupHandler(_SystemReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        return None


@cache
def registered_system_read_only_capability_definition() -> CapabilityDefinition:
    """Return exact CAP-001 metadata for bounded System inspection preparation."""

    raw_schema = SystemHostAgentInspectionRequest.model_json_schema(by_alias=True)
    raw_schema["required"] = sorted(raw_schema["required"])
    schema = cast(Mapping[str, JsonValue], raw_schema)
    return capability_definition_from_tool(
        SystemReadOnlyInspectionTool.spec,
        ToolCapabilityRegistration(
            capabilityId=SYSTEM_READ_ONLY_CAPABILITY_ID,
            capabilityVersion=SYSTEM_READ_ONLY_CAPABILITY_VERSION,
            toolId=SYSTEM_READ_ONLY_TOOL_ID,
            domain="system",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=_supported_locator_kinds(),
            threatClasses=("host-inventory", "system-configuration"),
            preconditions=(
                "authenticated-host-agent-deployment",
                "current-campaign-scope",
                "exact-system-surface",
                "fresh-signed-authorization",
                "non-root-runtime-attestation",
                "one-use-action-permit",
            ),
            parameterSchemaDigest=capability_parameter_schema_digest(schema),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=1,
        ),
    )


def system_read_only_capability_bundle(tools: ToolRegistry) -> SystemReadOnlyCapabilityBundle:
    """Bind the exact System Tool identity to all seven required CAP-002 roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("System read-only Capability requires a ToolRegistry")
    try:
        tool = tools.tool(SYSTEM_READ_ONLY_TOOL_ID)
        spec = tools.spec(SYSTEM_READ_ONLY_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise SystemReadOnlyCapabilityError("System read-only Tool is unavailable") from exc
    if type(tool) is not SystemReadOnlyInspectionTool or spec != SystemReadOnlyInspectionTool.spec:
        raise SystemReadOnlyCapabilityError("System read-only Tool implementation drifted")
    definition = registered_system_read_only_capability_definition()
    definitions = CapabilityDefinitionRegistry((definition,))
    typed_tool = tool
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _SystemReadOnlyActionCompiler(definition, typed_tool),
        _SystemReadOnlyCleanupHandler(definition, typed_tool),
        _SystemReadOnlyExecutorAdapter(definition, typed_tool),
        _SystemReadOnlyMaterializer(definition, typed_tool),
        _SystemReadOnlyReplayStrategy(definition, typed_tool),
        _SystemReadOnlyResultNormalizer(definition, typed_tool),
        _SystemReadOnlySuccessOracle(definition, typed_tool),
    )
    return SystemReadOnlyCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_system_read_only_capability(
    *,
    bundle: SystemReadOnlyCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> SystemReadOnlyCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, SystemReadOnlyCapabilityBundle):
        raise TypeError("System read-only activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("System read-only activation requires a verified lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability()
        definition = bundle.definitions.resolve(capability.capability)
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise SystemReadOnlyCapabilityError(
            "System read-only signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition != registered_system_read_only_capability_definition()
    ):
        raise SystemReadOnlyCapabilityError(
            "System read-only signed release differs from code authority"
        )
    binding = SystemReadOnlyCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return SystemReadOnlyCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=SystemReadOnlyCapabilityActivationSet(binding=binding),
    )


class SystemReadOnlyInspectionBindingRef(StrictModel):
    """Exact content-addressed reference to the SYS-001B static binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: Literal["pajin.system.read-only-inspection.binding"] = Field(alias="bindingId")
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class SystemReadOnlyInspectionBinding(StrictModel):
    """Exact Surface/CAP-002/Worker contract without host-agent invocation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-read-only-inspection-binding/v1alpha1"] = Field(
        default=SYSTEM_READ_ONLY_BINDING_API_VERSION, alias="apiVersion"
    )
    kind: Literal["SystemReadOnlyInspectionBinding"] = "SystemReadOnlyInspectionBinding"
    binding_id: Literal["pajin.system.read-only-inspection.binding"] = Field(
        default="pajin.system.read-only-inspection.binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["system.host-resource"] = Field(
        default="system.host-resource",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.system.host-resource.v1"] = Field(
        default="pajin.locator.system.host-resource.v1",
        alias="locatorSchema",
    )
    locator_registry: SystemHostResourceLocatorRegistryRef = Field(alias="locatorRegistry")
    supported_locators: tuple[SystemHostResourceLocatorRef, ...] = Field(
        alias="supportedLocators",
        min_length=5,
        max_length=5,
    )
    capability: CodeBackedCapabilityRef
    capability_domain_classification: SystemReadOnlyCapabilityDomainClassification = Field(
        alias="capabilityDomainClassification"
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    supported_operations: tuple[SystemReadOnlyOperation, ...] = Field(
        default=_SUPPORTED_OPERATIONS,
        alias="supportedOperations",
    )
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    complete_cap_002_verified: Literal[True] = Field(
        default=True,
        alias="completeCAP002Verified",
    )
    preparation_available: Literal[True] = Field(default=True, alias="preparationAvailable")
    exact_surface_operation_binding_required: Literal[True] = Field(
        default=True,
        alias="exactSurfaceOperationBindingRequired",
    )
    bounded_budget_required: Literal[True] = Field(
        default=True,
        alias="boundedBudgetRequired",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    authenticated_non_root_host_agent_required: Literal[True] = Field(
        default=True,
        alias="authenticatedNonRootHostAgentRequired",
    )
    action_permit_required: Literal[True] = Field(default=True, alias="actionPermitRequired")
    gateway_policy_reentry_required: Literal[True] = Field(
        default=True,
        alias="gatewayPolicyReentryRequired",
    )
    worker_direct_mtls_required: Literal[True] = Field(
        default=True,
        alias="workerDirectMTLSRequired",
    )
    worker_bearer_authentication_required: Literal[True] = Field(
        default=True,
        alias="workerBearerAuthenticationRequired",
    )
    non_root_runtime_attestation_required: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeAttestationRequired",
    )
    agent_session_opened: Literal[False] = Field(default=False, alias="agentSessionOpened")
    host_connection_opened: Literal[False] = Field(
        default=False,
        alias="hostConnectionOpened",
    )
    host_read_authorized: Literal[False] = Field(default=False, alias="hostReadAuthorized")
    process_inspection_authorized: Literal[False] = Field(
        default=False,
        alias="processInspectionAuthorized",
    )
    filesystem_read_authorized: Literal[False] = Field(
        default=False,
        alias="filesystemReadAuthorized",
    )
    service_inspection_authorized: Literal[False] = Field(
        default=False,
        alias="serviceInspectionAuthorized",
    )
    configuration_read_authorized: Literal[False] = Field(
        default=False,
        alias="configurationReadAuthorized",
    )
    service_control_authorized: Literal[False] = Field(
        default=False,
        alias="serviceControlAuthorized",
    )
    host_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="hostMutationAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    root_authority_asserted: Literal[False] = Field(
        default=False,
        alias="rootAuthorityAsserted",
    )
    privilege_escalation_authorized: Literal[False] = Field(
        default=False,
        alias="privilegeEscalationAuthorized",
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
    observation_production_authorized: Literal[False] = Field(
        default=False,
        alias="observationProductionAuthorized",
    )
    evidence_sealing_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceSealingAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    runtime_support_asserted_by_binding: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAssertedByBinding",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "binding_only",
        "complete_cap_002_verified",
        "preparation_available",
        "exact_surface_operation_binding_required",
        "bounded_budget_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "authenticated_non_root_host_agent_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "worker_direct_mtls_required",
        "worker_bearer_authentication_required",
        "non_root_runtime_attestation_required",
        "agent_session_opened",
        "host_connection_opened",
        "host_read_authorized",
        "process_inspection_authorized",
        "filesystem_read_authorized",
        "service_inspection_authorized",
        "configuration_read_authorized",
        "service_control_authorized",
        "host_mutation_authorized",
        "credential_use_authorized",
        "root_authority_asserted",
        "privilege_escalation_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "observation_production_authorized",
        "evidence_sealing_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted_by_binding",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System read-only binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_system_read_only_capability_definition()
        registry = registered_system_host_resource_locator_registry()
        worker = _system_worker_boundary_profile()
        expected_locators = tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        )
        if (
            self.locator_registry != registry.reference()
            or self.supported_locators != expected_locators
            or self.capability != _system_code_backed_capability()
            or self.capability_domain_classification
            != registered_system_read_only_capability_domain_classification()
            or self.worker_profile != worker.reference()
            or self.supported_operations != _SUPPORTED_OPERATIONS
            or definition.supported_surface_types != _supported_locator_kinds()
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != SYSTEM_READ_ONLY_TOOL_ID
            or definition.network_access is not False
            or definition.approval_required is not True
            or worker.network_boundary is not WorkerNetworkBoundary.DEPLOYMENT_SCOPED
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.BOUNDED_HOST_READ
            or worker.credential_boundary is not WorkerCredentialBoundary.DEPLOYMENT_AUTHENTICATION
            or worker.runtime_boundary is not WorkerRuntimeBoundary.AUTHENTICATED_NON_ROOT_AGENT
            or worker.required_identity_dimensions != ("authorized-host", "host-agent")
            or worker.required_budget_dimensions != ("artifact-bytes", "runtime")
        ):
            raise ValueError("System read-only binding differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.system-read-only-inspection-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("System read-only binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> SystemReadOnlyInspectionBindingRef:
        return SystemReadOnlyInspectionBindingRef(
            bindingId=self.binding_id,
            bindingVersion=self.binding_version,
            bindingDigest=self.binding_digest,
        )


class SystemReadOnlyInspectionPreparation(StrictModel):
    """Exact signed preparation with no host authentication, access, or dispatch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-read-only-inspection-preparation/v1alpha1"] = Field(
        default=SYSTEM_READ_ONLY_PREPARATION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["SystemReadOnlyInspectionPreparation"] = "SystemReadOnlyInspectionPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=100)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: SystemReadOnlyInspectionBinding
    surface: SystemHostResourceSurface
    operation: SystemReadOnlyOperation
    host_agent_deployment: SystemHostAgentDeploymentBinding = Field(alias="hostAgentDeployment")
    inspection_request: SystemHostAgentInspectionRequest = Field(alias="inspectionRequest")
    campaign_scope: SystemCampaignScopeBinding = Field(alias="campaignScope")
    matched_surface_allow_rule: str = Field(
        alias="matchedSurfaceAllowRule",
        min_length=1,
        max_length=2_000,
    )
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    current_campaign_bound: Literal[True] = Field(default=True, alias="currentCampaignBound")
    exact_host_agent_bound: Literal[True] = Field(default=True, alias="exactHostAgentBound")
    inspection_request_adapted: Literal[True] = Field(
        default=True,
        alias="inspectionRequestAdapted",
    )
    capability_prepared: Literal[True] = Field(default=True, alias="capabilityPrepared")
    live_host_agent_runtime_available: Literal[False] = Field(
        default=False,
        alias="liveHostAgentRuntimeAvailable",
    )
    bearer_authenticated: Literal[False] = Field(default=False, alias="bearerAuthenticated")
    live_direct_mtls_authenticated: Literal[False] = Field(
        default=False,
        alias="liveDirectMTLSAuthenticated",
    )
    non_root_runtime_verified: Literal[False] = Field(
        default=False,
        alias="nonRootRuntimeVerified",
    )
    agent_session_opened: Literal[False] = Field(default=False, alias="agentSessionOpened")
    host_connection_opened: Literal[False] = Field(
        default=False,
        alias="hostConnectionOpened",
    )
    host_read_authorized: Literal[False] = Field(default=False, alias="hostReadAuthorized")
    process_inspection_authorized: Literal[False] = Field(
        default=False,
        alias="processInspectionAuthorized",
    )
    filesystem_read_authorized: Literal[False] = Field(
        default=False,
        alias="filesystemReadAuthorized",
    )
    service_inspection_authorized: Literal[False] = Field(
        default=False,
        alias="serviceInspectionAuthorized",
    )
    configuration_read_authorized: Literal[False] = Field(
        default=False,
        alias="configurationReadAuthorized",
    )
    service_control_authorized: Literal[False] = Field(
        default=False,
        alias="serviceControlAuthorized",
    )
    host_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="hostMutationAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    root_authority_asserted: Literal[False] = Field(
        default=False,
        alias="rootAuthorityAsserted",
    )
    privilege_escalation_authorized: Literal[False] = Field(
        default=False,
        alias="privilegeEscalationAuthorized",
    )
    budget_reserved: Literal[False] = Field(default=False, alias="budgetReserved")
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    network_request_performed: Literal[False] = Field(
        default=False,
        alias="networkRequestPerformed",
    )
    observation_produced: Literal[False] = Field(
        default=False,
        alias="observationProduced",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    gateway_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayDispatchAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "current_campaign_bound",
        "exact_host_agent_bound",
        "inspection_request_adapted",
        "capability_prepared",
        "live_host_agent_runtime_available",
        "bearer_authenticated",
        "live_direct_mtls_authenticated",
        "non_root_runtime_verified",
        "agent_session_opened",
        "host_connection_opened",
        "host_read_authorized",
        "process_inspection_authorized",
        "filesystem_read_authorized",
        "service_inspection_authorized",
        "configuration_read_authorized",
        "service_control_authorized",
        "host_mutation_authorized",
        "credential_use_authorized",
        "root_authority_asserted",
        "privilege_escalation_authorized",
        "budget_reserved",
        "worker_job_materialized",
        "network_request_performed",
        "observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "approval_satisfied",
        "permit_issuance_authorized",
        "gateway_dispatch_authorized",
        "worker_selection_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System read-only preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        expected_action = registered_action_capability(
            registered_system_read_only_capability_definition()
        ).reference()
        expected_surface_rule = _require_exact_scope_allow(
            self.campaign_scope,
            system_surface_scope_target(self.surface),
            label="System Surface",
        )
        expected_request = BoundedSystemHostAgentAdapter(
            self.host_agent_deployment
        ).prepare_request(surface=self.surface, operation=self.operation)
        request = self.prepared_action.request
        if (
            self.binding != registered_system_read_only_inspection_binding()
            or self.surface.initial_state != "registered-not-authorized"
            or self.inspection_request != expected_request
            or self.matched_surface_allow_rule != expected_surface_rule
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != SYSTEM_READ_ONLY_TOOL_ID
            or request.method != "GET"
            or request.target != self.inspection_request.target
            or request.arguments != self.inspection_request.model_dump(mode="json", by_alias=True)
        ):
            raise ValueError("System read-only preparation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.system-read-only-inspection-preparation/v1",
            material,
        )
        preparation_id = f"system-read-only-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("System read-only preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("System read-only preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def bind_system_host_agent_deployment(
    *,
    deployment_id: str,
    authorized_host_id: str,
    trust_policy: WorkerMTLSTrustPolicy,
    certificate_binding: WorkerCertificateBinding,
    agent_executable_sha256: str,
    run_as_identity: str,
    allowed_operations: tuple[SystemReadOnlyOperation, ...] = _SUPPORTED_OPERATIONS,
    max_artifact_bytes: int = 262_144,
    max_runtime_seconds: int = 30,
) -> SystemHostAgentDeploymentBinding:
    """Pin deployment configuration without performing bearer, mTLS, or runtime admission."""

    try:
        canonical_policy = WorkerMTLSTrustPolicy.model_validate(
            trust_policy.model_dump(mode="json")
        )
        canonical_certificate = WorkerCertificateBinding.model_validate(
            certificate_binding.model_dump(mode="json")
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise SystemReadOnlyCapabilityError(
            "System host agent mTLS policy or certificate binding is not canonical"
        ) from exc
    if canonical_certificate not in canonical_policy.bindings:
        raise SystemReadOnlyCapabilityError(
            "System host agent certificate is outside the exact mTLS trust policy"
        )
    if (
        not isinstance(run_as_identity, str)
        or run_as_identity != run_as_identity.strip()
        or _is_forbidden_root_identity(run_as_identity)
    ):
        raise SystemReadOnlyCapabilityError(
            "System host agent run-as identity must be explicit and non-root"
        )
    try:
        canonical_operations = tuple(SystemReadOnlyOperation(item) for item in allowed_operations)
        if canonical_operations != tuple(
            sorted(set(canonical_operations), key=lambda item: item.value)
        ):
            raise SystemReadOnlyCapabilityError(
                "System host agent operations must be sorted and unique"
            )
        return SystemHostAgentDeploymentBinding(
            deploymentId=deployment_id,
            authorizedHostId=authorized_host_id,
            workerProfile=_system_worker_boundary_profile().reference(),
            workerMTLSPolicy=canonical_policy,
            workerMTLSPolicyId=canonical_policy.policy_id,
            workerMTLSPolicyDigest=worker_mtls_trust_policy_digest(canonical_policy),
            certificateBinding=canonical_certificate,
            agentExecutableSHA256=agent_executable_sha256,
            runAsIdentity=run_as_identity,
            allowedOperations=canonical_operations,
            maxArtifactBytes=max_artifact_bytes,
            maxRuntimeSeconds=max_runtime_seconds,
        )
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, SystemReadOnlyCapabilityError):
            raise
        raise SystemReadOnlyCapabilityError(
            "System host agent deployment binding failed closed"
        ) from exc


def worker_mtls_trust_policy_digest(policy: WorkerMTLSTrustPolicy) -> str:
    """Return an exact non-secret digest over the deployment-owned mTLS policy."""

    try:
        canonical = WorkerMTLSTrustPolicy.model_validate(policy.model_dump(mode="json"))
    except (AttributeError, ValidationError, ValueError) as exc:
        raise SystemReadOnlyCapabilityError(
            "System host agent mTLS policy is not canonical"
        ) from exc
    return capability_definition_digest(
        "pajin.capability.system-host-agent-mtls-policy/v1",
        canonical.model_dump(mode="json"),
    )


@cache
def registered_system_read_only_inspection_binding() -> SystemReadOnlyInspectionBinding:
    """Return the exact SYS-001B binding without host-agent or Worker selection."""

    registry = registered_system_host_resource_locator_registry()
    return SystemReadOnlyInspectionBinding(
        locatorRegistry=registry.reference(),
        supportedLocators=tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        ),
        capability=_system_code_backed_capability(),
        capabilityDomainClassification=(
            registered_system_read_only_capability_domain_classification()
        ),
        workerProfile=_system_worker_boundary_profile().reference(),
    )


def resolve_system_read_only_inspection_binding(
    reference: SystemReadOnlyInspectionBindingRef,
) -> SystemReadOnlyInspectionBinding:
    binding = registered_system_read_only_inspection_binding()
    if binding.reference() == reference:
        return binding.model_copy(deep=True)
    raise SystemReadOnlyCapabilityError(
        "System read-only inspection binding is not registered exactly"
    )


@cache
def registered_system_read_only_capability_domain_classification() -> (
    SystemReadOnlyCapabilityDomainClassification
):
    capability = _system_code_backed_capability()
    return SystemReadOnlyCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=_system_worker_boundary_profile().domain_classification,
    )


def resolve_system_read_only_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
) -> SystemReadOnlyCapabilityDomainClassification:
    classification = registered_system_read_only_capability_domain_classification()
    if classification.reference() == reference:
        return classification.model_copy(deep=True)
    raise SystemReadOnlyCapabilityError(
        "System read-only Capability Domain classification is not registered exactly"
    )


def system_surface_scope_target(surface: SystemHostResourceSurface) -> str:
    """Return a non-routable exact Campaign Scope token for one typed System Surface."""

    canonical = _canonical_surface(surface)
    return f"{SYSTEM_SURFACE_SCOPE_ORIGIN}/surfaces/{canonical.surface_id}"


def prepare_system_read_only_inspection(
    *,
    activation: SystemReadOnlyCapabilityActivation,
    release: CapabilityReleaseRef,
    campaign: CampaignManifest,
    surface: SystemHostResourceSurface,
    operation: SystemReadOnlyOperation,
    host_agent: BoundedSystemHostAgentAdapter,
    request_id: str,
    agent_id: str,
) -> SystemReadOnlyInspectionPreparation:
    """Compile exact signed metadata inspection and stop before authentication or dispatch."""

    if not isinstance(activation, SystemReadOnlyCapabilityActivation):
        raise TypeError("System read-only preparation requires System activation")
    if not isinstance(host_agent, BoundedSystemHostAgentAdapter):
        raise TypeError("System read-only preparation requires a bounded host-agent adapter")
    try:
        canonical_operation = SystemReadOnlyOperation(operation)
    except ValueError as exc:
        raise SystemReadOnlyCapabilityError("System read-only operation is unsupported") from exc
    canonical_campaign = _canonical_campaign(campaign)
    canonical_surface = _canonical_surface(surface)
    deployment = host_agent.deployment
    scope_binding = _campaign_scope_binding(canonical_campaign)
    surface_allow = _require_exact_scope_allow(
        scope_binding,
        system_surface_scope_target(canonical_surface),
        label="System Surface",
    )
    inspection_request = host_agent.prepare_request(
        surface=canonical_surface,
        operation=canonical_operation,
    )
    binding = registered_system_read_only_inspection_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition() != registered_system_read_only_capability_definition()
        ):
            raise SystemReadOnlyCapabilityError(
                "System read-only activation differs from the registered Capability"
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=SYSTEM_READ_ONLY_TOOL_ID,
            target=inspection_request.target,
            method="GET",
            arguments={},
        )
        prepared = activation.prepare_action(
            release=release,
            request=request,
            parameters=cast(
                Mapping[str, JsonValue],
                inspection_request.model_dump(mode="json", by_alias=True),
            ),
        )
        return SystemReadOnlyInspectionPreparation(
            binding=binding,
            surface=canonical_surface,
            operation=canonical_operation,
            hostAgentDeployment=deployment,
            inspectionRequest=inspection_request,
            campaignScope=scope_binding,
            matchedSurfaceAllowRule=surface_allow,
            release=release,
            preparedAction=prepared,
        )
    except (CapabilityAuthorityError, ValidationError, ValueError) as exc:
        if isinstance(exc, SystemReadOnlyCapabilityError):
            raise
        raise SystemReadOnlyCapabilityError(
            "System read-only CAP-002 preparation failed closed"
        ) from exc


def _verify_activation(activation: SystemReadOnlyCapabilityActivation) -> None:
    try:
        canonical_set = SystemReadOnlyCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise SystemReadOnlyCapabilityError(
            "System read-only activation set is not canonical"
        ) from exc
    if canonical_set != activation.activation_set:
        raise SystemReadOnlyCapabilityError("System read-only activation set drifted")
    _resolve_activation_binding(activation, canonical_set.binding)


def _resolve_activation_binding(
    activation: SystemReadOnlyCapabilityActivation,
    binding: SystemReadOnlyCapabilityActivationBinding,
) -> ResolvedCapabilityRelease:
    try:
        resolved = activation.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = activation.lifecycle.resolve_release(binding.release)
        definition = activation.bundle.definitions.resolve(resolved.capability.capability)
        expected_action = registered_action_capability(definition)
    except (CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise SystemReadOnlyCapabilityError(
            "System read-only current signed release could not be resolved"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
        or expected_action != binding.action_capability
    ):
        raise SystemReadOnlyCapabilityError("System read-only signed release binding drifted")
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.system-read-only-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise SystemReadOnlyCapabilityError(
            "System read-only release reference is not canonical"
        ) from exc


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    try:
        return ToolRequest.model_validate(request.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise SystemReadOnlyCapabilityError(
            "System read-only Tool request is not canonical"
        ) from exc


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    try:
        return CampaignManifest.model_validate(campaign.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise SystemReadOnlyCapabilityError("System Campaign is not canonical") from exc


def _canonical_surface(surface: SystemHostResourceSurface) -> SystemHostResourceSurface:
    try:
        return SystemHostResourceSurface.model_validate(
            surface.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise SystemReadOnlyCapabilityError("System Surface is not canonical") from exc


def _campaign_scope_binding(campaign: CampaignManifest) -> SystemCampaignScopeBinding:
    return SystemCampaignScopeBinding(
        campaignName=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        scope=campaign.spec.scope.model_copy(deep=True),
        allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
        allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
    )


def _require_exact_scope_allow(
    scope_binding: SystemCampaignScopeBinding,
    target: str,
    *,
    label: str,
) -> str:
    try:
        canonical_target = normalize_target_url(target)
        normalized_allow = tuple(
            normalize_scope_pattern(rule) for rule in scope_binding.scope.allow
        )
        normalized_deny = tuple(normalize_scope_pattern(rule) for rule in scope_binding.scope.deny)
    except InvalidScopeURL as exc:
        raise SystemReadOnlyCapabilityError(
            f"{label} Campaign Scope cannot be evaluated safely"
        ) from exc
    if canonical_target not in normalized_allow:
        raise SystemReadOnlyCapabilityError(f"{label} lacks an exact current Campaign allow rule")
    if any(scope_matches(rule, canonical_target) for rule in normalized_deny):
        raise SystemReadOnlyCapabilityError(f"{label} overlaps a current Campaign deny rule")
    return canonical_target


def _canonical_system_surface_target(value: str) -> str:
    try:
        canonical = normalize_target_url(value)
    except InvalidScopeURL as exc:
        raise ValueError("System Surface target is invalid") from exc
    if canonical != value or not value.startswith(f"{SYSTEM_SURFACE_SCOPE_ORIGIN}/surfaces/"):
        raise ValueError("System Surface target must be one canonical non-routable token")
    return value


def _is_forbidden_root_identity(value: str) -> bool:
    canonical = value.casefold()
    if canonical in _NON_ROOT_FORBIDDEN_IDENTITIES:
        return True
    if canonical.isdecimal() and int(canonical) == 0:
        return True
    for prefix in ("uid:", "uid-"):
        suffix = canonical.removeprefix(prefix)
        if suffix != canonical and suffix.isdecimal() and int(suffix) == 0:
            return True
    if canonical.startswith("s-1-5-") and canonical.endswith("-500"):
        return True
    privileged_names = ("administrator", "root", "system")
    separators = (":", "@", ".", "-")
    return any(
        canonical.startswith(f"{name}{separator}") or canonical.endswith(f"{separator}{name}")
        for name in privileged_names
        for separator in separators
    )


def _surface_host(surface: SystemHostResourceSurface) -> SystemHostSurfaceLocator:
    locator = surface.locator
    if isinstance(locator, SystemHostSurfaceLocator):
        return locator
    if isinstance(locator, SystemConfigurationSurfaceLocator):
        parent = locator.parent
        if isinstance(parent, SystemHostSurfaceLocator):
            return parent
        return parent.host
    if isinstance(
        locator,
        (SystemProcessSurfaceLocator, SystemFilesystemSurfaceLocator, SystemServiceSurfaceLocator),
    ):
        return locator.host
    raise SystemReadOnlyCapabilityError("System Surface locator type is unsupported")


def _validate_system_tool_request(request: ToolRequest) -> SystemHostAgentInspectionRequest:
    try:
        inspection = SystemHostAgentInspectionRequest.model_validate(request.arguments)
    except (ValidationError, ValueError) as exc:
        raise SystemReadOnlyCapabilityError("System Tool request arguments are invalid") from exc
    if (
        request.tool_id != SYSTEM_READ_ONLY_TOOL_ID
        or request.method != "GET"
        or request.target != inspection.target
    ):
        raise SystemReadOnlyCapabilityError(
            "System Tool request differs from bounded GET authority"
        )
    return inspection


def _supported_locator_kinds() -> tuple[SystemSurfaceLocatorKind, ...]:
    return (
        "system-configuration",
        "system-filesystem",
        "system-host",
        "system-process",
        "system-service",
    )


@cache
def _system_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(SystemReadOnlyInspectionTool())
    return system_read_only_capability_bundle(tools).capability()


@cache
def _system_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.SYSTEM
    )


__all__ = [
    "SYSTEM_CAMPAIGN_SCOPE_BINDING_API_VERSION",
    "SYSTEM_HOST_AGENT_DEPLOYMENT_BINDING_API_VERSION",
    "SYSTEM_HOST_AGENT_INSPECTION_REQUEST_API_VERSION",
    "SYSTEM_READ_ONLY_BINDING_API_VERSION",
    "SYSTEM_READ_ONLY_CAPABILITY_ACTIVATION_SET_API_VERSION",
    "SYSTEM_READ_ONLY_CAPABILITY_ADAPTER_VERSION",
    "SYSTEM_READ_ONLY_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION",
    "SYSTEM_READ_ONLY_CAPABILITY_ID",
    "SYSTEM_READ_ONLY_CAPABILITY_VERSION",
    "SYSTEM_READ_ONLY_PREPARATION_API_VERSION",
    "SYSTEM_READ_ONLY_TOOL_ID",
    "SYSTEM_SURFACE_SCOPE_ORIGIN",
    "BoundedSystemHostAgentAdapter",
    "SystemCampaignScopeBinding",
    "SystemHostAgentDeploymentBinding",
    "SystemHostAgentDeploymentRef",
    "SystemHostAgentInspectionRequest",
    "SystemInspectionBudget",
    "SystemReadOnlyCapabilityActivation",
    "SystemReadOnlyCapabilityActivationBinding",
    "SystemReadOnlyCapabilityActivationSet",
    "SystemReadOnlyCapabilityBundle",
    "SystemReadOnlyCapabilityDomainClassification",
    "SystemReadOnlyCapabilityError",
    "SystemReadOnlyInspectionBinding",
    "SystemReadOnlyInspectionBindingRef",
    "SystemReadOnlyInspectionPreparation",
    "SystemReadOnlyInspectionTool",
    "SystemReadOnlyOperation",
    "activate_system_read_only_capability",
    "bind_system_host_agent_deployment",
    "prepare_system_read_only_inspection",
    "registered_system_read_only_capability_definition",
    "registered_system_read_only_capability_domain_classification",
    "registered_system_read_only_inspection_binding",
    "resolve_system_read_only_capability_domain_classification",
    "resolve_system_read_only_inspection_binding",
    "system_read_only_capability_bundle",
    "system_surface_scope_target",
    "worker_mtls_trust_policy_digest",
]
