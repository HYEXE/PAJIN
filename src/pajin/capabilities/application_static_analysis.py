"""APP-001B read-only Application static-analysis preparation boundaries."""

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
from pajin.discovery.application_surfaces import (
    ApplicationArtifactRuntimeLocatorRef,
    ApplicationArtifactRuntimeLocatorRegistryRef,
    ApplicationArtifactRuntimeSurface,
    ApplicationArtifactRuntimeSurfaceRef,
    ApplicationSurfaceClass,
    ApplicationSurfaceLocatorKind,
    registered_application_artifact_runtime_locator_registry,
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

APPLICATION_STATIC_ANALYSIS_CAPABILITY_ADAPTER_VERSION = (
    "pajin.application-static-analysis-capability-adapter/v1"
)
APPLICATION_STATIC_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-capability-activation-set/v1alpha1"
] = "pajin.dev/application-static-analysis-capability-activation-set/v1alpha1"
APPLICATION_STATIC_ANALYSIS_BINDING_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-binding/v1alpha1"
] = "pajin.dev/application-static-analysis-binding/v1alpha1"
APPLICATION_STATIC_ANALYSIS_PREPARATION_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-preparation/v1alpha1"
] = "pajin.dev/application-static-analysis-preparation/v1alpha1"
APPLICATION_CAMPAIGN_SCOPE_BINDING_API_VERSION: Literal[
    "pajin.dev/application-campaign-scope-binding/v1alpha1"
] = "pajin.dev/application-campaign-scope-binding/v1alpha1"
APPLICATION_ARTIFACT_CUSTODY_BINDING_API_VERSION: Literal[
    "pajin.dev/application-artifact-custody-binding/v1alpha1"
] = "pajin.dev/application-artifact-custody-binding/v1alpha1"
APPLICATION_STATIC_ANALYSIS_SANDBOX_BINDING_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-sandbox-binding/v1alpha1"
] = "pajin.dev/application-static-analysis-sandbox-binding/v1alpha1"
APPLICATION_STATIC_ANALYSIS_REQUEST_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-request/v1alpha1"
] = "pajin.dev/application-static-analysis-request/v1alpha1"
APPLICATION_STATIC_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-capability-domain-classification/v1alpha1"
] = "pajin.dev/application-static-analysis-capability-domain-classification/v1alpha1"

APPLICATION_STATIC_ANALYSIS_CAPABILITY_ID = "pajin.application.read-only-static-analysis"
APPLICATION_STATIC_ANALYSIS_CAPABILITY_VERSION = "1.0.0"
APPLICATION_STATIC_ANALYSIS_TOOL_ID = "application.read-only-static-analysis"
APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA: Literal[
    "pajin.application.static-analysis-result.v1"
] = "pajin.application.static-analysis-result.v1"
APPLICATION_SURFACE_SCOPE_ORIGIN = "https://application-scope.pajin.invalid"
APPLICATION_ARTIFACT_MOUNT_TARGET: Literal["/pajin/input/artifact"] = "/pajin/input/artifact"

_AUTHORITY_VERSION = "1.0.0"
_MAX_ARTIFACT_BYTES = 536_870_912
_MAX_OUTPUT_BYTES = 16_777_216
_MAX_RUNTIME_SECONDS = 300
_MAX_MEMORY_MIB = 4_096
_MAX_PROCESS_COUNT = 64
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_OpaqueIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
]
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


class ApplicationStaticAnalysisCapabilityError(ValueError):
    """Raised when APP-001B Scope, custody, sandbox, or preparation drifts."""


class ApplicationStaticAnalysisOperation(StrEnum):
    """One structure-only operation for each APP-001A Surface class."""

    BINARY_METADATA = "binary-metadata-read"
    CONFIGURATION_STRUCTURE = "configuration-structure-read"
    RUNTIME_METADATA = "runtime-metadata-read"
    LIBRARY_METADATA = "library-metadata-read"


class ApplicationStaticParser(StrEnum):
    """Logical parser contract selected before any executable is admitted."""

    BINARY_METADATA = "binary-metadata-parser"
    CONFIGURATION_STRUCTURE = "configuration-structure-parser"
    RUNTIME_METADATA = "runtime-metadata-parser"
    LIBRARY_METADATA = "library-metadata-parser"


_OPERATION_BY_SURFACE_CLASS = {
    ApplicationSurfaceClass.BINARY: ApplicationStaticAnalysisOperation.BINARY_METADATA,
    ApplicationSurfaceClass.CONFIGURATION: (
        ApplicationStaticAnalysisOperation.CONFIGURATION_STRUCTURE
    ),
    ApplicationSurfaceClass.RUNTIME: ApplicationStaticAnalysisOperation.RUNTIME_METADATA,
    ApplicationSurfaceClass.LIBRARY: ApplicationStaticAnalysisOperation.LIBRARY_METADATA,
}
_PARSER_BY_OPERATION = {
    ApplicationStaticAnalysisOperation.BINARY_METADATA: ApplicationStaticParser.BINARY_METADATA,
    ApplicationStaticAnalysisOperation.CONFIGURATION_STRUCTURE: (
        ApplicationStaticParser.CONFIGURATION_STRUCTURE
    ),
    ApplicationStaticAnalysisOperation.RUNTIME_METADATA: ApplicationStaticParser.RUNTIME_METADATA,
    ApplicationStaticAnalysisOperation.LIBRARY_METADATA: ApplicationStaticParser.LIBRARY_METADATA,
}
_SUPPORTED_OPERATIONS = tuple(
    sorted(ApplicationStaticAnalysisOperation, key=lambda item: item.value)
)
_SUPPORTED_PARSERS = tuple(sorted(ApplicationStaticParser, key=lambda item: item.value))


class ApplicationArtifactCustodyRef(StrictModel):
    """Exact secret-free reference to deployment-authorized immutable custody."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    custody_binding_id: str = Field(
        alias="custodyBindingId",
        pattern=r"^application-artifact-custody_[a-f0-9]{64}$",
    )
    custody_binding_version: Literal["1.0.0"] = Field(alias="custodyBindingVersion")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    surface: ApplicationArtifactRuntimeSurfaceRef
    custody_authority_id: _Identifier = Field(alias="custodyAuthorityId")
    custody_object_id: _OpaqueIdentifier = Field(alias="custodyObjectId")
    authorization_id: _OpaqueIdentifier = Field(alias="authorizationId")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)

    @field_validator("artifact_bytes", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Application custody artifact bytes must be an integer")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        expected_id = f"application-artifact-custody_{self.custody_binding_digest}"
        if self.custody_binding_id != expected_id:
            raise ValueError("Application artifact custody reference identity differs")
        return self


class ApplicationArtifactCustodyBinding(StrictModel):
    """Configuration-only custody binding; no artifact is resolved or read here."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-artifact-custody-binding/v1alpha1"] = Field(
        default=APPLICATION_ARTIFACT_CUSTODY_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationArtifactCustodyBinding"] = "ApplicationArtifactCustodyBinding"
    custody_binding_id: str = Field(default="", alias="custodyBindingId", max_length=97)
    custody_binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="custodyBindingVersion",
    )
    custody_binding_digest: str = Field(
        default="",
        alias="custodyBindingDigest",
        max_length=64,
    )
    surface: ApplicationArtifactRuntimeSurface
    custody_authority_id: _Identifier = Field(alias="custodyAuthorityId")
    custody_object_id: _OpaqueIdentifier = Field(alias="custodyObjectId")
    authorization_id: _OpaqueIdentifier = Field(alias="authorizationId")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    configuration_only: Literal[True] = Field(default=True, alias="configurationOnly")
    deployment_authorization_reference_bound: Literal[True] = Field(
        default=True,
        alias="deploymentAuthorizationReferenceBound",
    )
    immutable_digest_required: Literal[True] = Field(
        default=True,
        alias="immutableDigestRequired",
    )
    read_only_mount_required: Literal[True] = Field(
        default=True,
        alias="readOnlyMountRequired",
    )
    raw_artifact_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentEmbedded",
    )
    mutable_path_embedded: Literal[False] = Field(
        default=False,
        alias="mutablePathEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    authorization_verified_by_preparation: Literal[False] = Field(
        default=False,
        alias="authorizationVerifiedByPreparation",
    )
    custody_runtime_verified: Literal[False] = Field(
        default=False,
        alias="custodyRuntimeVerified",
    )
    artifact_resolved: Literal[False] = Field(default=False, alias="artifactResolved")
    artifact_bytes_verified: Literal[False] = Field(
        default=False,
        alias="artifactBytesVerified",
    )
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    mount_materialized: Literal[False] = Field(default=False, alias="mountMaterialized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("artifact_bytes", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Application custody artifact bytes must be an integer")
        return value

    @field_validator(
        "configuration_only",
        "deployment_authorization_reference_bound",
        "immutable_digest_required",
        "read_only_mount_required",
        "raw_artifact_content_embedded",
        "mutable_path_embedded",
        "secret_material_embedded",
        "authorization_verified_by_preparation",
        "custody_runtime_verified",
        "artifact_resolved",
        "artifact_bytes_verified",
        "artifact_read_authorized",
        "mount_materialized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application artifact custody markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_custody_identity(self) -> Self:
        canonical_surface = _canonical_surface(self.surface)
        if (
            canonical_surface != self.surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.artifact_sha256 != _artifact_sha256(self.surface)
        ):
            raise ValueError("Application artifact custody differs from the exact Surface")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"custody_binding_id", "custody_binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.application-artifact-custody/v1",
            material,
        )
        binding_id = f"application-artifact-custody_{digest}"
        if self.custody_binding_digest and self.custody_binding_digest != digest:
            raise ValueError("Application artifact custody digest differs")
        if self.custody_binding_id and self.custody_binding_id != binding_id:
            raise ValueError("Application artifact custody ID differs")
        object.__setattr__(self, "custody_binding_digest", digest)
        object.__setattr__(self, "custody_binding_id", binding_id)
        return self

    def reference(self) -> ApplicationArtifactCustodyRef:
        return ApplicationArtifactCustodyRef(
            custodyBindingId=self.custody_binding_id,
            custodyBindingVersion=self.custody_binding_version,
            custodyBindingDigest=self.custody_binding_digest,
            surface=self.surface.reference(),
            custodyAuthorityId=self.custody_authority_id,
            custodyObjectId=self.custody_object_id,
            authorizationId=self.authorization_id,
            authorizationDigest=self.authorization_digest,
            artifactSHA256=self.artifact_sha256,
            artifactBytes=self.artifact_bytes,
        )


class ApplicationStaticAnalysisSandboxRef(StrictModel):
    """Exact non-secret reference to one network-disabled sandbox configuration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    sandbox_binding_id: str = Field(
        alias="sandboxBindingId",
        pattern=r"^application-static-analysis-sandbox_[a-f0-9]{64}$",
    )
    sandbox_binding_version: Literal["1.0.0"] = Field(alias="sandboxBindingVersion")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    operation: ApplicationStaticAnalysisOperation
    parser: ApplicationStaticParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    output_schema: Literal["pajin.application.static-analysis-result.v1"] = Field(
        alias="outputSchema"
    )
    max_artifact_bytes: int = Field(alias="maxArtifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(
        alias="maxOutputBytes",
        ge=1_024,
        le=_MAX_OUTPUT_BYTES,
    )
    max_runtime_seconds: int = Field(
        alias="maxRuntimeSeconds",
        ge=1,
        le=_MAX_RUNTIME_SECONDS,
    )
    max_memory_mib: int = Field(alias="maxMemoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    max_process_count: int = Field(
        alias="maxProcessCount",
        ge=1,
        le=_MAX_PROCESS_COUNT,
    )

    @field_validator(
        "max_artifact_bytes",
        "max_output_bytes",
        "max_runtime_seconds",
        "max_memory_mib",
        "max_process_count",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Application sandbox reference ceilings must be integers")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        expected_id = f"application-static-analysis-sandbox_{self.sandbox_binding_digest}"
        if self.sandbox_binding_id != expected_id:
            raise ValueError("Application static-analysis sandbox reference identity differs")
        if _PARSER_BY_OPERATION[self.operation] is not self.parser:
            raise ValueError("Application static-analysis sandbox parser differs")
        return self


class ApplicationStaticAnalysisSandboxBinding(StrictModel):
    """Configuration-only offline sandbox boundary without selection or execution."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-static-analysis-sandbox-binding/v1alpha1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_SANDBOX_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisSandboxBinding"] = (
        "ApplicationStaticAnalysisSandboxBinding"
    )
    sandbox_binding_id: str = Field(default="", alias="sandboxBindingId", max_length=104)
    sandbox_binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="sandboxBindingVersion",
    )
    sandbox_binding_digest: str = Field(
        default="",
        alias="sandboxBindingDigest",
        max_length=64,
    )
    deployment_id: _Identifier = Field(alias="deploymentId")
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    operation: ApplicationStaticAnalysisOperation
    parser: ApplicationStaticParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    artifact_mount_target: Literal["/pajin/input/artifact"] = Field(
        default=APPLICATION_ARTIFACT_MOUNT_TARGET,
        alias="artifactMountTarget",
    )
    output_schema: Literal["pajin.application.static-analysis-result.v1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    output_transport: Literal["bounded-json-stdout"] = Field(
        default="bounded-json-stdout",
        alias="outputTransport",
    )
    max_artifact_bytes: int = Field(alias="maxArtifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(
        alias="maxOutputBytes",
        ge=1_024,
        le=_MAX_OUTPUT_BYTES,
    )
    max_runtime_seconds: int = Field(
        alias="maxRuntimeSeconds",
        ge=1,
        le=_MAX_RUNTIME_SECONDS,
    )
    max_memory_mib: int = Field(alias="maxMemoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    max_process_count: int = Field(
        alias="maxProcessCount",
        ge=1,
        le=_MAX_PROCESS_COUNT,
    )
    configuration_only: Literal[True] = Field(default=True, alias="configurationOnly")
    network_disabled_required: Literal[True] = Field(
        default=True,
        alias="networkDisabledRequired",
    )
    read_only_root_filesystem_required: Literal[True] = Field(
        default=True,
        alias="readOnlyRootFilesystemRequired",
    )
    read_only_artifact_mount_required: Literal[True] = Field(
        default=True,
        alias="readOnlyArtifactMountRequired",
    )
    artifact_mount_noexec_required: Literal[True] = Field(
        default=True,
        alias="artifactMountNoexecRequired",
    )
    no_new_privileges_required: Literal[True] = Field(
        default=True,
        alias="noNewPrivilegesRequired",
    )
    non_root_runtime_required: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeRequired",
    )
    exact_parser_executable_digest_required: Literal[True] = Field(
        default=True,
        alias="exactParserExecutableDigestRequired",
    )
    exact_sandbox_image_digest_required: Literal[True] = Field(
        default=True,
        alias="exactSandboxImageDigestRequired",
    )
    host_filesystem_access_allowed: Literal[False] = Field(
        default=False,
        alias="hostFilesystemAccessAllowed",
    )
    credential_injection_allowed: Literal[False] = Field(
        default=False,
        alias="credentialInjectionAllowed",
    )
    environment_inheritance_allowed: Literal[False] = Field(
        default=False,
        alias="environmentInheritanceAllowed",
    )
    symlink_traversal_allowed: Literal[False] = Field(
        default=False,
        alias="symlinkTraversalAllowed",
    )
    runtime_attested: Literal[False] = Field(default=False, alias="runtimeAttested")
    sandbox_selected: Literal[False] = Field(default=False, alias="sandboxSelected")
    artifact_mount_materialized: Literal[False] = Field(
        default=False,
        alias="artifactMountMaterialized",
    )
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
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
            raise ValueError("Application sandbox run-as identity must be explicit and non-root")
        return value

    @field_validator(
        "max_artifact_bytes",
        "max_output_bytes",
        "max_runtime_seconds",
        "max_memory_mib",
        "max_process_count",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Application sandbox resource ceilings must be integers")
        return value

    @field_validator(
        "configuration_only",
        "network_disabled_required",
        "read_only_root_filesystem_required",
        "read_only_artifact_mount_required",
        "artifact_mount_noexec_required",
        "no_new_privileges_required",
        "non_root_runtime_required",
        "exact_parser_executable_digest_required",
        "exact_sandbox_image_digest_required",
        "host_filesystem_access_allowed",
        "credential_injection_allowed",
        "environment_inheritance_allowed",
        "symlink_traversal_allowed",
        "runtime_attested",
        "sandbox_selected",
        "artifact_mount_materialized",
        "artifact_read_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "dynamic_target_execution_authorized",
        "debugger_attach_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application sandbox markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_sandbox_identity(self) -> Self:
        worker = _application_worker_boundary_profile()
        if (
            self.worker_profile != worker.reference()
            or _PARSER_BY_OPERATION[self.operation] is not self.parser
            or worker.network_boundary is not WorkerNetworkBoundary.DISABLED_BY_DEFAULT
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.READ_ONLY_ARTIFACT
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.OFFLINE_SANDBOX
            or worker.required_identity_dimensions != ("analyzer", "artifact-digest")
            or worker.required_budget_dimensions != ("artifact-bytes", "runtime")
        ):
            raise ValueError("Application static-analysis sandbox differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"sandbox_binding_id", "sandbox_binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.application-static-analysis-sandbox/v1",
            material,
        )
        binding_id = f"application-static-analysis-sandbox_{digest}"
        if self.sandbox_binding_digest and self.sandbox_binding_digest != digest:
            raise ValueError("Application static-analysis sandbox digest differs")
        if self.sandbox_binding_id and self.sandbox_binding_id != binding_id:
            raise ValueError("Application static-analysis sandbox ID differs")
        object.__setattr__(self, "sandbox_binding_digest", digest)
        object.__setattr__(self, "sandbox_binding_id", binding_id)
        return self

    def reference(self) -> ApplicationStaticAnalysisSandboxRef:
        return ApplicationStaticAnalysisSandboxRef(
            sandboxBindingId=self.sandbox_binding_id,
            sandboxBindingVersion=self.sandbox_binding_version,
            sandboxBindingDigest=self.sandbox_binding_digest,
            deploymentId=self.deployment_id,
            operation=self.operation,
            parser=self.parser,
            parserExecutableSHA256=self.parser_executable_sha256,
            sandboxImageSHA256=self.sandbox_image_sha256,
            outputSchema=self.output_schema,
            maxArtifactBytes=self.max_artifact_bytes,
            maxOutputBytes=self.max_output_bytes,
            maxRuntimeSeconds=self.max_runtime_seconds,
            maxMemoryMiB=self.max_memory_mib,
            maxProcessCount=self.max_process_count,
        )


class ApplicationStaticAnalysisBudget(StrictModel):
    """Attenuating artifact, output, runtime, memory, and process ceilings."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    request_count: Literal[1] = Field(default=1, alias="requestCount")
    artifact_bytes: int = Field(alias="artifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1_024, le=_MAX_OUTPUT_BYTES)
    runtime_seconds: int = Field(alias="runtimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    memory_mib: int = Field(alias="memoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    process_count: int = Field(alias="processCount", ge=1, le=_MAX_PROCESS_COUNT)
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dynamic_target_executions: Literal[0] = Field(
        default=0,
        alias="dynamicTargetExecutions",
    )
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")
    artifact_write_operations: Literal[0] = Field(
        default=0,
        alias="artifactWriteOperations",
    )
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    attenuation_only: Literal[True] = Field(default=True, alias="attenuationOnly")
    reservation_created: Literal[False] = Field(default=False, alias="reservationCreated")

    @field_validator(
        "request_count",
        "artifact_bytes",
        "max_output_bytes",
        "runtime_seconds",
        "memory_mib",
        "process_count",
        "network_requests",
        "dynamic_target_executions",
        "debugger_attaches",
        "artifact_write_operations",
        "host_filesystem_reads",
        "credential_reads",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Application static-analysis budget values must be integers")
        return value

    @field_validator("attenuation_only", "reservation_created", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application static-analysis budget markers must be booleans")
        return value


class ApplicationStaticAnalysisRequest(StrictModel):
    """Secret-free request description; it resolves, mounts, and executes nothing."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-static-analysis-request/v1alpha1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisRequest"] = "ApplicationStaticAnalysisRequest"
    operation: ApplicationStaticAnalysisOperation
    parser: ApplicationStaticParser
    surface: ApplicationArtifactRuntimeSurface
    custody: ApplicationArtifactCustodyRef
    sandbox: ApplicationStaticAnalysisSandboxRef
    target: str = Field(min_length=9, max_length=2_000)
    method: Literal["GET"] = "GET"
    output_schema: Literal["pajin.application.static-analysis-result.v1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    budget: ApplicationStaticAnalysisBudget
    raw_artifact_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentEmbedded",
    )
    mutable_artifact_path_embedded: Literal[False] = Field(
        default=False,
        alias="mutableArtifactPathEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    artifact_resolution_performed: Literal[False] = Field(
        default=False,
        alias="artifactResolutionPerformed",
    )
    artifact_read_performed: Literal[False] = Field(
        default=False,
        alias="artifactReadPerformed",
    )
    artifact_mount_materialized: Literal[False] = Field(
        default=False,
        alias="artifactMountMaterialized",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )

    @field_validator("target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        return _canonical_application_surface_target(value)

    @field_validator(
        "raw_artifact_content_embedded",
        "mutable_artifact_path_embedded",
        "credential_material_embedded",
        "artifact_resolution_performed",
        "artifact_read_performed",
        "artifact_mount_materialized",
        "sandbox_invocation_authorized",
        "network_access_authorized",
        "dynamic_target_execution_authorized",
        "debugger_attach_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application static-analysis request markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_request(self) -> Self:
        expected_operation = _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class]
        expected_parser = _PARSER_BY_OPERATION[self.operation]
        if (
            self.surface.initial_state != "registered-not-authorized"
            or self.operation is not expected_operation
            or self.parser is not expected_parser
            or self.custody.surface != self.surface.reference()
            or self.custody.artifact_sha256 != _artifact_sha256(self.surface)
            or self.sandbox.operation is not self.operation
            or self.sandbox.parser is not self.parser
            or self.sandbox.output_schema != self.output_schema
            or self.target != application_surface_scope_target(self.surface)
            or self.budget.artifact_bytes != self.custody.artifact_bytes
            or self.budget.artifact_bytes > self.sandbox.max_artifact_bytes
            or self.budget.max_output_bytes != self.sandbox.max_output_bytes
            or self.budget.runtime_seconds != self.sandbox.max_runtime_seconds
            or self.budget.memory_mib != self.sandbox.max_memory_mib
            or self.budget.process_count != self.sandbox.max_process_count
        ):
            raise ValueError("Application static-analysis request differs from exact bindings")
        return self


@dataclass(frozen=True, slots=True)
class BoundedApplicationStaticAnalyzerAdapter:
    """Adapt exact custody and sandbox metadata without reading or executing it."""

    _custody: ApplicationArtifactCustodyBinding
    _sandbox: ApplicationStaticAnalysisSandboxBinding

    def __post_init__(self) -> None:
        try:
            custody = ApplicationArtifactCustodyBinding.model_validate(
                self._custody.model_dump(mode="json", by_alias=True)
            )
            sandbox = ApplicationStaticAnalysisSandboxBinding.model_validate(
                self._sandbox.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application custody or sandbox binding is not canonical"
            ) from exc
        object.__setattr__(self, "_custody", custody)
        object.__setattr__(self, "_sandbox", sandbox)

    @property
    def custody(self) -> ApplicationArtifactCustodyBinding:
        return self._custody.model_copy(deep=True)

    @property
    def sandbox(self) -> ApplicationStaticAnalysisSandboxBinding:
        return self._sandbox.model_copy(deep=True)

    def prepare_request(
        self,
        *,
        surface: ApplicationArtifactRuntimeSurface,
        operation: ApplicationStaticAnalysisOperation,
    ) -> ApplicationStaticAnalysisRequest:
        """Return one bounded request description without artifact or sandbox authority."""

        canonical_surface = _canonical_surface(surface)
        try:
            canonical_operation = ApplicationStaticAnalysisOperation(operation)
        except ValueError as exc:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application static-analysis operation is unsupported"
            ) from exc
        expected_operation = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
        if canonical_surface.reference() != self._custody.surface.reference():
            raise ApplicationStaticAnalysisCapabilityError(
                "Application custody differs from the exact Surface"
            )
        if canonical_operation is not expected_operation:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application static-analysis operation differs from the exact Surface class"
            )
        if canonical_operation is not self._sandbox.operation:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application operation is outside the exact sandbox parser binding"
            )
        if self._custody.artifact_bytes > self._sandbox.max_artifact_bytes:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application artifact exceeds the sandbox artifact-byte ceiling"
            )
        return ApplicationStaticAnalysisRequest(
            operation=canonical_operation,
            parser=self._sandbox.parser,
            surface=canonical_surface,
            custody=self._custody.reference(),
            sandbox=self._sandbox.reference(),
            target=application_surface_scope_target(canonical_surface),
            budget=ApplicationStaticAnalysisBudget(
                artifactBytes=self._custody.artifact_bytes,
                maxOutputBytes=self._sandbox.max_output_bytes,
                runtimeSeconds=self._sandbox.max_runtime_seconds,
                memoryMiB=self._sandbox.max_memory_mib,
                processCount=self._sandbox.max_process_count,
            ),
        )


class ApplicationStaticAnalysisTool(Tool):
    """CAP-001 Tool identity whose offline sandbox runtime remains unavailable."""

    spec = ToolSpec(
        tool_id=APPLICATION_STATIC_ANALYSIS_TOOL_ID,
        version="1.0.0",
        description="Prepare one exact network-disabled read-only Application static analysis",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"application", "offline-sandbox", "read-only", "static-analysis"}),
        evidence_types=frozenset({"application-static-analysis-json", "json"}),
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
            "outputSchema": APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
            "artifactCustodyRuntimeAvailable": False,
            "offlineSandboxRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        _validate_application_tool_request(request)
        raise ApplicationStaticAnalysisCapabilityError(
            "APP-001B does not materialize an offline sandbox Worker job"
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        _validate_application_tool_request(request)
        raise ApplicationStaticAnalysisCapabilityError(
            "APP-001B has no sandbox result to normalize"
        )


class ApplicationStaticAnalysisCapabilityDomainClassification(StrictModel):
    """Exact Application classification for the additive APP-001B CAP-002 bundle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/application-static-analysis-capability-domain-classification/v1alpha1"
    ] = Field(
        default=APPLICATION_STATIC_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisCapabilityDomainClassification"] = (
        "ApplicationStaticAnalysisCapabilityDomainClassification"
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
    reviewed_surface_types: tuple[ApplicationSurfaceLocatorKind, ...] = Field(
        default=(
            "application-binary",
            "application-configuration",
            "application-library",
            "application-runtime",
        ),
        alias="reviewedSurfaceTypes",
    )
    mapping_basis: Literal["app-001b-explicit-code-reviewed-capability-and-surface-set"] = Field(
        default="app-001b-explicit-code-reviewed-capability-and-surface-set",
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
            raise ValueError("Application Capability Domain markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        capability = _application_code_backed_capability()
        worker = _application_worker_boundary_profile()
        if (
            self.capability != capability.capability
            or self.code_backed_capability != capability
            or self.domain_classification != worker.domain_classification
            or self.reviewed_surface_types != _supported_locator_kinds()
        ):
            raise ValueError("Application Capability Domain classification differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.application-domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Application Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("Application Capability Domain classification ID differs")
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


class ApplicationCampaignScopeBinding(StrictModel):
    """Content-addressed current Campaign projection for exact Application preparation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-campaign-scope-binding/v1alpha1"] = Field(
        default=APPLICATION_CAMPAIGN_SCOPE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationCampaignScopeBinding"] = "ApplicationCampaignScopeBinding"
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
            raise ValueError("Application Campaign Scope markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_scope_projection(self) -> Self:
        if self.allowed_methods != tuple(sorted(set(self.allowed_methods))):
            raise ValueError("Application Campaign allowed methods must be sorted and unique")
        if "GET" not in self.allowed_methods:
            raise ValueError("Application Campaign Scope requires reviewed GET authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.application-campaign-scope-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Application Campaign Scope binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class ApplicationStaticAnalysisCapabilityBundle:
    """Frozen CAP-001/CAP-002 registries for one Application Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapabilityRef:
        manifests = self.authorities.capabilities()
        if len(manifests) != 1:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application static-analysis Capability authority inventory drifted"
            )
        return manifests[0].reference()


class ApplicationStaticAnalysisCapabilityActivationBinding(StrictModel):
    """One exact externally signed release admitted for Range-only use."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        definition = registered_application_static_analysis_capability_definition()
        action = self.action_capability
        if (
            self.capability != _application_code_backed_capability()
            or action != registered_action_capability(definition)
        ):
            raise ValueError("Application activation references another Capability")
        return self


class ApplicationStaticAnalysisCapabilityActivationSet(StrictModel):
    """Content-addressed activation of exactly one signed Application release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/application-static-analysis-capability-activation-set/v1alpha1"
    ] = Field(
        default=APPLICATION_STATIC_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisCapabilityActivationSet"] = (
        "ApplicationStaticAnalysisCapabilityActivationSet"
    )
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(
        default="",
        alias="activationSetDigest",
        max_length=64,
    )
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: ApplicationStaticAnalysisCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.application-static-analysis-activation-set/v1",
            material,
        )
        activation_set_id = f"application-static-analysis-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("Application activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("Application activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class ApplicationStaticAnalysisCapabilityActivation:
    """Runtime activation that rechecks the signed current release on every use."""

    bundle: ApplicationStaticAnalysisCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: ApplicationStaticAnalysisCapabilityActivationSet

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
            raise ApplicationStaticAnalysisCapabilityError(
                "Application activated Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application CAP-002 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(self, reference: ActionCapabilityRef) -> ResolvedCapabilityRelease:
        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application GRAPH Capability reference is not canonical"
            ) from exc
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise ApplicationStaticAnalysisCapabilityError(
                "Application GRAPH Capability is outside the activation"
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
            raise ApplicationStaticAnalysisCapabilityError(
                "Application release is outside the activation"
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
            raise ApplicationStaticAnalysisCapabilityError(
                "Application CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _ApplicationStaticAnalysisAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        definition: CapabilityDefinition,
        tool: ApplicationStaticAnalysisTool,
    ) -> None:
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{APPLICATION_STATIC_ANALYSIS_CAPABILITY_ID}.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": APPLICATION_STATIC_ANALYSIS_CAPABILITY_ADAPTER_VERSION,
            "method": "GET",
            "parameterSchemaDigest": self._definition.parameter_schema_digest,
            "artifactCustodyRequestAdaptationAvailable": True,
            "offlineSandboxRequestAdaptationAvailable": True,
            "artifactCustodyRuntimeAvailable": False,
            "offlineSandboxRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
            "replayAuthorized": False,
            "cleanupAuthorized": False,
            "tool": {
                "type": f"{type(self._tool).__module__}.{type(self._tool).__qualname__}",
                "context": self._tool.stable_execution_context(),
            },
        }


class _ApplicationStaticAnalysisMaterializer(_ApplicationStaticAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            request = ApplicationStaticAnalysisRequest.model_validate(dict(parameters))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Application parameters differ from the bounded static-analysis request"
            ) from exc
        return cast(Mapping[str, JsonValue], request.model_dump(mode="json", by_alias=True))


class _ApplicationStaticAnalysisActionCompiler(_ApplicationStaticAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        try:
            analysis = ApplicationStaticAnalysisRequest.model_validate(dict(materialized_arguments))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Application materialized static-analysis request is invalid"
            ) from exc
        if (
            request.tool_id != APPLICATION_STATIC_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != analysis.target
            or request.arguments
        ):
            raise CapabilityAuthorityError(
                "Application compiler accepts only one exact empty GET request"
            )
        return request.model_copy(
            update={"arguments": analysis.model_dump(mode="json", by_alias=True)}
        )


class _ApplicationStaticAnalysisExecutorAdapter(_ApplicationStaticAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _ApplicationStaticAnalysisResultNormalizer(_ApplicationStaticAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _ApplicationStaticAnalysisSuccessOracle(_ApplicationStaticAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del request, result
        return CapabilityOracleDecision.INCONCLUSIVE


class _ApplicationStaticAnalysisReplayStrategy(_ApplicationStaticAnalysisAuthorityBase):
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


class _ApplicationStaticAnalysisCleanupHandler(_ApplicationStaticAnalysisAuthorityBase):
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
def registered_application_static_analysis_capability_definition() -> CapabilityDefinition:
    """Return exact CAP-001 metadata for bounded Application analysis preparation."""

    raw_schema = ApplicationStaticAnalysisRequest.model_json_schema(by_alias=True)
    raw_schema["required"] = sorted(raw_schema["required"])
    schema = cast(Mapping[str, JsonValue], raw_schema)
    return capability_definition_from_tool(
        ApplicationStaticAnalysisTool.spec,
        ToolCapabilityRegistration(
            capabilityId=APPLICATION_STATIC_ANALYSIS_CAPABILITY_ID,
            capabilityVersion=APPLICATION_STATIC_ANALYSIS_CAPABILITY_VERSION,
            toolId=APPLICATION_STATIC_ANALYSIS_TOOL_ID,
            domain="application",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=_supported_locator_kinds(),
            threatClasses=("application-artifact-metadata", "application-configuration"),
            preconditions=(
                "current-campaign-scope",
                "deployment-custody-authorization-reference",
                "exact-application-surface",
                "fresh-signed-authorization",
                "network-disabled-offline-sandbox",
                "one-use-action-permit",
                "read-only-artifact-mount",
            ),
            parameterSchemaDigest=capability_parameter_schema_digest(schema),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=1,
        ),
    )


def application_static_analysis_capability_bundle(
    tools: ToolRegistry,
) -> ApplicationStaticAnalysisCapabilityBundle:
    """Bind the exact Application Tool identity to all seven CAP-002 roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("Application static-analysis Capability requires a ToolRegistry")
    try:
        tool = tools.tool(APPLICATION_STATIC_ANALYSIS_TOOL_ID)
        spec = tools.spec(APPLICATION_STATIC_ANALYSIS_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application static-analysis Tool is unavailable"
        ) from exc
    if (
        type(tool) is not ApplicationStaticAnalysisTool
        or spec != ApplicationStaticAnalysisTool.spec
    ):
        raise ApplicationStaticAnalysisCapabilityError(
            "Application static-analysis Tool implementation drifted"
        )
    typed_tool = tool
    definition = registered_application_static_analysis_capability_definition()
    definitions = CapabilityDefinitionRegistry((definition,))
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _ApplicationStaticAnalysisActionCompiler(definition, typed_tool),
        _ApplicationStaticAnalysisCleanupHandler(definition, typed_tool),
        _ApplicationStaticAnalysisExecutorAdapter(definition, typed_tool),
        _ApplicationStaticAnalysisMaterializer(definition, typed_tool),
        _ApplicationStaticAnalysisReplayStrategy(definition, typed_tool),
        _ApplicationStaticAnalysisResultNormalizer(definition, typed_tool),
        _ApplicationStaticAnalysisSuccessOracle(definition, typed_tool),
    )
    return ApplicationStaticAnalysisCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_application_static_analysis_capability(
    *,
    bundle: ApplicationStaticAnalysisCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> ApplicationStaticAnalysisCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, ApplicationStaticAnalysisCapabilityBundle):
        raise TypeError("Application activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Application activation requires a verified lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability()
        definition = bundle.definitions.resolve(capability.capability)
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition != registered_application_static_analysis_capability_definition()
    ):
        raise ApplicationStaticAnalysisCapabilityError(
            "Application signed release differs from code authority"
        )
    binding = ApplicationStaticAnalysisCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return ApplicationStaticAnalysisCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=ApplicationStaticAnalysisCapabilityActivationSet(binding=binding),
    )


class ApplicationStaticAnalysisBindingRef(StrictModel):
    """Exact content-addressed reference to the APP-001B static binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: Literal["pajin.application.read-only-static-analysis.binding"] = Field(
        alias="bindingId"
    )
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class ApplicationStaticAnalysisBinding(StrictModel):
    """Exact Surface/CAP-002/custody/sandbox contract without artifact access."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-static-analysis-binding/v1alpha1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisBinding"] = "ApplicationStaticAnalysisBinding"
    binding_id: Literal["pajin.application.read-only-static-analysis.binding"] = Field(
        default="pajin.application.read-only-static-analysis.binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["application.artifact-runtime"] = Field(
        default="application.artifact-runtime",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.application.artifact-runtime.v1"] = Field(
        default="pajin.locator.application.artifact-runtime.v1",
        alias="locatorSchema",
    )
    locator_registry: ApplicationArtifactRuntimeLocatorRegistryRef = Field(alias="locatorRegistry")
    supported_locators: tuple[ApplicationArtifactRuntimeLocatorRef, ...] = Field(
        alias="supportedLocators",
        min_length=4,
        max_length=4,
    )
    capability: CodeBackedCapabilityRef
    capability_domain_classification: ApplicationStaticAnalysisCapabilityDomainClassification = (
        Field(alias="capabilityDomainClassification")
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    supported_operations: tuple[ApplicationStaticAnalysisOperation, ...] = Field(
        default=_SUPPORTED_OPERATIONS,
        alias="supportedOperations",
    )
    supported_parsers: tuple[ApplicationStaticParser, ...] = Field(
        default=_SUPPORTED_PARSERS,
        alias="supportedParsers",
    )
    output_schema: Literal["pajin.application.static-analysis-result.v1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    complete_cap_002_verified: Literal[True] = Field(
        default=True,
        alias="completeCAP002Verified",
    )
    preparation_available: Literal[True] = Field(default=True, alias="preparationAvailable")
    exact_surface_custody_sandbox_binding_required: Literal[True] = Field(
        default=True,
        alias="exactSurfaceCustodySandboxBindingRequired",
    )
    bounded_budget_required: Literal[True] = Field(
        default=True,
        alias="boundedBudgetRequired",
    )
    network_disabled_sandbox_required: Literal[True] = Field(
        default=True,
        alias="networkDisabledSandboxRequired",
    )
    read_only_artifact_mount_required: Literal[True] = Field(
        default=True,
        alias="readOnlyArtifactMountRequired",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    action_permit_required: Literal[True] = Field(default=True, alias="actionPermitRequired")
    gateway_policy_reentry_required: Literal[True] = Field(
        default=True,
        alias="gatewayPolicyReentryRequired",
    )
    custody_runtime_verified: Literal[False] = Field(
        default=False,
        alias="custodyRuntimeVerified",
    )
    artifact_resolved: Literal[False] = Field(default=False, alias="artifactResolved")
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    static_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="staticAnalysisAuthorized",
    )
    sandbox_selected: Literal[False] = Field(default=False, alias="sandboxSelected")
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    artifact_mount_materialized: Literal[False] = Field(
        default=False,
        alias="artifactMountMaterialized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
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
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
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
    runtime_support_asserted_by_binding: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAssertedByBinding",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "binding_only",
        "complete_cap_002_verified",
        "preparation_available",
        "exact_surface_custody_sandbox_binding_required",
        "bounded_budget_required",
        "network_disabled_sandbox_required",
        "read_only_artifact_mount_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "custody_runtime_verified",
        "artifact_resolved",
        "artifact_read_authorized",
        "static_analysis_authorized",
        "sandbox_selected",
        "worker_selection_authorized",
        "artifact_mount_materialized",
        "network_access_authorized",
        "dynamic_target_execution_authorized",
        "debugger_attach_authorized",
        "artifact_mutation_authorized",
        "observation_production_authorized",
        "evidence_sealing_authorized",
        "graph_admission_authorized",
        "finding_authority",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "runtime_support_asserted_by_binding",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application static-analysis binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_application_static_analysis_capability_definition()
        registry = registered_application_artifact_runtime_locator_registry()
        worker = _application_worker_boundary_profile()
        expected_locators = tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        )
        if (
            self.locator_registry != registry.reference()
            or self.supported_locators != expected_locators
            or self.capability != _application_code_backed_capability()
            or self.capability_domain_classification
            != registered_application_static_analysis_capability_domain_classification()
            or self.worker_profile != worker.reference()
            or self.supported_operations != _SUPPORTED_OPERATIONS
            or self.supported_parsers != _SUPPORTED_PARSERS
            or definition.supported_surface_types != _supported_locator_kinds()
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != APPLICATION_STATIC_ANALYSIS_TOOL_ID
            or definition.network_access is not False
            or definition.approval_required is not True
            or worker.network_boundary is not WorkerNetworkBoundary.DISABLED_BY_DEFAULT
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.READ_ONLY_ARTIFACT
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.OFFLINE_SANDBOX
            or worker.required_identity_dimensions != ("analyzer", "artifact-digest")
            or worker.required_budget_dimensions != ("artifact-bytes", "runtime")
        ):
            raise ValueError("Application static-analysis binding differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.application-static-analysis-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Application static-analysis binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> ApplicationStaticAnalysisBindingRef:
        return ApplicationStaticAnalysisBindingRef(
            bindingId=self.binding_id,
            bindingVersion=self.binding_version,
            bindingDigest=self.binding_digest,
        )


class ApplicationStaticAnalysisPreparation(StrictModel):
    """Exact signed preparation with no artifact read, sandbox dispatch, or finding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-static-analysis-preparation/v1alpha1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisPreparation"] = "ApplicationStaticAnalysisPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=105)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: ApplicationStaticAnalysisBinding
    surface: ApplicationArtifactRuntimeSurface
    operation: ApplicationStaticAnalysisOperation
    artifact_custody: ApplicationArtifactCustodyBinding = Field(alias="artifactCustody")
    sandbox: ApplicationStaticAnalysisSandboxBinding
    analysis_request: ApplicationStaticAnalysisRequest = Field(alias="analysisRequest")
    campaign_scope: ApplicationCampaignScopeBinding = Field(alias="campaignScope")
    matched_surface_allow_rule: str = Field(
        alias="matchedSurfaceAllowRule",
        min_length=1,
        max_length=2_000,
    )
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    current_campaign_bound: Literal[True] = Field(default=True, alias="currentCampaignBound")
    custody_authorization_reference_bound: Literal[True] = Field(
        default=True,
        alias="custodyAuthorizationReferenceBound",
    )
    network_disabled_sandbox_bound: Literal[True] = Field(
        default=True,
        alias="networkDisabledSandboxBound",
    )
    analysis_request_adapted: Literal[True] = Field(
        default=True,
        alias="analysisRequestAdapted",
    )
    capability_prepared: Literal[True] = Field(default=True, alias="capabilityPrepared")
    custody_runtime_verified: Literal[False] = Field(
        default=False,
        alias="custodyRuntimeVerified",
    )
    authorization_verified_by_preparation: Literal[False] = Field(
        default=False,
        alias="authorizationVerifiedByPreparation",
    )
    artifact_resolved: Literal[False] = Field(default=False, alias="artifactResolved")
    artifact_bytes_verified: Literal[False] = Field(
        default=False,
        alias="artifactBytesVerified",
    )
    artifact_read_performed: Literal[False] = Field(
        default=False,
        alias="artifactReadPerformed",
    )
    sandbox_runtime_available: Literal[False] = Field(
        default=False,
        alias="sandboxRuntimeAvailable",
    )
    sandbox_runtime_attested: Literal[False] = Field(
        default=False,
        alias="sandboxRuntimeAttested",
    )
    sandbox_selected: Literal[False] = Field(default=False, alias="sandboxSelected")
    artifact_mount_materialized: Literal[False] = Field(
        default=False,
        alias="artifactMountMaterialized",
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
    dynamic_target_execution_performed: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionPerformed",
    )
    debugger_attached: Literal[False] = Field(default=False, alias="debuggerAttached")
    artifact_mutated: Literal[False] = Field(default=False, alias="artifactMutated")
    observation_produced: Literal[False] = Field(default=False, alias="observationProduced")
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    finding_produced: Literal[False] = Field(default=False, alias="findingProduced")
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
        "custody_authorization_reference_bound",
        "network_disabled_sandbox_bound",
        "analysis_request_adapted",
        "capability_prepared",
        "custody_runtime_verified",
        "authorization_verified_by_preparation",
        "artifact_resolved",
        "artifact_bytes_verified",
        "artifact_read_performed",
        "sandbox_runtime_available",
        "sandbox_runtime_attested",
        "sandbox_selected",
        "artifact_mount_materialized",
        "budget_reserved",
        "worker_job_materialized",
        "network_request_performed",
        "dynamic_target_execution_performed",
        "debugger_attached",
        "artifact_mutated",
        "observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "finding_produced",
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
            raise ValueError("Application static-analysis preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        expected_action = registered_action_capability(
            registered_application_static_analysis_capability_definition()
        ).reference()
        expected_surface_rule = _require_exact_scope_allow(
            self.campaign_scope,
            application_surface_scope_target(self.surface),
            label="Application Surface",
        )
        expected_request = BoundedApplicationStaticAnalyzerAdapter(
            self.artifact_custody,
            self.sandbox,
        ).prepare_request(surface=self.surface, operation=self.operation)
        request = self.prepared_action.request
        if (
            self.binding != registered_application_static_analysis_binding()
            or self.surface.initial_state != "registered-not-authorized"
            or self.analysis_request != expected_request
            or self.matched_surface_allow_rule != expected_surface_rule
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != APPLICATION_STATIC_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != self.analysis_request.target
            or request.arguments != self.analysis_request.model_dump(mode="json", by_alias=True)
        ):
            raise ValueError("Application static-analysis preparation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.application-static-analysis-preparation/v1",
            material,
        )
        preparation_id = f"application-static-analysis-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Application static-analysis preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("Application static-analysis preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def bind_application_artifact_custody(
    *,
    surface: ApplicationArtifactRuntimeSurface,
    custody_authority_id: str,
    custody_object_id: str,
    authorization_id: str,
    authorization_digest: str,
    artifact_bytes: int,
) -> ApplicationArtifactCustodyBinding:
    """Pin an externally reviewed custody reference without resolving artifact bytes."""

    canonical_surface = _canonical_surface(surface)
    try:
        return ApplicationArtifactCustodyBinding(
            surface=canonical_surface,
            custodyAuthorityId=custody_authority_id,
            custodyObjectId=custody_object_id,
            authorizationId=authorization_id,
            authorizationDigest=authorization_digest,
            artifactSHA256=_artifact_sha256(canonical_surface),
            artifactBytes=artifact_bytes,
        )
    except (ValidationError, ValueError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application artifact custody binding failed closed"
        ) from exc


def bind_application_static_analysis_sandbox(
    *,
    deployment_id: str,
    operation: ApplicationStaticAnalysisOperation,
    parser_executable_sha256: str,
    sandbox_image_sha256: str,
    run_as_identity: str,
    max_artifact_bytes: int = 67_108_864,
    max_output_bytes: int = 1_048_576,
    max_runtime_seconds: int = 60,
    max_memory_mib: int = 512,
    max_process_count: int = 8,
) -> ApplicationStaticAnalysisSandboxBinding:
    """Pin an offline sandbox configuration without selecting or invoking a Worker."""

    try:
        canonical_operation = ApplicationStaticAnalysisOperation(operation)
    except ValueError as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application static-analysis sandbox operation is unsupported"
        ) from exc
    if (
        not isinstance(run_as_identity, str)
        or run_as_identity != run_as_identity.strip()
        or _is_forbidden_root_identity(run_as_identity)
    ):
        raise ApplicationStaticAnalysisCapabilityError(
            "Application sandbox run-as identity must be explicit and non-root"
        )
    try:
        return ApplicationStaticAnalysisSandboxBinding(
            deploymentId=deployment_id,
            workerProfile=_application_worker_boundary_profile().reference(),
            operation=canonical_operation,
            parser=_PARSER_BY_OPERATION[canonical_operation],
            parserExecutableSHA256=parser_executable_sha256,
            sandboxImageSHA256=sandbox_image_sha256,
            runAsIdentity=run_as_identity,
            maxArtifactBytes=max_artifact_bytes,
            maxOutputBytes=max_output_bytes,
            maxRuntimeSeconds=max_runtime_seconds,
            maxMemoryMiB=max_memory_mib,
            maxProcessCount=max_process_count,
        )
    except (ValidationError, ValueError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application static-analysis sandbox binding failed closed"
        ) from exc


@cache
def registered_application_static_analysis_binding() -> ApplicationStaticAnalysisBinding:
    """Return the exact APP-001B binding without custody resolution or sandbox selection."""

    registry = registered_application_artifact_runtime_locator_registry()
    return ApplicationStaticAnalysisBinding(
        locatorRegistry=registry.reference(),
        supportedLocators=tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        ),
        capability=_application_code_backed_capability(),
        capabilityDomainClassification=(
            registered_application_static_analysis_capability_domain_classification()
        ),
        workerProfile=_application_worker_boundary_profile().reference(),
    )


def resolve_application_static_analysis_binding(
    reference: ApplicationStaticAnalysisBindingRef,
) -> ApplicationStaticAnalysisBinding:
    binding = registered_application_static_analysis_binding()
    if binding.reference() == reference:
        return binding.model_copy(deep=True)
    raise ApplicationStaticAnalysisCapabilityError(
        "Application static-analysis binding is not registered exactly"
    )


@cache
def registered_application_static_analysis_capability_domain_classification() -> (
    ApplicationStaticAnalysisCapabilityDomainClassification
):
    capability = _application_code_backed_capability()
    return ApplicationStaticAnalysisCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=_application_worker_boundary_profile().domain_classification,
    )


def resolve_application_static_analysis_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
) -> ApplicationStaticAnalysisCapabilityDomainClassification:
    classification = registered_application_static_analysis_capability_domain_classification()
    if classification.reference() == reference:
        return classification.model_copy(deep=True)
    raise ApplicationStaticAnalysisCapabilityError(
        "Application Capability Domain classification is not registered exactly"
    )


def application_surface_scope_target(surface: ApplicationArtifactRuntimeSurface) -> str:
    """Return a non-routable exact Campaign Scope token for one Application Surface."""

    canonical = _canonical_surface(surface)
    return f"{APPLICATION_SURFACE_SCOPE_ORIGIN}/surfaces/{canonical.surface_id}"


def prepare_application_static_analysis(
    *,
    activation: ApplicationStaticAnalysisCapabilityActivation,
    release: CapabilityReleaseRef,
    campaign: CampaignManifest,
    surface: ApplicationArtifactRuntimeSurface,
    operation: ApplicationStaticAnalysisOperation,
    analyzer: BoundedApplicationStaticAnalyzerAdapter,
    request_id: str,
    agent_id: str,
) -> ApplicationStaticAnalysisPreparation:
    """Compile exact signed static-analysis metadata and stop before artifact access."""

    if not isinstance(activation, ApplicationStaticAnalysisCapabilityActivation):
        raise TypeError("Application preparation requires Application activation")
    if not isinstance(analyzer, BoundedApplicationStaticAnalyzerAdapter):
        raise TypeError("Application preparation requires a bounded analyzer adapter")
    try:
        canonical_operation = ApplicationStaticAnalysisOperation(operation)
    except ValueError as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application static-analysis operation is unsupported"
        ) from exc
    canonical_campaign = _canonical_campaign(campaign)
    canonical_surface = _canonical_surface(surface)
    custody = analyzer.custody
    sandbox = analyzer.sandbox
    scope_binding = _campaign_scope_binding(canonical_campaign)
    surface_allow = _require_exact_scope_allow(
        scope_binding,
        application_surface_scope_target(canonical_surface),
        label="Application Surface",
    )
    analysis_request = analyzer.prepare_request(
        surface=canonical_surface,
        operation=canonical_operation,
    )
    binding = registered_application_static_analysis_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition()
            != registered_application_static_analysis_capability_definition()
        ):
            raise ApplicationStaticAnalysisCapabilityError(
                "Application activation differs from the registered Capability"
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=APPLICATION_STATIC_ANALYSIS_TOOL_ID,
            target=analysis_request.target,
            method="GET",
            arguments={},
        )
        prepared = activation.prepare_action(
            release=release,
            request=request,
            parameters=cast(
                Mapping[str, JsonValue],
                analysis_request.model_dump(mode="json", by_alias=True),
            ),
        )
        return ApplicationStaticAnalysisPreparation(
            binding=binding,
            surface=canonical_surface,
            operation=canonical_operation,
            artifactCustody=custody,
            sandbox=sandbox,
            analysisRequest=analysis_request,
            campaignScope=scope_binding,
            matchedSurfaceAllowRule=surface_allow,
            release=release,
            preparedAction=prepared,
        )
    except (CapabilityAuthorityError, ValidationError, ValueError) as exc:
        if isinstance(exc, ApplicationStaticAnalysisCapabilityError):
            raise
        raise ApplicationStaticAnalysisCapabilityError(
            "Application CAP-002 preparation failed closed"
        ) from exc


def _verify_activation(activation: ApplicationStaticAnalysisCapabilityActivation) -> None:
    try:
        canonical_set = ApplicationStaticAnalysisCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application activation set is not canonical"
        ) from exc
    if canonical_set != activation.activation_set:
        raise ApplicationStaticAnalysisCapabilityError("Application activation set drifted")
    _resolve_activation_binding(activation, canonical_set.binding)


def _resolve_activation_binding(
    activation: ApplicationStaticAnalysisCapabilityActivation,
    binding: ApplicationStaticAnalysisCapabilityActivationBinding,
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
        raise ApplicationStaticAnalysisCapabilityError(
            "Application current signed release could not be resolved"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
        or expected_action != binding.action_capability
    ):
        raise ApplicationStaticAnalysisCapabilityError("Application signed release binding drifted")
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.application-static-analysis-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application release reference is not canonical"
        ) from exc


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    try:
        return ToolRequest.model_validate(request.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application Tool request is not canonical"
        ) from exc


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    try:
        return CampaignManifest.model_validate(campaign.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application Campaign is not canonical"
        ) from exc


def _canonical_surface(
    surface: ApplicationArtifactRuntimeSurface,
) -> ApplicationArtifactRuntimeSurface:
    try:
        return ApplicationArtifactRuntimeSurface.model_validate(
            surface.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application Surface is not canonical"
        ) from exc


def _campaign_scope_binding(campaign: CampaignManifest) -> ApplicationCampaignScopeBinding:
    return ApplicationCampaignScopeBinding(
        campaignName=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        scope=campaign.spec.scope.model_copy(deep=True),
        allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
        allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
    )


def _require_exact_scope_allow(
    scope_binding: ApplicationCampaignScopeBinding,
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
        raise ApplicationStaticAnalysisCapabilityError(
            f"{label} Campaign Scope cannot be evaluated safely"
        ) from exc
    if canonical_target not in normalized_allow:
        raise ApplicationStaticAnalysisCapabilityError(
            f"{label} lacks an exact current Campaign allow rule"
        )
    if any(scope_matches(rule, canonical_target) for rule in normalized_deny):
        raise ApplicationStaticAnalysisCapabilityError(
            f"{label} overlaps a current Campaign deny rule"
        )
    return canonical_target


def _canonical_application_surface_target(value: str) -> str:
    try:
        canonical = normalize_target_url(value)
    except InvalidScopeURL as exc:
        raise ValueError("Application Surface target is invalid") from exc
    if canonical != value or not value.startswith(f"{APPLICATION_SURFACE_SCOPE_ORIGIN}/surfaces/"):
        raise ValueError("Application Surface target must be one canonical non-routable token")
    return value


def _validate_application_tool_request(
    request: ToolRequest,
) -> ApplicationStaticAnalysisRequest:
    try:
        analysis = ApplicationStaticAnalysisRequest.model_validate(request.arguments)
    except (ValidationError, ValueError) as exc:
        raise ApplicationStaticAnalysisCapabilityError(
            "Application Tool request arguments are invalid"
        ) from exc
    if (
        request.tool_id != APPLICATION_STATIC_ANALYSIS_TOOL_ID
        or request.method != "GET"
        or request.target != analysis.target
    ):
        raise ApplicationStaticAnalysisCapabilityError(
            "Application Tool request differs from bounded GET authority"
        )
    return analysis


def _artifact_sha256(surface: ApplicationArtifactRuntimeSurface) -> str:
    return surface.locator.artifact_sha256


def _supported_locator_kinds() -> tuple[ApplicationSurfaceLocatorKind, ...]:
    return (
        "application-binary",
        "application-configuration",
        "application-library",
        "application-runtime",
    )


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


@cache
def _application_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(ApplicationStaticAnalysisTool())
    return application_static_analysis_capability_bundle(tools).capability()


@cache
def _application_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.APPLICATION
    )


__all__ = [
    "APPLICATION_ARTIFACT_CUSTODY_BINDING_API_VERSION",
    "APPLICATION_ARTIFACT_MOUNT_TARGET",
    "APPLICATION_CAMPAIGN_SCOPE_BINDING_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_BINDING_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_CAPABILITY_ADAPTER_VERSION",
    "APPLICATION_STATIC_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_CAPABILITY_ID",
    "APPLICATION_STATIC_ANALYSIS_CAPABILITY_VERSION",
    "APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA",
    "APPLICATION_STATIC_ANALYSIS_PREPARATION_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_REQUEST_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_SANDBOX_BINDING_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_TOOL_ID",
    "APPLICATION_SURFACE_SCOPE_ORIGIN",
    "ApplicationArtifactCustodyBinding",
    "ApplicationArtifactCustodyRef",
    "ApplicationCampaignScopeBinding",
    "ApplicationStaticAnalysisBinding",
    "ApplicationStaticAnalysisBindingRef",
    "ApplicationStaticAnalysisBudget",
    "ApplicationStaticAnalysisCapabilityActivation",
    "ApplicationStaticAnalysisCapabilityActivationBinding",
    "ApplicationStaticAnalysisCapabilityActivationSet",
    "ApplicationStaticAnalysisCapabilityBundle",
    "ApplicationStaticAnalysisCapabilityDomainClassification",
    "ApplicationStaticAnalysisCapabilityError",
    "ApplicationStaticAnalysisOperation",
    "ApplicationStaticAnalysisPreparation",
    "ApplicationStaticAnalysisRequest",
    "ApplicationStaticAnalysisSandboxBinding",
    "ApplicationStaticAnalysisSandboxRef",
    "ApplicationStaticAnalysisTool",
    "ApplicationStaticParser",
    "BoundedApplicationStaticAnalyzerAdapter",
    "activate_application_static_analysis_capability",
    "application_static_analysis_capability_bundle",
    "application_surface_scope_target",
    "bind_application_artifact_custody",
    "bind_application_static_analysis_sandbox",
    "prepare_application_static_analysis",
    "registered_application_static_analysis_binding",
    "registered_application_static_analysis_capability_definition",
    "registered_application_static_analysis_capability_domain_classification",
    "resolve_application_static_analysis_binding",
    "resolve_application_static_analysis_capability_domain_classification",
]
