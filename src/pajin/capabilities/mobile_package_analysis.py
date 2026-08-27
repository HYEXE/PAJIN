"""MOBILE-001B read-only Mobile static-analysis preparation boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, ClassVar, Literal, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

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
from pajin.discovery.mobile_surfaces import (
    MobileAPKSurfaceLocator,
    MobileApplicationRuntimeLocatorRef,
    MobileApplicationRuntimeLocatorRegistryRef,
    MobileApplicationRuntimeSurface,
    MobileApplicationRuntimeSurfaceRef,
    MobileApplicationSurfaceLocator,
    MobileAuthenticationSurfaceLocator,
    MobileDeepLinkSurfaceLocator,
    MobileIPASurfaceLocator,
    MobileRuntimeSurfaceLocator,
    MobileStorageSurfaceLocator,
    MobileSurfaceClass,
    MobileSurfaceLocatorKind,
    MobileTLSPolicySurfaceLocator,
    registered_mobile_application_runtime_locator_registry,
    typed_mobile_application_runtime_surface,
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
from pajin.domain.security_domain import SecurityDomainClassificationRef
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

MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ADAPTER_VERSION = (
    "pajin.mobile-package-analysis-capability-adapter/v1"
)
MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-capability-activation-set/v1alpha1"
] = "pajin.dev/mobile-package-analysis-capability-activation-set/v1alpha1"
MOBILE_PACKAGE_ANALYSIS_BINDING_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-binding/v1alpha1"
] = "pajin.dev/mobile-package-analysis-binding/v1alpha1"
MOBILE_PACKAGE_ANALYSIS_PREPARATION_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-preparation/v1alpha1"
] = "pajin.dev/mobile-package-analysis-preparation/v1alpha1"
MOBILE_CAMPAIGN_SCOPE_BINDING_API_VERSION: Literal[
    "pajin.dev/mobile-campaign-scope-binding/v1alpha1"
] = "pajin.dev/mobile-campaign-scope-binding/v1alpha1"
MOBILE_PACKAGE_CUSTODY_BINDING_API_VERSION: Literal[
    "pajin.dev/mobile-package-custody-binding/v1alpha1"
] = "pajin.dev/mobile-package-custody-binding/v1alpha1"
MOBILE_PACKAGE_ANALYSIS_SANDBOX_BINDING_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-sandbox-binding/v1alpha1"
] = "pajin.dev/mobile-package-analysis-sandbox-binding/v1alpha1"
MOBILE_PACKAGE_ANALYSIS_REQUEST_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-request/v1alpha1"
] = "pajin.dev/mobile-package-analysis-request/v1alpha1"
MOBILE_PACKAGE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-capability-domain-classification/v1alpha1"
] = "pajin.dev/mobile-package-analysis-capability-domain-classification/v1alpha1"

MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ID = "pajin.mobile.read-only-package-analysis"
MOBILE_PACKAGE_ANALYSIS_CAPABILITY_VERSION = "1.0.0"
MOBILE_PACKAGE_ANALYSIS_TOOL_ID = "mobile.read-only-package-analysis"
MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA: Literal["pajin.mobile.package-analysis-result.v1"] = (
    "pajin.mobile.package-analysis-result.v1"
)
MOBILE_SURFACE_SCOPE_ORIGIN = "https://mobile-scope.pajin.invalid"
MOBILE_PACKAGE_MOUNT_TARGET: Literal["/pajin/input/package"] = "/pajin/input/package"

_AUTHORITY_VERSION = "1.0.0"
_MAX_ARTIFACT_BYTES = 536_870_912
_MAX_OUTPUT_BYTES = 16_777_216
_MAX_RUNTIME_SECONDS = 300
_MAX_MEMORY_MIB = 4_096
_MAX_PROCESS_COUNT = 64
_MAX_ARCHIVE_ENTRIES = 100_000
_MAX_TOTAL_UNCOMPRESSED_BYTES = 1_073_741_824
_MAX_SINGLE_UNCOMPRESSED_BYTES = 268_435_456
_MAX_ARCHIVE_PATH_BYTES = 4_096
_MAX_ARCHIVE_NESTING_DEPTH = 32
_MAX_COMPRESSION_RATIO = 1_000
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


class MobilePackageAnalysisCapabilityError(ValueError):
    """Raised when MOBILE-001B Scope, custody, sandbox, or preparation drifts."""


class _MobilePackageAnalysisModel(StrictModel):
    """Strict immutable model that always revalidates nested model instances."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    """Reject unmodeled state that Pydantic model_copy(update=...) can retain."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        unknown = set(value.__dict__) - set(type(value).model_fields)
        if unknown:
            raise MobilePackageAnalysisCapabilityError(f"{label} contains unmodeled instance state")
        for field_name in type(value).model_fields:
            _require_known_instance_fields(
                getattr(value, field_name),
                label=label,
                _seen=seen,
            )
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)


def _canonical_model[ModelT: BaseModel](
    model_type: type[ModelT],
    value: object,
    *,
    label: str,
    by_alias: bool = True,
) -> ModelT:
    _require_known_instance_fields(value, label=label)
    try:
        if not isinstance(value, BaseModel):
            raise TypeError
        canonical = model_type.model_validate(value.model_dump(mode="json", by_alias=by_alias))
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        if isinstance(exc, MobilePackageAnalysisCapabilityError):
            raise
        raise MobilePackageAnalysisCapabilityError(f"{label} is not canonical") from exc
    _require_known_instance_fields(canonical, label=label)
    if canonical != value:
        raise MobilePackageAnalysisCapabilityError(f"{label} drifted")
    return canonical


class MobilePackageAnalysisOperation(StrEnum):
    """One structure-only operation for each MOBILE-001A Surface class."""

    APK_PACKAGE_STRUCTURE = "apk-package-structure-read"
    IPA_PACKAGE_STRUCTURE = "ipa-package-structure-read"
    APPLICATION_DECLARATION = "application-declaration-read"
    RUNTIME_DECLARATION = "runtime-declaration-read"
    STORAGE_DECLARATION = "storage-declaration-read"
    DEEP_LINK_DECLARATION = "deep-link-declaration-read"
    TLS_POLICY_DECLARATION = "tls-policy-declaration-read"
    AUTHENTICATION_FLOW_DECLARATION = "authentication-flow-declaration-read"


class MobilePackageParser(StrEnum):
    """Logical parser family derived only from the root package lineage."""

    ANDROID_APK_STRUCTURE = "android-apk-structure-parser"
    IOS_IPA_STRUCTURE = "ios-ipa-structure-parser"


_OPERATION_BY_SURFACE_CLASS = {
    MobileSurfaceClass.APK: MobilePackageAnalysisOperation.APK_PACKAGE_STRUCTURE,
    MobileSurfaceClass.IPA: MobilePackageAnalysisOperation.IPA_PACKAGE_STRUCTURE,
    MobileSurfaceClass.APPLICATION: MobilePackageAnalysisOperation.APPLICATION_DECLARATION,
    MobileSurfaceClass.RUNTIME: MobilePackageAnalysisOperation.RUNTIME_DECLARATION,
    MobileSurfaceClass.STORAGE: MobilePackageAnalysisOperation.STORAGE_DECLARATION,
    MobileSurfaceClass.DEEPLINK: MobilePackageAnalysisOperation.DEEP_LINK_DECLARATION,
    MobileSurfaceClass.TLS: MobilePackageAnalysisOperation.TLS_POLICY_DECLARATION,
    MobileSurfaceClass.AUTH: (MobilePackageAnalysisOperation.AUTHENTICATION_FLOW_DECLARATION),
}
_PARSER_BY_PACKAGE_CLASS = {
    MobileSurfaceClass.APK: MobilePackageParser.ANDROID_APK_STRUCTURE,
    MobileSurfaceClass.IPA: MobilePackageParser.IOS_IPA_STRUCTURE,
}
_SUPPORTED_OPERATIONS = tuple(sorted(MobilePackageAnalysisOperation, key=lambda item: item.value))
_SUPPORTED_PARSERS = tuple(sorted(MobilePackageParser, key=lambda item: item.value))


def _mobile_package_custody_digest(
    *,
    custody_binding_version: str,
    surface: MobileApplicationRuntimeSurfaceRef,
    package_surface: MobileApplicationRuntimeSurfaceRef,
    custody_authority_id: str,
    custody_object_id: str,
    authorization_id: str,
    authorization_digest: str,
    artifact_sha256: str,
    artifact_bytes: int,
) -> str:
    """Digest every variable custody claim carried by the public reference."""

    return capability_definition_digest(
        "pajin.capability.mobile-package-custody/v1",
        {
            "custodyBindingVersion": custody_binding_version,
            "surface": surface.model_dump(mode="json", by_alias=True),
            "packageSurface": package_surface.model_dump(mode="json", by_alias=True),
            "custodyAuthorityId": custody_authority_id,
            "custodyObjectId": custody_object_id,
            "authorizationId": authorization_id,
            "authorizationDigest": authorization_digest,
            "artifactSHA256": artifact_sha256,
            "artifactBytes": artifact_bytes,
        },
    )


def _mobile_package_sandbox_digest(
    *,
    sandbox_binding_version: str,
    deployment_id: str,
    surface: MobileApplicationRuntimeSurfaceRef,
    package_surface: MobileApplicationRuntimeSurfaceRef,
    operation: MobilePackageAnalysisOperation,
    parser: MobilePackageParser,
    parser_executable_sha256: str,
    sandbox_image_sha256: str,
    run_as_identity: str,
    output_schema: str,
    max_artifact_bytes: int,
    max_output_bytes: int,
    max_runtime_seconds: int,
    max_memory_mib: int,
    max_process_count: int,
    max_archive_entries: int,
    max_total_uncompressed_bytes: int,
    max_single_uncompressed_bytes: int,
    max_archive_path_bytes: int,
    max_archive_nesting_depth: int,
    max_compression_ratio: int,
) -> str:
    """Digest every variable sandbox claim carried by the public reference."""

    return capability_definition_digest(
        "pajin.capability.mobile-package-analysis-sandbox/v1",
        {
            "sandboxBindingVersion": sandbox_binding_version,
            "deploymentId": deployment_id,
            "surface": surface.model_dump(mode="json", by_alias=True),
            "packageSurface": package_surface.model_dump(mode="json", by_alias=True),
            "operation": operation.value,
            "parser": parser.value,
            "parserExecutableSHA256": parser_executable_sha256,
            "sandboxImageSHA256": sandbox_image_sha256,
            "runAsIdentity": run_as_identity,
            "outputSchema": output_schema,
            "maxArtifactBytes": max_artifact_bytes,
            "maxOutputBytes": max_output_bytes,
            "maxRuntimeSeconds": max_runtime_seconds,
            "maxMemoryMiB": max_memory_mib,
            "maxProcessCount": max_process_count,
            "maxArchiveEntries": max_archive_entries,
            "maxTotalUncompressedBytes": max_total_uncompressed_bytes,
            "maxSingleUncompressedBytes": max_single_uncompressed_bytes,
            "maxArchivePathBytes": max_archive_path_bytes,
            "maxArchiveNestingDepth": max_archive_nesting_depth,
            "maxCompressionRatio": max_compression_ratio,
        },
    )


class MobilePackageCustodyRef(_MobilePackageAnalysisModel):
    """Exact secret-free reference to deployment-authorized immutable custody."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    custody_binding_id: str = Field(
        alias="custodyBindingId",
        pattern=r"^mobile-package-custody_[a-f0-9]{64}$",
    )
    custody_binding_version: Literal["1.0.0"] = Field(alias="custodyBindingVersion")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    surface: MobileApplicationRuntimeSurfaceRef
    package_surface: MobileApplicationRuntimeSurfaceRef = Field(alias="packageSurface")
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
            raise ValueError("Mobile custody artifact bytes must be an integer")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _mobile_package_custody_digest(
            custody_binding_version=self.custody_binding_version,
            surface=self.surface,
            package_surface=self.package_surface,
            custody_authority_id=self.custody_authority_id,
            custody_object_id=self.custody_object_id,
            authorization_id=self.authorization_id,
            authorization_digest=self.authorization_digest,
            artifact_sha256=self.artifact_sha256,
            artifact_bytes=self.artifact_bytes,
        )
        expected_id = f"mobile-package-custody_{digest}"
        if (
            self.custody_binding_digest != digest
            or self.custody_binding_id != expected_id
            or self.package_surface.surface_class
            not in {MobileSurfaceClass.APK, MobileSurfaceClass.IPA}
        ):
            raise ValueError("Mobile artifact custody reference identity differs")
        return self


class MobilePackageCustodyBinding(_MobilePackageAnalysisModel):
    """Configuration-only custody binding; no artifact is resolved or read here."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mobile-package-custody-binding/v1alpha1"] = Field(
        default=MOBILE_PACKAGE_CUSTODY_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobilePackageCustodyBinding"] = "MobilePackageCustodyBinding"
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
    surface: MobileApplicationRuntimeSurface
    package_surface: MobileApplicationRuntimeSurface = Field(alias="packageSurface")
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
    exact_package_lineage_bound: Literal[True] = Field(
        default=True,
        alias="exactPackageLineageBound",
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
            raise ValueError("Mobile custody artifact bytes must be an integer")
        return value

    @field_validator(
        "configuration_only",
        "deployment_authorization_reference_bound",
        "exact_package_lineage_bound",
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
            raise ValueError("Mobile artifact custody markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_custody_identity(self) -> Self:
        canonical_surface = _canonical_surface(self.surface)
        canonical_package = _package_surface(canonical_surface)
        if (
            canonical_surface != self.surface
            or canonical_package != self.package_surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.package_surface.initial_state != "registered-not-authorized"
            or self.artifact_sha256 != _artifact_sha256(self.surface)
        ):
            raise ValueError("Mobile artifact custody differs from the exact Surface")
        digest = _mobile_package_custody_digest(
            custody_binding_version=self.custody_binding_version,
            surface=canonical_surface.reference(),
            package_surface=canonical_package.reference(),
            custody_authority_id=self.custody_authority_id,
            custody_object_id=self.custody_object_id,
            authorization_id=self.authorization_id,
            authorization_digest=self.authorization_digest,
            artifact_sha256=self.artifact_sha256,
            artifact_bytes=self.artifact_bytes,
        )
        binding_id = f"mobile-package-custody_{digest}"
        if self.custody_binding_digest and self.custody_binding_digest != digest:
            raise ValueError("Mobile artifact custody digest differs")
        if self.custody_binding_id and self.custody_binding_id != binding_id:
            raise ValueError("Mobile artifact custody ID differs")
        object.__setattr__(self, "custody_binding_digest", digest)
        object.__setattr__(self, "custody_binding_id", binding_id)
        return self

    def reference(self) -> MobilePackageCustodyRef:
        canonical = _canonical_model(
            MobilePackageCustodyBinding,
            self,
            label="Mobile package custody binding",
        )
        return MobilePackageCustodyRef(
            custodyBindingId=canonical.custody_binding_id,
            custodyBindingVersion=canonical.custody_binding_version,
            custodyBindingDigest=canonical.custody_binding_digest,
            surface=canonical.surface.reference(),
            packageSurface=canonical.package_surface.reference(),
            custodyAuthorityId=canonical.custody_authority_id,
            custodyObjectId=canonical.custody_object_id,
            authorizationId=canonical.authorization_id,
            authorizationDigest=canonical.authorization_digest,
            artifactSHA256=canonical.artifact_sha256,
            artifactBytes=canonical.artifact_bytes,
        )


class MobilePackageAnalysisSandboxRef(_MobilePackageAnalysisModel):
    """Exact non-secret reference to one network-disabled sandbox configuration."""

    sandbox_binding_id: str = Field(
        alias="sandboxBindingId",
        pattern=r"^mobile-package-analysis-sandbox_[a-f0-9]{64}$",
    )
    sandbox_binding_version: Literal["1.0.0"] = Field(alias="sandboxBindingVersion")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    surface: MobileApplicationRuntimeSurfaceRef
    package_surface: MobileApplicationRuntimeSurfaceRef = Field(alias="packageSurface")
    operation: MobilePackageAnalysisOperation
    parser: MobilePackageParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    output_schema: Literal["pajin.mobile.package-analysis-result.v1"] = Field(alias="outputSchema")
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
    max_archive_entries: int = Field(
        alias="maxArchiveEntries",
        ge=1,
        le=_MAX_ARCHIVE_ENTRIES,
    )
    max_total_uncompressed_bytes: int = Field(
        alias="maxTotalUncompressedBytes",
        ge=1,
        le=_MAX_TOTAL_UNCOMPRESSED_BYTES,
    )
    max_single_uncompressed_bytes: int = Field(
        alias="maxSingleUncompressedBytes",
        ge=1,
        le=_MAX_SINGLE_UNCOMPRESSED_BYTES,
    )
    max_archive_path_bytes: int = Field(
        alias="maxArchivePathBytes",
        ge=1,
        le=_MAX_ARCHIVE_PATH_BYTES,
    )
    max_archive_nesting_depth: int = Field(
        alias="maxArchiveNestingDepth",
        ge=1,
        le=_MAX_ARCHIVE_NESTING_DEPTH,
    )
    max_compression_ratio: int = Field(
        alias="maxCompressionRatio",
        ge=1,
        le=_MAX_COMPRESSION_RATIO,
    )

    @field_validator(
        "max_artifact_bytes",
        "max_output_bytes",
        "max_runtime_seconds",
        "max_memory_mib",
        "max_process_count",
        "max_archive_entries",
        "max_total_uncompressed_bytes",
        "max_single_uncompressed_bytes",
        "max_archive_path_bytes",
        "max_archive_nesting_depth",
        "max_compression_ratio",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Mobile sandbox reference ceilings must be integers")
        return value

    @field_validator("run_as_identity", mode="before")
    @classmethod
    def require_explicit_non_root_identity(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        if value != value.strip() or _is_forbidden_root_identity(value):
            raise ValueError("Mobile sandbox reference run-as identity must be non-root")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _mobile_package_sandbox_digest(
            sandbox_binding_version=self.sandbox_binding_version,
            deployment_id=self.deployment_id,
            surface=self.surface,
            package_surface=self.package_surface,
            operation=self.operation,
            parser=self.parser,
            parser_executable_sha256=self.parser_executable_sha256,
            sandbox_image_sha256=self.sandbox_image_sha256,
            run_as_identity=self.run_as_identity,
            output_schema=self.output_schema,
            max_artifact_bytes=self.max_artifact_bytes,
            max_output_bytes=self.max_output_bytes,
            max_runtime_seconds=self.max_runtime_seconds,
            max_memory_mib=self.max_memory_mib,
            max_process_count=self.max_process_count,
            max_archive_entries=self.max_archive_entries,
            max_total_uncompressed_bytes=self.max_total_uncompressed_bytes,
            max_single_uncompressed_bytes=self.max_single_uncompressed_bytes,
            max_archive_path_bytes=self.max_archive_path_bytes,
            max_archive_nesting_depth=self.max_archive_nesting_depth,
            max_compression_ratio=self.max_compression_ratio,
        )
        expected_id = f"mobile-package-analysis-sandbox_{digest}"
        if (
            self.sandbox_binding_digest != digest
            or self.sandbox_binding_id != expected_id
            or self.operation is not _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class]
            or self.package_surface.surface_class
            not in {MobileSurfaceClass.APK, MobileSurfaceClass.IPA}
            or self.parser is not _PARSER_BY_PACKAGE_CLASS[self.package_surface.surface_class]
            or self.max_single_uncompressed_bytes > self.max_total_uncompressed_bytes
        ):
            raise ValueError("Mobile package-analysis sandbox reference differs")
        return self


class MobilePackageAnalysisSandboxBinding(_MobilePackageAnalysisModel):
    """Configuration-only static sandbox boundary without profile binding or execution."""

    api_version: Literal["pajin.dev/mobile-package-analysis-sandbox-binding/v1alpha1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_SANDBOX_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisSandboxBinding"] = "MobilePackageAnalysisSandboxBinding"
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
    surface: MobileApplicationRuntimeSurface
    package_surface: MobileApplicationRuntimeSurface = Field(alias="packageSurface")
    operation: MobilePackageAnalysisOperation
    parser: MobilePackageParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    artifact_mount_target: Literal["/pajin/input/package"] = Field(
        default=MOBILE_PACKAGE_MOUNT_TARGET,
        alias="artifactMountTarget",
    )
    output_schema: Literal["pajin.mobile.package-analysis-result.v1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
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
    max_archive_entries: int = Field(
        default=10_000,
        alias="maxArchiveEntries",
        ge=1,
        le=_MAX_ARCHIVE_ENTRIES,
    )
    max_total_uncompressed_bytes: int = Field(
        default=536_870_912,
        alias="maxTotalUncompressedBytes",
        ge=1,
        le=_MAX_TOTAL_UNCOMPRESSED_BYTES,
    )
    max_single_uncompressed_bytes: int = Field(
        default=67_108_864,
        alias="maxSingleUncompressedBytes",
        ge=1,
        le=_MAX_SINGLE_UNCOMPRESSED_BYTES,
    )
    max_archive_path_bytes: int = Field(
        default=1_024,
        alias="maxArchivePathBytes",
        ge=1,
        le=_MAX_ARCHIVE_PATH_BYTES,
    )
    max_archive_nesting_depth: int = Field(
        default=8,
        alias="maxArchiveNestingDepth",
        ge=1,
        le=_MAX_ARCHIVE_NESTING_DEPTH,
    )
    max_compression_ratio: int = Field(
        default=100,
        alias="maxCompressionRatio",
        ge=1,
        le=_MAX_COMPRESSION_RATIO,
    )
    configuration_only: Literal[True] = Field(default=True, alias="configurationOnly")
    network_disabled_required: Literal[True] = Field(
        default=True,
        alias="networkDisabledRequired",
    )
    dns_disabled_required: Literal[True] = Field(default=True, alias="dnsDisabledRequired")
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
    archive_path_traversal_rejected: Literal[True] = Field(
        default=True,
        alias="archivePathTraversalRejected",
    )
    archive_symlinks_rejected: Literal[True] = Field(
        default=True,
        alias="archiveSymlinksRejected",
    )
    archive_duplicate_names_rejected: Literal[True] = Field(
        default=True,
        alias="archiveDuplicateNamesRejected",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
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
    worker_job_materialization_available: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAvailable",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    emulator_selection_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorSelectionAuthorized",
    )
    device_selection_authorized: Literal[False] = Field(
        default=False,
        alias="deviceSelectionAuthorized",
    )
    device_access_authorized: Literal[False] = Field(
        default=False,
        alias="deviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
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
            raise ValueError("Mobile sandbox run-as identity must be explicit and non-root")
        return value

    @field_validator(
        "max_artifact_bytes",
        "max_output_bytes",
        "max_runtime_seconds",
        "max_memory_mib",
        "max_process_count",
        "max_archive_entries",
        "max_total_uncompressed_bytes",
        "max_single_uncompressed_bytes",
        "max_archive_path_bytes",
        "max_archive_nesting_depth",
        "max_compression_ratio",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Mobile sandbox resource ceilings must be integers")
        return value

    @field_validator(
        "configuration_only",
        "network_disabled_required",
        "dns_disabled_required",
        "read_only_root_filesystem_required",
        "read_only_artifact_mount_required",
        "artifact_mount_noexec_required",
        "no_new_privileges_required",
        "non_root_runtime_required",
        "exact_parser_executable_digest_required",
        "exact_sandbox_image_digest_required",
        "archive_path_traversal_rejected",
        "archive_symlinks_rejected",
        "archive_duplicate_names_rejected",
        "domain_worker_profile_bound",
        "domain_worker_profile_binding_deferred",
        "device_bound_runtime_profile_applied",
        "host_filesystem_access_allowed",
        "credential_injection_allowed",
        "environment_inheritance_allowed",
        "symlink_traversal_allowed",
        "runtime_attested",
        "sandbox_selected",
        "artifact_mount_materialized",
        "artifact_read_authorized",
        "worker_selection_authorized",
        "worker_job_materialization_available",
        "network_access_authorized",
        "dns_access_authorized",
        "emulator_selection_authorized",
        "device_selection_authorized",
        "device_access_authorized",
        "package_installation_authorized",
        "application_launch_authorized",
        "instrumentation_authorized",
        "dynamic_target_execution_authorized",
        "storage_read_authorized",
        "tls_invocation_authorized",
        "authentication_invocation_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Mobile sandbox markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_sandbox_identity(self) -> Self:
        canonical_surface = _canonical_surface(self.surface)
        canonical_package = _package_surface(canonical_surface)
        if (
            canonical_surface != self.surface
            or canonical_package != self.package_surface
            or self.operation is not _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class]
            or self.parser is not _package_parser(self.surface)
            or self.max_single_uncompressed_bytes > self.max_total_uncompressed_bytes
        ):
            raise ValueError("Mobile package-analysis sandbox differs from code authority")
        digest = _mobile_package_sandbox_digest(
            sandbox_binding_version=self.sandbox_binding_version,
            deployment_id=self.deployment_id,
            surface=canonical_surface.reference(),
            package_surface=canonical_package.reference(),
            operation=self.operation,
            parser=self.parser,
            parser_executable_sha256=self.parser_executable_sha256,
            sandbox_image_sha256=self.sandbox_image_sha256,
            run_as_identity=self.run_as_identity,
            output_schema=self.output_schema,
            max_artifact_bytes=self.max_artifact_bytes,
            max_output_bytes=self.max_output_bytes,
            max_runtime_seconds=self.max_runtime_seconds,
            max_memory_mib=self.max_memory_mib,
            max_process_count=self.max_process_count,
            max_archive_entries=self.max_archive_entries,
            max_total_uncompressed_bytes=self.max_total_uncompressed_bytes,
            max_single_uncompressed_bytes=self.max_single_uncompressed_bytes,
            max_archive_path_bytes=self.max_archive_path_bytes,
            max_archive_nesting_depth=self.max_archive_nesting_depth,
            max_compression_ratio=self.max_compression_ratio,
        )
        binding_id = f"mobile-package-analysis-sandbox_{digest}"
        if self.sandbox_binding_digest and self.sandbox_binding_digest != digest:
            raise ValueError("Mobile package-analysis sandbox digest differs")
        if self.sandbox_binding_id and self.sandbox_binding_id != binding_id:
            raise ValueError("Mobile package-analysis sandbox ID differs")
        object.__setattr__(self, "sandbox_binding_digest", digest)
        object.__setattr__(self, "sandbox_binding_id", binding_id)
        return self

    def reference(self) -> MobilePackageAnalysisSandboxRef:
        canonical = _canonical_model(
            MobilePackageAnalysisSandboxBinding,
            self,
            label="Mobile package-analysis sandbox binding",
        )
        return MobilePackageAnalysisSandboxRef(
            sandboxBindingId=canonical.sandbox_binding_id,
            sandboxBindingVersion=canonical.sandbox_binding_version,
            sandboxBindingDigest=canonical.sandbox_binding_digest,
            deploymentId=canonical.deployment_id,
            surface=canonical.surface.reference(),
            packageSurface=canonical.package_surface.reference(),
            operation=canonical.operation,
            parser=canonical.parser,
            parserExecutableSHA256=canonical.parser_executable_sha256,
            sandboxImageSHA256=canonical.sandbox_image_sha256,
            runAsIdentity=canonical.run_as_identity,
            outputSchema=canonical.output_schema,
            maxArtifactBytes=canonical.max_artifact_bytes,
            maxOutputBytes=canonical.max_output_bytes,
            maxRuntimeSeconds=canonical.max_runtime_seconds,
            maxMemoryMiB=canonical.max_memory_mib,
            maxProcessCount=canonical.max_process_count,
            maxArchiveEntries=canonical.max_archive_entries,
            maxTotalUncompressedBytes=canonical.max_total_uncompressed_bytes,
            maxSingleUncompressedBytes=canonical.max_single_uncompressed_bytes,
            maxArchivePathBytes=canonical.max_archive_path_bytes,
            maxArchiveNestingDepth=canonical.max_archive_nesting_depth,
            maxCompressionRatio=canonical.max_compression_ratio,
        )


class MobilePackageAnalysisBudget(_MobilePackageAnalysisModel):
    """Attenuating static package-analysis ceilings with every live channel at zero."""

    request_count: Literal[1] = Field(default=1, alias="requestCount")
    artifact_bytes: int = Field(alias="artifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1_024, le=_MAX_OUTPUT_BYTES)
    runtime_seconds: int = Field(alias="runtimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    memory_mib: int = Field(alias="memoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    process_count: int = Field(alias="processCount", ge=1, le=_MAX_PROCESS_COUNT)
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_requests: Literal[0] = Field(default=0, alias="dnsRequests")
    package_installations: Literal[0] = Field(default=0, alias="packageInstallations")
    application_launches: Literal[0] = Field(default=0, alias="applicationLaunches")
    emulator_sessions: Literal[0] = Field(default=0, alias="emulatorSessions")
    device_sessions: Literal[0] = Field(default=0, alias="deviceSessions")
    instrumentation_sessions: Literal[0] = Field(
        default=0,
        alias="instrumentationSessions",
    )
    dynamic_target_executions: Literal[0] = Field(
        default=0,
        alias="dynamicTargetExecutions",
    )
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")
    storage_reads: Literal[0] = Field(default=0, alias="storageReads")
    tls_connections: Literal[0] = Field(default=0, alias="tlsConnections")
    authentication_invocations: Literal[0] = Field(
        default=0,
        alias="authenticationInvocations",
    )
    package_write_operations: Literal[0] = Field(
        default=0,
        alias="packageWriteOperations",
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
        "dns_requests",
        "package_installations",
        "application_launches",
        "emulator_sessions",
        "device_sessions",
        "instrumentation_sessions",
        "dynamic_target_executions",
        "debugger_attaches",
        "storage_reads",
        "tls_connections",
        "authentication_invocations",
        "package_write_operations",
        "host_filesystem_reads",
        "credential_reads",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Mobile package-analysis budget values must be integers")
        return value

    @field_validator("attenuation_only", "reservation_created", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Mobile package-analysis budget markers must be booleans")
        return value


class MobilePackageAnalysisRequest(_MobilePackageAnalysisModel):
    """Secret-free request description; it resolves, mounts, and executes nothing."""

    api_version: Literal["pajin.dev/mobile-package-analysis-request/v1alpha1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisRequest"] = "MobilePackageAnalysisRequest"
    operation: MobilePackageAnalysisOperation
    parser: MobilePackageParser
    surface: MobileApplicationRuntimeSurface
    package_surface: MobileApplicationRuntimeSurface = Field(alias="packageSurface")
    custody: MobilePackageCustodyRef
    sandbox: MobilePackageAnalysisSandboxRef
    target: str = Field(min_length=9, max_length=2_000)
    package_target: str = Field(alias="packageTarget", min_length=9, max_length=2_000)
    method: Literal["GET"] = "GET"
    output_schema: Literal["pajin.mobile.package-analysis-result.v1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    budget: MobilePackageAnalysisBudget
    raw_package_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawPackageContentEmbedded",
    )
    raw_manifest_embedded: Literal[False] = Field(
        default=False,
        alias="rawManifestEmbedded",
    )
    signing_material_embedded: Literal[False] = Field(
        default=False,
        alias="signingMaterialEmbedded",
    )
    mutable_package_path_embedded: Literal[False] = Field(
        default=False,
        alias="mutablePackagePathEmbedded",
    )
    routable_package_url_embedded: Literal[False] = Field(
        default=False,
        alias="routablePackageURLEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    device_identity_embedded: Literal[False] = Field(
        default=False,
        alias="deviceIdentityEmbedded",
    )
    package_resolution_performed: Literal[False] = Field(
        default=False,
        alias="packageResolutionPerformed",
    )
    package_read_performed: Literal[False] = Field(
        default=False,
        alias="packageReadPerformed",
    )
    package_mount_materialized: Literal[False] = Field(
        default=False,
        alias="packageMountMaterialized",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    worker_job_materialization_available: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAvailable",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    emulator_selection_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorSelectionAuthorized",
    )
    device_selection_authorized: Literal[False] = Field(
        default=False,
        alias="deviceSelectionAuthorized",
    )
    device_access_authorized: Literal[False] = Field(
        default=False,
        alias="deviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )

    @field_validator("target", "package_target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        return _canonical_mobile_surface_target(value)

    @field_validator(
        "raw_package_content_embedded",
        "raw_manifest_embedded",
        "signing_material_embedded",
        "mutable_package_path_embedded",
        "routable_package_url_embedded",
        "credential_material_embedded",
        "device_identity_embedded",
        "package_resolution_performed",
        "package_read_performed",
        "package_mount_materialized",
        "sandbox_invocation_authorized",
        "worker_job_materialization_available",
        "network_access_authorized",
        "dns_access_authorized",
        "emulator_selection_authorized",
        "device_selection_authorized",
        "device_access_authorized",
        "package_installation_authorized",
        "application_launch_authorized",
        "instrumentation_authorized",
        "dynamic_target_execution_authorized",
        "storage_read_authorized",
        "tls_invocation_authorized",
        "authentication_invocation_authorized",
        "credential_access_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Mobile package-analysis request markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_request(self) -> Self:
        canonical_surface = _canonical_surface(self.surface)
        canonical_package = _package_surface(canonical_surface)
        expected_operation = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
        expected_parser = _package_parser(canonical_surface)
        if (
            canonical_surface != self.surface
            or canonical_package != self.package_surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.package_surface.initial_state != "registered-not-authorized"
            or self.operation is not expected_operation
            or self.parser is not expected_parser
            or self.custody.surface != self.surface.reference()
            or self.custody.package_surface != self.package_surface.reference()
            or self.custody.artifact_sha256 != _artifact_sha256(self.surface)
            or self.sandbox.surface != self.surface.reference()
            or self.sandbox.package_surface != self.package_surface.reference()
            or self.sandbox.operation is not self.operation
            or self.sandbox.parser is not self.parser
            or self.sandbox.output_schema != self.output_schema
            or self.target != mobile_surface_scope_target(self.surface)
            or self.package_target != mobile_surface_scope_target(self.package_surface)
            or self.budget.artifact_bytes != self.custody.artifact_bytes
            or self.budget.artifact_bytes > self.sandbox.max_artifact_bytes
            or self.budget.max_output_bytes != self.sandbox.max_output_bytes
            or self.budget.runtime_seconds != self.sandbox.max_runtime_seconds
            or self.budget.memory_mib != self.sandbox.max_memory_mib
            or self.budget.process_count != self.sandbox.max_process_count
        ):
            raise ValueError("Mobile package-analysis request differs from exact bindings")
        return self


@dataclass(frozen=True, slots=True)
class BoundedMobilePackageAnalyzerAdapter:
    """Adapt exact custody and sandbox metadata without reading or executing it."""

    _custody: MobilePackageCustodyBinding
    _sandbox: MobilePackageAnalysisSandboxBinding

    def __post_init__(self) -> None:
        custody = _canonical_model(
            MobilePackageCustodyBinding,
            self._custody,
            label="Mobile package custody binding",
        )
        sandbox = _canonical_model(
            MobilePackageAnalysisSandboxBinding,
            self._sandbox,
            label="Mobile package-analysis sandbox binding",
        )
        if custody.surface != sandbox.surface or custody.package_surface != sandbox.package_surface:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile custody and sandbox differ from the exact package lineage"
            )
        object.__setattr__(self, "_custody", custody)
        object.__setattr__(self, "_sandbox", sandbox)

    @property
    def custody(self) -> MobilePackageCustodyBinding:
        canonical = _canonical_model(
            MobilePackageCustodyBinding,
            self._custody,
            label="Mobile package custody binding",
        )
        return canonical.model_copy(deep=True)

    @property
    def sandbox(self) -> MobilePackageAnalysisSandboxBinding:
        canonical = _canonical_model(
            MobilePackageAnalysisSandboxBinding,
            self._sandbox,
            label="Mobile package-analysis sandbox binding",
        )
        return canonical.model_copy(deep=True)

    def prepare_request(
        self,
        *,
        surface: MobileApplicationRuntimeSurface,
        operation: MobilePackageAnalysisOperation,
    ) -> MobilePackageAnalysisRequest:
        """Return one bounded request description without artifact or sandbox authority."""

        canonical_surface = _canonical_surface(surface)
        try:
            canonical_operation = MobilePackageAnalysisOperation(operation)
        except ValueError as exc:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile package-analysis operation is unsupported"
            ) from exc
        expected_operation = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
        package_surface = _package_surface(canonical_surface)
        custody = self.custody
        sandbox = self.sandbox
        if canonical_surface != custody.surface or canonical_surface != sandbox.surface:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile custody differs from the exact Surface"
            )
        if package_surface != custody.package_surface or package_surface != sandbox.package_surface:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile package lineage differs across custody and sandbox bindings"
            )
        if canonical_operation is not expected_operation:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile static-analysis operation differs from the exact Surface class"
            )
        if canonical_operation is not sandbox.operation:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile operation is outside the exact sandbox parser binding"
            )
        if custody.artifact_bytes > sandbox.max_artifact_bytes:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile artifact exceeds the sandbox artifact-byte ceiling"
            )
        return MobilePackageAnalysisRequest(
            operation=canonical_operation,
            parser=_package_parser(canonical_surface),
            surface=canonical_surface,
            packageSurface=package_surface,
            custody=custody.reference(),
            sandbox=sandbox.reference(),
            target=mobile_surface_scope_target(canonical_surface),
            packageTarget=mobile_surface_scope_target(package_surface),
            budget=MobilePackageAnalysisBudget(
                artifactBytes=custody.artifact_bytes,
                maxOutputBytes=sandbox.max_output_bytes,
                runtimeSeconds=sandbox.max_runtime_seconds,
                memoryMiB=sandbox.max_memory_mib,
                processCount=sandbox.max_process_count,
            ),
        )


class MobilePackageAnalysisTool(Tool):
    """CAP-001 Tool identity whose offline sandbox runtime remains unavailable."""

    spec = ToolSpec(
        tool_id=MOBILE_PACKAGE_ANALYSIS_TOOL_ID,
        version="1.0.0",
        description="Prepare one exact network-disabled read-only Mobile package analysis",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"mobile", "offline-sandbox", "read-only", "static-analysis"}),
        evidence_types=frozenset({"mobile-package-analysis-json", "json"}),
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
            "outputSchema": MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
            "packageResolverRuntimeAvailable": False,
            "packageParserRuntimeAvailable": False,
            "domainWorkerProfileBound": False,
            "deviceOrEmulatorRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        _validate_mobile_tool_request(request)
        raise MobilePackageAnalysisCapabilityError(
            "MOBILE-001B does not materialize an offline sandbox Worker job"
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        _validate_mobile_tool_request(request)
        raise MobilePackageAnalysisCapabilityError("MOBILE-001B has no sandbox result to normalize")


class MobilePackageAnalysisCapabilityDomainClassification(_MobilePackageAnalysisModel):
    """Exact Mobile classification for the additive MOBILE-001B CAP-002 bundle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/mobile-package-analysis-capability-domain-classification/v1alpha1"
    ] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisCapabilityDomainClassification"] = (
        "MobilePackageAnalysisCapabilityDomainClassification"
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
    reviewed_surface_types: tuple[MobileSurfaceLocatorKind, ...] = Field(
        default=(
            "mobile-apk-package",
            "mobile-application",
            "mobile-authentication",
            "mobile-deeplink",
            "mobile-ipa-package",
            "mobile-runtime",
            "mobile-storage",
            "mobile-tls-policy",
        ),
        alias="reviewedSurfaceTypes",
    )
    mapping_basis: Literal["mobile-001b-explicit-code-reviewed-capability-and-surface-set"] = Field(
        default="mobile-001b-explicit-code-reviewed-capability-and-surface-set",
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
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    worker_job_materialization_available: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAvailable",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "projection_only",
        "complete_code_authority_set_verified",
        "global_domain_inventory_changed",
        "capability_activation_authorized",
        "worker_selection_authorized",
        "domain_worker_profile_bound",
        "domain_worker_profile_binding_deferred",
        "worker_job_materialization_available",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Mobile Capability Domain markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        capability = _mobile_code_backed_capability()
        registry = registered_mobile_application_runtime_locator_registry()
        if (
            self.capability != capability.capability
            or self.code_backed_capability != capability
            or self.domain_classification != registry.domain_classification
            or self.reviewed_surface_types != _supported_locator_kinds()
        ):
            raise ValueError("Mobile Capability Domain classification differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.mobile-package-analysis-domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Mobile Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("Mobile Capability Domain classification ID differs")
        object.__setattr__(self, "classification_digest", digest)
        object.__setattr__(self, "classification_id", classification_id)
        return self

    def reference(self) -> CapabilityDomainClassificationRef:
        canonical = _canonical_model(
            MobilePackageAnalysisCapabilityDomainClassification,
            self,
            label="Mobile Capability Domain classification",
        )
        return CapabilityDomainClassificationRef(
            classificationId=canonical.classification_id,
            classificationDigest=canonical.classification_digest,
            capability=canonical.capability,
            domainClassification=canonical.domain_classification,
        )


class MobileCampaignScopeBinding(_MobilePackageAnalysisModel):
    """Content-addressed current Campaign projection for exact Mobile preparation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mobile-campaign-scope-binding/v1alpha1"] = Field(
        default=MOBILE_CAMPAIGN_SCOPE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobileCampaignScopeBinding"] = "MobileCampaignScopeBinding"
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
            raise ValueError("Mobile Campaign Scope markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_scope_projection(self) -> Self:
        if self.allowed_methods != tuple(sorted(set(self.allowed_methods))):
            raise ValueError("Mobile Campaign allowed methods must be sorted and unique")
        if "GET" not in self.allowed_methods:
            raise ValueError("Mobile Campaign Scope requires reviewed GET authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.mobile-campaign-scope-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Mobile Campaign Scope binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class MobilePackageAnalysisCapabilityBundle:
    """Frozen CAP-001/CAP-002 registries for one Mobile Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapabilityRef:
        manifests = self.authorities.capabilities()
        if len(manifests) != 1:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile static-analysis Capability authority inventory drifted"
            )
        return manifests[0].reference()


class MobilePackageAnalysisCapabilityActivationBinding(_MobilePackageAnalysisModel):
    """One exact externally signed release admitted for Range-only use."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        definition = registered_mobile_package_analysis_capability_definition()
        action = self.action_capability
        if (
            self.capability != _mobile_code_backed_capability()
            or action != registered_action_capability(definition)
        ):
            raise ValueError("Mobile activation references another Capability")
        return self


class MobilePackageAnalysisCapabilityActivationSet(_MobilePackageAnalysisModel):
    """Content-addressed activation of exactly one signed Mobile release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mobile-package-analysis-capability-activation-set/v1alpha1"] = (
        Field(
            default=MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["MobilePackageAnalysisCapabilityActivationSet"] = (
        "MobilePackageAnalysisCapabilityActivationSet"
    )
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(
        default="",
        alias="activationSetDigest",
        max_length=64,
    )
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: MobilePackageAnalysisCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.mobile-package-analysis-activation-set/v1",
            material,
        )
        activation_set_id = f"mobile-package-analysis-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("Mobile activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("Mobile activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class MobilePackageAnalysisCapabilityActivation:
    """Runtime activation that rechecks the signed current release on every use."""

    bundle: MobilePackageAnalysisCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: MobilePackageAnalysisCapabilityActivationSet

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
            raise MobilePackageAnalysisCapabilityError(
                "Mobile activated Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile CAP-002 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(self, reference: ActionCapabilityRef) -> ResolvedCapabilityRelease:
        canonical = _canonical_model(
            ActionCapabilityRef,
            reference,
            label="Mobile GRAPH Capability reference",
        )
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise MobilePackageAnalysisCapabilityError(
                "Mobile GRAPH Capability is outside the activation"
            )
        return _resolve_activation_binding(self, binding)

    def prepare_action(
        self,
        *,
        release: CapabilityReleaseRef,
        request: ToolRequest,
        parameters: Mapping[str, JsonValue],
    ) -> PreparedCapabilityAction:
        _require_known_instance_fields(parameters, label="Mobile Capability parameters")
        binding = self.activation_set.binding
        canonical_release = _canonical_release_ref(release)
        if binding.release != canonical_release:
            raise MobilePackageAnalysisCapabilityError("Mobile release is outside the activation")
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
            raise MobilePackageAnalysisCapabilityError(
                "Mobile CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _MobilePackageAnalysisAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        definition: CapabilityDefinition,
        tool: MobilePackageAnalysisTool,
    ) -> None:
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ID}.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ADAPTER_VERSION,
            "method": "GET",
            "parameterSchemaDigest": self._definition.parameter_schema_digest,
            "packageCustodyRequestAdaptationAvailable": True,
            "staticSandboxRequestAdaptationAvailable": True,
            "packageCustodyRuntimeAvailable": False,
            "packageParserRuntimeAvailable": False,
            "domainWorkerProfileBound": False,
            "deviceOrEmulatorRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
            "replayAuthorized": False,
            "cleanupAuthorized": False,
            "tool": {
                "type": f"{type(self._tool).__module__}.{type(self._tool).__qualname__}",
                "context": self._tool.stable_execution_context(),
            },
        }


class _MobilePackageAnalysisMaterializer(_MobilePackageAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            request = MobilePackageAnalysisRequest.model_validate(dict(parameters))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Mobile parameters differ from the bounded static-analysis request"
            ) from exc
        return cast(Mapping[str, JsonValue], request.model_dump(mode="json", by_alias=True))


class _MobilePackageAnalysisActionCompiler(_MobilePackageAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        try:
            analysis = MobilePackageAnalysisRequest.model_validate(dict(materialized_arguments))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Mobile materialized static-analysis request is invalid"
            ) from exc
        if (
            request.tool_id != MOBILE_PACKAGE_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != analysis.target
            or request.arguments
        ):
            raise CapabilityAuthorityError(
                "Mobile compiler accepts only one exact empty GET request"
            )
        return request.model_copy(
            update={"arguments": analysis.model_dump(mode="json", by_alias=True)}
        )


class _MobilePackageAnalysisExecutorAdapter(_MobilePackageAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _MobilePackageAnalysisResultNormalizer(_MobilePackageAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _MobilePackageAnalysisSuccessOracle(_MobilePackageAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del request, result
        return CapabilityOracleDecision.INCONCLUSIVE


class _MobilePackageAnalysisReplayStrategy(_MobilePackageAnalysisAuthorityBase):
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


class _MobilePackageAnalysisCleanupHandler(_MobilePackageAnalysisAuthorityBase):
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
def registered_mobile_package_analysis_capability_definition() -> CapabilityDefinition:
    """Return exact CAP-001 metadata for bounded Mobile analysis preparation."""

    raw_schema = MobilePackageAnalysisRequest.model_json_schema(by_alias=True)
    raw_schema["required"] = sorted(raw_schema["required"])
    schema = cast(Mapping[str, JsonValue], raw_schema)
    return capability_definition_from_tool(
        MobilePackageAnalysisTool.spec,
        ToolCapabilityRegistration(
            capabilityId=MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ID,
            capabilityVersion=MOBILE_PACKAGE_ANALYSIS_CAPABILITY_VERSION,
            toolId=MOBILE_PACKAGE_ANALYSIS_TOOL_ID,
            domain="mobile",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=_supported_locator_kinds(),
            threatClasses=("mobile-declaration-metadata", "mobile-package-structure"),
            preconditions=(
                "current-campaign-scope",
                "deployment-custody-authorization-reference",
                "domain-worker-profile-binding-deferred",
                "exact-mobile-surface",
                "exact-root-package-scope",
                "exact-root-package-surface",
                "fresh-signed-authorization",
                "network-disabled-static-sandbox-configuration",
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


def mobile_package_analysis_capability_bundle(
    tools: ToolRegistry,
) -> MobilePackageAnalysisCapabilityBundle:
    """Bind the exact Mobile Tool identity to all seven CAP-002 roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("Mobile static-analysis Capability requires a ToolRegistry")
    try:
        tool = tools.tool(MOBILE_PACKAGE_ANALYSIS_TOOL_ID)
        spec = tools.spec(MOBILE_PACKAGE_ANALYSIS_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile static-analysis Tool is unavailable"
        ) from exc
    if type(tool) is not MobilePackageAnalysisTool or spec != MobilePackageAnalysisTool.spec:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile static-analysis Tool implementation drifted"
        )
    typed_tool = tool
    definition = registered_mobile_package_analysis_capability_definition()
    definitions = CapabilityDefinitionRegistry((definition,))
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _MobilePackageAnalysisActionCompiler(definition, typed_tool),
        _MobilePackageAnalysisCleanupHandler(definition, typed_tool),
        _MobilePackageAnalysisExecutorAdapter(definition, typed_tool),
        _MobilePackageAnalysisMaterializer(definition, typed_tool),
        _MobilePackageAnalysisReplayStrategy(definition, typed_tool),
        _MobilePackageAnalysisResultNormalizer(definition, typed_tool),
        _MobilePackageAnalysisSuccessOracle(definition, typed_tool),
    )
    return MobilePackageAnalysisCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_mobile_package_analysis_capability(
    *,
    bundle: MobilePackageAnalysisCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> MobilePackageAnalysisCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, MobilePackageAnalysisCapabilityBundle):
        raise TypeError("Mobile activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Mobile activation requires a verified lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability()
        definition = bundle.definitions.resolve(capability.capability)
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition != registered_mobile_package_analysis_capability_definition()
    ):
        raise MobilePackageAnalysisCapabilityError(
            "Mobile signed release differs from code authority"
        )
    binding = MobilePackageAnalysisCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return MobilePackageAnalysisCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=MobilePackageAnalysisCapabilityActivationSet(binding=binding),
    )


class MobilePackageAnalysisBindingRef(_MobilePackageAnalysisModel):
    """Exact content-addressed reference to the MOBILE-001B static binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: Literal["pajin.mobile.read-only-package-analysis.binding"] = Field(
        alias="bindingId"
    )
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class MobilePackageAnalysisBinding(_MobilePackageAnalysisModel):
    """Exact MOBILE-001A/CAP-002 static preparation contract without runtime authority."""

    api_version: Literal["pajin.dev/mobile-package-analysis-binding/v1alpha1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisBinding"] = "MobilePackageAnalysisBinding"
    binding_id: Literal["pajin.mobile.read-only-package-analysis.binding"] = Field(
        default="pajin.mobile.read-only-package-analysis.binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["mobile.application-runtime"] = Field(
        default="mobile.application-runtime",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.mobile.application-runtime.v1"] = Field(
        default="pajin.locator.mobile.application-runtime.v1",
        alias="locatorSchema",
    )
    locator_registry: MobileApplicationRuntimeLocatorRegistryRef = Field(alias="locatorRegistry")
    supported_locators: tuple[MobileApplicationRuntimeLocatorRef, ...] = Field(
        alias="supportedLocators",
        min_length=8,
        max_length=8,
    )
    capability: CodeBackedCapabilityRef
    capability_domain_classification: MobilePackageAnalysisCapabilityDomainClassification = Field(
        alias="capabilityDomainClassification"
    )
    supported_operations: tuple[MobilePackageAnalysisOperation, ...] = Field(
        default=_SUPPORTED_OPERATIONS,
        alias="supportedOperations",
    )
    supported_parsers: tuple[MobilePackageParser, ...] = Field(
        default=_SUPPORTED_PARSERS,
        alias="supportedParsers",
    )
    output_schema: Literal["pajin.mobile.package-analysis-result.v1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    complete_cap_002_verified: Literal[True] = Field(
        default=True,
        alias="completeCAP002Verified",
    )
    preparation_available: Literal[True] = Field(default=True, alias="preparationAvailable")
    exact_surface_package_custody_sandbox_binding_required: Literal[True] = Field(
        default=True,
        alias="exactSurfacePackageCustodySandboxBindingRequired",
    )
    complete_surface_operation_map_required: Literal[True] = Field(
        default=True,
        alias="completeSurfaceOperationMapRequired",
    )
    package_lineage_parser_binding_required: Literal[True] = Field(
        default=True,
        alias="packageLineageParserBindingRequired",
    )
    bounded_budget_required: Literal[True] = Field(
        default=True,
        alias="boundedBudgetRequired",
    )
    network_and_dns_disabled_sandbox_required: Literal[True] = Field(
        default=True,
        alias="networkAndDNSDisabledSandboxRequired",
    )
    read_only_noexec_package_mount_required: Literal[True] = Field(
        default=True,
        alias="readOnlyNoexecPackageMountRequired",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    exact_surface_and_package_scope_required: Literal[True] = Field(
        default=True,
        alias="exactSurfaceAndPackageScopeRequired",
    )
    action_permit_required: Literal[True] = Field(default=True, alias="actionPermitRequired")
    gateway_policy_reentry_required: Literal[True] = Field(
        default=True,
        alias="gatewayPolicyReentryRequired",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    configuration_requirements_only: Literal[True] = Field(
        default=True,
        alias="configurationRequirementsOnly",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    custody_runtime_verified: Literal[False] = Field(
        default=False,
        alias="custodyRuntimeVerified",
    )
    package_resolved: Literal[False] = Field(default=False, alias="packageResolved")
    package_read_authorized: Literal[False] = Field(
        default=False,
        alias="packageReadAuthorized",
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
    worker_job_materialization_available: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAvailable",
    )
    package_mount_materialized: Literal[False] = Field(
        default=False,
        alias="packageMountMaterialized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    emulator_selection_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorSelectionAuthorized",
    )
    device_selection_authorized: Literal[False] = Field(
        default=False,
        alias="deviceSelectionAuthorized",
    )
    device_access_authorized: Literal[False] = Field(
        default=False,
        alias="deviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
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
    hypothesis_authority: Literal[False] = Field(default=False, alias="hypothesisAuthority")
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
        "exact_surface_package_custody_sandbox_binding_required",
        "complete_surface_operation_map_required",
        "package_lineage_parser_binding_required",
        "bounded_budget_required",
        "network_and_dns_disabled_sandbox_required",
        "read_only_noexec_package_mount_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "exact_surface_and_package_scope_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "domain_worker_profile_binding_deferred",
        "configuration_requirements_only",
        "domain_worker_profile_bound",
        "device_bound_runtime_profile_applied",
        "custody_runtime_verified",
        "package_resolved",
        "package_read_authorized",
        "static_analysis_authorized",
        "sandbox_selected",
        "worker_selection_authorized",
        "worker_job_materialization_available",
        "package_mount_materialized",
        "network_access_authorized",
        "dns_access_authorized",
        "emulator_selection_authorized",
        "device_selection_authorized",
        "device_access_authorized",
        "package_installation_authorized",
        "application_launch_authorized",
        "instrumentation_authorized",
        "dynamic_target_execution_authorized",
        "storage_read_authorized",
        "tls_invocation_authorized",
        "authentication_invocation_authorized",
        "credential_access_authorized",
        "package_mutation_authorized",
        "observation_production_authorized",
        "evidence_sealing_authorized",
        "graph_admission_authorized",
        "hypothesis_authority",
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
            raise ValueError("Mobile package-analysis binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_mobile_package_analysis_capability_definition()
        registry = registered_mobile_application_runtime_locator_registry()
        expected_locators = tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        )
        if (
            self.locator_registry != registry.reference()
            or self.supported_locators != expected_locators
            or self.capability != _mobile_code_backed_capability()
            or self.capability_domain_classification
            != registered_mobile_package_analysis_capability_domain_classification()
            or self.supported_operations != _SUPPORTED_OPERATIONS
            or self.supported_parsers != _SUPPORTED_PARSERS
            or set(_OPERATION_BY_SURFACE_CLASS) != set(MobileSurfaceClass)
            or set(_PARSER_BY_PACKAGE_CLASS) != {MobileSurfaceClass.APK, MobileSurfaceClass.IPA}
            or definition.supported_surface_types != _supported_locator_kinds()
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != MOBILE_PACKAGE_ANALYSIS_TOOL_ID
            or definition.network_access is not False
            or definition.approval_required is not True
        ):
            raise ValueError("Mobile package-analysis binding differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.mobile-package-analysis-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Mobile package-analysis binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> MobilePackageAnalysisBindingRef:
        canonical = _canonical_model(
            MobilePackageAnalysisBinding,
            self,
            label="Mobile package-analysis binding",
        )
        return MobilePackageAnalysisBindingRef(
            bindingId=canonical.binding_id,
            bindingVersion=canonical.binding_version,
            bindingDigest=canonical.binding_digest,
        )


class MobilePackageAnalysisPreparation(_MobilePackageAnalysisModel):
    """Exact signed preparation with no package read, Worker dispatch, or finding."""

    api_version: Literal["pajin.dev/mobile-package-analysis-preparation/v1alpha1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisPreparation"] = "MobilePackageAnalysisPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=105)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: MobilePackageAnalysisBinding
    surface: MobileApplicationRuntimeSurface
    package_surface: MobileApplicationRuntimeSurface = Field(alias="packageSurface")
    operation: MobilePackageAnalysisOperation
    package_custody: MobilePackageCustodyBinding = Field(alias="packageCustody")
    sandbox: MobilePackageAnalysisSandboxBinding
    analysis_request: MobilePackageAnalysisRequest = Field(alias="analysisRequest")
    campaign_scope: MobileCampaignScopeBinding = Field(alias="campaignScope")
    matched_surface_allow_rule: str = Field(
        alias="matchedSurfaceAllowRule",
        min_length=1,
        max_length=2_000,
    )
    matched_package_allow_rule: str = Field(
        alias="matchedPackageAllowRule",
        min_length=1,
        max_length=2_000,
    )
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    current_campaign_bound: Literal[True] = Field(default=True, alias="currentCampaignBound")
    exact_surface_and_package_scope_bound: Literal[True] = Field(
        default=True,
        alias="exactSurfaceAndPackageScopeBound",
    )
    custody_authorization_reference_bound: Literal[True] = Field(
        default=True,
        alias="custodyAuthorizationReferenceBound",
    )
    network_and_dns_disabled_sandbox_bound: Literal[True] = Field(
        default=True,
        alias="networkAndDNSDisabledSandboxBound",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
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
    package_resolved: Literal[False] = Field(default=False, alias="packageResolved")
    package_bytes_verified: Literal[False] = Field(
        default=False,
        alias="packageBytesVerified",
    )
    package_format_verified: Literal[False] = Field(
        default=False,
        alias="packageFormatVerified",
    )
    manifest_verified: Literal[False] = Field(default=False, alias="manifestVerified")
    signing_identity_verified: Literal[False] = Field(
        default=False,
        alias="signingIdentityVerified",
    )
    package_read_performed: Literal[False] = Field(
        default=False,
        alias="packageReadPerformed",
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
    package_mount_materialized: Literal[False] = Field(
        default=False,
        alias="packageMountMaterialized",
    )
    budget_reserved: Literal[False] = Field(default=False, alias="budgetReserved")
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    network_request_performed: Literal[False] = Field(
        default=False,
        alias="networkRequestPerformed",
    )
    dns_request_performed: Literal[False] = Field(
        default=False,
        alias="dnsRequestPerformed",
    )
    emulator_or_device_selected: Literal[False] = Field(
        default=False,
        alias="emulatorOrDeviceSelected",
    )
    package_installed: Literal[False] = Field(default=False, alias="packageInstalled")
    application_launched: Literal[False] = Field(default=False, alias="applicationLaunched")
    instrumentation_performed: Literal[False] = Field(
        default=False,
        alias="instrumentationPerformed",
    )
    dynamic_target_execution_performed: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionPerformed",
    )
    storage_read_performed: Literal[False] = Field(
        default=False,
        alias="storageReadPerformed",
    )
    tls_invocation_performed: Literal[False] = Field(
        default=False,
        alias="tlsInvocationPerformed",
    )
    authentication_invocation_performed: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationPerformed",
    )
    credential_read_performed: Literal[False] = Field(
        default=False,
        alias="credentialReadPerformed",
    )
    package_mutated: Literal[False] = Field(default=False, alias="packageMutated")
    observation_produced: Literal[False] = Field(default=False, alias="observationProduced")
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    hypothesis_produced: Literal[False] = Field(default=False, alias="hypothesisProduced")
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
        "exact_surface_and_package_scope_bound",
        "custody_authorization_reference_bound",
        "network_and_dns_disabled_sandbox_bound",
        "domain_worker_profile_binding_deferred",
        "analysis_request_adapted",
        "capability_prepared",
        "custody_runtime_verified",
        "authorization_verified_by_preparation",
        "package_resolved",
        "package_bytes_verified",
        "package_format_verified",
        "manifest_verified",
        "signing_identity_verified",
        "package_read_performed",
        "sandbox_runtime_available",
        "sandbox_runtime_attested",
        "sandbox_selected",
        "package_mount_materialized",
        "budget_reserved",
        "domain_worker_profile_bound",
        "worker_job_materialized",
        "network_request_performed",
        "dns_request_performed",
        "emulator_or_device_selected",
        "package_installed",
        "application_launched",
        "instrumentation_performed",
        "dynamic_target_execution_performed",
        "storage_read_performed",
        "tls_invocation_performed",
        "authentication_invocation_performed",
        "credential_read_performed",
        "package_mutated",
        "observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "hypothesis_produced",
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
            raise ValueError("Mobile package-analysis preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        canonical_surface = _canonical_surface(self.surface)
        canonical_package = _package_surface(canonical_surface)
        expected_action = registered_action_capability(
            registered_mobile_package_analysis_capability_definition()
        ).reference()
        expected_surface_rule = _require_exact_scope_allow(
            self.campaign_scope,
            mobile_surface_scope_target(canonical_surface),
            label="Mobile Surface",
        )
        expected_package_rule = _require_exact_scope_allow(
            self.campaign_scope,
            mobile_surface_scope_target(canonical_package),
            label="Mobile root package Surface",
        )
        expected_request = BoundedMobilePackageAnalyzerAdapter(
            self.package_custody,
            self.sandbox,
        ).prepare_request(surface=canonical_surface, operation=self.operation)
        request = self.prepared_action.request
        if (
            canonical_surface != self.surface
            or canonical_package != self.package_surface
            or self.binding != registered_mobile_package_analysis_binding()
            or self.surface.initial_state != "registered-not-authorized"
            or self.package_surface.initial_state != "registered-not-authorized"
            or self.package_custody.surface != self.surface
            or self.package_custody.package_surface != self.package_surface
            or self.sandbox.surface != self.surface
            or self.sandbox.package_surface != self.package_surface
            or self.analysis_request != expected_request
            or self.matched_surface_allow_rule != expected_surface_rule
            or self.matched_package_allow_rule != expected_package_rule
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != MOBILE_PACKAGE_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != self.analysis_request.target
            or request.arguments != self.analysis_request.model_dump(mode="json", by_alias=True)
            or self.prepared_action.request_digest != capability_tool_request_digest(request)
            or self.prepared_action.normalized_parameters_digest
            != capability_normalized_parameters_digest(request.arguments)
        ):
            raise ValueError("Mobile package-analysis preparation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.mobile-package-analysis-preparation/v1",
            material,
        )
        preparation_id = f"mobile-package-analysis-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Mobile package-analysis preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("Mobile package-analysis preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def bind_mobile_package_custody(
    *,
    surface: MobileApplicationRuntimeSurface,
    custody_authority_id: str,
    custody_object_id: str,
    authorization_id: str,
    authorization_digest: str,
    artifact_bytes: int,
) -> MobilePackageCustodyBinding:
    """Pin an externally reviewed custody reference without resolving artifact bytes."""

    canonical_surface = _canonical_surface(surface)
    package_surface = _package_surface(canonical_surface)
    try:
        return MobilePackageCustodyBinding(
            surface=canonical_surface,
            packageSurface=package_surface,
            custodyAuthorityId=custody_authority_id,
            custodyObjectId=custody_object_id,
            authorizationId=authorization_id,
            authorizationDigest=authorization_digest,
            artifactSHA256=_artifact_sha256(canonical_surface),
            artifactBytes=artifact_bytes,
        )
    except (ValidationError, ValueError) as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile artifact custody binding failed closed"
        ) from exc


def bind_mobile_package_analysis_sandbox(
    *,
    deployment_id: str,
    surface: MobileApplicationRuntimeSurface,
    operation: MobilePackageAnalysisOperation,
    parser_executable_sha256: str,
    sandbox_image_sha256: str,
    run_as_identity: str,
    max_artifact_bytes: int = 67_108_864,
    max_output_bytes: int = 1_048_576,
    max_runtime_seconds: int = 60,
    max_memory_mib: int = 512,
    max_process_count: int = 8,
    max_archive_entries: int = 10_000,
    max_total_uncompressed_bytes: int = 536_870_912,
    max_single_uncompressed_bytes: int = 67_108_864,
    max_archive_path_bytes: int = 1_024,
    max_archive_nesting_depth: int = 8,
    max_compression_ratio: int = 100,
) -> MobilePackageAnalysisSandboxBinding:
    """Pin an offline sandbox configuration without selecting or invoking a Worker."""

    canonical_surface = _canonical_surface(surface)
    package_surface = _package_surface(canonical_surface)
    try:
        canonical_operation = MobilePackageAnalysisOperation(operation)
    except ValueError as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile package-analysis sandbox operation is unsupported"
        ) from exc
    if canonical_operation is not _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile package-analysis operation differs from the exact Surface class"
        )
    if (
        not isinstance(run_as_identity, str)
        or run_as_identity != run_as_identity.strip()
        or _is_forbidden_root_identity(run_as_identity)
    ):
        raise MobilePackageAnalysisCapabilityError(
            "Mobile sandbox run-as identity must be explicit and non-root"
        )
    try:
        return MobilePackageAnalysisSandboxBinding(
            deploymentId=deployment_id,
            surface=canonical_surface,
            packageSurface=package_surface,
            operation=canonical_operation,
            parser=_package_parser(canonical_surface),
            parserExecutableSHA256=parser_executable_sha256,
            sandboxImageSHA256=sandbox_image_sha256,
            runAsIdentity=run_as_identity,
            maxArtifactBytes=max_artifact_bytes,
            maxOutputBytes=max_output_bytes,
            maxRuntimeSeconds=max_runtime_seconds,
            maxMemoryMiB=max_memory_mib,
            maxProcessCount=max_process_count,
            maxArchiveEntries=max_archive_entries,
            maxTotalUncompressedBytes=max_total_uncompressed_bytes,
            maxSingleUncompressedBytes=max_single_uncompressed_bytes,
            maxArchivePathBytes=max_archive_path_bytes,
            maxArchiveNestingDepth=max_archive_nesting_depth,
            maxCompressionRatio=max_compression_ratio,
        )
    except (ValidationError, ValueError) as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile package-analysis sandbox binding failed closed"
        ) from exc


@cache
def registered_mobile_package_analysis_binding() -> MobilePackageAnalysisBinding:
    """Return the exact MOBILE-001B binding without custody resolution or sandbox selection."""

    registry = registered_mobile_application_runtime_locator_registry()
    return MobilePackageAnalysisBinding(
        locatorRegistry=registry.reference(),
        supportedLocators=tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        ),
        capability=_mobile_code_backed_capability(),
        capabilityDomainClassification=(
            registered_mobile_package_analysis_capability_domain_classification()
        ),
    )


def resolve_mobile_package_analysis_binding(
    reference: MobilePackageAnalysisBindingRef,
) -> MobilePackageAnalysisBinding:
    canonical_reference = _canonical_model(
        MobilePackageAnalysisBindingRef,
        reference,
        label="Mobile package-analysis binding reference",
    )
    binding = registered_mobile_package_analysis_binding()
    if binding.reference() == canonical_reference:
        return binding.model_copy(deep=True)
    raise MobilePackageAnalysisCapabilityError(
        "Mobile package-analysis binding is not registered exactly"
    )


@cache
def registered_mobile_package_analysis_capability_domain_classification() -> (
    MobilePackageAnalysisCapabilityDomainClassification
):
    capability = _mobile_code_backed_capability()
    return MobilePackageAnalysisCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=(
            registered_mobile_application_runtime_locator_registry().domain_classification
        ),
    )


def resolve_mobile_package_analysis_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
) -> MobilePackageAnalysisCapabilityDomainClassification:
    canonical_reference = _canonical_model(
        CapabilityDomainClassificationRef,
        reference,
        label="Mobile Capability Domain classification reference",
    )
    classification = registered_mobile_package_analysis_capability_domain_classification()
    if classification.reference() == canonical_reference:
        return classification.model_copy(deep=True)
    raise MobilePackageAnalysisCapabilityError(
        "Mobile Capability Domain classification is not registered exactly"
    )


def mobile_surface_scope_target(surface: MobileApplicationRuntimeSurface) -> str:
    """Return a non-routable exact Campaign Scope token for one Mobile Surface."""

    canonical = _canonical_surface(surface)
    return f"{MOBILE_SURFACE_SCOPE_ORIGIN}/surfaces/{canonical.surface_id}"


def prepare_mobile_package_analysis(
    *,
    activation: MobilePackageAnalysisCapabilityActivation,
    release: CapabilityReleaseRef,
    campaign: CampaignManifest,
    surface: MobileApplicationRuntimeSurface,
    operation: MobilePackageAnalysisOperation,
    analyzer: BoundedMobilePackageAnalyzerAdapter,
    request_id: str,
    agent_id: str,
) -> MobilePackageAnalysisPreparation:
    """Compile exact signed static-analysis metadata and stop before artifact access."""

    if not isinstance(activation, MobilePackageAnalysisCapabilityActivation):
        raise TypeError("Mobile preparation requires Mobile activation")
    if not isinstance(analyzer, BoundedMobilePackageAnalyzerAdapter):
        raise TypeError("Mobile preparation requires a bounded analyzer adapter")
    try:
        canonical_operation = MobilePackageAnalysisOperation(operation)
    except ValueError as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile package-analysis operation is unsupported"
        ) from exc
    canonical_campaign = _canonical_campaign(campaign)
    canonical_surface = _canonical_surface(surface)
    package_surface = _package_surface(canonical_surface)
    custody = analyzer.custody
    sandbox = analyzer.sandbox
    scope_binding = _campaign_scope_binding(canonical_campaign)
    surface_allow = _require_exact_scope_allow(
        scope_binding,
        mobile_surface_scope_target(canonical_surface),
        label="Mobile Surface",
    )
    package_allow = _require_exact_scope_allow(
        scope_binding,
        mobile_surface_scope_target(package_surface),
        label="Mobile root package Surface",
    )
    analysis_request = analyzer.prepare_request(
        surface=canonical_surface,
        operation=canonical_operation,
    )
    binding = registered_mobile_package_analysis_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition() != registered_mobile_package_analysis_capability_definition()
        ):
            raise MobilePackageAnalysisCapabilityError(
                "Mobile activation differs from the registered Capability"
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=MOBILE_PACKAGE_ANALYSIS_TOOL_ID,
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
        return MobilePackageAnalysisPreparation(
            binding=binding,
            surface=canonical_surface,
            packageSurface=package_surface,
            operation=canonical_operation,
            packageCustody=custody,
            sandbox=sandbox,
            analysisRequest=analysis_request,
            campaignScope=scope_binding,
            matchedSurfaceAllowRule=surface_allow,
            matchedPackageAllowRule=package_allow,
            release=_canonical_release_ref(release),
            preparedAction=prepared,
        )
    except (CapabilityAuthorityError, ValidationError, ValueError) as exc:
        if isinstance(exc, MobilePackageAnalysisCapabilityError):
            raise
        raise MobilePackageAnalysisCapabilityError(
            "Mobile CAP-002 preparation failed closed"
        ) from exc


def _verify_activation(activation: MobilePackageAnalysisCapabilityActivation) -> None:
    canonical_set = _canonical_model(
        MobilePackageAnalysisCapabilityActivationSet,
        activation.activation_set,
        label="Mobile activation set",
    )
    _resolve_activation_binding(activation, canonical_set.binding)


def _resolve_activation_binding(
    activation: MobilePackageAnalysisCapabilityActivation,
    binding: MobilePackageAnalysisCapabilityActivationBinding,
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
        raise MobilePackageAnalysisCapabilityError(
            "Mobile current signed release could not be resolved"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
        or expected_action != binding.action_capability
    ):
        raise MobilePackageAnalysisCapabilityError("Mobile signed release binding drifted")
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.mobile-package-analysis-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    return _canonical_model(
        CapabilityReleaseRef,
        reference,
        label="Mobile release reference",
    )


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    return _canonical_model(
        ToolRequest,
        request,
        label="Mobile Tool request",
    )


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    return _canonical_model(
        CampaignManifest,
        campaign,
        label="Mobile Campaign",
    )


def _canonical_surface(
    surface: MobileApplicationRuntimeSurface,
) -> MobileApplicationRuntimeSurface:
    _require_known_instance_fields(surface, label="Mobile Surface")
    try:
        surface.reference()
    except (AttributeError, ValidationError, ValueError) as exc:
        if isinstance(exc, MobilePackageAnalysisCapabilityError):
            raise
        raise MobilePackageAnalysisCapabilityError(
            "Mobile Surface reference is not canonical"
        ) from exc
    return _canonical_model(
        MobileApplicationRuntimeSurface,
        surface,
        label="Mobile Surface",
    )


def _campaign_scope_binding(campaign: CampaignManifest) -> MobileCampaignScopeBinding:
    try:
        return MobileCampaignScopeBinding(
            campaignName=campaign.metadata.name,
            campaignDigest=campaign_manifest_digest(campaign),
            scope=campaign.spec.scope.model_copy(deep=True),
            allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
            allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
        )
    except (ValidationError, ValueError) as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile Campaign Scope binding failed closed"
        ) from exc


def _require_exact_scope_allow(
    scope_binding: MobileCampaignScopeBinding,
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
        raise MobilePackageAnalysisCapabilityError(
            f"{label} Campaign Scope cannot be evaluated safely"
        ) from exc
    if canonical_target not in normalized_allow:
        raise MobilePackageAnalysisCapabilityError(
            f"{label} lacks an exact current Campaign allow rule"
        )
    if any(scope_matches(rule, canonical_target) for rule in normalized_deny):
        raise MobilePackageAnalysisCapabilityError(f"{label} overlaps a current Campaign deny rule")
    return canonical_target


def _canonical_mobile_surface_target(value: str) -> str:
    try:
        canonical = normalize_target_url(value)
    except InvalidScopeURL as exc:
        raise ValueError("Mobile Surface target is invalid") from exc
    if canonical != value or not value.startswith(f"{MOBILE_SURFACE_SCOPE_ORIGIN}/surfaces/"):
        raise ValueError("Mobile Surface target must be one canonical non-routable token")
    return value


def _validate_mobile_tool_request(
    request: ToolRequest,
) -> MobilePackageAnalysisRequest:
    canonical_request = _canonical_tool_request(request)
    try:
        analysis = MobilePackageAnalysisRequest.model_validate(canonical_request.arguments)
    except (ValidationError, ValueError) as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile Tool request arguments are invalid"
        ) from exc
    if (
        canonical_request.tool_id != MOBILE_PACKAGE_ANALYSIS_TOOL_ID
        or canonical_request.method != "GET"
        or canonical_request.target != analysis.target
    ):
        raise MobilePackageAnalysisCapabilityError(
            "Mobile Tool request differs from bounded GET authority"
        )
    return analysis


def _artifact_sha256(surface: MobileApplicationRuntimeSurface) -> str:
    package = _package_locator(surface)
    return package.application_artifact.artifact_sha256


def _package_locator(
    surface: MobileApplicationRuntimeSurface,
) -> MobileAPKSurfaceLocator | MobileIPASurfaceLocator:
    locator = surface.locator
    if isinstance(locator, (MobileAPKSurfaceLocator, MobileIPASurfaceLocator)):
        return locator
    if isinstance(locator, MobileApplicationSurfaceLocator):
        return locator.parent
    if isinstance(
        locator,
        (
            MobileRuntimeSurfaceLocator,
            MobileStorageSurfaceLocator,
            MobileDeepLinkSurfaceLocator,
            MobileTLSPolicySurfaceLocator,
            MobileAuthenticationSurfaceLocator,
        ),
    ):
        return locator.parent.parent
    raise MobilePackageAnalysisCapabilityError(
        "Mobile Surface has no exact APK or IPA package lineage"
    )


def _package_surface(
    surface: MobileApplicationRuntimeSurface,
) -> MobileApplicationRuntimeSurface:
    canonical = _canonical_surface(surface)
    try:
        return typed_mobile_application_runtime_surface(locator=_package_locator(canonical))
    except (ValidationError, ValueError) as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile root package Surface could not be reconstructed exactly"
        ) from exc


def _package_parser(surface: MobileApplicationRuntimeSurface) -> MobilePackageParser:
    package_class = _package_surface(surface).surface_class
    try:
        return _PARSER_BY_PACKAGE_CLASS[package_class]
    except KeyError as exc:
        raise MobilePackageAnalysisCapabilityError(
            "Mobile root package class has no registered static parser"
        ) from exc


def _supported_locator_kinds() -> tuple[MobileSurfaceLocatorKind, ...]:
    return (
        "mobile-apk-package",
        "mobile-application",
        "mobile-authentication",
        "mobile-deeplink",
        "mobile-ipa-package",
        "mobile-runtime",
        "mobile-storage",
        "mobile-tls-policy",
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
def _mobile_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(MobilePackageAnalysisTool())
    return mobile_package_analysis_capability_bundle(tools).capability()


__all__ = [
    "MOBILE_CAMPAIGN_SCOPE_BINDING_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_BINDING_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ADAPTER_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ID",
    "MOBILE_PACKAGE_ANALYSIS_CAPABILITY_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA",
    "MOBILE_PACKAGE_ANALYSIS_PREPARATION_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_REQUEST_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_SANDBOX_BINDING_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_TOOL_ID",
    "MOBILE_PACKAGE_CUSTODY_BINDING_API_VERSION",
    "MOBILE_PACKAGE_MOUNT_TARGET",
    "MOBILE_SURFACE_SCOPE_ORIGIN",
    "BoundedMobilePackageAnalyzerAdapter",
    "MobileCampaignScopeBinding",
    "MobilePackageAnalysisBinding",
    "MobilePackageAnalysisBindingRef",
    "MobilePackageAnalysisBudget",
    "MobilePackageAnalysisCapabilityActivation",
    "MobilePackageAnalysisCapabilityActivationBinding",
    "MobilePackageAnalysisCapabilityActivationSet",
    "MobilePackageAnalysisCapabilityBundle",
    "MobilePackageAnalysisCapabilityDomainClassification",
    "MobilePackageAnalysisCapabilityError",
    "MobilePackageAnalysisOperation",
    "MobilePackageAnalysisPreparation",
    "MobilePackageAnalysisRequest",
    "MobilePackageAnalysisSandboxBinding",
    "MobilePackageAnalysisSandboxRef",
    "MobilePackageAnalysisTool",
    "MobilePackageCustodyBinding",
    "MobilePackageCustodyRef",
    "MobilePackageParser",
    "activate_mobile_package_analysis_capability",
    "bind_mobile_package_analysis_sandbox",
    "bind_mobile_package_custody",
    "mobile_package_analysis_capability_bundle",
    "mobile_surface_scope_target",
    "prepare_mobile_package_analysis",
    "registered_mobile_package_analysis_binding",
    "registered_mobile_package_analysis_capability_definition",
    "registered_mobile_package_analysis_capability_domain_classification",
    "resolve_mobile_package_analysis_binding",
    "resolve_mobile_package_analysis_capability_domain_classification",
]
