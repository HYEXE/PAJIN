"""CRYPTO-001B offline Cryptographic misuse-analysis preparation boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from types import MappingProxyType
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
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    RegisteredDomainWorkerBoundaryProfile,
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    registered_domain_worker_boundary_profiles,
)
from pajin.discovery.cryptography_surfaces import (
    CryptographicCiphertextSurfaceLocator,
    CryptographicConfigurationSurfaceLocator,
    CryptographicKeyUsageSurfaceLocator,
    CryptographicProtocolSurfaceLocator,
    CryptographyProtocolKeyArtifactLocatorRef,
    CryptographyProtocolKeyArtifactLocatorRegistryRef,
    CryptographyProtocolKeyArtifactSurface,
    CryptographyProtocolKeyArtifactSurfaceRef,
    CryptographySurfaceClass,
    CryptographySurfaceLocatorKind,
    registered_cryptography_protocol_key_artifact_locator_registry,
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

CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ADAPTER_VERSION = (
    "pajin.cryptographic-misuse-analysis-capability-adapter/v1"
)
CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-capability-activation-set/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-capability-activation-set/v1alpha1"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_BINDING_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-binding/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-binding/v1alpha1"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_PREPARATION_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-preparation/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-preparation/v1alpha1"
CRYPTOGRAPHIC_CAMPAIGN_SCOPE_BINDING_API_VERSION: Literal[
    "pajin.dev/cryptographic-campaign-scope-binding/v1alpha1"
] = "pajin.dev/cryptographic-campaign-scope-binding/v1alpha1"
CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_BINDING_API_VERSION: Literal[
    "pajin.dev/cryptographic-analysis-artifact-custody-binding/v1alpha1"
] = "pajin.dev/cryptographic-analysis-artifact-custody-binding/v1alpha1"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_SANDBOX_BINDING_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-sandbox-binding/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-sandbox-binding/v1alpha1"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_REQUEST_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-request/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-request/v1alpha1"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-capability-domain-classification/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-capability-domain-classification/v1alpha1"
CRYPTOGRAPHIC_MISUSE_RULE_SET_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-rule-set/v1alpha1"
] = "pajin.dev/cryptographic-misuse-rule-set/v1alpha1"

CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ID = "pajin.cryptography.offline-misuse-analysis"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_VERSION = "1.0.0"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID = "cryptography.offline-misuse-analysis"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA: Literal[
    "pajin.cryptography.offline-misuse-analysis-result.v1"
] = "pajin.cryptography.offline-misuse-analysis-result.v1"
CRYPTOGRAPHIC_SURFACE_SCOPE_ORIGIN = "https://cryptography-scope.pajin.invalid"
CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_MOUNT_TARGET: Literal["/pajin/input/artifact"] = (
    "/pajin/input/artifact"
)
CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_AUTHORITY_ID: Literal[
    "pajin.cryptography.immutable-analysis-artifact-custody"
] = "pajin.cryptography.immutable-analysis-artifact-custody"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_DEPLOYMENT_ID: Literal["deployment:cryptographic-misuse-analysis"] = (
    "deployment:cryptographic-misuse-analysis"
)
CRYPTOGRAPHIC_MISUSE_ANALYSIS_RUN_AS_IDENTITY: Literal["svc:pajin-crypto-analyzer"] = (
    "svc:pajin-crypto-analyzer"
)

_AUTHORITY_VERSION = "1.0.0"
_MAX_ARTIFACT_BYTES = 536_870_912
_MAX_OUTPUT_BYTES = 16_777_216
_MAX_RUNTIME_SECONDS = 300
_MAX_MEMORY_MIB = 4_096
_MAX_PROCESS_COUNT = 64
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class CryptographicMisuseAnalysisCapabilityError(ValueError):
    """Raised when CRYPTO-001B Scope, custody, sandbox, or preparation drifts."""


class _CryptographicMisuseAnalysisModel(StrictModel):
    """Strict immutable model that revalidates nested Pydantic instances."""

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
    """Reject state inserted by unchecked model_copy(update=...)."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        unknown = set(value.__dict__) - set(type(value).model_fields)
        if unknown:
            raise CryptographicMisuseAnalysisCapabilityError(
                f"{label} contains unmodeled instance state"
            )
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
        if type(value) is not model_type:
            raise TypeError
        canonical = model_type.model_validate(value.model_dump(mode="json", by_alias=by_alias))
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        if isinstance(exc, CryptographicMisuseAnalysisCapabilityError):
            raise
        raise CryptographicMisuseAnalysisCapabilityError(f"{label} is not canonical") from exc
    _require_known_instance_fields(canonical, label=label)
    if canonical != value:
        raise CryptographicMisuseAnalysisCapabilityError(f"{label} drifted")
    return canonical


class CryptographicMisuseAnalysisOperation(StrEnum):
    """One read-only logical operation for each CRYPTO-001A Surface class."""

    PROTOCOL_DECLARATION = "protocol-declaration-read"
    KEY_USAGE_DECLARATION = "key-usage-declaration-read"
    CIPHERTEXT_STRUCTURE = "ciphertext-structure-read"
    CONFIGURATION_DECLARATION = "configuration-declaration-read"


class CryptographicMisuseAnalyzer(StrEnum):
    """Logical analyzer contract selected without runtime support claims."""

    PROTOCOL_DECLARATION = "protocol-declaration-analyzer"
    KEY_USAGE_DECLARATION = "key-usage-declaration-analyzer"
    CIPHERTEXT_STRUCTURE = "ciphertext-structure-analyzer"
    CONFIGURATION_DECLARATION = "configuration-declaration-analyzer"


class CryptographicAnalysisInputKind(StrEnum):
    """Class-owned meaning of one externally retained immutable input."""

    SANITIZED_PROTOCOL_DECLARATION = "sanitized-protocol-declaration"
    SANITIZED_KEY_USAGE_DECLARATION = "sanitized-key-usage-declaration"
    CIPHERTEXT_ARTIFACT = "ciphertext-artifact"
    SANITIZED_CONFIGURATION_DECLARATION = "sanitized-configuration-declaration"


class CryptographicAnalysisDigestSource(StrEnum):
    """Exact CRYPTO-001A locator field that identifies retained analysis input."""

    DECLARATION_SHA256 = "declaration-sha256"
    ARTIFACT_SHA256 = "artifact-sha256"


class CryptographicMisuseSignalKind(StrEnum):
    """Bounded future result vocabulary; no member is a Finding."""

    PROTOCOL_POLICY = "cryptography.protocol-policy"
    KEY_USAGE_POLICY = "cryptography.key-usage-policy"
    CIPHERTEXT_STRUCTURE = "cryptography.ciphertext-structure"
    CONFIGURATION_POLICY = "cryptography.configuration-policy"


_OPERATION_BY_SURFACE_CLASS: Mapping[
    CryptographySurfaceClass,
    CryptographicMisuseAnalysisOperation,
] = MappingProxyType(
    {
        CryptographySurfaceClass.PROTOCOL: (
            CryptographicMisuseAnalysisOperation.PROTOCOL_DECLARATION
        ),
        CryptographySurfaceClass.KEY_USAGE: (
            CryptographicMisuseAnalysisOperation.KEY_USAGE_DECLARATION
        ),
        CryptographySurfaceClass.CIPHERTEXT: (
            CryptographicMisuseAnalysisOperation.CIPHERTEXT_STRUCTURE
        ),
        CryptographySurfaceClass.CONFIGURATION: (
            CryptographicMisuseAnalysisOperation.CONFIGURATION_DECLARATION
        ),
    }
)
_ANALYZER_BY_OPERATION: Mapping[
    CryptographicMisuseAnalysisOperation,
    CryptographicMisuseAnalyzer,
] = MappingProxyType(
    {
        CryptographicMisuseAnalysisOperation.PROTOCOL_DECLARATION: (
            CryptographicMisuseAnalyzer.PROTOCOL_DECLARATION
        ),
        CryptographicMisuseAnalysisOperation.KEY_USAGE_DECLARATION: (
            CryptographicMisuseAnalyzer.KEY_USAGE_DECLARATION
        ),
        CryptographicMisuseAnalysisOperation.CIPHERTEXT_STRUCTURE: (
            CryptographicMisuseAnalyzer.CIPHERTEXT_STRUCTURE
        ),
        CryptographicMisuseAnalysisOperation.CONFIGURATION_DECLARATION: (
            CryptographicMisuseAnalyzer.CONFIGURATION_DECLARATION
        ),
    }
)
_INPUT_KIND_BY_SURFACE_CLASS: Mapping[
    CryptographySurfaceClass,
    CryptographicAnalysisInputKind,
] = MappingProxyType(
    {
        CryptographySurfaceClass.PROTOCOL: (
            CryptographicAnalysisInputKind.SANITIZED_PROTOCOL_DECLARATION
        ),
        CryptographySurfaceClass.KEY_USAGE: (
            CryptographicAnalysisInputKind.SANITIZED_KEY_USAGE_DECLARATION
        ),
        CryptographySurfaceClass.CIPHERTEXT: CryptographicAnalysisInputKind.CIPHERTEXT_ARTIFACT,
        CryptographySurfaceClass.CONFIGURATION: (
            CryptographicAnalysisInputKind.SANITIZED_CONFIGURATION_DECLARATION
        ),
    }
)
_LOCATOR_KIND_BY_SURFACE_CLASS: Mapping[
    CryptographySurfaceClass,
    CryptographySurfaceLocatorKind,
] = MappingProxyType(
    {
        CryptographySurfaceClass.PROTOCOL: "cryptography-protocol",
        CryptographySurfaceClass.KEY_USAGE: "cryptography-key-usage",
        CryptographySurfaceClass.CIPHERTEXT: "cryptography-ciphertext",
        CryptographySurfaceClass.CONFIGURATION: "cryptography-configuration",
    }
)
_DIGEST_SOURCE_BY_SURFACE_CLASS: Mapping[
    CryptographySurfaceClass,
    CryptographicAnalysisDigestSource,
] = MappingProxyType(
    {
        CryptographySurfaceClass.PROTOCOL: CryptographicAnalysisDigestSource.DECLARATION_SHA256,
        CryptographySurfaceClass.KEY_USAGE: CryptographicAnalysisDigestSource.DECLARATION_SHA256,
        CryptographySurfaceClass.CIPHERTEXT: CryptographicAnalysisDigestSource.ARTIFACT_SHA256,
        CryptographySurfaceClass.CONFIGURATION: (
            CryptographicAnalysisDigestSource.DECLARATION_SHA256
        ),
    }
)
_SUPPORTED_OPERATIONS = tuple(
    sorted(CryptographicMisuseAnalysisOperation, key=lambda item: item.value)
)
_SUPPORTED_ANALYZERS = tuple(sorted(CryptographicMisuseAnalyzer, key=lambda item: item.value))
_SUPPORTED_SIGNALS = tuple(sorted(CryptographicMisuseSignalKind, key=lambda item: item.value))


class CryptographicSurfaceAnalysisMapping(_CryptographicMisuseAnalysisModel):
    """One exact Surface-to-input-to-analyzer semantic mapping row."""

    surface_class: CryptographySurfaceClass = Field(alias="surfaceClass")
    locator_kind: CryptographySurfaceLocatorKind = Field(alias="locatorKind")
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    digest_source: CryptographicAnalysisDigestSource = Field(alias="digestSource")
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer

    @model_validator(mode="after")
    def bind_exact_mapping(self) -> Self:
        operation = _OPERATION_BY_SURFACE_CLASS[self.surface_class]
        if (
            self.locator_kind != _LOCATOR_KIND_BY_SURFACE_CLASS[self.surface_class]
            or self.input_kind is not _INPUT_KIND_BY_SURFACE_CLASS[self.surface_class]
            or self.digest_source is not _DIGEST_SOURCE_BY_SURFACE_CLASS[self.surface_class]
            or self.operation is not operation
            or self.analyzer is not _ANALYZER_BY_OPERATION[operation]
        ):
            raise ValueError("Cryptographic Surface analysis mapping differs")
        return self


_SUPPORTED_SURFACE_ANALYSIS_MAPPING = tuple(
    CryptographicSurfaceAnalysisMapping(
        surfaceClass=surface_class,
        locatorKind=_LOCATOR_KIND_BY_SURFACE_CLASS[surface_class],
        inputKind=_INPUT_KIND_BY_SURFACE_CLASS[surface_class],
        digestSource=_DIGEST_SOURCE_BY_SURFACE_CLASS[surface_class],
        operation=_OPERATION_BY_SURFACE_CLASS[surface_class],
        analyzer=_ANALYZER_BY_OPERATION[_OPERATION_BY_SURFACE_CLASS[surface_class]],
    )
    for surface_class in sorted(CryptographySurfaceClass, key=lambda item: item.value)
)


def _cryptographic_misuse_rule_set_digest(
    *,
    rule_set_id: str,
    rule_set_version: str,
    signal_vocabulary: tuple[CryptographicMisuseSignalKind, ...],
    surface_analysis_mapping: tuple[CryptographicSurfaceAnalysisMapping, ...],
) -> str:
    return capability_definition_digest(
        "pajin.capability.cryptographic-misuse-rule-set/v1",
        {
            "ruleSetId": rule_set_id,
            "ruleSetVersion": rule_set_version,
            "signalVocabulary": [item.value for item in signal_vocabulary],
            "surfaceAnalysisMapping": [
                item.model_dump(mode="json", by_alias=True) for item in surface_analysis_mapping
            ],
        },
    )


class CryptographicMisuseRuleSetRef(_CryptographicMisuseAnalysisModel):
    """Exact reference to the code-owned bounded rule and signal vocabulary."""

    rule_set_id: Literal["pajin.cryptography.misuse-rules.baseline"] = Field(alias="ruleSetId")
    rule_set_version: Literal["1.0.0"] = Field(alias="ruleSetVersion")
    rule_set_digest: _Sha256 = Field(alias="ruleSetDigest")
    signal_vocabulary: tuple[CryptographicMisuseSignalKind, ...] = Field(
        alias="signalVocabulary",
        min_length=4,
        max_length=4,
    )
    surface_analysis_mapping: tuple[CryptographicSurfaceAnalysisMapping, ...] = Field(
        alias="surfaceAnalysisMapping",
        min_length=4,
        max_length=4,
    )

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _cryptographic_misuse_rule_set_digest(
            rule_set_id=self.rule_set_id,
            rule_set_version=self.rule_set_version,
            signal_vocabulary=self.signal_vocabulary,
            surface_analysis_mapping=self.surface_analysis_mapping,
        )
        if (
            self.rule_set_digest != digest
            or self.signal_vocabulary != _SUPPORTED_SIGNALS
            or self.surface_analysis_mapping != _SUPPORTED_SURFACE_ANALYSIS_MAPPING
        ):
            raise ValueError("Cryptographic misuse rule-set reference differs")
        return self


class RegisteredCryptographicMisuseRuleSet(_CryptographicMisuseAnalysisModel):
    """One code-owned rule vocabulary without analyzer or Finding authority."""

    api_version: Literal["pajin.dev/cryptographic-misuse-rule-set/v1alpha1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_RULE_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredCryptographicMisuseRuleSet"] = "RegisteredCryptographicMisuseRuleSet"
    rule_set_id: Literal["pajin.cryptography.misuse-rules.baseline"] = Field(
        default="pajin.cryptography.misuse-rules.baseline",
        alias="ruleSetId",
    )
    rule_set_version: Literal["1.0.0"] = Field(default="1.0.0", alias="ruleSetVersion")
    rule_set_digest: str = Field(default="", alias="ruleSetDigest", max_length=64)
    signal_vocabulary: tuple[CryptographicMisuseSignalKind, ...] = Field(
        default=_SUPPORTED_SIGNALS,
        alias="signalVocabulary",
        min_length=4,
        max_length=4,
    )
    surface_analysis_mapping: tuple[CryptographicSurfaceAnalysisMapping, ...] = Field(
        default_factory=lambda: tuple(
            item.model_copy(deep=True) for item in _SUPPORTED_SURFACE_ANALYSIS_MAPPING
        ),
        alias="surfaceAnalysisMapping",
        min_length=4,
        max_length=4,
    )
    rule_set_only: Literal[True] = Field(default=True, alias="ruleSetOnly")
    caller_rule_selection_allowed: Literal[False] = Field(
        default=False,
        alias="callerRuleSelectionAllowed",
    )
    plugin_loading_allowed: Literal[False] = Field(default=False, alias="pluginLoadingAllowed")
    analyzer_runtime_available: Literal[False] = Field(
        default=False,
        alias="analyzerRuntimeAvailable",
    )
    misuse_confirmed: Literal[False] = Field(default=False, alias="misuseConfirmed")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "rule_set_only",
        "caller_rule_selection_allowed",
        "plugin_loading_allowed",
        "analyzer_runtime_available",
        "misuse_confirmed",
        "finding_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic misuse rule-set markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_rule_set_identity(self) -> Self:
        if (
            self.signal_vocabulary != _SUPPORTED_SIGNALS
            or self.surface_analysis_mapping != _SUPPORTED_SURFACE_ANALYSIS_MAPPING
        ):
            raise ValueError("Cryptographic misuse rule-set semantics differ")
        digest = _cryptographic_misuse_rule_set_digest(
            rule_set_id=self.rule_set_id,
            rule_set_version=self.rule_set_version,
            signal_vocabulary=self.signal_vocabulary,
            surface_analysis_mapping=self.surface_analysis_mapping,
        )
        if self.rule_set_digest and self.rule_set_digest != digest:
            raise ValueError("Cryptographic misuse rule-set digest differs")
        object.__setattr__(self, "rule_set_digest", digest)
        return self

    def reference(self) -> CryptographicMisuseRuleSetRef:
        canonical = _canonical_model(
            RegisteredCryptographicMisuseRuleSet,
            self,
            label="Registered Cryptographic misuse rule set",
        )
        return CryptographicMisuseRuleSetRef(
            ruleSetId=canonical.rule_set_id,
            ruleSetVersion=canonical.rule_set_version,
            ruleSetDigest=canonical.rule_set_digest,
            signalVocabulary=canonical.signal_vocabulary,
            surfaceAnalysisMapping=canonical.surface_analysis_mapping,
        )


@cache
def _registered_cryptographic_misuse_rule_set() -> RegisteredCryptographicMisuseRuleSet:
    return RegisteredCryptographicMisuseRuleSet()


def registered_cryptographic_misuse_rule_set() -> RegisteredCryptographicMisuseRuleSet:
    """Return an isolated copy of the exact non-executable rule vocabulary."""

    return _registered_cryptographic_misuse_rule_set().model_copy(deep=True)


def resolve_registered_cryptographic_misuse_rule_set(
    reference: CryptographicMisuseRuleSetRef,
) -> RegisteredCryptographicMisuseRuleSet:
    canonical = _canonical_model(
        CryptographicMisuseRuleSetRef,
        reference,
        label="Cryptographic misuse rule-set reference",
    )
    rule_set = registered_cryptographic_misuse_rule_set()
    if canonical == rule_set.reference():
        return rule_set.model_copy(deep=True)
    raise CryptographicMisuseAnalysisCapabilityError(
        "Cryptographic misuse rule set is not registered exactly"
    )


def _cryptographic_artifact_custody_digest(
    *,
    custody_binding_version: str,
    surface: CryptographyProtocolKeyArtifactSurfaceRef,
    input_kind: CryptographicAnalysisInputKind,
    custody_authority_id: str,
    custody_object_id: str,
    authorization_id: str,
    authorization_digest: str,
    artifact_sha256: str,
    artifact_bytes: int,
) -> str:
    return capability_definition_digest(
        "pajin.capability.cryptographic-analysis-artifact-custody/v1",
        {
            "custodyBindingVersion": custody_binding_version,
            "surface": surface.model_dump(mode="json", by_alias=True),
            "inputKind": input_kind.value,
            "custodyAuthorityId": custody_authority_id,
            "custodyObjectId": custody_object_id,
            "authorizationId": authorization_id,
            "authorizationDigest": authorization_digest,
            "artifactSHA256": artifact_sha256,
            "artifactBytes": artifact_bytes,
        },
    )


def _cryptographic_artifact_object_id(artifact_sha256: str) -> str:
    return f"cryptographic-analysis-artifact_{artifact_sha256}"


def _cryptographic_authorization_reference_id(authorization_digest: str) -> str:
    return f"cryptographic-analysis-authorization_{authorization_digest}"


def _cryptographic_analysis_sandbox_digest(
    *,
    sandbox_binding_version: str,
    deployment_id: str,
    worker_profile: DomainWorkerBoundaryProfileRef,
    surface: CryptographyProtocolKeyArtifactSurfaceRef,
    rule_set: CryptographicMisuseRuleSetRef,
    operation: CryptographicMisuseAnalysisOperation,
    analyzer: CryptographicMisuseAnalyzer,
    analyzer_executable_sha256: str,
    sandbox_image_sha256: str,
    run_as_identity: str,
    output_schema: str,
    max_artifact_bytes: int,
    max_output_bytes: int,
    max_runtime_seconds: int,
    max_memory_mib: int,
    max_process_count: int,
) -> str:
    return capability_definition_digest(
        "pajin.capability.cryptographic-misuse-analysis-sandbox/v1",
        {
            "sandboxBindingVersion": sandbox_binding_version,
            "deploymentId": deployment_id,
            "workerProfile": worker_profile.model_dump(mode="json", by_alias=True),
            "surface": surface.model_dump(mode="json", by_alias=True),
            "ruleSet": rule_set.model_dump(mode="json", by_alias=True),
            "operation": operation.value,
            "analyzer": analyzer.value,
            "analyzerExecutableSHA256": analyzer_executable_sha256,
            "sandboxImageSHA256": sandbox_image_sha256,
            "runAsIdentity": run_as_identity,
            "outputSchema": output_schema,
            "maxArtifactBytes": max_artifact_bytes,
            "maxOutputBytes": max_output_bytes,
            "maxRuntimeSeconds": max_runtime_seconds,
            "maxMemoryMiB": max_memory_mib,
            "maxProcessCount": max_process_count,
        },
    )


class CryptographicAnalysisArtifactCustodyRef(_CryptographicMisuseAnalysisModel):
    """Exact secret-free reference to deployment-authorized immutable custody."""

    custody_binding_id: str = Field(
        alias="custodyBindingId",
        pattern=r"^cryptographic-artifact-custody_[a-f0-9]{64}$",
    )
    custody_binding_version: Literal["1.0.0"] = Field(alias="custodyBindingVersion")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    surface: CryptographyProtocolKeyArtifactSurfaceRef
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    custody_authority_id: Literal["pajin.cryptography.immutable-analysis-artifact-custody"] = Field(
        alias="custodyAuthorityId"
    )
    custody_object_id: str = Field(
        alias="custodyObjectId",
        pattern=r"^cryptographic-analysis-artifact_[a-f0-9]{64}$",
    )
    authorization_id: str = Field(
        alias="authorizationId",
        pattern=r"^cryptographic-analysis-authorization_[a-f0-9]{64}$",
    )
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)

    @field_validator("artifact_bytes", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Cryptographic custody artifact bytes must be an integer")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _cryptographic_artifact_custody_digest(
            custody_binding_version=self.custody_binding_version,
            surface=self.surface,
            input_kind=self.input_kind,
            custody_authority_id=self.custody_authority_id,
            custody_object_id=self.custody_object_id,
            authorization_id=self.authorization_id,
            authorization_digest=self.authorization_digest,
            artifact_sha256=self.artifact_sha256,
            artifact_bytes=self.artifact_bytes,
        )
        if (
            self.custody_binding_digest != digest
            or self.custody_binding_id != f"cryptographic-artifact-custody_{digest}"
            or self.input_kind is not _input_kind_from_surface_ref(self.surface)
            or self.custody_object_id != _cryptographic_artifact_object_id(self.artifact_sha256)
            or self.authorization_id
            != _cryptographic_authorization_reference_id(self.authorization_digest)
        ):
            raise ValueError("Cryptographic artifact custody reference identity differs")
        return self


class CryptographicAnalysisArtifactCustodyBinding(_CryptographicMisuseAnalysisModel):
    """Configuration-only custody binding; no artifact is resolved or read."""

    api_version: Literal["pajin.dev/cryptographic-analysis-artifact-custody-binding/v1alpha1"] = (
        Field(
            default=CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_BINDING_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["CryptographicAnalysisArtifactCustodyBinding"] = (
        "CryptographicAnalysisArtifactCustodyBinding"
    )
    custody_binding_id: str = Field(default="", alias="custodyBindingId", max_length=98)
    custody_binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="custodyBindingVersion",
    )
    custody_binding_digest: str = Field(default="", alias="custodyBindingDigest", max_length=64)
    surface: CryptographyProtocolKeyArtifactSurface
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    custody_authority_id: Literal["pajin.cryptography.immutable-analysis-artifact-custody"] = Field(
        alias="custodyAuthorityId"
    )
    custody_object_id: str = Field(
        alias="custodyObjectId",
        pattern=r"^cryptographic-analysis-artifact_[a-f0-9]{64}$",
    )
    authorization_id: str = Field(
        alias="authorizationId",
        pattern=r"^cryptographic-analysis-authorization_[a-f0-9]{64}$",
    )
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
    raw_key_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawKeyMaterialEmbedded",
    )
    key_reference_embedded: Literal[False] = Field(
        default=False,
        alias="keyReferenceEmbedded",
    )
    raw_plaintext_embedded: Literal[False] = Field(
        default=False,
        alias="rawPlaintextEmbedded",
    )
    raw_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawConfigurationEmbedded",
    )
    mutable_path_embedded: Literal[False] = Field(default=False, alias="mutablePathEmbedded")
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )
    authorization_verified_by_preparation: Literal[False] = Field(
        default=False,
        alias="authorizationVerifiedByPreparation",
    )
    declaration_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="declarationSanitizationVerified",
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
            raise ValueError("Cryptographic custody artifact bytes must be an integer")
        return value

    @field_validator(
        "configuration_only",
        "deployment_authorization_reference_bound",
        "immutable_digest_required",
        "read_only_mount_required",
        "raw_artifact_content_embedded",
        "raw_key_material_embedded",
        "key_reference_embedded",
        "raw_plaintext_embedded",
        "raw_configuration_embedded",
        "mutable_path_embedded",
        "secret_material_embedded",
        "credential_reference_embedded",
        "authorization_verified_by_preparation",
        "declaration_sanitization_verified",
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
            raise ValueError("Cryptographic artifact custody markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_custody_identity(self) -> Self:
        surface = _canonical_surface(self.surface)
        if (
            surface != self.surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.input_kind is not _input_kind(self.surface)
            or self.artifact_sha256 != _artifact_sha256(self.surface)
            or self.custody_authority_id != CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_AUTHORITY_ID
            or self.custody_object_id != _cryptographic_artifact_object_id(self.artifact_sha256)
            or self.authorization_id
            != _cryptographic_authorization_reference_id(self.authorization_digest)
        ):
            raise ValueError("Cryptographic artifact custody differs from the exact Surface")
        digest = _cryptographic_artifact_custody_digest(
            custody_binding_version=self.custody_binding_version,
            surface=surface.reference(),
            input_kind=self.input_kind,
            custody_authority_id=self.custody_authority_id,
            custody_object_id=self.custody_object_id,
            authorization_id=self.authorization_id,
            authorization_digest=self.authorization_digest,
            artifact_sha256=self.artifact_sha256,
            artifact_bytes=self.artifact_bytes,
        )
        binding_id = f"cryptographic-artifact-custody_{digest}"
        if self.custody_binding_digest and self.custody_binding_digest != digest:
            raise ValueError("Cryptographic artifact custody digest differs")
        if self.custody_binding_id and self.custody_binding_id != binding_id:
            raise ValueError("Cryptographic artifact custody ID differs")
        object.__setattr__(self, "custody_binding_digest", digest)
        object.__setattr__(self, "custody_binding_id", binding_id)
        return self

    def reference(self) -> CryptographicAnalysisArtifactCustodyRef:
        canonical = _canonical_model(
            CryptographicAnalysisArtifactCustodyBinding,
            self,
            label="Cryptographic artifact custody binding",
        )
        return CryptographicAnalysisArtifactCustodyRef(
            custodyBindingId=canonical.custody_binding_id,
            custodyBindingVersion=canonical.custody_binding_version,
            custodyBindingDigest=canonical.custody_binding_digest,
            surface=canonical.surface.reference(),
            inputKind=canonical.input_kind,
            custodyAuthorityId=canonical.custody_authority_id,
            custodyObjectId=canonical.custody_object_id,
            authorizationId=canonical.authorization_id,
            authorizationDigest=canonical.authorization_digest,
            artifactSHA256=canonical.artifact_sha256,
            artifactBytes=canonical.artifact_bytes,
        )


class CryptographicMisuseAnalysisSandboxRef(_CryptographicMisuseAnalysisModel):
    """Exact non-secret reference to one network-disabled sandbox configuration."""

    sandbox_binding_id: str = Field(
        alias="sandboxBindingId",
        pattern=r"^cryptographic-analysis-sandbox_[a-f0-9]{64}$",
    )
    sandbox_binding_version: Literal["1.0.0"] = Field(alias="sandboxBindingVersion")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: Literal["deployment:cryptographic-misuse-analysis"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_DEPLOYMENT_ID,
        alias="deploymentId",
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    surface: CryptographyProtocolKeyArtifactSurfaceRef
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer
    analyzer_executable_sha256: _Sha256 = Field(alias="analyzerExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: Literal["svc:pajin-crypto-analyzer"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_RUN_AS_IDENTITY,
        alias="runAsIdentity",
    )
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        alias="outputSchema"
    )
    max_artifact_bytes: int = Field(alias="maxArtifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1_024, le=_MAX_OUTPUT_BYTES)
    max_runtime_seconds: int = Field(alias="maxRuntimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    max_memory_mib: int = Field(alias="maxMemoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    max_process_count: int = Field(alias="maxProcessCount", ge=1, le=_MAX_PROCESS_COUNT)

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
            raise ValueError("Cryptographic sandbox reference ceilings must be integers")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _cryptographic_analysis_sandbox_digest(
            sandbox_binding_version=self.sandbox_binding_version,
            deployment_id=self.deployment_id,
            worker_profile=self.worker_profile,
            surface=self.surface,
            rule_set=self.rule_set,
            operation=self.operation,
            analyzer=self.analyzer,
            analyzer_executable_sha256=self.analyzer_executable_sha256,
            sandbox_image_sha256=self.sandbox_image_sha256,
            run_as_identity=self.run_as_identity,
            output_schema=self.output_schema,
            max_artifact_bytes=self.max_artifact_bytes,
            max_output_bytes=self.max_output_bytes,
            max_runtime_seconds=self.max_runtime_seconds,
            max_memory_mib=self.max_memory_mib,
            max_process_count=self.max_process_count,
        )
        if (
            self.sandbox_binding_digest != digest
            or self.sandbox_binding_id != f"cryptographic-analysis-sandbox_{digest}"
            or self.worker_profile != _cryptographic_worker_boundary_profile().reference()
            or self.rule_set != registered_cryptographic_misuse_rule_set().reference()
            or self.operation is not _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class]
            or self.analyzer is not _ANALYZER_BY_OPERATION[self.operation]
        ):
            raise ValueError("Cryptographic analysis sandbox reference differs")
        return self


class CryptographicMisuseAnalysisSandboxBinding(_CryptographicMisuseAnalysisModel):
    """Configuration-only offline sandbox boundary without selection or execution."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-sandbox-binding/v1alpha1"] = (
        Field(
            default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_SANDBOX_BINDING_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["CryptographicMisuseAnalysisSandboxBinding"] = (
        "CryptographicMisuseAnalysisSandboxBinding"
    )
    sandbox_binding_id: str = Field(default="", alias="sandboxBindingId", max_length=100)
    sandbox_binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="sandboxBindingVersion",
    )
    sandbox_binding_digest: str = Field(default="", alias="sandboxBindingDigest", max_length=64)
    deployment_id: Literal["deployment:cryptographic-misuse-analysis"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_DEPLOYMENT_ID,
        alias="deploymentId",
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    surface: CryptographyProtocolKeyArtifactSurface
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer
    analyzer_executable_sha256: _Sha256 = Field(alias="analyzerExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: Literal["svc:pajin-crypto-analyzer"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_RUN_AS_IDENTITY,
        alias="runAsIdentity",
    )
    artifact_mount_target: Literal["/pajin/input/artifact"] = Field(
        default=CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_MOUNT_TARGET,
        alias="artifactMountTarget",
    )
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    output_transport: Literal["bounded-json-stdout"] = Field(
        default="bounded-json-stdout",
        alias="outputTransport",
    )
    max_artifact_bytes: int = Field(alias="maxArtifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1_024, le=_MAX_OUTPUT_BYTES)
    max_runtime_seconds: int = Field(alias="maxRuntimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    max_memory_mib: int = Field(alias="maxMemoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    max_process_count: int = Field(alias="maxProcessCount", ge=1, le=_MAX_PROCESS_COUNT)
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
    exact_analyzer_executable_digest_required: Literal[True] = Field(
        default=True,
        alias="exactAnalyzerExecutableDigestRequired",
    )
    exact_sandbox_image_digest_required: Literal[True] = Field(
        default=True,
        alias="exactSandboxImageDigestRequired",
    )
    exact_rule_set_required: Literal[True] = Field(
        default=True,
        alias="exactRuleSetRequired",
    )
    core_dump_disabled_required: Literal[True] = Field(
        default=True,
        alias="coreDumpDisabledRequired",
    )
    host_filesystem_access_allowed: Literal[False] = Field(
        default=False,
        alias="hostFilesystemAccessAllowed",
    )
    credential_injection_allowed: Literal[False] = Field(
        default=False,
        alias="credentialInjectionAllowed",
    )
    key_material_injection_allowed: Literal[False] = Field(
        default=False,
        alias="keyMaterialInjectionAllowed",
    )
    environment_inheritance_allowed: Literal[False] = Field(
        default=False,
        alias="environmentInheritanceAllowed",
    )
    symlink_traversal_allowed: Literal[False] = Field(
        default=False,
        alias="symlinkTraversalAllowed",
    )
    device_access_allowed: Literal[False] = Field(default=False, alias="deviceAccessAllowed")
    plugin_loading_allowed: Literal[False] = Field(default=False, alias="pluginLoadingAllowed")
    shell_command_allowed: Literal[False] = Field(default=False, alias="shellCommandAllowed")
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
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    key_search_authorized: Literal[False] = Field(default=False, alias="keySearchAuthorized")
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="oracleInvocationAuthorized",
    )
    raw_result_echo_allowed: Literal[False] = Field(
        default=False,
        alias="rawResultEchoAllowed",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

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
            raise ValueError("Cryptographic sandbox resource ceilings must be integers")
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
        "exact_analyzer_executable_digest_required",
        "exact_sandbox_image_digest_required",
        "exact_rule_set_required",
        "core_dump_disabled_required",
        "host_filesystem_access_allowed",
        "credential_injection_allowed",
        "key_material_injection_allowed",
        "environment_inheritance_allowed",
        "symlink_traversal_allowed",
        "device_access_allowed",
        "plugin_loading_allowed",
        "shell_command_allowed",
        "runtime_attested",
        "sandbox_selected",
        "artifact_mount_materialized",
        "artifact_read_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "dns_access_authorized",
        "key_material_access_authorized",
        "credential_use_authorized",
        "cryptographic_operation_authorized",
        "key_search_authorized",
        "protocol_negotiation_authorized",
        "oracle_invocation_authorized",
        "raw_result_echo_allowed",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic sandbox markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_sandbox_identity(self) -> Self:
        surface = _canonical_surface(self.surface)
        worker = _cryptographic_worker_boundary_profile()
        rule_set = registered_cryptographic_misuse_rule_set().reference()
        if (
            surface != self.surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.worker_profile != worker.reference()
            or self.rule_set != rule_set
            or self.operation is not _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class]
            or self.analyzer is not _ANALYZER_BY_OPERATION[self.operation]
            or worker.domain_classification.domain is not SecurityDomain.CRYPTOGRAPHY
            or worker.network_boundary is not WorkerNetworkBoundary.DISABLED_BY_DEFAULT
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.READ_ONLY_ARTIFACT
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.OFFLINE_SANDBOX
            or worker.required_identity_dimensions != ("analyzer", "artifact-digest")
            or worker.required_budget_dimensions != ("artifact-bytes", "runtime")
        ):
            raise ValueError("Cryptographic analysis sandbox differs from code authority")
        digest = _cryptographic_analysis_sandbox_digest(
            sandbox_binding_version=self.sandbox_binding_version,
            deployment_id=self.deployment_id,
            worker_profile=self.worker_profile,
            surface=surface.reference(),
            rule_set=self.rule_set,
            operation=self.operation,
            analyzer=self.analyzer,
            analyzer_executable_sha256=self.analyzer_executable_sha256,
            sandbox_image_sha256=self.sandbox_image_sha256,
            run_as_identity=self.run_as_identity,
            output_schema=self.output_schema,
            max_artifact_bytes=self.max_artifact_bytes,
            max_output_bytes=self.max_output_bytes,
            max_runtime_seconds=self.max_runtime_seconds,
            max_memory_mib=self.max_memory_mib,
            max_process_count=self.max_process_count,
        )
        binding_id = f"cryptographic-analysis-sandbox_{digest}"
        if self.sandbox_binding_digest and self.sandbox_binding_digest != digest:
            raise ValueError("Cryptographic analysis sandbox digest differs")
        if self.sandbox_binding_id and self.sandbox_binding_id != binding_id:
            raise ValueError("Cryptographic analysis sandbox ID differs")
        object.__setattr__(self, "sandbox_binding_digest", digest)
        object.__setattr__(self, "sandbox_binding_id", binding_id)
        return self

    def reference(self) -> CryptographicMisuseAnalysisSandboxRef:
        canonical = _canonical_model(
            CryptographicMisuseAnalysisSandboxBinding,
            self,
            label="Cryptographic misuse-analysis sandbox binding",
        )
        return CryptographicMisuseAnalysisSandboxRef(
            sandboxBindingId=canonical.sandbox_binding_id,
            sandboxBindingVersion=canonical.sandbox_binding_version,
            sandboxBindingDigest=canonical.sandbox_binding_digest,
            deploymentId=canonical.deployment_id,
            workerProfile=canonical.worker_profile,
            surface=canonical.surface.reference(),
            ruleSet=canonical.rule_set,
            operation=canonical.operation,
            analyzer=canonical.analyzer,
            analyzerExecutableSHA256=canonical.analyzer_executable_sha256,
            sandboxImageSHA256=canonical.sandbox_image_sha256,
            runAsIdentity=canonical.run_as_identity,
            outputSchema=canonical.output_schema,
            maxArtifactBytes=canonical.max_artifact_bytes,
            maxOutputBytes=canonical.max_output_bytes,
            maxRuntimeSeconds=canonical.max_runtime_seconds,
            maxMemoryMiB=canonical.max_memory_mib,
            maxProcessCount=canonical.max_process_count,
        )


class CryptographicMisuseAnalysisBudget(_CryptographicMisuseAnalysisModel):
    """Attenuating input, output, runtime, memory, and zero-live-channel ceilings."""

    request_count: Literal[1] = Field(default=1, alias="requestCount")
    artifact_bytes: int = Field(alias="artifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1_024, le=_MAX_OUTPUT_BYTES)
    runtime_seconds: int = Field(alias="runtimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    memory_mib: int = Field(alias="memoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    process_count: int = Field(alias="processCount", ge=1, le=_MAX_PROCESS_COUNT)
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_queries: Literal[0] = Field(default=0, alias="dnsQueries")
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    artifact_write_operations: Literal[0] = Field(
        default=0,
        alias="artifactWriteOperations",
    )
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    key_material_reads: Literal[0] = Field(default=0, alias="keyMaterialReads")
    key_store_sessions: Literal[0] = Field(default=0, alias="keyStoreSessions")
    cryptographic_operations: Literal[0] = Field(default=0, alias="cryptographicOperations")
    key_search_attempts: Literal[0] = Field(default=0, alias="keySearchAttempts")
    protocol_negotiations: Literal[0] = Field(default=0, alias="protocolNegotiations")
    oracle_invocations: Literal[0] = Field(default=0, alias="oracleInvocations")
    plaintext_outputs: Literal[0] = Field(default=0, alias="plaintextOutputs")
    key_material_outputs: Literal[0] = Field(default=0, alias="keyMaterialOutputs")
    target_process_executions: Literal[0] = Field(default=0, alias="targetProcessExecutions")
    shell_commands: Literal[0] = Field(default=0, alias="shellCommands")
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
        "dns_queries",
        "host_filesystem_reads",
        "artifact_write_operations",
        "credential_reads",
        "key_material_reads",
        "key_store_sessions",
        "cryptographic_operations",
        "key_search_attempts",
        "protocol_negotiations",
        "oracle_invocations",
        "plaintext_outputs",
        "key_material_outputs",
        "target_process_executions",
        "shell_commands",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Cryptographic analysis budget values must be integers")
        return value

    @field_validator("attenuation_only", "reservation_created", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic analysis budget markers must be booleans")
        return value


class CryptographicMisuseAnalysisRequest(_CryptographicMisuseAnalysisModel):
    """Secret-free request description; it resolves, reads, and executes nothing."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-request/v1alpha1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisRequest"] = "CryptographicMisuseAnalysisRequest"
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    surface: CryptographyProtocolKeyArtifactSurface
    custody: CryptographicAnalysisArtifactCustodyRef
    sandbox: CryptographicMisuseAnalysisSandboxRef
    target: str = Field(min_length=9, max_length=2_000)
    method: Literal["GET"] = "GET"
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    budget: CryptographicMisuseAnalysisBudget
    raw_artifact_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentEmbedded",
    )
    raw_key_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawKeyMaterialEmbedded",
    )
    key_reference_embedded: Literal[False] = Field(
        default=False,
        alias="keyReferenceEmbedded",
    )
    raw_ciphertext_embedded: Literal[False] = Field(
        default=False,
        alias="rawCiphertextEmbedded",
    )
    raw_plaintext_embedded: Literal[False] = Field(
        default=False,
        alias="rawPlaintextEmbedded",
    )
    raw_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawConfigurationEmbedded",
    )
    raw_parameter_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawParameterMaterialEmbedded",
    )
    mutable_artifact_path_embedded: Literal[False] = Field(
        default=False,
        alias="mutableArtifactPathEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    caller_rule_or_plugin_embedded: Literal[False] = Field(
        default=False,
        alias="callerRuleOrPluginEmbedded",
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
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    key_search_authorized: Literal[False] = Field(default=False, alias="keySearchAuthorized")
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="oracleInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    misuse_analysis_executed: Literal[False] = Field(
        default=False,
        alias="misuseAnalysisExecuted",
    )

    @field_validator("target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        return _canonical_cryptographic_surface_target(value)

    @field_validator(
        "raw_artifact_content_embedded",
        "raw_key_material_embedded",
        "key_reference_embedded",
        "raw_ciphertext_embedded",
        "raw_plaintext_embedded",
        "raw_configuration_embedded",
        "raw_parameter_material_embedded",
        "mutable_artifact_path_embedded",
        "credential_material_embedded",
        "caller_rule_or_plugin_embedded",
        "artifact_resolution_performed",
        "artifact_read_performed",
        "artifact_mount_materialized",
        "sandbox_invocation_authorized",
        "key_material_access_authorized",
        "credential_use_authorized",
        "cryptographic_operation_authorized",
        "key_search_authorized",
        "protocol_negotiation_authorized",
        "oracle_invocation_authorized",
        "network_access_authorized",
        "misuse_analysis_executed",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic misuse-analysis request markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_request(self) -> Self:
        surface = _canonical_surface(self.surface)
        expected_operation = _OPERATION_BY_SURFACE_CLASS[surface.surface_class]
        expected_analyzer = _ANALYZER_BY_OPERATION[expected_operation]
        expected_rule_set = registered_cryptographic_misuse_rule_set().reference()
        if (
            surface != self.surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.input_kind is not _input_kind(self.surface)
            or self.operation is not expected_operation
            or self.analyzer is not expected_analyzer
            or self.rule_set != expected_rule_set
            or self.custody.surface != self.surface.reference()
            or self.custody.input_kind is not self.input_kind
            or self.custody.artifact_sha256 != _artifact_sha256(self.surface)
            or self.sandbox.surface != self.surface.reference()
            or self.sandbox.worker_profile != _cryptographic_worker_boundary_profile().reference()
            or self.sandbox.rule_set != self.rule_set
            or self.sandbox.operation is not self.operation
            or self.sandbox.analyzer is not self.analyzer
            or self.sandbox.output_schema != self.output_schema
            or self.target != cryptographic_surface_scope_target(self.surface)
            or self.budget.artifact_bytes != self.custody.artifact_bytes
            or self.budget.artifact_bytes > self.sandbox.max_artifact_bytes
            or self.budget.max_output_bytes != self.sandbox.max_output_bytes
            or self.budget.runtime_seconds != self.sandbox.max_runtime_seconds
            or self.budget.memory_mib != self.sandbox.max_memory_mib
            or self.budget.process_count != self.sandbox.max_process_count
        ):
            raise ValueError("Cryptographic misuse-analysis request differs from exact bindings")
        return self


@dataclass(frozen=True, slots=True)
class BoundedCryptographicMisuseAnalyzerAdapter:
    """Adapt exact custody and sandbox metadata without reading or executing it."""

    _custody: CryptographicAnalysisArtifactCustodyBinding
    _sandbox: CryptographicMisuseAnalysisSandboxBinding

    def __post_init__(self) -> None:
        custody = _canonical_model(
            CryptographicAnalysisArtifactCustodyBinding,
            self._custody,
            label="Cryptographic artifact custody binding",
        )
        sandbox = _canonical_model(
            CryptographicMisuseAnalysisSandboxBinding,
            self._sandbox,
            label="Cryptographic misuse-analysis sandbox binding",
        )
        if custody.surface != sandbox.surface:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic custody and sandbox bind different Surfaces"
            )
        object.__setattr__(self, "_custody", custody)
        object.__setattr__(self, "_sandbox", sandbox)

    @property
    def custody(self) -> CryptographicAnalysisArtifactCustodyBinding:
        return self._custody.model_copy(deep=True)

    @property
    def sandbox(self) -> CryptographicMisuseAnalysisSandboxBinding:
        return self._sandbox.model_copy(deep=True)

    def prepare_request(
        self,
        *,
        surface: CryptographyProtocolKeyArtifactSurface,
        operation: CryptographicMisuseAnalysisOperation,
    ) -> CryptographicMisuseAnalysisRequest:
        """Return a bounded request description without artifact or sandbox authority."""

        canonical_surface = _canonical_surface(surface)
        try:
            canonical_operation = CryptographicMisuseAnalysisOperation(operation)
        except ValueError as exc:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic misuse-analysis operation is unsupported"
            ) from exc
        expected_operation = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
        if canonical_surface != self._custody.surface:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic custody differs from the exact Surface"
            )
        if canonical_surface != self._sandbox.surface:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic sandbox differs from the exact Surface"
            )
        if canonical_operation is not expected_operation:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic operation differs from the exact Surface class"
            )
        if canonical_operation is not self._sandbox.operation:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic operation is outside the exact sandbox binding"
            )
        if self._custody.artifact_bytes > self._sandbox.max_artifact_bytes:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic artifact exceeds the sandbox byte ceiling"
            )
        return CryptographicMisuseAnalysisRequest(
            inputKind=self._custody.input_kind,
            operation=canonical_operation,
            analyzer=self._sandbox.analyzer,
            ruleSet=self._sandbox.rule_set,
            surface=canonical_surface,
            custody=self._custody.reference(),
            sandbox=self._sandbox.reference(),
            target=cryptographic_surface_scope_target(canonical_surface),
            budget=CryptographicMisuseAnalysisBudget(
                artifactBytes=self._custody.artifact_bytes,
                maxOutputBytes=self._sandbox.max_output_bytes,
                runtimeSeconds=self._sandbox.max_runtime_seconds,
                memoryMiB=self._sandbox.max_memory_mib,
                processCount=self._sandbox.max_process_count,
            ),
        )


class CryptographicMisuseAnalysisTool(Tool):
    """CAP-001 Tool identity whose offline analyzer runtime remains unavailable."""

    spec = ToolSpec(
        tool_id=CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID,
        version="1.0.0",
        description="Prepare one exact offline read-only Cryptographic misuse analysis",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"cryptography", "misuse-analysis", "offline-sandbox", "read-only"}),
        evidence_types=frozenset({"cryptographic-misuse-analysis-json", "json"}),
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
            "outputSchema": CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
            "ruleSet": registered_cryptographic_misuse_rule_set()
            .reference()
            .model_dump(
                mode="json",
                by_alias=True,
            ),
            "artifactCustodyRuntimeAvailable": False,
            "offlineSandboxRuntimeAvailable": False,
            "keyMaterialRuntimeAvailable": False,
            "cryptographicOperationRuntimeAvailable": False,
            "oracleRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        _validate_cryptographic_tool_request(request)
        raise CryptographicMisuseAnalysisCapabilityError(
            "CRYPTO-001B does not materialize an offline sandbox Worker job"
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        _validate_cryptographic_tool_request(request)
        raise CryptographicMisuseAnalysisCapabilityError(
            "CRYPTO-001B has no sandbox result to normalize"
        )


class CryptographicMisuseAnalysisCapabilityDomainClassification(_CryptographicMisuseAnalysisModel):
    """Exact Cryptography classification for the additive CRYPTO-001B bundle."""

    api_version: Literal[
        "pajin.dev/cryptographic-misuse-analysis-capability-domain-classification/v1alpha1"
    ] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisCapabilityDomainClassification"] = (
        "CryptographicMisuseAnalysisCapabilityDomainClassification"
    )
    classification_id: str = Field(default="", alias="classificationId", max_length=97)
    classification_digest: str = Field(default="", alias="classificationDigest", max_length=64)
    capability: CapabilityDefinitionRef
    code_backed_capability: CodeBackedCapabilityRef = Field(alias="codeBackedCapability")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    reviewed_surface_types: tuple[CryptographySurfaceLocatorKind, ...] = Field(
        default=(
            "cryptography-ciphertext",
            "cryptography-configuration",
            "cryptography-key-usage",
            "cryptography-protocol",
        ),
        alias="reviewedSurfaceTypes",
    )
    mapping_basis: Literal["crypto-001b-explicit-code-reviewed-capability-surface-and-rule-set"] = (
        Field(
            default="crypto-001b-explicit-code-reviewed-capability-surface-and-rule-set",
            alias="mappingBasis",
        )
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
    ctf_capability_reused: Literal[False] = Field(default=False, alias="ctfCapabilityReused")
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
        "ctf_capability_reused",
        "capability_activation_authorized",
        "worker_selection_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic Capability Domain markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        capability = _cryptographic_code_backed_capability()
        worker = _cryptographic_worker_boundary_profile()
        if (
            self.capability != capability.capability
            or self.code_backed_capability != capability
            or self.domain_classification != worker.domain_classification
            or self.reviewed_surface_types != _supported_locator_kinds()
        ):
            raise ValueError("Cryptographic Capability Domain classification differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cryptographic-misuse-domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Cryptographic Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("Cryptographic Capability Domain classification ID differs")
        object.__setattr__(self, "classification_digest", digest)
        object.__setattr__(self, "classification_id", classification_id)
        return self

    def reference(self) -> CapabilityDomainClassificationRef:
        canonical = _canonical_model(
            CryptographicMisuseAnalysisCapabilityDomainClassification,
            self,
            label="Cryptographic Capability Domain classification",
        )
        return CapabilityDomainClassificationRef(
            classificationId=canonical.classification_id,
            classificationDigest=canonical.classification_digest,
            capability=canonical.capability,
            domainClassification=canonical.domain_classification,
        )


class CryptographicCampaignScopeBinding(_CryptographicMisuseAnalysisModel):
    """Content-addressed current Campaign projection for exact preparation."""

    api_version: Literal["pajin.dev/cryptographic-campaign-scope-binding/v1alpha1"] = Field(
        default=CRYPTOGRAPHIC_CAMPAIGN_SCOPE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicCampaignScopeBinding"] = "CryptographicCampaignScopeBinding"
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    campaign_name: str = Field(
        alias="campaignName",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    scope: Scope
    allowed_methods: tuple[str, ...] = Field(alias="allowedMethods", min_length=1, max_length=32)
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
            raise ValueError("Cryptographic Campaign Scope markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_scope_projection(self) -> Self:
        if self.allowed_methods != tuple(sorted(set(self.allowed_methods))):
            raise ValueError("Cryptographic Campaign allowed methods must be sorted and unique")
        if "GET" not in self.allowed_methods:
            raise ValueError("Cryptographic Campaign Scope requires reviewed GET authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"binding_digest"})
        digest = capability_definition_digest(
            "pajin.capability.cryptographic-campaign-scope-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Cryptographic Campaign Scope binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class CryptographicMisuseAnalysisCapabilityBundle:
    """Frozen CAP-001/CAP-002 registries for one Cryptographic Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapabilityRef:
        manifests = self.authorities.capabilities()
        if len(manifests) != 1:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic misuse-analysis Capability authority inventory drifted"
            )
        return manifests[0].reference()


class CryptographicMisuseAnalysisCapabilityActivationBinding(_CryptographicMisuseAnalysisModel):
    """One exact externally signed release admitted for Range-only use."""

    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        definition = registered_cryptographic_misuse_analysis_capability_definition()
        if (
            self.capability != _cryptographic_code_backed_capability()
            or self.action_capability != registered_action_capability(definition)
        ):
            raise ValueError("Cryptographic activation references another Capability")
        return self


class CryptographicMisuseAnalysisCapabilityActivationSet(_CryptographicMisuseAnalysisModel):
    """Content-addressed activation of exactly one signed Cryptographic release."""

    api_version: Literal[
        "pajin.dev/cryptographic-misuse-analysis-capability-activation-set/v1alpha1"
    ] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisCapabilityActivationSet"] = (
        "CryptographicMisuseAnalysisCapabilityActivationSet"
    )
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(default="", alias="activationSetDigest", max_length=64)
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: CryptographicMisuseAnalysisCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cryptographic-misuse-analysis-activation-set/v1",
            material,
        )
        activation_set_id = f"cryptographic-misuse-analysis-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("Cryptographic activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("Cryptographic activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class CryptographicMisuseAnalysisCapabilityActivation:
    """Runtime activation that rechecks the signed current release on every use."""

    bundle: CryptographicMisuseAnalysisCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: CryptographicMisuseAnalysisCapabilityActivationSet

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
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic activated Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic CAP-002 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(self, reference: ActionCapabilityRef) -> ResolvedCapabilityRelease:
        canonical = _canonical_model(
            ActionCapabilityRef,
            reference,
            label="Cryptographic GRAPH Capability reference",
        )
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic GRAPH Capability is outside the activation"
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
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic release is outside the activation"
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
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _CryptographicMisuseAnalysisAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        definition: CapabilityDefinition,
        tool: CryptographicMisuseAnalysisTool,
    ) -> None:
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ID}.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ADAPTER_VERSION,
            "method": "GET",
            "parameterSchemaDigest": self._definition.parameter_schema_digest,
            "ruleSet": registered_cryptographic_misuse_rule_set()
            .reference()
            .model_dump(
                mode="json",
                by_alias=True,
            ),
            "artifactCustodyRequestAdaptationAvailable": True,
            "offlineSandboxRequestAdaptationAvailable": True,
            "artifactCustodyRuntimeAvailable": False,
            "offlineSandboxRuntimeAvailable": False,
            "keyMaterialRuntimeAvailable": False,
            "cryptographicOperationRuntimeAvailable": False,
            "oracleRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
            "replayAuthorized": False,
            "cleanupAuthorized": False,
            "tool": {
                "type": f"{type(self._tool).__module__}.{type(self._tool).__qualname__}",
                "context": self._tool.stable_execution_context(),
            },
        }


class _CryptographicMisuseAnalysisMaterializer(_CryptographicMisuseAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            request = CryptographicMisuseAnalysisRequest.model_validate(dict(parameters))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Cryptographic parameters differ from the bounded analysis request"
            ) from exc
        return cast(Mapping[str, JsonValue], request.model_dump(mode="json", by_alias=True))


class _CryptographicMisuseAnalysisActionCompiler(_CryptographicMisuseAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        try:
            analysis = CryptographicMisuseAnalysisRequest.model_validate(
                dict(materialized_arguments)
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Cryptographic materialized analysis request is invalid"
            ) from exc
        if (
            request.tool_id != CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != analysis.target
            or request.arguments
        ):
            raise CapabilityAuthorityError(
                "Cryptographic compiler accepts only one exact empty GET request"
            )
        payload = request.model_dump(mode="json")
        payload["arguments"] = analysis.model_dump(mode="json", by_alias=True)
        return ToolRequest.model_validate(payload)


class _CryptographicMisuseAnalysisExecutorAdapter(_CryptographicMisuseAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _CryptographicMisuseAnalysisResultNormalizer(_CryptographicMisuseAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _CryptographicMisuseAnalysisSuccessOracle(_CryptographicMisuseAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del request, result
        return CapabilityOracleDecision.INCONCLUSIVE


class _CryptographicMisuseAnalysisReplayStrategy(_CryptographicMisuseAnalysisAuthorityBase):
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


class _CryptographicMisuseAnalysisCleanupHandler(_CryptographicMisuseAnalysisAuthorityBase):
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
def _registered_cryptographic_misuse_analysis_capability_definition() -> CapabilityDefinition:
    raw_schema = CryptographicMisuseAnalysisRequest.model_json_schema(by_alias=True)
    raw_schema["required"] = sorted(raw_schema["required"])
    schema = cast(Mapping[str, JsonValue], raw_schema)
    return capability_definition_from_tool(
        CryptographicMisuseAnalysisTool.spec,
        ToolCapabilityRegistration(
            capabilityId=CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ID,
            capabilityVersion=CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_VERSION,
            toolId=CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID,
            domain="cryptography",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=_supported_locator_kinds(),
            threatClasses=("cryptographic-configuration", "cryptographic-misuse"),
            preconditions=(
                "current-campaign-scope",
                "deployment-custody-authorization-reference",
                "exact-code-owned-rule-set",
                "exact-cryptography-surface",
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


def registered_cryptographic_misuse_analysis_capability_definition() -> CapabilityDefinition:
    """Return an isolated copy of exact CAP-001 metadata for bounded preparation."""

    return _registered_cryptographic_misuse_analysis_capability_definition().model_copy(deep=True)


def cryptographic_misuse_analysis_capability_bundle(
    tools: ToolRegistry,
) -> CryptographicMisuseAnalysisCapabilityBundle:
    """Bind the exact Cryptographic Tool identity to all seven CAP-002 roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("Cryptographic misuse-analysis Capability requires a ToolRegistry")
    try:
        tool = tools.tool(CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID)
        spec = tools.spec(CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic misuse-analysis Tool is unavailable"
        ) from exc
    if (
        type(tool) is not CryptographicMisuseAnalysisTool
        or spec != CryptographicMisuseAnalysisTool.spec
    ):
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic misuse-analysis Tool implementation drifted"
        )
    definition = registered_cryptographic_misuse_analysis_capability_definition()
    definitions = CapabilityDefinitionRegistry((definition,))
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _CryptographicMisuseAnalysisActionCompiler(definition, tool),
        _CryptographicMisuseAnalysisCleanupHandler(definition, tool),
        _CryptographicMisuseAnalysisExecutorAdapter(definition, tool),
        _CryptographicMisuseAnalysisMaterializer(definition, tool),
        _CryptographicMisuseAnalysisReplayStrategy(definition, tool),
        _CryptographicMisuseAnalysisResultNormalizer(definition, tool),
        _CryptographicMisuseAnalysisSuccessOracle(definition, tool),
    )
    return CryptographicMisuseAnalysisCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_cryptographic_misuse_analysis_capability(
    *,
    bundle: CryptographicMisuseAnalysisCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> CryptographicMisuseAnalysisCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, CryptographicMisuseAnalysisCapabilityBundle):
        raise TypeError("Cryptographic activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Cryptographic activation requires a verified lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability()
        definition = bundle.definitions.resolve(capability.capability)
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition != registered_cryptographic_misuse_analysis_capability_definition()
    ):
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic signed release differs from code authority"
        )
    binding = CryptographicMisuseAnalysisCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return CryptographicMisuseAnalysisCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=CryptographicMisuseAnalysisCapabilityActivationSet(binding=binding),
    )


class CryptographicMisuseAnalysisBindingRef(_CryptographicMisuseAnalysisModel):
    """Exact content-addressed reference to the CRYPTO-001B static binding."""

    binding_id: Literal["pajin.cryptography.offline-misuse-analysis.binding"] = Field(
        alias="bindingId"
    )
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class CryptographicMisuseAnalysisBinding(_CryptographicMisuseAnalysisModel):
    """Exact Surface/CAP-002/custody/sandbox contract without artifact access."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-binding/v1alpha1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisBinding"] = "CryptographicMisuseAnalysisBinding"
    binding_id: Literal["pajin.cryptography.offline-misuse-analysis.binding"] = Field(
        default="pajin.cryptography.offline-misuse-analysis.binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["cryptography.protocol-key-artifact"] = Field(
        default="cryptography.protocol-key-artifact",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.cryptography.protocol-key-artifact.v1"] = Field(
        default="pajin.locator.cryptography.protocol-key-artifact.v1",
        alias="locatorSchema",
    )
    locator_registry: CryptographyProtocolKeyArtifactLocatorRegistryRef = Field(
        alias="locatorRegistry"
    )
    supported_locators: tuple[CryptographyProtocolKeyArtifactLocatorRef, ...] = Field(
        alias="supportedLocators",
        min_length=4,
        max_length=4,
    )
    capability: CodeBackedCapabilityRef
    capability_domain_classification: CryptographicMisuseAnalysisCapabilityDomainClassification = (
        Field(alias="capabilityDomainClassification")
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    rule_set: RegisteredCryptographicMisuseRuleSet = Field(alias="ruleSet")
    supported_input_kinds: tuple[CryptographicAnalysisInputKind, ...] = Field(
        default=tuple(sorted(CryptographicAnalysisInputKind, key=lambda item: item.value)),
        alias="supportedInputKinds",
    )
    supported_operations: tuple[CryptographicMisuseAnalysisOperation, ...] = Field(
        default=_SUPPORTED_OPERATIONS,
        alias="supportedOperations",
    )
    supported_analyzers: tuple[CryptographicMisuseAnalyzer, ...] = Field(
        default=_SUPPORTED_ANALYZERS,
        alias="supportedAnalyzers",
    )
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
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
    exact_rule_set_required: Literal[True] = Field(
        default=True,
        alias="exactRuleSetRequired",
    )
    bounded_budget_required: Literal[True] = Field(default=True, alias="boundedBudgetRequired")
    zero_live_channels_required: Literal[True] = Field(
        default=True,
        alias="zeroLiveChannelsRequired",
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
    authorization_verified: Literal[False] = Field(default=False, alias="authorizationVerified")
    declaration_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="declarationSanitizationVerified",
    )
    artifact_resolved: Literal[False] = Field(default=False, alias="artifactResolved")
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    misuse_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="misuseAnalysisAuthorized",
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
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    key_search_authorized: Literal[False] = Field(default=False, alias="keySearchAuthorized")
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="oracleInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
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
    ctf_runtime_reused: Literal[False] = Field(default=False, alias="ctfRuntimeReused")
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
        "exact_rule_set_required",
        "bounded_budget_required",
        "zero_live_channels_required",
        "network_disabled_sandbox_required",
        "read_only_artifact_mount_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "custody_runtime_verified",
        "authorization_verified",
        "declaration_sanitization_verified",
        "artifact_resolved",
        "artifact_read_authorized",
        "misuse_analysis_authorized",
        "sandbox_selected",
        "worker_selection_authorized",
        "artifact_mount_materialized",
        "key_material_access_authorized",
        "credential_use_authorized",
        "cryptographic_operation_authorized",
        "key_search_authorized",
        "protocol_negotiation_authorized",
        "oracle_invocation_authorized",
        "network_access_authorized",
        "artifact_mutation_authorized",
        "observation_production_authorized",
        "evidence_sealing_authorized",
        "graph_admission_authorized",
        "hypothesis_authority",
        "finding_authority",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "ctf_runtime_reused",
        "runtime_support_asserted_by_binding",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic misuse-analysis binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_cryptographic_misuse_analysis_capability_definition()
        registry = registered_cryptography_protocol_key_artifact_locator_registry()
        worker = _cryptographic_worker_boundary_profile()
        rule_set = registered_cryptographic_misuse_rule_set()
        expected_locators = tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        )
        if (
            self.locator_registry != registry.reference()
            or self.supported_locators != expected_locators
            or self.capability != _cryptographic_code_backed_capability()
            or self.capability_domain_classification
            != registered_cryptographic_misuse_analysis_capability_domain_classification()
            or self.worker_profile != worker.reference()
            or self.rule_set != rule_set
            or self.supported_input_kinds
            != tuple(sorted(CryptographicAnalysisInputKind, key=lambda item: item.value))
            or self.supported_operations != _SUPPORTED_OPERATIONS
            or self.supported_analyzers != _SUPPORTED_ANALYZERS
            or definition.supported_surface_types != _supported_locator_kinds()
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID
            or definition.network_access is not False
            or definition.approval_required is not True
            or worker.domain_classification.domain is not SecurityDomain.CRYPTOGRAPHY
            or worker.network_boundary is not WorkerNetworkBoundary.DISABLED_BY_DEFAULT
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.READ_ONLY_ARTIFACT
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.OFFLINE_SANDBOX
            or worker.required_identity_dimensions != ("analyzer", "artifact-digest")
            or worker.required_budget_dimensions != ("artifact-bytes", "runtime")
        ):
            raise ValueError("Cryptographic misuse-analysis binding differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"binding_digest"})
        digest = capability_definition_digest(
            "pajin.capability.cryptographic-misuse-analysis-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Cryptographic misuse-analysis binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> CryptographicMisuseAnalysisBindingRef:
        canonical = _canonical_model(
            CryptographicMisuseAnalysisBinding,
            self,
            label="Cryptographic misuse-analysis binding",
        )
        return CryptographicMisuseAnalysisBindingRef(
            bindingId=canonical.binding_id,
            bindingVersion=canonical.binding_version,
            bindingDigest=canonical.binding_digest,
        )


class CryptographicMisuseAnalysisPreparation(_CryptographicMisuseAnalysisModel):
    """Exact signed preparation with no artifact read, sandbox dispatch, or Finding."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-preparation/v1alpha1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisPreparation"] = (
        "CryptographicMisuseAnalysisPreparation"
    )
    preparation_id: str = Field(default="", alias="preparationId", max_length=110)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: CryptographicMisuseAnalysisBinding
    surface: CryptographyProtocolKeyArtifactSurface
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    operation: CryptographicMisuseAnalysisOperation
    artifact_custody: CryptographicAnalysisArtifactCustodyBinding = Field(alias="artifactCustody")
    sandbox: CryptographicMisuseAnalysisSandboxBinding
    analysis_request: CryptographicMisuseAnalysisRequest = Field(alias="analysisRequest")
    campaign_scope: CryptographicCampaignScopeBinding = Field(alias="campaignScope")
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
    exact_rule_set_bound: Literal[True] = Field(default=True, alias="exactRuleSetBound")
    network_disabled_sandbox_bound: Literal[True] = Field(
        default=True,
        alias="networkDisabledSandboxBound",
    )
    zero_live_channels_bound: Literal[True] = Field(
        default=True,
        alias="zeroLiveChannelsBound",
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
    declaration_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="declarationSanitizationVerified",
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
    key_material_accessed: Literal[False] = Field(default=False, alias="keyMaterialAccessed")
    credential_used: Literal[False] = Field(default=False, alias="credentialUsed")
    cryptographic_operation_performed: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationPerformed",
    )
    key_search_performed: Literal[False] = Field(default=False, alias="keySearchPerformed")
    protocol_negotiation_performed: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationPerformed",
    )
    oracle_invoked: Literal[False] = Field(default=False, alias="oracleInvoked")
    network_request_performed: Literal[False] = Field(
        default=False,
        alias="networkRequestPerformed",
    )
    misuse_analysis_executed: Literal[False] = Field(
        default=False,
        alias="misuseAnalysisExecuted",
    )
    artifact_mutated: Literal[False] = Field(default=False, alias="artifactMutated")
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
    ctf_runtime_reused: Literal[False] = Field(default=False, alias="ctfRuntimeReused")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "current_campaign_bound",
        "custody_authorization_reference_bound",
        "exact_rule_set_bound",
        "network_disabled_sandbox_bound",
        "zero_live_channels_bound",
        "analysis_request_adapted",
        "capability_prepared",
        "custody_runtime_verified",
        "authorization_verified_by_preparation",
        "declaration_sanitization_verified",
        "artifact_resolved",
        "artifact_bytes_verified",
        "artifact_read_performed",
        "sandbox_runtime_available",
        "sandbox_runtime_attested",
        "sandbox_selected",
        "artifact_mount_materialized",
        "budget_reserved",
        "worker_job_materialized",
        "key_material_accessed",
        "credential_used",
        "cryptographic_operation_performed",
        "key_search_performed",
        "protocol_negotiation_performed",
        "oracle_invoked",
        "network_request_performed",
        "misuse_analysis_executed",
        "artifact_mutated",
        "observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "hypothesis_produced",
        "finding_produced",
        "approval_satisfied",
        "permit_issuance_authorized",
        "gateway_dispatch_authorized",
        "worker_selection_authorized",
        "ctf_runtime_reused",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic misuse-analysis preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        expected_action = registered_action_capability(
            registered_cryptographic_misuse_analysis_capability_definition()
        ).reference()
        expected_surface_rule = _require_exact_scope_allow(
            self.campaign_scope,
            cryptographic_surface_scope_target(self.surface),
            label="Cryptographic Surface",
        )
        expected_request = BoundedCryptographicMisuseAnalyzerAdapter(
            self.artifact_custody,
            self.sandbox,
        ).prepare_request(surface=self.surface, operation=self.operation)
        request = self.prepared_action.request
        if (
            self.binding != registered_cryptographic_misuse_analysis_binding()
            or self.surface.initial_state != "registered-not-authorized"
            or self.input_kind is not _input_kind(self.surface)
            or self.analysis_request != expected_request
            or self.matched_surface_allow_rule != expected_surface_rule
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != self.analysis_request.target
            or request.arguments != self.analysis_request.model_dump(mode="json", by_alias=True)
        ):
            raise ValueError(
                "Cryptographic misuse-analysis preparation differs from code authority"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cryptographic-misuse-analysis-preparation/v1",
            material,
        )
        preparation_id = f"cryptographic-misuse-analysis-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Cryptographic misuse-analysis preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("Cryptographic misuse-analysis preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def bind_cryptographic_analysis_artifact_custody(
    *,
    surface: CryptographyProtocolKeyArtifactSurface,
    authorization_digest: str,
    artifact_bytes: int,
) -> CryptographicAnalysisArtifactCustodyBinding:
    """Pin an authorization-reference custody configuration without resolving bytes."""

    canonical_surface = _canonical_surface(surface)
    artifact_sha256 = _artifact_sha256(canonical_surface)
    try:
        return CryptographicAnalysisArtifactCustodyBinding(
            surface=canonical_surface,
            inputKind=_input_kind(canonical_surface),
            custodyAuthorityId=CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_AUTHORITY_ID,
            custodyObjectId=_cryptographic_artifact_object_id(artifact_sha256),
            authorizationId=_cryptographic_authorization_reference_id(authorization_digest),
            authorizationDigest=authorization_digest,
            artifactSHA256=artifact_sha256,
            artifactBytes=artifact_bytes,
        )
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, CryptographicMisuseAnalysisCapabilityError):
            raise
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic artifact custody binding failed closed"
        ) from exc


def bind_cryptographic_misuse_analysis_sandbox(
    *,
    surface: CryptographyProtocolKeyArtifactSurface,
    analyzer_executable_sha256: str,
    sandbox_image_sha256: str,
    max_artifact_bytes: int = 67_108_864,
    max_output_bytes: int = 1_048_576,
    max_runtime_seconds: int = 60,
    max_memory_mib: int = 512,
    max_process_count: int = 8,
) -> CryptographicMisuseAnalysisSandboxBinding:
    """Pin an offline sandbox configuration without selecting or invoking a Worker."""

    canonical_surface = _canonical_surface(surface)
    operation = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
    try:
        return CryptographicMisuseAnalysisSandboxBinding(
            deploymentId=CRYPTOGRAPHIC_MISUSE_ANALYSIS_DEPLOYMENT_ID,
            workerProfile=_cryptographic_worker_boundary_profile().reference(),
            surface=canonical_surface,
            ruleSet=registered_cryptographic_misuse_rule_set().reference(),
            operation=operation,
            analyzer=_ANALYZER_BY_OPERATION[operation],
            analyzerExecutableSHA256=analyzer_executable_sha256,
            sandboxImageSHA256=sandbox_image_sha256,
            runAsIdentity=CRYPTOGRAPHIC_MISUSE_ANALYSIS_RUN_AS_IDENTITY,
            maxArtifactBytes=max_artifact_bytes,
            maxOutputBytes=max_output_bytes,
            maxRuntimeSeconds=max_runtime_seconds,
            maxMemoryMiB=max_memory_mib,
            maxProcessCount=max_process_count,
        )
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, CryptographicMisuseAnalysisCapabilityError):
            raise
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic misuse-analysis sandbox binding failed closed"
        ) from exc


@cache
def _registered_cryptographic_misuse_analysis_binding() -> CryptographicMisuseAnalysisBinding:
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    return CryptographicMisuseAnalysisBinding(
        locatorRegistry=registry.reference(),
        supportedLocators=tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        ),
        capability=_cryptographic_code_backed_capability(),
        capabilityDomainClassification=(
            registered_cryptographic_misuse_analysis_capability_domain_classification()
        ),
        workerProfile=_cryptographic_worker_boundary_profile().reference(),
        ruleSet=registered_cryptographic_misuse_rule_set(),
    )


def registered_cryptographic_misuse_analysis_binding() -> CryptographicMisuseAnalysisBinding:
    """Return an isolated exact binding without artifact or sandbox access."""

    return _registered_cryptographic_misuse_analysis_binding().model_copy(deep=True)


def resolve_cryptographic_misuse_analysis_binding(
    reference: CryptographicMisuseAnalysisBindingRef,
) -> CryptographicMisuseAnalysisBinding:
    canonical = _canonical_model(
        CryptographicMisuseAnalysisBindingRef,
        reference,
        label="Cryptographic misuse-analysis binding reference",
    )
    binding = registered_cryptographic_misuse_analysis_binding()
    if binding.reference() == canonical:
        return binding.model_copy(deep=True)
    raise CryptographicMisuseAnalysisCapabilityError(
        "Cryptographic misuse-analysis binding is not registered exactly"
    )


@cache
def _registered_cryptographic_misuse_analysis_capability_domain_classification() -> (
    CryptographicMisuseAnalysisCapabilityDomainClassification
):
    capability = _cryptographic_code_backed_capability()
    return CryptographicMisuseAnalysisCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=_cryptographic_worker_boundary_profile().domain_classification,
    )


def registered_cryptographic_misuse_analysis_capability_domain_classification() -> (
    CryptographicMisuseAnalysisCapabilityDomainClassification
):
    """Return an isolated local exact Cryptography classification."""

    return _registered_cryptographic_misuse_analysis_capability_domain_classification().model_copy(
        deep=True
    )


def resolve_cryptographic_misuse_analysis_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
) -> CryptographicMisuseAnalysisCapabilityDomainClassification:
    canonical = _canonical_model(
        CapabilityDomainClassificationRef,
        reference,
        label="Cryptographic Capability Domain classification reference",
    )
    classification = registered_cryptographic_misuse_analysis_capability_domain_classification()
    if classification.reference() == canonical:
        return classification.model_copy(deep=True)
    raise CryptographicMisuseAnalysisCapabilityError(
        "Cryptographic Capability Domain classification is not registered exactly"
    )


def cryptographic_surface_scope_target(
    surface: CryptographyProtocolKeyArtifactSurface,
) -> str:
    """Return a non-routable exact Campaign Scope token for one Cryptography Surface."""

    canonical = _canonical_surface(surface)
    return f"{CRYPTOGRAPHIC_SURFACE_SCOPE_ORIGIN}/surfaces/{canonical.surface_id}"


def prepare_cryptographic_misuse_analysis(
    *,
    activation: CryptographicMisuseAnalysisCapabilityActivation,
    release: CapabilityReleaseRef,
    campaign: CampaignManifest,
    surface: CryptographyProtocolKeyArtifactSurface,
    operation: CryptographicMisuseAnalysisOperation,
    analyzer: BoundedCryptographicMisuseAnalyzerAdapter,
    request_id: str,
    agent_id: str,
) -> CryptographicMisuseAnalysisPreparation:
    """Compile exact signed analysis metadata and stop before artifact access."""

    if not isinstance(activation, CryptographicMisuseAnalysisCapabilityActivation):
        raise TypeError("Cryptographic preparation requires Cryptographic activation")
    if not isinstance(analyzer, BoundedCryptographicMisuseAnalyzerAdapter):
        raise TypeError("Cryptographic preparation requires a bounded analyzer adapter")
    try:
        canonical_operation = CryptographicMisuseAnalysisOperation(operation)
    except ValueError as exc:
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic misuse-analysis operation is unsupported"
        ) from exc
    canonical_campaign = _canonical_campaign(campaign)
    canonical_surface = _canonical_surface(surface)
    custody = analyzer.custody
    sandbox = analyzer.sandbox
    try:
        scope_binding = _campaign_scope_binding(canonical_campaign)
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, CryptographicMisuseAnalysisCapabilityError):
            raise
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic Campaign Scope binding failed closed"
        ) from exc
    surface_allow = _require_exact_scope_allow(
        scope_binding,
        cryptographic_surface_scope_target(canonical_surface),
        label="Cryptographic Surface",
    )
    analysis_request = analyzer.prepare_request(
        surface=canonical_surface,
        operation=canonical_operation,
    )
    binding = registered_cryptographic_misuse_analysis_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition()
            != registered_cryptographic_misuse_analysis_capability_definition()
        ):
            raise CryptographicMisuseAnalysisCapabilityError(
                "Cryptographic activation differs from the registered Capability"
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID,
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
        return CryptographicMisuseAnalysisPreparation(
            binding=binding,
            surface=canonical_surface,
            inputKind=_input_kind(canonical_surface),
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
        if isinstance(exc, CryptographicMisuseAnalysisCapabilityError):
            raise
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic CAP-002 preparation failed closed"
        ) from exc


def _verify_activation(activation: CryptographicMisuseAnalysisCapabilityActivation) -> None:
    if (
        type(activation.bundle) is not CryptographicMisuseAnalysisCapabilityBundle
        or type(activation.lifecycle) is not CapabilityLifecycleRegistry
        or type(activation.activation_set) is not CryptographicMisuseAnalysisCapabilityActivationSet
    ):
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic activation uses the wrong runtime types"
        )
    canonical_set = _canonical_model(
        CryptographicMisuseAnalysisCapabilityActivationSet,
        activation.activation_set,
        label="Cryptographic activation set",
    )
    _resolve_activation_binding(activation, canonical_set.binding)


def _resolve_activation_binding(
    activation: CryptographicMisuseAnalysisCapabilityActivation,
    binding: CryptographicMisuseAnalysisCapabilityActivationBinding,
) -> ResolvedCapabilityRelease:
    try:
        resolved = activation.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = activation.lifecycle.resolve_release(binding.release)
        definition = activation.bundle.definitions.resolve(resolved.capability.capability)
        expected_action = registered_action_capability(definition)
        bundle_capability = activation.bundle.capability()
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic current signed release could not be resolved"
        ) from exc
    if (
        bundle_capability != _cryptographic_code_backed_capability()
        or resolved.capability.reference() != binding.capability
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
        or expected_action != binding.action_capability
    ):
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic signed release binding drifted"
        )
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.cryptographic-misuse-analysis-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    return _canonical_model(
        CapabilityReleaseRef,
        reference,
        label="Cryptographic release reference",
    )


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    return _canonical_model(
        ToolRequest,
        request,
        label="Cryptographic Tool request",
        by_alias=False,
    )


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    return _canonical_model(
        CampaignManifest,
        campaign,
        label="Cryptographic Campaign",
    )


def _canonical_surface(
    surface: CryptographyProtocolKeyArtifactSurface,
) -> CryptographyProtocolKeyArtifactSurface:
    return _canonical_model(
        CryptographyProtocolKeyArtifactSurface,
        surface,
        label="Cryptography protocol/key/artifact Surface",
    )


def _campaign_scope_binding(campaign: CampaignManifest) -> CryptographicCampaignScopeBinding:
    return CryptographicCampaignScopeBinding(
        campaignName=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        scope=campaign.spec.scope.model_copy(deep=True),
        allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
        allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
    )


def _require_exact_scope_allow(
    scope_binding: CryptographicCampaignScopeBinding,
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
        raise CryptographicMisuseAnalysisCapabilityError(
            f"{label} Campaign Scope cannot be evaluated safely"
        ) from exc
    if canonical_target not in normalized_allow:
        raise CryptographicMisuseAnalysisCapabilityError(
            f"{label} lacks an exact current Campaign allow rule"
        )
    if any(scope_matches(rule, canonical_target) for rule in normalized_deny):
        raise CryptographicMisuseAnalysisCapabilityError(
            f"{label} overlaps a current Campaign deny rule"
        )
    return canonical_target


def _canonical_cryptographic_surface_target(value: str) -> str:
    try:
        canonical = normalize_target_url(value)
    except InvalidScopeURL as exc:
        raise ValueError("Cryptographic Surface target is invalid") from exc
    if canonical != value or not value.startswith(
        f"{CRYPTOGRAPHIC_SURFACE_SCOPE_ORIGIN}/surfaces/"
    ):
        raise ValueError("Cryptographic Surface target must be one canonical non-routable token")
    return value


def _validate_cryptographic_tool_request(
    request: ToolRequest,
) -> CryptographicMisuseAnalysisRequest:
    canonical_request = _canonical_tool_request(request)
    try:
        analysis = CryptographicMisuseAnalysisRequest.model_validate(canonical_request.arguments)
    except (ValidationError, ValueError) as exc:
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic Tool request arguments are invalid"
        ) from exc
    if (
        canonical_request.tool_id != CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID
        or canonical_request.method != "GET"
        or canonical_request.target != analysis.target
    ):
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic Tool request differs from bounded GET authority"
        )
    return analysis


def _input_kind(
    surface: CryptographyProtocolKeyArtifactSurface,
) -> CryptographicAnalysisInputKind:
    return _INPUT_KIND_BY_SURFACE_CLASS[surface.surface_class]


def _input_kind_from_surface_ref(
    surface: CryptographyProtocolKeyArtifactSurfaceRef,
) -> CryptographicAnalysisInputKind:
    return _INPUT_KIND_BY_SURFACE_CLASS[surface.surface_class]


def _artifact_sha256(surface: CryptographyProtocolKeyArtifactSurface) -> str:
    locator = surface.locator
    surface_class = surface.surface_class
    if locator.kind != _LOCATOR_KIND_BY_SURFACE_CLASS[surface_class]:
        raise CryptographicMisuseAnalysisCapabilityError(
            "Cryptographic Surface locator kind differs from analysis mapping"
        )
    digest_source = _DIGEST_SOURCE_BY_SURFACE_CLASS[surface_class]
    if digest_source is CryptographicAnalysisDigestSource.ARTIFACT_SHA256 and isinstance(
        locator, CryptographicCiphertextSurfaceLocator
    ):
        return locator.artifact_sha256
    if digest_source is CryptographicAnalysisDigestSource.DECLARATION_SHA256 and isinstance(
        locator,
        (
            CryptographicProtocolSurfaceLocator,
            CryptographicKeyUsageSurfaceLocator,
            CryptographicConfigurationSurfaceLocator,
        ),
    ):
        return locator.declaration_sha256
    raise CryptographicMisuseAnalysisCapabilityError(
        "Cryptographic Surface has no supported artifact coordinate"
    )


def _supported_locator_kinds() -> tuple[CryptographySurfaceLocatorKind, ...]:
    return (
        "cryptography-ciphertext",
        "cryptography-configuration",
        "cryptography-key-usage",
        "cryptography-protocol",
    )


@cache
def _cryptographic_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(CryptographicMisuseAnalysisTool())
    return cryptographic_misuse_analysis_capability_bundle(tools).capability()


@cache
def _cryptographic_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    )


__all__ = [
    "CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_AUTHORITY_ID",
    "CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_BINDING_API_VERSION",
    "CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_MOUNT_TARGET",
    "CRYPTOGRAPHIC_CAMPAIGN_SCOPE_BINDING_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_BINDING_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ADAPTER_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ID",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_DEPLOYMENT_ID",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_PREPARATION_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_REQUEST_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_RUN_AS_IDENTITY",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_SANDBOX_BINDING_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID",
    "CRYPTOGRAPHIC_MISUSE_RULE_SET_API_VERSION",
    "CRYPTOGRAPHIC_SURFACE_SCOPE_ORIGIN",
    "BoundedCryptographicMisuseAnalyzerAdapter",
    "CryptographicAnalysisArtifactCustodyBinding",
    "CryptographicAnalysisArtifactCustodyRef",
    "CryptographicAnalysisDigestSource",
    "CryptographicAnalysisInputKind",
    "CryptographicCampaignScopeBinding",
    "CryptographicMisuseAnalysisBinding",
    "CryptographicMisuseAnalysisBindingRef",
    "CryptographicMisuseAnalysisBudget",
    "CryptographicMisuseAnalysisCapabilityActivation",
    "CryptographicMisuseAnalysisCapabilityActivationBinding",
    "CryptographicMisuseAnalysisCapabilityActivationSet",
    "CryptographicMisuseAnalysisCapabilityBundle",
    "CryptographicMisuseAnalysisCapabilityDomainClassification",
    "CryptographicMisuseAnalysisCapabilityError",
    "CryptographicMisuseAnalysisOperation",
    "CryptographicMisuseAnalysisPreparation",
    "CryptographicMisuseAnalysisRequest",
    "CryptographicMisuseAnalysisSandboxBinding",
    "CryptographicMisuseAnalysisSandboxRef",
    "CryptographicMisuseAnalysisTool",
    "CryptographicMisuseAnalyzer",
    "CryptographicMisuseRuleSetRef",
    "CryptographicMisuseSignalKind",
    "CryptographicSurfaceAnalysisMapping",
    "RegisteredCryptographicMisuseRuleSet",
    "activate_cryptographic_misuse_analysis_capability",
    "bind_cryptographic_analysis_artifact_custody",
    "bind_cryptographic_misuse_analysis_sandbox",
    "cryptographic_misuse_analysis_capability_bundle",
    "cryptographic_surface_scope_target",
    "prepare_cryptographic_misuse_analysis",
    "registered_cryptographic_misuse_analysis_binding",
    "registered_cryptographic_misuse_analysis_capability_definition",
    "registered_cryptographic_misuse_analysis_capability_domain_classification",
    "registered_cryptographic_misuse_rule_set",
    "resolve_cryptographic_misuse_analysis_binding",
    "resolve_cryptographic_misuse_analysis_capability_domain_classification",
    "resolve_registered_cryptographic_misuse_rule_set",
]
