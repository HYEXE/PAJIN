"""FORENSICS-001B offline Forensic evidence analysis preparation boundaries."""

from __future__ import annotations

import re
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
from pajin.discovery.forensics_surfaces import (
    ForensicImmutableArtifactLocatorRef,
    ForensicImmutableArtifactLocatorRegistryRef,
    ForensicImmutableArtifactSurface,
    ForensicImmutableArtifactSurfaceRef,
    ForensicSurfaceClass,
    ForensicSurfaceLocatorKind,
    bind_forensic_immutable_artifact_surface_reference,
    registered_forensic_immutable_artifact_locator_registry,
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

FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ADAPTER_VERSION = (
    "pajin.forensic-evidence-analysis-capability-adapter/v1"
)
FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-capability-activation-set/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-capability-activation-set/v1alpha1"
FORENSIC_EVIDENCE_ANALYSIS_BINDING_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-binding/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-binding/v1alpha1"
FORENSIC_EVIDENCE_ANALYSIS_PREPARATION_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-preparation/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-preparation/v1alpha1"
FORENSIC_CAMPAIGN_SCOPE_BINDING_API_VERSION: Literal[
    "pajin.dev/forensic-campaign-scope-binding/v1alpha1"
] = "pajin.dev/forensic-campaign-scope-binding/v1alpha1"
FORENSIC_EVIDENCE_CUSTODY_BINDING_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-custody-binding/v1alpha1"
] = "pajin.dev/forensic-evidence-custody-binding/v1alpha1"
FORENSIC_EVIDENCE_ANALYSIS_SANDBOX_BINDING_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-sandbox-binding/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-sandbox-binding/v1alpha1"
FORENSIC_EVIDENCE_ANALYSIS_REQUEST_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-request/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-request/v1alpha1"
FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-capability-domain-classification/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-capability-domain-classification/v1alpha1"
FORENSIC_EVIDENCE_RULE_SET_API_VERSION: Literal["pajin.dev/forensic-parser-rule-set/v1alpha1"] = (
    "pajin.dev/forensic-parser-rule-set/v1alpha1"
)

FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ID = "pajin.forensics.read-only-evidence-analysis"
FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_VERSION = "1.0.0"
FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID = "forensics.read-only-evidence-analysis"
FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA: Literal[
    "pajin.forensics.read-only-evidence-analysis-result.v1"
] = "pajin.forensics.read-only-evidence-analysis-result.v1"
FORENSIC_SURFACE_SCOPE_ORIGIN = "https://forensics-scope.pajin.invalid"
FORENSIC_EVIDENCE_MOUNT_TARGET: Literal["/pajin/input/evidence"] = "/pajin/input/evidence"
FORENSIC_EVIDENCE_CUSTODY_AUTHORITY_ID: Literal[
    "pajin.forensics.unverified-immutable-evidence-custody-coordinate"
] = "pajin.forensics.unverified-immutable-evidence-custody-coordinate"
FORENSIC_EVIDENCE_ANALYSIS_DEPLOYMENT_ID: Literal["deployment:forensic-evidence-analysis"] = (
    "deployment:forensic-evidence-analysis"
)
FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY: Literal["svc:pajin-forensic-parser"] = (
    "svc:pajin-forensic-parser"
)
FORENSIC_PARSER_WORK_UNIT: Literal["one-source-or-expanded-byte-processed"] = (
    "one-source-or-expanded-byte-processed"
)

_AUTHORITY_VERSION = "1.0.0"
_MAX_ARTIFACT_BYTES = 536_870_912
_MAX_OUTPUT_BYTES = 16_777_216
_MAX_RUNTIME_SECONDS = 300
_MAX_MEMORY_MIB = 4_096
_MAX_PROCESS_COUNT = 64
_MAX_PARSER_WORK_UNITS = 8_589_934_592
_MAX_RECURSION_DEPTH = 128
_MAX_DECOMPRESSION_RATIO = 1_000
_MAX_DECOMPRESSED_BYTES = 4_294_967_296
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class ForensicEvidenceAnalysisCapabilityError(ValueError):
    """Raised when FORENSICS-001B Scope, custody, sandbox, or preparation drifts."""


class _ForensicEvidenceAnalysisModel(StrictModel):
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
            raise ForensicEvidenceAnalysisCapabilityError(
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
        if isinstance(exc, ForensicEvidenceAnalysisCapabilityError):
            raise
        raise ForensicEvidenceAnalysisCapabilityError(f"{label} is not canonical") from exc
    _require_known_instance_fields(canonical, label=label)
    if canonical != value:
        raise ForensicEvidenceAnalysisCapabilityError(f"{label} drifted")
    return canonical


class ForensicEvidenceAnalysisOperation(StrEnum):
    """One read-only logical operation for each FORENSICS-001A Surface class."""

    DISK_EVIDENCE = "disk-evidence-parse"
    MEMORY_EVIDENCE = "memory-evidence-parse"
    LOG_EVIDENCE = "log-evidence-parse"
    ARTIFACT_EVIDENCE = "artifact-evidence-parse"


class ForensicEvidenceParser(StrEnum):
    """Logical parser contract selected without runtime support claims."""

    DISK_EVIDENCE = "disk-evidence-parser"
    MEMORY_EVIDENCE = "memory-evidence-parser"
    LOG_EVIDENCE = "log-evidence-parser"
    ARTIFACT_EVIDENCE = "artifact-evidence-parser"


class ForensicEvidenceInputKind(StrEnum):
    """Class-owned meaning of one externally retained immutable input."""

    DISK_EVIDENCE = "disk-evidence"
    MEMORY_EVIDENCE = "memory-evidence"
    LOG_EVIDENCE = "log-evidence"
    ARTIFACT_EVIDENCE = "artifact-evidence"


class ForensicEvidenceDigestSource(StrEnum):
    """Exact FORENSICS-001A provenance field that identifies retained analysis input."""

    ARTIFACT_SHA256 = "artifact-sha256"


class ForensicEvidenceSignalKind(StrEnum):
    """Bounded future result vocabulary; no member is a Finding."""

    DISK_EVIDENCE = "forensics.disk-analysis"
    MEMORY_EVIDENCE = "forensics.memory-analysis"
    LOG_EVIDENCE = "forensics.log-analysis"
    ARTIFACT_EVIDENCE = "forensics.artifact-analysis"


_OPERATION_BY_SURFACE_CLASS: Mapping[
    ForensicSurfaceClass,
    ForensicEvidenceAnalysisOperation,
] = MappingProxyType(
    {
        ForensicSurfaceClass.DISK: ForensicEvidenceAnalysisOperation.DISK_EVIDENCE,
        ForensicSurfaceClass.MEMORY: ForensicEvidenceAnalysisOperation.MEMORY_EVIDENCE,
        ForensicSurfaceClass.LOG: ForensicEvidenceAnalysisOperation.LOG_EVIDENCE,
        ForensicSurfaceClass.ARTIFACT: ForensicEvidenceAnalysisOperation.ARTIFACT_EVIDENCE,
    }
)
_PARSER_BY_OPERATION: Mapping[
    ForensicEvidenceAnalysisOperation,
    ForensicEvidenceParser,
] = MappingProxyType(
    {
        ForensicEvidenceAnalysisOperation.DISK_EVIDENCE: ForensicEvidenceParser.DISK_EVIDENCE,
        ForensicEvidenceAnalysisOperation.MEMORY_EVIDENCE: (ForensicEvidenceParser.MEMORY_EVIDENCE),
        ForensicEvidenceAnalysisOperation.LOG_EVIDENCE: ForensicEvidenceParser.LOG_EVIDENCE,
        ForensicEvidenceAnalysisOperation.ARTIFACT_EVIDENCE: (
            ForensicEvidenceParser.ARTIFACT_EVIDENCE
        ),
    }
)
_INPUT_KIND_BY_SURFACE_CLASS: Mapping[
    ForensicSurfaceClass,
    ForensicEvidenceInputKind,
] = MappingProxyType(
    {
        ForensicSurfaceClass.DISK: ForensicEvidenceInputKind.DISK_EVIDENCE,
        ForensicSurfaceClass.MEMORY: ForensicEvidenceInputKind.MEMORY_EVIDENCE,
        ForensicSurfaceClass.LOG: ForensicEvidenceInputKind.LOG_EVIDENCE,
        ForensicSurfaceClass.ARTIFACT: ForensicEvidenceInputKind.ARTIFACT_EVIDENCE,
    }
)
_LOCATOR_KIND_BY_SURFACE_CLASS: Mapping[
    ForensicSurfaceClass,
    ForensicSurfaceLocatorKind,
] = MappingProxyType(
    {
        ForensicSurfaceClass.DISK: "forensics-disk",
        ForensicSurfaceClass.MEMORY: "forensics-memory",
        ForensicSurfaceClass.LOG: "forensics-log",
        ForensicSurfaceClass.ARTIFACT: "forensics-artifact",
    }
)
_DIGEST_SOURCE_BY_SURFACE_CLASS: Mapping[
    ForensicSurfaceClass,
    ForensicEvidenceDigestSource,
] = MappingProxyType(
    {
        ForensicSurfaceClass.DISK: ForensicEvidenceDigestSource.ARTIFACT_SHA256,
        ForensicSurfaceClass.MEMORY: ForensicEvidenceDigestSource.ARTIFACT_SHA256,
        ForensicSurfaceClass.LOG: ForensicEvidenceDigestSource.ARTIFACT_SHA256,
        ForensicSurfaceClass.ARTIFACT: ForensicEvidenceDigestSource.ARTIFACT_SHA256,
    }
)
_SUPPORTED_OPERATIONS = tuple(
    sorted(ForensicEvidenceAnalysisOperation, key=lambda item: item.value)
)
_SUPPORTED_PARSERS = tuple(sorted(ForensicEvidenceParser, key=lambda item: item.value))
_SUPPORTED_SIGNALS = tuple(sorted(ForensicEvidenceSignalKind, key=lambda item: item.value))


class ForensicSurfaceAnalysisMapping(_ForensicEvidenceAnalysisModel):
    """One exact Surface-to-input-to-parser semantic mapping row."""

    surface_class: ForensicSurfaceClass = Field(alias="surfaceClass")
    locator_kind: ForensicSurfaceLocatorKind = Field(alias="locatorKind")
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    digest_source: ForensicEvidenceDigestSource = Field(alias="digestSource")
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser

    @model_validator(mode="after")
    def bind_exact_mapping(self) -> Self:
        operation = _OPERATION_BY_SURFACE_CLASS[self.surface_class]
        if (
            self.locator_kind != _LOCATOR_KIND_BY_SURFACE_CLASS[self.surface_class]
            or self.input_kind is not _INPUT_KIND_BY_SURFACE_CLASS[self.surface_class]
            or self.digest_source is not _DIGEST_SOURCE_BY_SURFACE_CLASS[self.surface_class]
            or self.operation is not operation
            or self.parser is not _PARSER_BY_OPERATION[operation]
        ):
            raise ValueError("Forensic Surface analysis mapping differs")
        return self


_SUPPORTED_SURFACE_ANALYSIS_MAPPING = tuple(
    ForensicSurfaceAnalysisMapping(
        surfaceClass=surface_class,
        locatorKind=_LOCATOR_KIND_BY_SURFACE_CLASS[surface_class],
        inputKind=_INPUT_KIND_BY_SURFACE_CLASS[surface_class],
        digestSource=_DIGEST_SOURCE_BY_SURFACE_CLASS[surface_class],
        operation=_OPERATION_BY_SURFACE_CLASS[surface_class],
        parser=_PARSER_BY_OPERATION[_OPERATION_BY_SURFACE_CLASS[surface_class]],
    )
    for surface_class in sorted(ForensicSurfaceClass, key=lambda item: item.value)
)


def _forensic_evidence_rule_set_digest(
    *,
    rule_set_id: str,
    rule_set_version: str,
    signal_vocabulary: tuple[ForensicEvidenceSignalKind, ...],
    surface_analysis_mapping: tuple[ForensicSurfaceAnalysisMapping, ...],
) -> str:
    return capability_definition_digest(
        "pajin.capability.forensic-parser-rule-set/v1",
        {
            "ruleSetId": rule_set_id,
            "ruleSetVersion": rule_set_version,
            "signalVocabulary": [item.value for item in signal_vocabulary],
            "surfaceAnalysisMapping": [
                item.model_dump(mode="json", by_alias=True) for item in surface_analysis_mapping
            ],
        },
    )


class ForensicEvidenceRuleSetRef(_ForensicEvidenceAnalysisModel):
    """Exact reference to the code-owned parser mapping and bounded signal vocabulary."""

    rule_set_id: Literal["pajin.forensics.parser-rules.baseline"] = Field(alias="ruleSetId")
    rule_set_version: Literal["1.0.0"] = Field(alias="ruleSetVersion")
    rule_set_digest: _Sha256 = Field(alias="ruleSetDigest")
    signal_vocabulary: tuple[ForensicEvidenceSignalKind, ...] = Field(
        alias="signalVocabulary",
        min_length=4,
        max_length=4,
    )
    surface_analysis_mapping: tuple[ForensicSurfaceAnalysisMapping, ...] = Field(
        alias="surfaceAnalysisMapping",
        min_length=4,
        max_length=4,
    )

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _forensic_evidence_rule_set_digest(
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
            raise ValueError("Forensic parser rule-set reference differs")
        return self


class RegisteredForensicEvidenceRuleSet(_ForensicEvidenceAnalysisModel):
    """One code-owned parser vocabulary without runtime or Finding authority."""

    api_version: Literal["pajin.dev/forensic-parser-rule-set/v1alpha1"] = Field(
        default=FORENSIC_EVIDENCE_RULE_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredForensicEvidenceRuleSet"] = "RegisteredForensicEvidenceRuleSet"
    rule_set_id: Literal["pajin.forensics.parser-rules.baseline"] = Field(
        default="pajin.forensics.parser-rules.baseline",
        alias="ruleSetId",
    )
    rule_set_version: Literal["1.0.0"] = Field(default="1.0.0", alias="ruleSetVersion")
    rule_set_digest: str = Field(default="", alias="ruleSetDigest", max_length=64)
    signal_vocabulary: tuple[ForensicEvidenceSignalKind, ...] = Field(
        default=_SUPPORTED_SIGNALS,
        alias="signalVocabulary",
        min_length=4,
        max_length=4,
    )
    surface_analysis_mapping: tuple[ForensicSurfaceAnalysisMapping, ...] = Field(
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
    parser_runtime_available: Literal[False] = Field(
        default=False,
        alias="parserRuntimeAvailable",
    )
    analysis_truth_confirmed: Literal[False] = Field(
        default=False,
        alias="analysisTruthConfirmed",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "rule_set_only",
        "caller_rule_selection_allowed",
        "plugin_loading_allowed",
        "parser_runtime_available",
        "analysis_truth_confirmed",
        "finding_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic parser rule-set markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_rule_set_identity(self) -> Self:
        if (
            self.signal_vocabulary != _SUPPORTED_SIGNALS
            or self.surface_analysis_mapping != _SUPPORTED_SURFACE_ANALYSIS_MAPPING
        ):
            raise ValueError("Forensic parser rule-set semantics differ")
        digest = _forensic_evidence_rule_set_digest(
            rule_set_id=self.rule_set_id,
            rule_set_version=self.rule_set_version,
            signal_vocabulary=self.signal_vocabulary,
            surface_analysis_mapping=self.surface_analysis_mapping,
        )
        if self.rule_set_digest and self.rule_set_digest != digest:
            raise ValueError("Forensic parser rule-set digest differs")
        object.__setattr__(self, "rule_set_digest", digest)
        return self

    def reference(self) -> ForensicEvidenceRuleSetRef:
        canonical = _canonical_model(
            RegisteredForensicEvidenceRuleSet,
            self,
            label="Registered Forensic parser rule set",
        )
        return ForensicEvidenceRuleSetRef(
            ruleSetId=canonical.rule_set_id,
            ruleSetVersion=canonical.rule_set_version,
            ruleSetDigest=canonical.rule_set_digest,
            signalVocabulary=canonical.signal_vocabulary,
            surfaceAnalysisMapping=canonical.surface_analysis_mapping,
        )


@cache
def _registered_forensic_evidence_rule_set() -> RegisteredForensicEvidenceRuleSet:
    return RegisteredForensicEvidenceRuleSet()


def registered_forensic_evidence_rule_set() -> RegisteredForensicEvidenceRuleSet:
    """Return an isolated copy of the exact non-executable parser vocabulary."""

    return _registered_forensic_evidence_rule_set().model_copy(deep=True)


def resolve_registered_forensic_evidence_rule_set(
    reference: ForensicEvidenceRuleSetRef,
) -> RegisteredForensicEvidenceRuleSet:
    canonical = _canonical_model(
        ForensicEvidenceRuleSetRef,
        reference,
        label="Forensic parser rule-set reference",
    )
    rule_set = registered_forensic_evidence_rule_set()
    if canonical == rule_set.reference():
        return rule_set.model_copy(deep=True)
    raise ForensicEvidenceAnalysisCapabilityError(
        "Forensic parser rule set is not registered exactly"
    )


def _forensic_evidence_custody_digest(
    *,
    custody_binding_version: str,
    surface: ForensicImmutableArtifactSurfaceRef,
    input_kind: ForensicEvidenceInputKind,
    custody_authority_id: str,
    custody_object_id: str,
    authorization_id: str,
    authorization_digest: str,
    artifact_sha256: str,
    artifact_bytes: int,
) -> str:
    return capability_definition_digest(
        "pajin.capability.forensic-evidence-custody/v1",
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


def _forensic_evidence_object_id(surface_digest: str) -> str:
    return f"forensic-evidence_{surface_digest}"


def _forensic_authorization_reference_id(authorization_digest: str) -> str:
    return f"forensic-analysis-authorization_{authorization_digest}"


def _forensic_analysis_sandbox_digest(
    *,
    sandbox_binding_version: str,
    deployment_id: str,
    worker_profile: DomainWorkerBoundaryProfileRef,
    surface: ForensicImmutableArtifactSurfaceRef,
    rule_set: ForensicEvidenceRuleSetRef,
    operation: ForensicEvidenceAnalysisOperation,
    parser: ForensicEvidenceParser,
    parser_executable_sha256: str,
    parser_configuration_sha256: str,
    sandbox_image_sha256: str,
    run_as_identity: str,
    output_schema: str,
    max_artifact_bytes: int,
    max_output_bytes: int,
    max_runtime_seconds: int,
    max_memory_mib: int,
    max_process_count: int,
    parser_work_unit: str,
    max_parser_work_units: int,
    max_recursion_depth: int,
    max_decompression_ratio: int,
    max_decompressed_bytes: int,
) -> str:
    return capability_definition_digest(
        "pajin.capability.forensic-evidence-analysis-sandbox/v1",
        {
            "sandboxBindingVersion": sandbox_binding_version,
            "deploymentId": deployment_id,
            "workerProfile": worker_profile.model_dump(mode="json", by_alias=True),
            "surface": surface.model_dump(mode="json", by_alias=True),
            "ruleSet": rule_set.model_dump(mode="json", by_alias=True),
            "operation": operation.value,
            "parser": parser.value,
            "parserExecutableSHA256": parser_executable_sha256,
            "parserConfigurationSHA256": parser_configuration_sha256,
            "sandboxImageSHA256": sandbox_image_sha256,
            "runAsIdentity": run_as_identity,
            "outputSchema": output_schema,
            "maxArtifactBytes": max_artifact_bytes,
            "maxOutputBytes": max_output_bytes,
            "maxRuntimeSeconds": max_runtime_seconds,
            "maxMemoryMiB": max_memory_mib,
            "maxProcessCount": max_process_count,
            "parserWorkUnit": parser_work_unit,
            "maxParserWorkUnits": max_parser_work_units,
            "maxRecursionDepth": max_recursion_depth,
            "maxDecompressionRatio": max_decompression_ratio,
            "maxDecompressedBytes": max_decompressed_bytes,
        },
    )


class ForensicEvidenceCustodyRef(_ForensicEvidenceAnalysisModel):
    """Secret-free custody-coordinate reference that remains unverified until execution."""

    custody_binding_id: str = Field(
        alias="custodyBindingId",
        pattern=r"^forensic-evidence-custody_[a-f0-9]{64}$",
    )
    custody_binding_version: Literal["1.0.0"] = Field(alias="custodyBindingVersion")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    surface: ForensicImmutableArtifactSurfaceRef
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    custody_authority_id: Literal[
        "pajin.forensics.unverified-immutable-evidence-custody-coordinate"
    ] = Field(alias="custodyAuthorityId")
    custody_object_id: str = Field(
        alias="custodyObjectId",
        pattern=r"^forensic-evidence_[a-f0-9]{64}$",
    )
    authorization_id: str = Field(
        alias="authorizationId",
        pattern=r"^forensic-analysis-authorization_[a-f0-9]{64}$",
    )
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", ge=0, le=_MAX_ARTIFACT_BYTES)

    @field_validator("artifact_bytes", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forensic custody artifact bytes must be an integer")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _forensic_evidence_custody_digest(
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
            or self.custody_binding_id != f"forensic-evidence-custody_{digest}"
            or self.custody_object_id != _forensic_evidence_object_id(self.surface.surface_digest)
            or self.authorization_id
            != _forensic_authorization_reference_id(self.authorization_digest)
        ):
            raise ValueError("Forensic artifact custody reference identity differs")
        return self


class ForensicEvidenceCustodyBinding(_ForensicEvidenceAnalysisModel):
    """Configuration-only custody coordinate; no source is resolved, verified, or read."""

    api_version: Literal["pajin.dev/forensic-evidence-custody-binding/v1alpha1"] = Field(
        default=FORENSIC_EVIDENCE_CUSTODY_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceCustodyBinding"] = "ForensicEvidenceCustodyBinding"
    custody_binding_id: str = Field(default="", alias="custodyBindingId", max_length=98)
    custody_binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="custodyBindingVersion",
    )
    custody_binding_digest: str = Field(default="", alias="custodyBindingDigest", max_length=64)
    surface: ForensicImmutableArtifactSurface
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    custody_authority_id: Literal[
        "pajin.forensics.unverified-immutable-evidence-custody-coordinate"
    ] = Field(alias="custodyAuthorityId")
    custody_object_id: str = Field(
        alias="custodyObjectId",
        pattern=r"^forensic-evidence_[a-f0-9]{64}$",
    )
    authorization_id: str = Field(
        alias="authorizationId",
        pattern=r"^forensic-analysis-authorization_[a-f0-9]{64}$",
    )
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", ge=0, le=_MAX_ARTIFACT_BYTES)
    configuration_only: Literal[True] = Field(default=True, alias="configurationOnly")
    complete_surface_bound: Literal[True] = Field(
        default=True,
        alias="completeSurfaceBound",
    )
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
    provenance_preservation_required: Literal[True] = Field(
        default=True,
        alias="provenancePreservationRequired",
    )
    no_source_mutation_required: Literal[True] = Field(
        default=True,
        alias="noSourceMutationRequired",
    )
    raw_source_bytes_embedded: Literal[False] = Field(
        default=False,
        alias="rawSourceBytesEmbedded",
    )
    raw_disk_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawDiskContentEmbedded",
    )
    raw_memory_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawMemoryContentEmbedded",
    )
    raw_log_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawLogContentEmbedded",
    )
    raw_artifact_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentEmbedded",
    )
    raw_provenance_record_embedded: Literal[False] = Field(
        default=False,
        alias="rawProvenanceRecordEmbedded",
    )
    mutable_path_embedded: Literal[False] = Field(default=False, alias="mutablePathEmbedded")
    source_uri_embedded: Literal[False] = Field(default=False, alias="sourceURIEmbedded")
    object_key_embedded: Literal[False] = Field(default=False, alias="objectKeyEmbedded")
    filename_embedded: Literal[False] = Field(default=False, alias="filenameEmbedded")
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )
    authorization_verified_by_preparation: Literal[False] = Field(
        default=False,
        alias="authorizationVerifiedByPreparation",
    )
    source_root_verified: Literal[False] = Field(default=False, alias="sourceRootVerified")
    source_artifact_record_verified: Literal[False] = Field(
        default=False,
        alias="sourceArtifactRecordVerified",
    )
    provenance_record_verified: Literal[False] = Field(
        default=False,
        alias="provenanceRecordVerified",
    )
    source_seal_verified: Literal[False] = Field(default=False, alias="sourceSealVerified")
    source_authenticity_verified: Literal[False] = Field(
        default=False,
        alias="sourceAuthenticityVerified",
    )
    source_immutability_verified: Literal[False] = Field(
        default=False,
        alias="sourceImmutabilityVerified",
    )
    source_artifact_membership_verified: Literal[False] = Field(
        default=False,
        alias="sourceArtifactMembershipVerified",
    )
    chain_of_custody_verified: Literal[False] = Field(
        default=False,
        alias="chainOfCustodyVerified",
    )
    custody_runtime_verified: Literal[False] = Field(
        default=False,
        alias="custodyRuntimeVerified",
    )
    artifact_digest_verified: Literal[False] = Field(
        default=False,
        alias="artifactDigestVerified",
    )
    artifact_bytes_verified: Literal[False] = Field(
        default=False,
        alias="artifactBytesVerified",
    )
    evidence_class_verified: Literal[False] = Field(
        default=False,
        alias="evidenceClassVerified",
    )
    source_format_verified: Literal[False] = Field(default=False, alias="sourceFormatVerified")
    provenance_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="provenanceSanitizationVerified",
    )
    provenance_preserved: Literal[False] = Field(default=False, alias="provenancePreserved")
    provenance_preservation_verified: Literal[False] = Field(
        default=False,
        alias="provenancePreservationVerified",
    )
    parser_result_available: Literal[False] = Field(
        default=False,
        alias="parserResultAvailable",
    )
    source_resolved: Literal[False] = Field(default=False, alias="sourceResolved")
    source_read_authorized: Literal[False] = Field(
        default=False,
        alias="sourceReadAuthorized",
    )
    source_mount_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMountAuthorized",
    )
    source_copy_authorized: Literal[False] = Field(
        default=False,
        alias="sourceCopyAuthorized",
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceMutationAuthorized",
    )
    mount_materialized: Literal[False] = Field(default=False, alias="mountMaterialized")
    no_mutation_verified: Literal[False] = Field(default=False, alias="noMutationVerified")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("artifact_bytes", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forensic custody artifact bytes must be an integer")
        return value

    @field_validator(
        "configuration_only",
        "complete_surface_bound",
        "deployment_authorization_reference_bound",
        "immutable_digest_required",
        "read_only_mount_required",
        "provenance_preservation_required",
        "no_source_mutation_required",
        "raw_source_bytes_embedded",
        "raw_disk_content_embedded",
        "raw_memory_content_embedded",
        "raw_log_content_embedded",
        "raw_artifact_content_embedded",
        "raw_provenance_record_embedded",
        "mutable_path_embedded",
        "source_uri_embedded",
        "object_key_embedded",
        "filename_embedded",
        "secret_material_embedded",
        "credential_material_embedded",
        "credential_reference_embedded",
        "authorization_verified_by_preparation",
        "source_root_verified",
        "source_artifact_record_verified",
        "provenance_record_verified",
        "source_seal_verified",
        "source_authenticity_verified",
        "source_immutability_verified",
        "source_artifact_membership_verified",
        "chain_of_custody_verified",
        "custody_runtime_verified",
        "artifact_digest_verified",
        "artifact_bytes_verified",
        "evidence_class_verified",
        "source_format_verified",
        "provenance_sanitization_verified",
        "provenance_preserved",
        "provenance_preservation_verified",
        "parser_result_available",
        "source_resolved",
        "source_read_authorized",
        "source_mount_authorized",
        "source_copy_authorized",
        "evidence_mutation_authorized",
        "mount_materialized",
        "no_mutation_verified",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic artifact custody markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_custody_identity(self) -> Self:
        surface = _canonical_surface(self.surface)
        if (
            surface != self.surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.input_kind is not _input_kind(self.surface)
            or self.artifact_sha256 != _artifact_sha256(self.surface)
            or self.artifact_bytes != self.surface.locator.provenance.artifact_bytes
            or self.custody_authority_id != FORENSIC_EVIDENCE_CUSTODY_AUTHORITY_ID
            or self.custody_object_id != _forensic_evidence_object_id(self.surface.surface_digest)
            or self.authorization_id
            != _forensic_authorization_reference_id(self.authorization_digest)
        ):
            raise ValueError("Forensic artifact custody differs from the exact Surface")
        digest = _forensic_evidence_custody_digest(
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
        binding_id = f"forensic-evidence-custody_{digest}"
        if self.custody_binding_digest and self.custody_binding_digest != digest:
            raise ValueError("Forensic artifact custody digest differs")
        if self.custody_binding_id and self.custody_binding_id != binding_id:
            raise ValueError("Forensic artifact custody ID differs")
        object.__setattr__(self, "custody_binding_digest", digest)
        object.__setattr__(self, "custody_binding_id", binding_id)
        return self

    def reference(self) -> ForensicEvidenceCustodyRef:
        canonical = _canonical_model(
            ForensicEvidenceCustodyBinding,
            self,
            label="Forensic evidence custody binding",
        )
        return ForensicEvidenceCustodyRef(
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


class ForensicEvidenceAnalysisSandboxRef(_ForensicEvidenceAnalysisModel):
    """Exact non-secret reference to one network-disabled sandbox configuration."""

    sandbox_binding_id: str = Field(
        alias="sandboxBindingId",
        pattern=r"^forensic-analysis-sandbox_[a-f0-9]{64}$",
    )
    sandbox_binding_version: Literal["1.0.0"] = Field(alias="sandboxBindingVersion")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: Literal["deployment:forensic-evidence-analysis"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_DEPLOYMENT_ID,
        alias="deploymentId",
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    surface: ForensicImmutableArtifactSurfaceRef
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    parser_configuration_sha256: _Sha256 = Field(alias="parserConfigurationSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: Literal["svc:pajin-forensic-parser"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY,
        alias="runAsIdentity",
    )
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        alias="outputSchema"
    )
    max_artifact_bytes: int = Field(alias="maxArtifactBytes", ge=1, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1_024, le=_MAX_OUTPUT_BYTES)
    max_runtime_seconds: int = Field(alias="maxRuntimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    max_memory_mib: int = Field(alias="maxMemoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    max_process_count: int = Field(alias="maxProcessCount", ge=1, le=_MAX_PROCESS_COUNT)
    parser_work_unit: Literal["one-source-or-expanded-byte-processed"] = Field(
        default=FORENSIC_PARSER_WORK_UNIT,
        alias="parserWorkUnit",
    )
    max_parser_work_units: int = Field(
        alias="maxParserWorkUnits",
        ge=1,
        le=_MAX_PARSER_WORK_UNITS,
    )
    max_recursion_depth: int = Field(
        alias="maxRecursionDepth",
        ge=1,
        le=_MAX_RECURSION_DEPTH,
    )
    max_decompression_ratio: int = Field(
        alias="maxDecompressionRatio",
        ge=1,
        le=_MAX_DECOMPRESSION_RATIO,
    )
    max_decompressed_bytes: int = Field(
        alias="maxDecompressedBytes",
        ge=1,
        le=_MAX_DECOMPRESSED_BYTES,
    )

    @field_validator(
        "max_artifact_bytes",
        "max_output_bytes",
        "max_runtime_seconds",
        "max_memory_mib",
        "max_process_count",
        "max_parser_work_units",
        "max_recursion_depth",
        "max_decompression_ratio",
        "max_decompressed_bytes",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forensic sandbox reference ceilings must be integers")
        return value

    @model_validator(mode="after")
    def bind_reference_identity(self) -> Self:
        digest = _forensic_analysis_sandbox_digest(
            sandbox_binding_version=self.sandbox_binding_version,
            deployment_id=self.deployment_id,
            worker_profile=self.worker_profile,
            surface=self.surface,
            rule_set=self.rule_set,
            operation=self.operation,
            parser=self.parser,
            parser_executable_sha256=self.parser_executable_sha256,
            parser_configuration_sha256=self.parser_configuration_sha256,
            sandbox_image_sha256=self.sandbox_image_sha256,
            run_as_identity=self.run_as_identity,
            output_schema=self.output_schema,
            max_artifact_bytes=self.max_artifact_bytes,
            max_output_bytes=self.max_output_bytes,
            max_runtime_seconds=self.max_runtime_seconds,
            max_memory_mib=self.max_memory_mib,
            max_process_count=self.max_process_count,
            parser_work_unit=self.parser_work_unit,
            max_parser_work_units=self.max_parser_work_units,
            max_recursion_depth=self.max_recursion_depth,
            max_decompression_ratio=self.max_decompression_ratio,
            max_decompressed_bytes=self.max_decompressed_bytes,
        )
        if (
            self.sandbox_binding_digest != digest
            or self.sandbox_binding_id != f"forensic-analysis-sandbox_{digest}"
            or self.worker_profile != _forensic_worker_boundary_profile().reference()
            or self.rule_set != registered_forensic_evidence_rule_set().reference()
            or self.parser is not _PARSER_BY_OPERATION[self.operation]
            or self.max_parser_work_units < self.max_artifact_bytes
            or self.max_decompressed_bytes > self.max_artifact_bytes * self.max_decompression_ratio
        ):
            raise ValueError("Forensic analysis sandbox reference differs")
        return self


class ForensicEvidenceAnalysisSandboxBinding(_ForensicEvidenceAnalysisModel):
    """Configuration-only offline sandbox boundary without selection or execution."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-sandbox-binding/v1alpha1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_SANDBOX_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisSandboxBinding"] = (
        "ForensicEvidenceAnalysisSandboxBinding"
    )
    sandbox_binding_id: str = Field(default="", alias="sandboxBindingId", max_length=100)
    sandbox_binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="sandboxBindingVersion",
    )
    sandbox_binding_digest: str = Field(default="", alias="sandboxBindingDigest", max_length=64)
    deployment_id: Literal["deployment:forensic-evidence-analysis"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_DEPLOYMENT_ID,
        alias="deploymentId",
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    surface: ForensicImmutableArtifactSurface
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    parser_configuration_sha256: _Sha256 = Field(alias="parserConfigurationSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: Literal["svc:pajin-forensic-parser"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY,
        alias="runAsIdentity",
    )
    evidence_mount_target: Literal["/pajin/input/evidence"] = Field(
        default=FORENSIC_EVIDENCE_MOUNT_TARGET,
        alias="evidenceMountTarget",
    )
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
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
    parser_work_unit: Literal["one-source-or-expanded-byte-processed"] = Field(
        default=FORENSIC_PARSER_WORK_UNIT,
        alias="parserWorkUnit",
    )
    max_parser_work_units: int = Field(
        alias="maxParserWorkUnits",
        ge=1,
        le=_MAX_PARSER_WORK_UNITS,
    )
    max_recursion_depth: int = Field(
        alias="maxRecursionDepth",
        ge=1,
        le=_MAX_RECURSION_DEPTH,
    )
    max_decompression_ratio: int = Field(
        alias="maxDecompressionRatio",
        ge=1,
        le=_MAX_DECOMPRESSION_RATIO,
    )
    max_decompressed_bytes: int = Field(
        alias="maxDecompressedBytes",
        ge=1,
        le=_MAX_DECOMPRESSED_BYTES,
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
    immutable_read_only_evidence_mount_required: Literal[True] = Field(
        default=True,
        alias="immutableReadOnlyEvidenceMountRequired",
    )
    evidence_mount_noexec_required: Literal[True] = Field(
        default=True,
        alias="evidenceMountNoexecRequired",
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
    exact_parser_configuration_digest_required: Literal[True] = Field(
        default=True,
        alias="exactParserConfigurationDigestRequired",
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
    provenance_preservation_required: Literal[True] = Field(
        default=True,
        alias="provenancePreservationRequired",
    )
    no_source_mutation_required: Literal[True] = Field(
        default=True,
        alias="noSourceMutationRequired",
    )
    pre_post_no_mutation_evidence_required: Literal[True] = Field(
        default=True,
        alias="prePostNoMutationEvidenceRequired",
    )
    host_filesystem_access_allowed: Literal[False] = Field(
        default=False,
        alias="hostFilesystemAccessAllowed",
    )
    credential_injection_allowed: Literal[False] = Field(
        default=False,
        alias="credentialInjectionAllowed",
    )
    secret_material_injection_allowed: Literal[False] = Field(
        default=False,
        alias="secretMaterialInjectionAllowed",
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
    evidence_mount_materialized: Literal[False] = Field(
        default=False,
        alias="evidenceMountMaterialized",
    )
    source_read_authorized: Literal[False] = Field(
        default=False,
        alias="sourceReadAuthorized",
    )
    source_mount_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMountAuthorized",
    )
    source_copy_authorized: Literal[False] = Field(
        default=False,
        alias="sourceCopyAuthorized",
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
    secret_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="secretMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    lateral_movement_authorized: Literal[False] = Field(
        default=False,
        alias="lateralMovementAuthorized",
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceMutationAuthorized",
    )
    parser_conformance_verified: Literal[False] = Field(
        default=False,
        alias="parserConformanceVerified",
    )
    provenance_preserved: Literal[False] = Field(default=False, alias="provenancePreserved")
    provenance_preservation_verified: Literal[False] = Field(
        default=False,
        alias="provenancePreservationVerified",
    )
    parser_result_available: Literal[False] = Field(
        default=False,
        alias="parserResultAvailable",
    )
    no_mutation_verified: Literal[False] = Field(default=False, alias="noMutationVerified")
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    parser_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="parserInvocationAuthorized",
    )
    target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="targetExecutionAuthorized",
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
        "max_parser_work_units",
        "max_recursion_depth",
        "max_decompression_ratio",
        "max_decompressed_bytes",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forensic sandbox resource ceilings must be integers")
        return value

    @field_validator(
        "configuration_only",
        "network_disabled_required",
        "dns_disabled_required",
        "read_only_root_filesystem_required",
        "immutable_read_only_evidence_mount_required",
        "evidence_mount_noexec_required",
        "no_new_privileges_required",
        "non_root_runtime_required",
        "exact_parser_executable_digest_required",
        "exact_parser_configuration_digest_required",
        "exact_sandbox_image_digest_required",
        "exact_rule_set_required",
        "core_dump_disabled_required",
        "provenance_preservation_required",
        "no_source_mutation_required",
        "pre_post_no_mutation_evidence_required",
        "host_filesystem_access_allowed",
        "credential_injection_allowed",
        "secret_material_injection_allowed",
        "environment_inheritance_allowed",
        "symlink_traversal_allowed",
        "device_access_allowed",
        "plugin_loading_allowed",
        "shell_command_allowed",
        "runtime_attested",
        "sandbox_selected",
        "evidence_mount_materialized",
        "source_read_authorized",
        "source_mount_authorized",
        "source_copy_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "dns_access_authorized",
        "secret_material_access_authorized",
        "credential_use_authorized",
        "lateral_movement_authorized",
        "source_mutation_authorized",
        "evidence_mutation_authorized",
        "parser_conformance_verified",
        "provenance_preserved",
        "provenance_preservation_verified",
        "parser_result_available",
        "no_mutation_verified",
        "worker_job_materialized",
        "parser_invocation_authorized",
        "target_execution_authorized",
        "raw_result_echo_allowed",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic sandbox markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_sandbox_identity(self) -> Self:
        surface = _canonical_surface(self.surface)
        worker = _forensic_worker_boundary_profile()
        rule_set = registered_forensic_evidence_rule_set().reference()
        if (
            surface != self.surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.worker_profile != worker.reference()
            or self.rule_set != rule_set
            or self.operation is not _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class]
            or self.parser is not _PARSER_BY_OPERATION[self.operation]
            or self.max_parser_work_units < self.max_artifact_bytes
            or self.max_decompressed_bytes > self.max_artifact_bytes * self.max_decompression_ratio
            or worker.domain_classification.domain is not SecurityDomain.FORENSICS
            or worker.network_boundary is not WorkerNetworkBoundary.DISABLED_BY_DEFAULT
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.IMMUTABLE_EVIDENCE
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.PROVENANCE_PRESERVING_PARSER
            or worker.required_identity_dimensions != ("evidence-source", "parser")
            or worker.required_budget_dimensions != ("artifact-bytes", "runtime")
            or worker.provenance_preservation_required is not True
        ):
            raise ValueError("Forensic analysis sandbox differs from code authority")
        digest = _forensic_analysis_sandbox_digest(
            sandbox_binding_version=self.sandbox_binding_version,
            deployment_id=self.deployment_id,
            worker_profile=self.worker_profile,
            surface=surface.reference(),
            rule_set=self.rule_set,
            operation=self.operation,
            parser=self.parser,
            parser_executable_sha256=self.parser_executable_sha256,
            parser_configuration_sha256=self.parser_configuration_sha256,
            sandbox_image_sha256=self.sandbox_image_sha256,
            run_as_identity=self.run_as_identity,
            output_schema=self.output_schema,
            max_artifact_bytes=self.max_artifact_bytes,
            max_output_bytes=self.max_output_bytes,
            max_runtime_seconds=self.max_runtime_seconds,
            max_memory_mib=self.max_memory_mib,
            max_process_count=self.max_process_count,
            parser_work_unit=self.parser_work_unit,
            max_parser_work_units=self.max_parser_work_units,
            max_recursion_depth=self.max_recursion_depth,
            max_decompression_ratio=self.max_decompression_ratio,
            max_decompressed_bytes=self.max_decompressed_bytes,
        )
        binding_id = f"forensic-analysis-sandbox_{digest}"
        if self.sandbox_binding_digest and self.sandbox_binding_digest != digest:
            raise ValueError("Forensic analysis sandbox digest differs")
        if self.sandbox_binding_id and self.sandbox_binding_id != binding_id:
            raise ValueError("Forensic analysis sandbox ID differs")
        object.__setattr__(self, "sandbox_binding_digest", digest)
        object.__setattr__(self, "sandbox_binding_id", binding_id)
        return self

    def reference(self) -> ForensicEvidenceAnalysisSandboxRef:
        canonical = _canonical_model(
            ForensicEvidenceAnalysisSandboxBinding,
            self,
            label="Forensic evidence analysis sandbox binding",
        )
        return ForensicEvidenceAnalysisSandboxRef(
            sandboxBindingId=canonical.sandbox_binding_id,
            sandboxBindingVersion=canonical.sandbox_binding_version,
            sandboxBindingDigest=canonical.sandbox_binding_digest,
            deploymentId=canonical.deployment_id,
            workerProfile=canonical.worker_profile,
            surface=canonical.surface.reference(),
            ruleSet=canonical.rule_set,
            operation=canonical.operation,
            parser=canonical.parser,
            parserExecutableSHA256=canonical.parser_executable_sha256,
            parserConfigurationSHA256=canonical.parser_configuration_sha256,
            sandboxImageSHA256=canonical.sandbox_image_sha256,
            runAsIdentity=canonical.run_as_identity,
            outputSchema=canonical.output_schema,
            maxArtifactBytes=canonical.max_artifact_bytes,
            maxOutputBytes=canonical.max_output_bytes,
            maxRuntimeSeconds=canonical.max_runtime_seconds,
            maxMemoryMiB=canonical.max_memory_mib,
            maxProcessCount=canonical.max_process_count,
            parserWorkUnit=canonical.parser_work_unit,
            maxParserWorkUnits=canonical.max_parser_work_units,
            maxRecursionDepth=canonical.max_recursion_depth,
            maxDecompressionRatio=canonical.max_decompression_ratio,
            maxDecompressedBytes=canonical.max_decompressed_bytes,
        )


class ForensicEvidenceAnalysisBudget(_ForensicEvidenceAnalysisModel):
    """Attenuating input, output, runtime, memory, and zero-live-channel ceilings."""

    request_count: Literal[1] = Field(default=1, alias="requestCount")
    artifact_bytes: int = Field(alias="artifactBytes", ge=0, le=_MAX_ARTIFACT_BYTES)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1_024, le=_MAX_OUTPUT_BYTES)
    runtime_seconds: int = Field(alias="runtimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    memory_mib: int = Field(alias="memoryMiB", ge=64, le=_MAX_MEMORY_MIB)
    process_count: int = Field(alias="processCount", ge=1, le=_MAX_PROCESS_COUNT)
    parser_work_unit: Literal["one-source-or-expanded-byte-processed"] = Field(
        default=FORENSIC_PARSER_WORK_UNIT,
        alias="parserWorkUnit",
    )
    max_parser_work_units: int = Field(
        alias="maxParserWorkUnits",
        ge=1,
        le=_MAX_PARSER_WORK_UNITS,
    )
    max_recursion_depth: int = Field(
        alias="maxRecursionDepth",
        ge=1,
        le=_MAX_RECURSION_DEPTH,
    )
    max_decompression_ratio: int = Field(
        alias="maxDecompressionRatio",
        ge=1,
        le=_MAX_DECOMPRESSION_RATIO,
    )
    max_decompressed_bytes: int = Field(
        alias="maxDecompressedBytes",
        ge=1,
        le=_MAX_DECOMPRESSED_BYTES,
    )
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_queries: Literal[0] = Field(default=0, alias="dnsQueries")
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    source_write_operations: Literal[0] = Field(
        default=0,
        alias="sourceWriteOperations",
    )
    source_copy_operations: Literal[0] = Field(default=0, alias="sourceCopyOperations")
    evidence_mutation_operations: Literal[0] = Field(
        default=0,
        alias="evidenceMutationOperations",
    )
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    credential_uses: Literal[0] = Field(default=0, alias="credentialUses")
    secret_material_reads: Literal[0] = Field(default=0, alias="secretMaterialReads")
    device_sessions: Literal[0] = Field(default=0, alias="deviceSessions")
    plugin_loads: Literal[0] = Field(default=0, alias="pluginLoads")
    lateral_movement_attempts: Literal[0] = Field(
        default=0,
        alias="lateralMovementAttempts",
    )
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
        "max_parser_work_units",
        "max_recursion_depth",
        "max_decompression_ratio",
        "max_decompressed_bytes",
        "network_requests",
        "dns_queries",
        "host_filesystem_reads",
        "source_write_operations",
        "source_copy_operations",
        "evidence_mutation_operations",
        "credential_reads",
        "credential_uses",
        "secret_material_reads",
        "device_sessions",
        "plugin_loads",
        "lateral_movement_attempts",
        "target_process_executions",
        "shell_commands",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forensic analysis budget values must be integers")
        return value

    @field_validator("attenuation_only", "reservation_created", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic analysis budget markers must be booleans")
        return value


class ForensicEvidenceAnalysisRequest(_ForensicEvidenceAnalysisModel):
    """Secret-free request description; it resolves, reads, and executes nothing."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-request/v1alpha1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisRequest"] = "ForensicEvidenceAnalysisRequest"
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    surface: ForensicImmutableArtifactSurface
    custody: ForensicEvidenceCustodyRef
    sandbox: ForensicEvidenceAnalysisSandboxRef
    target: str = Field(min_length=9, max_length=2_000)
    method: Literal["GET"] = "GET"
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    budget: ForensicEvidenceAnalysisBudget
    raw_source_bytes_embedded: Literal[False] = Field(
        default=False,
        alias="rawSourceBytesEmbedded",
    )
    raw_disk_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawDiskContentEmbedded",
    )
    raw_memory_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawMemoryContentEmbedded",
    )
    raw_log_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawLogContentEmbedded",
    )
    raw_artifact_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentEmbedded",
    )
    raw_provenance_record_embedded: Literal[False] = Field(
        default=False,
        alias="rawProvenanceRecordEmbedded",
    )
    mutable_path_embedded: Literal[False] = Field(default=False, alias="mutablePathEmbedded")
    source_uri_embedded: Literal[False] = Field(default=False, alias="sourceURIEmbedded")
    object_key_embedded: Literal[False] = Field(default=False, alias="objectKeyEmbedded")
    filename_embedded: Literal[False] = Field(default=False, alias="filenameEmbedded")
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )
    caller_parser_or_plugin_embedded: Literal[False] = Field(
        default=False,
        alias="callerParserOrPluginEmbedded",
    )
    source_resolution_performed: Literal[False] = Field(
        default=False,
        alias="sourceResolutionPerformed",
    )
    source_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="sourceResolutionAuthorized",
    )
    source_read_performed: Literal[False] = Field(
        default=False,
        alias="sourceReadPerformed",
    )
    source_read_authorized: Literal[False] = Field(
        default=False,
        alias="sourceReadAuthorized",
    )
    source_mount_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMountAuthorized",
    )
    source_copy_authorized: Literal[False] = Field(
        default=False,
        alias="sourceCopyAuthorized",
    )
    evidence_mount_materialized: Literal[False] = Field(
        default=False,
        alias="evidenceMountMaterialized",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    parser_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="parserInvocationAuthorized",
    )
    worker_job_materialization_available: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAvailable",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    secret_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="secretMaterialAccessAuthorized",
    )
    lateral_movement_authorized: Literal[False] = Field(
        default=False,
        alias="lateralMovementAuthorized",
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceMutationAuthorized",
    )
    target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="targetExecutionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    provenance_preserved: Literal[False] = Field(default=False, alias="provenancePreserved")
    provenance_preservation_verified: Literal[False] = Field(
        default=False,
        alias="provenancePreservationVerified",
    )
    parser_result_available: Literal[False] = Field(
        default=False,
        alias="parserResultAvailable",
    )
    analysis_executed: Literal[False] = Field(
        default=False,
        alias="analysisExecuted",
    )

    @field_validator("target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        return _canonical_forensic_surface_target(value)

    @field_validator(
        "raw_source_bytes_embedded",
        "raw_disk_content_embedded",
        "raw_memory_content_embedded",
        "raw_log_content_embedded",
        "raw_artifact_content_embedded",
        "raw_provenance_record_embedded",
        "mutable_path_embedded",
        "source_uri_embedded",
        "object_key_embedded",
        "filename_embedded",
        "secret_material_embedded",
        "credential_material_embedded",
        "credential_reference_embedded",
        "caller_parser_or_plugin_embedded",
        "source_resolution_performed",
        "source_resolution_authorized",
        "source_read_performed",
        "source_read_authorized",
        "source_mount_authorized",
        "source_copy_authorized",
        "evidence_mount_materialized",
        "sandbox_invocation_authorized",
        "parser_invocation_authorized",
        "worker_job_materialization_available",
        "credential_access_authorized",
        "credential_use_authorized",
        "secret_material_access_authorized",
        "lateral_movement_authorized",
        "source_mutation_authorized",
        "evidence_mutation_authorized",
        "target_execution_authorized",
        "network_access_authorized",
        "dns_access_authorized",
        "provenance_preserved",
        "provenance_preservation_verified",
        "parser_result_available",
        "analysis_executed",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic evidence analysis request markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_request(self) -> Self:
        surface = _canonical_surface(self.surface)
        custody_surface = bind_forensic_immutable_artifact_surface_reference(
            reference=self.custody.surface,
            surface=surface,
        )
        sandbox_surface = bind_forensic_immutable_artifact_surface_reference(
            reference=self.sandbox.surface,
            surface=surface,
        )
        expected_operation = _OPERATION_BY_SURFACE_CLASS[surface.surface_class]
        expected_parser = _PARSER_BY_OPERATION[expected_operation]
        expected_rule_set = registered_forensic_evidence_rule_set().reference()
        if (
            surface != self.surface
            or custody_surface != surface
            or sandbox_surface != surface
            or self.surface.initial_state != "registered-not-authorized"
            or self.input_kind is not _input_kind(self.surface)
            or self.operation is not expected_operation
            or self.parser is not expected_parser
            or self.rule_set != expected_rule_set
            or self.custody.surface != self.surface.reference()
            or self.custody.input_kind is not self.input_kind
            or self.custody.artifact_sha256 != _artifact_sha256(self.surface)
            or self.custody.artifact_bytes != self.surface.locator.provenance.artifact_bytes
            or self.custody.custody_object_id
            != _forensic_evidence_object_id(self.surface.surface_digest)
            or self.sandbox.surface != self.surface.reference()
            or self.sandbox.worker_profile != _forensic_worker_boundary_profile().reference()
            or self.sandbox.rule_set != self.rule_set
            or self.sandbox.operation is not self.operation
            or self.sandbox.parser is not self.parser
            or self.sandbox.output_schema != self.output_schema
            or self.target != forensic_surface_scope_target(self.surface)
            or self.budget.artifact_bytes != self.custody.artifact_bytes
            or self.budget.artifact_bytes > self.sandbox.max_artifact_bytes
            or self.budget.max_output_bytes != self.sandbox.max_output_bytes
            or self.budget.runtime_seconds != self.sandbox.max_runtime_seconds
            or self.budget.memory_mib != self.sandbox.max_memory_mib
            or self.budget.process_count != self.sandbox.max_process_count
            or self.budget.parser_work_unit != self.sandbox.parser_work_unit
            or self.budget.max_parser_work_units != self.sandbox.max_parser_work_units
            or self.budget.max_recursion_depth != self.sandbox.max_recursion_depth
            or self.budget.max_decompression_ratio != self.sandbox.max_decompression_ratio
            or self.budget.max_decompressed_bytes != self.sandbox.max_decompressed_bytes
        ):
            raise ValueError("Forensic evidence analysis request differs from exact bindings")
        return self


@dataclass(frozen=True, slots=True)
class BoundedForensicEvidenceParserAdapter:
    """Adapt exact custody and sandbox metadata without reading or executing it."""

    _custody: ForensicEvidenceCustodyBinding
    _sandbox: ForensicEvidenceAnalysisSandboxBinding

    def __post_init__(self) -> None:
        custody = _canonical_model(
            ForensicEvidenceCustodyBinding,
            self._custody,
            label="Forensic artifact custody binding",
        )
        sandbox = _canonical_model(
            ForensicEvidenceAnalysisSandboxBinding,
            self._sandbox,
            label="Forensic evidence analysis sandbox binding",
        )
        if custody.surface != sandbox.surface:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic custody and sandbox bind different Surfaces"
            )
        object.__setattr__(self, "_custody", custody)
        object.__setattr__(self, "_sandbox", sandbox)

    @property
    def custody(self) -> ForensicEvidenceCustodyBinding:
        canonical = _canonical_model(
            ForensicEvidenceCustodyBinding,
            self._custody,
            label="Forensic artifact custody binding",
        )
        return canonical.model_copy(deep=True)

    @property
    def sandbox(self) -> ForensicEvidenceAnalysisSandboxBinding:
        canonical = _canonical_model(
            ForensicEvidenceAnalysisSandboxBinding,
            self._sandbox,
            label="Forensic evidence analysis sandbox binding",
        )
        return canonical.model_copy(deep=True)

    def prepare_request(
        self,
        *,
        surface: ForensicImmutableArtifactSurface,
        operation: ForensicEvidenceAnalysisOperation,
    ) -> ForensicEvidenceAnalysisRequest:
        """Return a bounded request description without artifact or sandbox authority."""

        canonical_surface = _canonical_surface(surface)
        try:
            canonical_operation = ForensicEvidenceAnalysisOperation(operation)
        except ValueError as exc:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic evidence analysis operation is unsupported"
            ) from exc
        expected_operation = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
        custody = self.custody
        sandbox = self.sandbox
        if canonical_surface != custody.surface:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic custody differs from the exact Surface"
            )
        if canonical_surface != sandbox.surface:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic sandbox differs from the exact Surface"
            )
        if canonical_operation is not expected_operation:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic operation differs from the exact Surface class"
            )
        if canonical_operation is not sandbox.operation:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic operation is outside the exact sandbox binding"
            )
        if custody.artifact_bytes > sandbox.max_artifact_bytes:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic artifact exceeds the sandbox byte ceiling"
            )
        return ForensicEvidenceAnalysisRequest(
            inputKind=custody.input_kind,
            operation=canonical_operation,
            parser=sandbox.parser,
            ruleSet=sandbox.rule_set,
            surface=canonical_surface,
            custody=custody.reference(),
            sandbox=sandbox.reference(),
            target=forensic_surface_scope_target(canonical_surface),
            budget=ForensicEvidenceAnalysisBudget(
                artifactBytes=custody.artifact_bytes,
                maxOutputBytes=sandbox.max_output_bytes,
                runtimeSeconds=sandbox.max_runtime_seconds,
                memoryMiB=sandbox.max_memory_mib,
                processCount=sandbox.max_process_count,
                parserWorkUnit=sandbox.parser_work_unit,
                maxParserWorkUnits=sandbox.max_parser_work_units,
                maxRecursionDepth=sandbox.max_recursion_depth,
                maxDecompressionRatio=sandbox.max_decompression_ratio,
                maxDecompressedBytes=sandbox.max_decompressed_bytes,
            ),
        )


class ForensicEvidenceAnalysisTool(Tool):
    """CAP-001 Tool identity whose offline parser runtime remains unavailable."""

    spec = ToolSpec(
        tool_id=FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID,
        version="1.0.0",
        description="Prepare one exact read-only immutable-evidence parser analysis",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"forensics", "immutable-evidence", "offline-parser", "read-only"}),
        evidence_types=frozenset({"forensic-evidence-analysis-json", "json"}),
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
            "outputSchema": FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
            "ruleSet": registered_forensic_evidence_rule_set()
            .reference()
            .model_dump(
                mode="json",
                by_alias=True,
            ),
            "sourceResolutionRuntimeAvailable": False,
            "evidenceCustodyRuntimeAvailable": False,
            "offlineParserRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        _validate_forensic_tool_request(request)
        raise ForensicEvidenceAnalysisCapabilityError(
            "FORENSICS-001B does not materialize an offline sandbox Worker job"
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        _validate_forensic_tool_request(request)
        raise ForensicEvidenceAnalysisCapabilityError(
            "FORENSICS-001B has no sandbox result to normalize"
        )


class ForensicEvidenceAnalysisCapabilityDomainClassification(_ForensicEvidenceAnalysisModel):
    """Exact Forensics classification for the additive FORENSICS-001B bundle."""

    api_version: Literal[
        "pajin.dev/forensic-evidence-analysis-capability-domain-classification/v1alpha1"
    ] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisCapabilityDomainClassification"] = (
        "ForensicEvidenceAnalysisCapabilityDomainClassification"
    )
    classification_id: str = Field(default="", alias="classificationId", max_length=97)
    classification_digest: str = Field(default="", alias="classificationDigest", max_length=64)
    capability: CapabilityDefinitionRef
    code_backed_capability: CodeBackedCapabilityRef = Field(alias="codeBackedCapability")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    reviewed_surface_types: tuple[ForensicSurfaceLocatorKind, ...] = Field(
        default=(
            "forensics-artifact",
            "forensics-disk",
            "forensics-log",
            "forensics-memory",
        ),
        alias="reviewedSurfaceTypes",
    )
    mapping_basis: Literal["forensics-001b-explicit-code-reviewed-surface-parser-map"] = Field(
        default="forensics-001b-explicit-code-reviewed-surface-parser-map",
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
    existing_capability_reused: Literal[False] = Field(
        default=False,
        alias="existingCapabilityReused",
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
        "existing_capability_reused",
        "capability_activation_authorized",
        "worker_selection_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic Capability Domain markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        capability = _forensic_code_backed_capability()
        worker = _forensic_worker_boundary_profile()
        if (
            self.capability != capability.capability
            or self.code_backed_capability != capability
            or self.domain_classification != worker.domain_classification
            or self.reviewed_surface_types != _supported_locator_kinds()
        ):
            raise ValueError("Forensic Capability Domain classification differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.forensic-evidence-analysis-domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Forensic Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("Forensic Capability Domain classification ID differs")
        object.__setattr__(self, "classification_digest", digest)
        object.__setattr__(self, "classification_id", classification_id)
        return self

    def reference(self) -> CapabilityDomainClassificationRef:
        canonical = _canonical_model(
            ForensicEvidenceAnalysisCapabilityDomainClassification,
            self,
            label="Forensic Capability Domain classification",
        )
        return CapabilityDomainClassificationRef(
            classificationId=canonical.classification_id,
            classificationDigest=canonical.classification_digest,
            capability=canonical.capability,
            domainClassification=canonical.domain_classification,
        )


class ForensicCampaignScopeBinding(_ForensicEvidenceAnalysisModel):
    """Content-addressed current Campaign projection for exact preparation."""

    api_version: Literal["pajin.dev/forensic-campaign-scope-binding/v1alpha1"] = Field(
        default=FORENSIC_CAMPAIGN_SCOPE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicCampaignScopeBinding"] = "ForensicCampaignScopeBinding"
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
            raise ValueError("Forensic Campaign Scope markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_scope_projection(self) -> Self:
        if self.allowed_methods != tuple(sorted(set(self.allowed_methods))):
            raise ValueError("Forensic Campaign allowed methods must be sorted and unique")
        if "GET" not in self.allowed_methods:
            raise ValueError("Forensic Campaign Scope requires reviewed GET authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"binding_digest"})
        digest = capability_definition_digest(
            "pajin.capability.forensic-campaign-scope-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Forensic Campaign Scope binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class ForensicEvidenceAnalysisCapabilityBundle:
    """Frozen CAP-001/CAP-002 registries for one Forensic Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapabilityRef:
        manifests = self.authorities.capabilities()
        if len(manifests) != 1:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic evidence analysis Capability authority inventory drifted"
            )
        return manifests[0].reference()


class ForensicEvidenceAnalysisCapabilityActivationBinding(_ForensicEvidenceAnalysisModel):
    """One exact externally signed release admitted for Range-only use."""

    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        definition = registered_forensic_evidence_analysis_capability_definition()
        if (
            self.capability != _forensic_code_backed_capability()
            or self.action_capability != registered_action_capability(definition)
        ):
            raise ValueError("Forensic activation references another Capability")
        return self


class ForensicEvidenceAnalysisCapabilityActivationSet(_ForensicEvidenceAnalysisModel):
    """Content-addressed activation of exactly one signed Forensic release."""

    api_version: Literal[
        "pajin.dev/forensic-evidence-analysis-capability-activation-set/v1alpha1"
    ] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisCapabilityActivationSet"] = (
        "ForensicEvidenceAnalysisCapabilityActivationSet"
    )
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(default="", alias="activationSetDigest", max_length=64)
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: ForensicEvidenceAnalysisCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.forensic-evidence-analysis-activation-set/v1",
            material,
        )
        activation_set_id = f"forensic-evidence-analysis-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("Forensic activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("Forensic activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class ForensicEvidenceAnalysisCapabilityActivation:
    """Runtime activation that rechecks the signed current release on every use."""

    bundle: ForensicEvidenceAnalysisCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: ForensicEvidenceAnalysisCapabilityActivationSet

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
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic activated Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic CAP-002 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(self, reference: ActionCapabilityRef) -> ResolvedCapabilityRelease:
        canonical = _canonical_model(
            ActionCapabilityRef,
            reference,
            label="Forensic GRAPH Capability reference",
        )
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic GRAPH Capability is outside the activation"
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
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic release is outside the activation"
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
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _ForensicEvidenceAnalysisAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        definition: CapabilityDefinition,
        tool: ForensicEvidenceAnalysisTool,
    ) -> None:
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ID}.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ADAPTER_VERSION,
            "method": "GET",
            "parameterSchemaDigest": self._definition.parameter_schema_digest,
            "ruleSet": registered_forensic_evidence_rule_set()
            .reference()
            .model_dump(
                mode="json",
                by_alias=True,
            ),
            "evidenceCustodyRequestAdaptationAvailable": True,
            "offlineParserRequestAdaptationAvailable": True,
            "sourceResolutionRuntimeAvailable": False,
            "evidenceCustodyRuntimeAvailable": False,
            "offlineParserRuntimeAvailable": False,
            "workerJobMaterializationAvailable": False,
            "replayAuthorized": False,
            "cleanupAuthorized": False,
            "tool": {
                "type": f"{type(self._tool).__module__}.{type(self._tool).__qualname__}",
                "context": self._tool.stable_execution_context(),
            },
        }


class _ForensicEvidenceAnalysisMaterializer(_ForensicEvidenceAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            request = ForensicEvidenceAnalysisRequest.model_validate(dict(parameters))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Forensic parameters differ from the bounded analysis request"
            ) from exc
        return cast(Mapping[str, JsonValue], request.model_dump(mode="json", by_alias=True))


class _ForensicEvidenceAnalysisActionCompiler(_ForensicEvidenceAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        try:
            analysis = ForensicEvidenceAnalysisRequest.model_validate(dict(materialized_arguments))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Forensic materialized analysis request is invalid"
            ) from exc
        if (
            request.tool_id != FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != analysis.target
            or request.arguments
        ):
            raise CapabilityAuthorityError(
                "Forensic compiler accepts only one exact empty GET request"
            )
        payload = request.model_dump(mode="json")
        payload["arguments"] = analysis.model_dump(mode="json", by_alias=True)
        return ToolRequest.model_validate(payload)


class _ForensicEvidenceAnalysisExecutorAdapter(_ForensicEvidenceAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _ForensicEvidenceAnalysisResultNormalizer(_ForensicEvidenceAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _ForensicEvidenceAnalysisSuccessOracle(_ForensicEvidenceAnalysisAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del request, result
        return CapabilityOracleDecision.INCONCLUSIVE


class _ForensicEvidenceAnalysisReplayStrategy(_ForensicEvidenceAnalysisAuthorityBase):
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


class _ForensicEvidenceAnalysisCleanupHandler(_ForensicEvidenceAnalysisAuthorityBase):
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
def _registered_forensic_evidence_analysis_capability_definition() -> CapabilityDefinition:
    raw_schema = ForensicEvidenceAnalysisRequest.model_json_schema(by_alias=True)
    raw_schema["required"] = sorted(raw_schema["required"])
    schema = cast(Mapping[str, JsonValue], raw_schema)
    return capability_definition_from_tool(
        ForensicEvidenceAnalysisTool.spec,
        ToolCapabilityRegistration(
            capabilityId=FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ID,
            capabilityVersion=FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_VERSION,
            toolId=FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID,
            domain="forensics",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=_supported_locator_kinds(),
            threatClasses=("forensic-artifact-analysis", "forensic-evidence-handling"),
            preconditions=(
                "current-campaign-scope",
                "deployment-custody-authorization-reference",
                "exact-code-owned-parser-rule-set",
                "exact-forensics-immutable-artifact-surface",
                "fresh-signed-authorization",
                "immutable-read-only-noexec-evidence-mount",
                "network-and-dns-disabled-non-root-parser-sandbox",
                "one-use-action-permit",
            ),
            parameterSchemaDigest=capability_parameter_schema_digest(schema),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=1,
        ),
    )


def registered_forensic_evidence_analysis_capability_definition() -> CapabilityDefinition:
    """Return an isolated copy of exact CAP-001 metadata for bounded preparation."""

    return _registered_forensic_evidence_analysis_capability_definition().model_copy(deep=True)


def forensic_evidence_analysis_capability_bundle(
    tools: ToolRegistry,
) -> ForensicEvidenceAnalysisCapabilityBundle:
    """Bind the exact Forensic Tool identity to all seven CAP-002 roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("Forensic evidence analysis Capability requires a ToolRegistry")
    try:
        tool = tools.tool(FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID)
        spec = tools.spec(FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic evidence analysis Tool is unavailable"
        ) from exc
    if type(tool) is not ForensicEvidenceAnalysisTool or spec != ForensicEvidenceAnalysisTool.spec:
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic evidence analysis Tool implementation drifted"
        )
    definition = registered_forensic_evidence_analysis_capability_definition()
    definitions = CapabilityDefinitionRegistry((definition,))
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _ForensicEvidenceAnalysisActionCompiler(definition, tool),
        _ForensicEvidenceAnalysisCleanupHandler(definition, tool),
        _ForensicEvidenceAnalysisExecutorAdapter(definition, tool),
        _ForensicEvidenceAnalysisMaterializer(definition, tool),
        _ForensicEvidenceAnalysisReplayStrategy(definition, tool),
        _ForensicEvidenceAnalysisResultNormalizer(definition, tool),
        _ForensicEvidenceAnalysisSuccessOracle(definition, tool),
    )
    return ForensicEvidenceAnalysisCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_forensic_evidence_analysis_capability(
    *,
    bundle: ForensicEvidenceAnalysisCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> ForensicEvidenceAnalysisCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, ForensicEvidenceAnalysisCapabilityBundle):
        raise TypeError("Forensic activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Forensic activation requires a verified lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability()
        definition = bundle.definitions.resolve(capability.capability)
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition != registered_forensic_evidence_analysis_capability_definition()
    ):
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic signed release differs from code authority"
        )
    binding = ForensicEvidenceAnalysisCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return ForensicEvidenceAnalysisCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=ForensicEvidenceAnalysisCapabilityActivationSet(binding=binding),
    )


class ForensicEvidenceAnalysisBindingRef(_ForensicEvidenceAnalysisModel):
    """Exact content-addressed reference to the FORENSICS-001B static binding."""

    binding_id: Literal["pajin.forensics.read-only-evidence-analysis.binding"] = Field(
        alias="bindingId"
    )
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class ForensicEvidenceAnalysisBinding(_ForensicEvidenceAnalysisModel):
    """Exact Surface/CAP-002/custody/sandbox contract without artifact access."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-binding/v1alpha1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisBinding"] = "ForensicEvidenceAnalysisBinding"
    binding_id: Literal["pajin.forensics.read-only-evidence-analysis.binding"] = Field(
        default="pajin.forensics.read-only-evidence-analysis.binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["forensics.immutable-artifact"] = Field(
        default="forensics.immutable-artifact",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.forensics.immutable-artifact.v1"] = Field(
        default="pajin.locator.forensics.immutable-artifact.v1",
        alias="locatorSchema",
    )
    locator_registry: ForensicImmutableArtifactLocatorRegistryRef = Field(alias="locatorRegistry")
    supported_locators: tuple[ForensicImmutableArtifactLocatorRef, ...] = Field(
        alias="supportedLocators",
        min_length=4,
        max_length=4,
    )
    capability: CodeBackedCapabilityRef
    capability_domain_classification: ForensicEvidenceAnalysisCapabilityDomainClassification = (
        Field(alias="capabilityDomainClassification")
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    rule_set: RegisteredForensicEvidenceRuleSet = Field(alias="ruleSet")
    supported_input_kinds: tuple[ForensicEvidenceInputKind, ...] = Field(
        default=tuple(sorted(ForensicEvidenceInputKind, key=lambda item: item.value)),
        alias="supportedInputKinds",
    )
    supported_operations: tuple[ForensicEvidenceAnalysisOperation, ...] = Field(
        default=_SUPPORTED_OPERATIONS,
        alias="supportedOperations",
    )
    supported_parsers: tuple[ForensicEvidenceParser, ...] = Field(
        default=_SUPPORTED_PARSERS,
        alias="supportedParsers",
    )
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
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
    complete_surface_operation_parser_map_required: Literal[True] = Field(
        default=True,
        alias="completeSurfaceOperationParserMapRequired",
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
    network_and_dns_disabled_sandbox_required: Literal[True] = Field(
        default=True,
        alias="networkAndDNSDisabledSandboxRequired",
    )
    immutable_read_only_noexec_evidence_mount_required: Literal[True] = Field(
        default=True,
        alias="immutableReadOnlyNoexecEvidenceMountRequired",
    )
    provenance_preservation_required: Literal[True] = Field(
        default=True,
        alias="provenancePreservationRequired",
    )
    pre_post_no_mutation_evidence_required: Literal[True] = Field(
        default=True,
        alias="prePostNoMutationEvidenceRequired",
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
    provenance_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="provenanceSanitizationVerified",
    )
    provenance_preserved: Literal[False] = Field(default=False, alias="provenancePreserved")
    provenance_preservation_verified: Literal[False] = Field(
        default=False,
        alias="provenancePreservationVerified",
    )
    parser_result_available: Literal[False] = Field(
        default=False,
        alias="parserResultAvailable",
    )
    source_resolved: Literal[False] = Field(default=False, alias="sourceResolved")
    source_read_authorized: Literal[False] = Field(
        default=False,
        alias="sourceReadAuthorized",
    )
    source_mount_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMountAuthorized",
    )
    source_copy_authorized: Literal[False] = Field(
        default=False,
        alias="sourceCopyAuthorized",
    )
    analysis_authorized: Literal[False] = Field(
        default=False,
        alias="analysisAuthorized",
    )
    parser_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="parserInvocationAuthorized",
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
    evidence_mount_materialized: Literal[False] = Field(
        default=False,
        alias="evidenceMountMaterialized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    secret_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="secretMaterialAccessAuthorized",
    )
    lateral_movement_authorized: Literal[False] = Field(
        default=False,
        alias="lateralMovementAuthorized",
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceMutationAuthorized",
    )
    target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="targetExecutionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
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
        "exact_surface_custody_sandbox_binding_required",
        "complete_surface_operation_parser_map_required",
        "exact_rule_set_required",
        "bounded_budget_required",
        "zero_live_channels_required",
        "network_and_dns_disabled_sandbox_required",
        "immutable_read_only_noexec_evidence_mount_required",
        "provenance_preservation_required",
        "pre_post_no_mutation_evidence_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "custody_runtime_verified",
        "authorization_verified",
        "provenance_sanitization_verified",
        "provenance_preserved",
        "provenance_preservation_verified",
        "parser_result_available",
        "source_resolved",
        "source_read_authorized",
        "source_mount_authorized",
        "source_copy_authorized",
        "analysis_authorized",
        "parser_invocation_authorized",
        "sandbox_selected",
        "worker_selection_authorized",
        "worker_job_materialization_available",
        "evidence_mount_materialized",
        "credential_access_authorized",
        "credential_use_authorized",
        "secret_material_access_authorized",
        "lateral_movement_authorized",
        "source_mutation_authorized",
        "evidence_mutation_authorized",
        "target_execution_authorized",
        "network_access_authorized",
        "dns_access_authorized",
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
            raise ValueError("Forensic evidence analysis binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_forensic_evidence_analysis_capability_definition()
        registry = registered_forensic_immutable_artifact_locator_registry()
        worker = _forensic_worker_boundary_profile()
        rule_set = registered_forensic_evidence_rule_set()
        expected_locators = tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        )
        if (
            self.locator_registry != registry.reference()
            or self.supported_locators != expected_locators
            or self.capability != _forensic_code_backed_capability()
            or self.capability_domain_classification
            != registered_forensic_evidence_analysis_capability_domain_classification()
            or self.worker_profile != worker.reference()
            or self.rule_set != rule_set
            or self.supported_input_kinds
            != tuple(sorted(ForensicEvidenceInputKind, key=lambda item: item.value))
            or self.supported_operations != _SUPPORTED_OPERATIONS
            or self.supported_parsers != _SUPPORTED_PARSERS
            or set(_OPERATION_BY_SURFACE_CLASS) != set(ForensicSurfaceClass)
            or set(_PARSER_BY_OPERATION) != set(ForensicEvidenceAnalysisOperation)
            or self.rule_set.surface_analysis_mapping != _SUPPORTED_SURFACE_ANALYSIS_MAPPING
            or definition.supported_surface_types != _supported_locator_kinds()
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID
            or definition.network_access is not False
            or definition.approval_required is not True
            or worker.domain_classification.domain is not SecurityDomain.FORENSICS
            or worker.network_boundary is not WorkerNetworkBoundary.DISABLED_BY_DEFAULT
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.IMMUTABLE_EVIDENCE
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.PROVENANCE_PRESERVING_PARSER
            or worker.required_identity_dimensions != ("evidence-source", "parser")
            or worker.required_budget_dimensions != ("artifact-bytes", "runtime")
            or worker.provenance_preservation_required is not True
        ):
            raise ValueError("Forensic evidence analysis binding differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"binding_digest"})
        digest = capability_definition_digest(
            "pajin.capability.forensic-evidence-analysis-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Forensic evidence analysis binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> ForensicEvidenceAnalysisBindingRef:
        canonical = _canonical_model(
            ForensicEvidenceAnalysisBinding,
            self,
            label="Forensic evidence analysis binding",
        )
        return ForensicEvidenceAnalysisBindingRef(
            bindingId=canonical.binding_id,
            bindingVersion=canonical.binding_version,
            bindingDigest=canonical.binding_digest,
        )


class ForensicEvidenceAnalysisPreparation(_ForensicEvidenceAnalysisModel):
    """Exact signed preparation with no artifact read, sandbox dispatch, or Finding."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-preparation/v1alpha1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisPreparation"] = "ForensicEvidenceAnalysisPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=110)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: ForensicEvidenceAnalysisBinding
    surface: ForensicImmutableArtifactSurface
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    operation: ForensicEvidenceAnalysisOperation
    artifact_custody: ForensicEvidenceCustodyBinding = Field(alias="artifactCustody")
    sandbox: ForensicEvidenceAnalysisSandboxBinding
    analysis_request: ForensicEvidenceAnalysisRequest = Field(alias="analysisRequest")
    campaign_scope: ForensicCampaignScopeBinding = Field(alias="campaignScope")
    matched_surface_allow_rule: str = Field(
        alias="matchedSurfaceAllowRule",
        min_length=1,
        max_length=2_000,
    )
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    current_campaign_bound: Literal[True] = Field(default=True, alias="currentCampaignBound")
    exact_surface_parser_scope_bound: Literal[True] = Field(
        default=True,
        alias="exactSurfaceParserScopeBound",
    )
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
    provenance_preservation_requirements_bound: Literal[True] = Field(
        default=True,
        alias="provenancePreservationRequirementsBound",
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
    source_root_verified: Literal[False] = Field(default=False, alias="sourceRootVerified")
    source_artifact_record_verified: Literal[False] = Field(
        default=False,
        alias="sourceArtifactRecordVerified",
    )
    provenance_record_verified: Literal[False] = Field(
        default=False,
        alias="provenanceRecordVerified",
    )
    source_seal_verified: Literal[False] = Field(default=False, alias="sourceSealVerified")
    source_authenticity_verified: Literal[False] = Field(
        default=False,
        alias="sourceAuthenticityVerified",
    )
    source_immutability_verified: Literal[False] = Field(
        default=False,
        alias="sourceImmutabilityVerified",
    )
    source_artifact_membership_verified: Literal[False] = Field(
        default=False,
        alias="sourceArtifactMembershipVerified",
    )
    chain_of_custody_verified: Literal[False] = Field(
        default=False,
        alias="chainOfCustodyVerified",
    )
    artifact_digest_verified: Literal[False] = Field(
        default=False,
        alias="artifactDigestVerified",
    )
    artifact_bytes_verified: Literal[False] = Field(
        default=False,
        alias="artifactBytesVerified",
    )
    evidence_class_verified: Literal[False] = Field(
        default=False,
        alias="evidenceClassVerified",
    )
    source_format_verified: Literal[False] = Field(default=False, alias="sourceFormatVerified")
    provenance_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="provenanceSanitizationVerified",
    )
    provenance_preserved: Literal[False] = Field(default=False, alias="provenancePreserved")
    provenance_preservation_verified: Literal[False] = Field(
        default=False,
        alias="provenancePreservationVerified",
    )
    parser_result_available: Literal[False] = Field(
        default=False,
        alias="parserResultAvailable",
    )
    no_mutation_verified: Literal[False] = Field(default=False, alias="noMutationVerified")
    source_resolved: Literal[False] = Field(default=False, alias="sourceResolved")
    source_read_performed: Literal[False] = Field(
        default=False,
        alias="sourceReadPerformed",
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
    evidence_mount_materialized: Literal[False] = Field(
        default=False,
        alias="evidenceMountMaterialized",
    )
    budget_reserved: Literal[False] = Field(default=False, alias="budgetReserved")
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    credential_accessed: Literal[False] = Field(default=False, alias="credentialAccessed")
    credential_used: Literal[False] = Field(default=False, alias="credentialUsed")
    secret_material_accessed: Literal[False] = Field(
        default=False,
        alias="secretMaterialAccessed",
    )
    source_copy_performed: Literal[False] = Field(
        default=False,
        alias="sourceCopyPerformed",
    )
    target_execution_performed: Literal[False] = Field(
        default=False,
        alias="targetExecutionPerformed",
    )
    lateral_movement_performed: Literal[False] = Field(
        default=False,
        alias="lateralMovementPerformed",
    )
    network_request_performed: Literal[False] = Field(
        default=False,
        alias="networkRequestPerformed",
    )
    dns_request_performed: Literal[False] = Field(
        default=False,
        alias="dnsRequestPerformed",
    )
    analysis_executed: Literal[False] = Field(default=False, alias="analysisExecuted")
    source_mutated: Literal[False] = Field(default=False, alias="sourceMutated")
    evidence_mutation_performed: Literal[False] = Field(
        default=False,
        alias="evidenceMutationPerformed",
    )
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
        "exact_surface_parser_scope_bound",
        "custody_authorization_reference_bound",
        "exact_rule_set_bound",
        "network_disabled_sandbox_bound",
        "zero_live_channels_bound",
        "provenance_preservation_requirements_bound",
        "analysis_request_adapted",
        "capability_prepared",
        "custody_runtime_verified",
        "authorization_verified_by_preparation",
        "source_root_verified",
        "source_artifact_record_verified",
        "provenance_record_verified",
        "source_seal_verified",
        "source_authenticity_verified",
        "source_immutability_verified",
        "source_artifact_membership_verified",
        "chain_of_custody_verified",
        "artifact_digest_verified",
        "artifact_bytes_verified",
        "evidence_class_verified",
        "source_format_verified",
        "provenance_sanitization_verified",
        "provenance_preserved",
        "provenance_preservation_verified",
        "parser_result_available",
        "no_mutation_verified",
        "source_resolved",
        "source_read_performed",
        "sandbox_runtime_available",
        "sandbox_runtime_attested",
        "sandbox_selected",
        "evidence_mount_materialized",
        "budget_reserved",
        "worker_job_materialized",
        "credential_accessed",
        "credential_used",
        "secret_material_accessed",
        "source_copy_performed",
        "target_execution_performed",
        "lateral_movement_performed",
        "network_request_performed",
        "dns_request_performed",
        "analysis_executed",
        "source_mutated",
        "evidence_mutation_performed",
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
            raise ValueError("Forensic evidence analysis preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        canonical_surface = _canonical_surface(self.surface)
        expected_action = registered_action_capability(
            registered_forensic_evidence_analysis_capability_definition()
        ).reference()
        expected_surface_rule = _require_exact_scope_allow(
            self.campaign_scope,
            forensic_surface_scope_target(canonical_surface),
            label="Forensic Surface",
        )
        expected_request = BoundedForensicEvidenceParserAdapter(
            self.artifact_custody,
            self.sandbox,
        ).prepare_request(surface=canonical_surface, operation=self.operation)
        request = self.prepared_action.request
        if (
            canonical_surface != self.surface
            or self.binding != registered_forensic_evidence_analysis_binding()
            or self.surface.initial_state != "registered-not-authorized"
            or self.input_kind is not _input_kind(self.surface)
            or self.operation is not _OPERATION_BY_SURFACE_CLASS[self.surface.surface_class]
            or self.artifact_custody.surface != self.surface
            or self.sandbox.surface != self.surface
            or self.analysis_request != expected_request
            or self.matched_surface_allow_rule != expected_surface_rule
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID
            or request.method != "GET"
            or request.target != self.analysis_request.target
            or request.arguments != self.analysis_request.model_dump(mode="json", by_alias=True)
            or self.prepared_action.request_digest != capability_tool_request_digest(request)
            or self.prepared_action.normalized_parameters_digest
            != capability_normalized_parameters_digest(request.arguments)
        ):
            raise ValueError("Forensic evidence analysis preparation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.forensic-evidence-analysis-preparation/v1",
            material,
        )
        preparation_id = f"forensic-evidence-analysis-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Forensic evidence analysis preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("Forensic evidence analysis preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def bind_forensic_evidence_custody(
    *,
    surface: ForensicImmutableArtifactSurface,
    authorization_digest: str,
) -> ForensicEvidenceCustodyBinding:
    """Pin an unverified authorization/custody coordinate without resolving source bytes."""

    canonical_surface = _canonical_surface(surface)
    artifact_sha256 = _artifact_sha256(canonical_surface)
    artifact_bytes = canonical_surface.locator.provenance.artifact_bytes
    try:
        return ForensicEvidenceCustodyBinding(
            surface=canonical_surface,
            inputKind=_input_kind(canonical_surface),
            custodyAuthorityId=FORENSIC_EVIDENCE_CUSTODY_AUTHORITY_ID,
            custodyObjectId=_forensic_evidence_object_id(canonical_surface.surface_digest),
            authorizationId=_forensic_authorization_reference_id(authorization_digest),
            authorizationDigest=authorization_digest,
            artifactSHA256=artifact_sha256,
            artifactBytes=artifact_bytes,
        )
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, ForensicEvidenceAnalysisCapabilityError):
            raise
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic evidence custody binding failed closed"
        ) from exc


def bind_forensic_evidence_analysis_sandbox(
    *,
    surface: ForensicImmutableArtifactSurface,
    parser_executable_sha256: str,
    parser_configuration_sha256: str,
    sandbox_image_sha256: str,
    max_artifact_bytes: int = 67_108_864,
    max_output_bytes: int = 1_048_576,
    max_runtime_seconds: int = 60,
    max_memory_mib: int = 512,
    max_process_count: int = 8,
    max_parser_work_units: int = 536_870_912,
    max_recursion_depth: int = 32,
    max_decompression_ratio: int = 100,
    max_decompressed_bytes: int = 268_435_456,
) -> ForensicEvidenceAnalysisSandboxBinding:
    """Pin an offline sandbox configuration without selecting or invoking a Worker."""

    canonical_surface = _canonical_surface(surface)
    operation = _OPERATION_BY_SURFACE_CLASS[canonical_surface.surface_class]
    try:
        return ForensicEvidenceAnalysisSandboxBinding(
            deploymentId=FORENSIC_EVIDENCE_ANALYSIS_DEPLOYMENT_ID,
            workerProfile=_forensic_worker_boundary_profile().reference(),
            surface=canonical_surface,
            ruleSet=registered_forensic_evidence_rule_set().reference(),
            operation=operation,
            parser=_PARSER_BY_OPERATION[operation],
            parserExecutableSHA256=parser_executable_sha256,
            parserConfigurationSHA256=parser_configuration_sha256,
            sandboxImageSHA256=sandbox_image_sha256,
            runAsIdentity=FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY,
            maxArtifactBytes=max_artifact_bytes,
            maxOutputBytes=max_output_bytes,
            maxRuntimeSeconds=max_runtime_seconds,
            maxMemoryMiB=max_memory_mib,
            maxProcessCount=max_process_count,
            maxParserWorkUnits=max_parser_work_units,
            maxRecursionDepth=max_recursion_depth,
            maxDecompressionRatio=max_decompression_ratio,
            maxDecompressedBytes=max_decompressed_bytes,
        )
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, ForensicEvidenceAnalysisCapabilityError):
            raise
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic evidence analysis sandbox binding failed closed"
        ) from exc


@cache
def _registered_forensic_evidence_analysis_binding() -> ForensicEvidenceAnalysisBinding:
    registry = registered_forensic_immutable_artifact_locator_registry()
    return ForensicEvidenceAnalysisBinding(
        locatorRegistry=registry.reference(),
        supportedLocators=tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        ),
        capability=_forensic_code_backed_capability(),
        capabilityDomainClassification=(
            registered_forensic_evidence_analysis_capability_domain_classification()
        ),
        workerProfile=_forensic_worker_boundary_profile().reference(),
        ruleSet=registered_forensic_evidence_rule_set(),
    )


def registered_forensic_evidence_analysis_binding() -> ForensicEvidenceAnalysisBinding:
    """Return an isolated exact binding without artifact or sandbox access."""

    return _registered_forensic_evidence_analysis_binding().model_copy(deep=True)


def resolve_forensic_evidence_analysis_binding(
    reference: ForensicEvidenceAnalysisBindingRef,
) -> ForensicEvidenceAnalysisBinding:
    canonical = _canonical_model(
        ForensicEvidenceAnalysisBindingRef,
        reference,
        label="Forensic evidence analysis binding reference",
    )
    binding = registered_forensic_evidence_analysis_binding()
    if binding.reference() == canonical:
        return binding.model_copy(deep=True)
    raise ForensicEvidenceAnalysisCapabilityError(
        "Forensic evidence analysis binding is not registered exactly"
    )


@cache
def _registered_forensic_evidence_analysis_capability_domain_classification() -> (
    ForensicEvidenceAnalysisCapabilityDomainClassification
):
    capability = _forensic_code_backed_capability()
    return ForensicEvidenceAnalysisCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=_forensic_worker_boundary_profile().domain_classification,
    )


def registered_forensic_evidence_analysis_capability_domain_classification() -> (
    ForensicEvidenceAnalysisCapabilityDomainClassification
):
    """Return an isolated local exact Forensics classification."""

    return _registered_forensic_evidence_analysis_capability_domain_classification().model_copy(
        deep=True
    )


def resolve_forensic_evidence_analysis_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
) -> ForensicEvidenceAnalysisCapabilityDomainClassification:
    canonical = _canonical_model(
        CapabilityDomainClassificationRef,
        reference,
        label="Forensic Capability Domain classification reference",
    )
    classification = registered_forensic_evidence_analysis_capability_domain_classification()
    if classification.reference() == canonical:
        return classification.model_copy(deep=True)
    raise ForensicEvidenceAnalysisCapabilityError(
        "Forensic Capability Domain classification is not registered exactly"
    )


def forensic_surface_scope_target(
    surface: ForensicImmutableArtifactSurface,
) -> str:
    """Return a non-routable exact Scope token for one Surface/parser pair."""

    canonical = _canonical_surface(surface)
    operation = _OPERATION_BY_SURFACE_CLASS[canonical.surface_class]
    parser = _PARSER_BY_OPERATION[operation]
    return f"{FORENSIC_SURFACE_SCOPE_ORIGIN}/surfaces/{canonical.surface_id}/parsers/{parser.value}"


def prepare_forensic_evidence_analysis(
    *,
    activation: ForensicEvidenceAnalysisCapabilityActivation,
    release: CapabilityReleaseRef,
    campaign: CampaignManifest,
    surface: ForensicImmutableArtifactSurface,
    operation: ForensicEvidenceAnalysisOperation,
    parser: BoundedForensicEvidenceParserAdapter,
    request_id: str,
    agent_id: str,
) -> ForensicEvidenceAnalysisPreparation:
    """Compile exact signed analysis metadata and stop before artifact access."""

    if not isinstance(activation, ForensicEvidenceAnalysisCapabilityActivation):
        raise TypeError("Forensic preparation requires Forensic activation")
    if not isinstance(parser, BoundedForensicEvidenceParserAdapter):
        raise TypeError("Forensic preparation requires a bounded parser adapter")
    try:
        canonical_operation = ForensicEvidenceAnalysisOperation(operation)
    except ValueError as exc:
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic evidence analysis operation is unsupported"
        ) from exc
    canonical_campaign = _canonical_campaign(campaign)
    canonical_surface = _canonical_surface(surface)
    custody = parser.custody
    sandbox = parser.sandbox
    try:
        scope_binding = _campaign_scope_binding(canonical_campaign)
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, ForensicEvidenceAnalysisCapabilityError):
            raise
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic Campaign Scope binding failed closed"
        ) from exc
    surface_allow = _require_exact_scope_allow(
        scope_binding,
        forensic_surface_scope_target(canonical_surface),
        label="Forensic Surface",
    )
    analysis_request = parser.prepare_request(
        surface=canonical_surface,
        operation=canonical_operation,
    )
    binding = registered_forensic_evidence_analysis_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition()
            != registered_forensic_evidence_analysis_capability_definition()
        ):
            raise ForensicEvidenceAnalysisCapabilityError(
                "Forensic activation differs from the registered Capability"
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID,
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
        return ForensicEvidenceAnalysisPreparation(
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
        if isinstance(exc, ForensicEvidenceAnalysisCapabilityError):
            raise
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic CAP-002 preparation failed closed"
        ) from exc


def _verify_activation(activation: ForensicEvidenceAnalysisCapabilityActivation) -> None:
    if (
        type(activation.bundle) is not ForensicEvidenceAnalysisCapabilityBundle
        or type(activation.lifecycle) is not CapabilityLifecycleRegistry
        or type(activation.activation_set) is not ForensicEvidenceAnalysisCapabilityActivationSet
    ):
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic activation uses the wrong runtime types"
        )
    canonical_set = _canonical_model(
        ForensicEvidenceAnalysisCapabilityActivationSet,
        activation.activation_set,
        label="Forensic activation set",
    )
    _resolve_activation_binding(activation, canonical_set.binding)


def _resolve_activation_binding(
    activation: ForensicEvidenceAnalysisCapabilityActivation,
    binding: ForensicEvidenceAnalysisCapabilityActivationBinding,
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
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic current signed release could not be resolved"
        ) from exc
    if (
        bundle_capability != _forensic_code_backed_capability()
        or resolved.capability.reference() != binding.capability
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
        or expected_action != binding.action_capability
    ):
        raise ForensicEvidenceAnalysisCapabilityError("Forensic signed release binding drifted")
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.forensic-evidence-analysis-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    return _canonical_model(
        CapabilityReleaseRef,
        reference,
        label="Forensic release reference",
    )


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    return _canonical_model(
        ToolRequest,
        request,
        label="Forensic Tool request",
        by_alias=False,
    )


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    return _canonical_model(
        CampaignManifest,
        campaign,
        label="Forensic Campaign",
    )


def _canonical_surface(
    surface: ForensicImmutableArtifactSurface,
) -> ForensicImmutableArtifactSurface:
    canonical = _canonical_model(
        ForensicImmutableArtifactSurface,
        surface,
        label="Forensics immutable-artifact Surface",
    )
    return bind_forensic_immutable_artifact_surface_reference(
        reference=canonical.reference(),
        surface=canonical,
    )


def _campaign_scope_binding(campaign: CampaignManifest) -> ForensicCampaignScopeBinding:
    return ForensicCampaignScopeBinding(
        campaignName=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        scope=campaign.spec.scope.model_copy(deep=True),
        allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
        allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
    )


def _require_exact_scope_allow(
    scope_binding: ForensicCampaignScopeBinding,
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
        raise ForensicEvidenceAnalysisCapabilityError(
            f"{label} Campaign Scope cannot be evaluated safely"
        ) from exc
    if canonical_target not in normalized_allow:
        raise ForensicEvidenceAnalysisCapabilityError(
            f"{label} lacks an exact current Campaign allow rule"
        )
    if any(scope_matches(rule, canonical_target) for rule in normalized_deny):
        raise ForensicEvidenceAnalysisCapabilityError(
            f"{label} overlaps a current Campaign deny rule"
        )
    return canonical_target


def _canonical_forensic_surface_target(value: str) -> str:
    try:
        canonical = normalize_target_url(value)
    except InvalidScopeURL as exc:
        raise ValueError("Forensic Surface target is invalid") from exc
    prefix = f"{FORENSIC_SURFACE_SCOPE_ORIGIN}/surfaces/"
    target_pattern = (
        rf"{re.escape(prefix)}"
        r"forensics-immutable-artifact-surface_[a-f0-9]{64}"
        rf"/parsers/(?:{'|'.join(re.escape(item.value) for item in _SUPPORTED_PARSERS)})"
    )
    if canonical != value or re.fullmatch(target_pattern, value) is None:
        raise ValueError("Forensic Surface target must be one canonical non-routable token")
    return value


def _validate_forensic_tool_request(
    request: ToolRequest,
) -> ForensicEvidenceAnalysisRequest:
    canonical_request = _canonical_tool_request(request)
    try:
        analysis = ForensicEvidenceAnalysisRequest.model_validate(canonical_request.arguments)
    except (ValidationError, ValueError) as exc:
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic Tool request arguments are invalid"
        ) from exc
    if (
        canonical_request.tool_id != FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID
        or canonical_request.method != "GET"
        or canonical_request.target != analysis.target
    ):
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic Tool request differs from bounded GET authority"
        )
    return analysis


def _input_kind(
    surface: ForensicImmutableArtifactSurface,
) -> ForensicEvidenceInputKind:
    return _INPUT_KIND_BY_SURFACE_CLASS[surface.surface_class]


def _artifact_sha256(surface: ForensicImmutableArtifactSurface) -> str:
    locator = surface.locator
    surface_class = surface.surface_class
    if locator.kind != _LOCATOR_KIND_BY_SURFACE_CLASS[surface_class]:
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic Surface locator kind differs from analysis mapping"
        )
    if (
        _DIGEST_SOURCE_BY_SURFACE_CLASS[surface_class]
        is not ForensicEvidenceDigestSource.ARTIFACT_SHA256
    ):
        raise ForensicEvidenceAnalysisCapabilityError(
            "Forensic Surface has no supported artifact coordinate"
        )
    return locator.provenance.artifact_sha256


def _supported_locator_kinds() -> tuple[ForensicSurfaceLocatorKind, ...]:
    return (
        "forensics-artifact",
        "forensics-disk",
        "forensics-log",
        "forensics-memory",
    )


@cache
def _forensic_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(ForensicEvidenceAnalysisTool())
    return forensic_evidence_analysis_capability_bundle(tools).capability()


@cache
def _forensic_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.FORENSICS
    )


__all__ = [
    "FORENSIC_CAMPAIGN_SCOPE_BINDING_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_BINDING_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ACTIVATION_SET_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ADAPTER_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ID",
    "FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_DEPLOYMENT_ID",
    "FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA",
    "FORENSIC_EVIDENCE_ANALYSIS_PREPARATION_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_REQUEST_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY",
    "FORENSIC_EVIDENCE_ANALYSIS_SANDBOX_BINDING_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID",
    "FORENSIC_EVIDENCE_CUSTODY_AUTHORITY_ID",
    "FORENSIC_EVIDENCE_CUSTODY_BINDING_API_VERSION",
    "FORENSIC_EVIDENCE_MOUNT_TARGET",
    "FORENSIC_EVIDENCE_RULE_SET_API_VERSION",
    "FORENSIC_PARSER_WORK_UNIT",
    "FORENSIC_SURFACE_SCOPE_ORIGIN",
    "BoundedForensicEvidenceParserAdapter",
    "ForensicCampaignScopeBinding",
    "ForensicEvidenceAnalysisBinding",
    "ForensicEvidenceAnalysisBindingRef",
    "ForensicEvidenceAnalysisBudget",
    "ForensicEvidenceAnalysisCapabilityActivation",
    "ForensicEvidenceAnalysisCapabilityActivationBinding",
    "ForensicEvidenceAnalysisCapabilityActivationSet",
    "ForensicEvidenceAnalysisCapabilityBundle",
    "ForensicEvidenceAnalysisCapabilityDomainClassification",
    "ForensicEvidenceAnalysisCapabilityError",
    "ForensicEvidenceAnalysisOperation",
    "ForensicEvidenceAnalysisPreparation",
    "ForensicEvidenceAnalysisRequest",
    "ForensicEvidenceAnalysisSandboxBinding",
    "ForensicEvidenceAnalysisSandboxRef",
    "ForensicEvidenceAnalysisTool",
    "ForensicEvidenceCustodyBinding",
    "ForensicEvidenceCustodyRef",
    "ForensicEvidenceDigestSource",
    "ForensicEvidenceInputKind",
    "ForensicEvidenceParser",
    "ForensicEvidenceRuleSetRef",
    "ForensicEvidenceSignalKind",
    "ForensicSurfaceAnalysisMapping",
    "RegisteredForensicEvidenceRuleSet",
    "activate_forensic_evidence_analysis_capability",
    "bind_forensic_evidence_analysis_sandbox",
    "bind_forensic_evidence_custody",
    "forensic_evidence_analysis_capability_bundle",
    "forensic_surface_scope_target",
    "prepare_forensic_evidence_analysis",
    "registered_forensic_evidence_analysis_binding",
    "registered_forensic_evidence_analysis_capability_definition",
    "registered_forensic_evidence_analysis_capability_domain_classification",
    "registered_forensic_evidence_rule_set",
    "resolve_forensic_evidence_analysis_binding",
    "resolve_forensic_evidence_analysis_capability_domain_classification",
    "resolve_registered_forensic_evidence_rule_set",
]
