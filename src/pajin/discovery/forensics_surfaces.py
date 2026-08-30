"""FORENSICS-001A typed immutable-source Surfaces without evidence access authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, TypeAdapter, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import DISCOVERY_API_VERSION
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SECURITY_DOMAIN_TAXONOMY_API_VERSION,
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)
from pajin.graph.domain_semantics import (
    MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
    SecurityDomainGraphTypeSetRef,
    registered_multi_domain_graph_semantics,
)

FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_API_VERSION: Literal[
    "pajin.dev/forensics-immutable-artifact-locator/v1alpha1"
] = "pajin.dev/forensics-immutable-artifact-locator/v1alpha1"
FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/forensics-immutable-artifact-locator-registry/v1alpha1"
] = "pajin.dev/forensics-immutable-artifact-locator-registry/v1alpha1"
FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_API_VERSION: Literal[
    "pajin.dev/forensics-immutable-artifact-surface/v1alpha1"
] = "pajin.dev/forensics-immutable-artifact-surface/v1alpha1"
FORENSICS_SOURCE_PROVENANCE_COORDINATE_API_VERSION: Literal[
    "pajin.dev/forensics-source-provenance-coordinate/v1alpha1"
] = "pajin.dev/forensics-source-provenance-coordinate/v1alpha1"

FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_TYPE: Literal["forensics.immutable-artifact"] = (
    "forensics.immutable-artifact"
)
FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_SCHEMA: Literal[
    "pajin.locator.forensics.immutable-artifact.v1"
] = "pajin.locator.forensics.immutable-artifact.v1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ByteCount = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^forensics-immutable-artifact-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 512 * 1024
_MAX_TYPED_SURFACE_BYTES = 512 * 1024


class ForensicSurfaceRegistryError(RuntimeError):
    """Raised when an exact FORENSICS-001A reference cannot be resolved or bound."""


class ForensicSurfaceClass(StrEnum):
    """Immutable-source evidence classes that grant no source access authority."""

    DISK = "disk"
    MEMORY = "memory"
    LOG = "log"
    ARTIFACT = "artifact"


class ForensicSourceRootKind(StrEnum):
    """Code-owned v1 source-root vocabulary, not an authenticity assertion."""

    PAJIN_RUN_INTEGRITY_V1 = "pajin.dev/run-integrity/v1"


class ForensicSourceProvenanceCoordinate(StrictModel):
    """Content-free caller provenance for one externally retained immutable source."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    api_version: Literal["pajin.dev/forensics-source-provenance-coordinate/v1alpha1"] = Field(
        default=FORENSICS_SOURCE_PROVENANCE_COORDINATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicSourceProvenanceCoordinate"] = "ForensicSourceProvenanceCoordinate"
    source_root_kind: ForensicSourceRootKind = Field(alias="sourceRootKind")
    source_root_sha256: _Sha256 = Field(alias="sourceRootSha256")
    source_artifact_record_sha256: _Sha256 = Field(alias="sourceArtifactRecordSha256")
    provenance_record_sha256: _Sha256 = Field(alias="provenanceRecordSha256")
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")
    artifact_bytes: _ByteCount = Field(alias="artifactBytes")
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
    source_uri_embedded: Literal[False] = Field(default=False, alias="sourceUriEmbedded")
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
    parser_output_embedded: Literal[False] = Field(default=False, alias="parserOutputEmbedded")

    @field_validator(
        "raw_source_bytes_embedded",
        "raw_disk_content_embedded",
        "raw_memory_content_embedded",
        "raw_log_content_embedded",
        "raw_artifact_content_embedded",
        "raw_provenance_record_embedded",
        "mutable_path_embedded",
        "source_uri_embedded",
        "secret_material_embedded",
        "credential_material_embedded",
        "credential_reference_embedded",
        "parser_output_embedded",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic provenance security markers must be boolean false")
        return value


class _ForensicImmutableSourceLocator(StrictModel):
    """Common exact provenance embedded by every FORENSICS-001A locator."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    provenance: ForensicSourceProvenanceCoordinate

    @model_validator(mode="after")
    def require_exact_provenance(self) -> Self:
        _validated_forensic_provenance(self.provenance)
        return self


class ForensicDiskSurfaceLocator(_ForensicImmutableSourceLocator):
    """One caller-declared disk source without path, mount, or read authority."""

    kind: Literal["forensics-disk"] = "forensics-disk"


class ForensicMemorySurfaceLocator(_ForensicImmutableSourceLocator):
    """One caller-declared memory source without process or memory-read authority."""

    kind: Literal["forensics-memory"] = "forensics-memory"


class ForensicLogSurfaceLocator(_ForensicImmutableSourceLocator):
    """One caller-declared log source without log content or system access authority."""

    kind: Literal["forensics-log"] = "forensics-log"


class ForensicArtifactSurfaceLocator(_ForensicImmutableSourceLocator):
    """One caller-declared generic artifact without resolution or parser authority."""

    kind: Literal["forensics-artifact"] = "forensics-artifact"


ForensicImmutableArtifactSurfaceLocator = Annotated[
    ForensicDiskSurfaceLocator
    | ForensicMemorySurfaceLocator
    | ForensicLogSurfaceLocator
    | ForensicArtifactSurfaceLocator,
    Field(discriminator="kind"),
]
_FORENSIC_LOCATOR_ADAPTER: TypeAdapter[ForensicImmutableArtifactSurfaceLocator] = TypeAdapter(
    ForensicImmutableArtifactSurfaceLocator
)

ForensicSurfaceLocatorKind = Literal[
    "forensics-disk",
    "forensics-memory",
    "forensics-log",
    "forensics-artifact",
]


@dataclass(frozen=True, slots=True)
class _ForensicLocatorSpec:
    locator_id: str
    locator_kind: ForensicSurfaceLocatorKind
    surface_class: ForensicSurfaceClass
    source_model_id: str


_FORENSIC_LOCATOR_SPECS = (
    _ForensicLocatorSpec(
        "pajin.locator.forensics.disk",
        "forensics-disk",
        ForensicSurfaceClass.DISK,
        "pajin.discovery.forensics_surfaces.ForensicDiskSurfaceLocator",
    ),
    _ForensicLocatorSpec(
        "pajin.locator.forensics.memory",
        "forensics-memory",
        ForensicSurfaceClass.MEMORY,
        "pajin.discovery.forensics_surfaces.ForensicMemorySurfaceLocator",
    ),
    _ForensicLocatorSpec(
        "pajin.locator.forensics.log",
        "forensics-log",
        ForensicSurfaceClass.LOG,
        "pajin.discovery.forensics_surfaces.ForensicLogSurfaceLocator",
    ),
    _ForensicLocatorSpec(
        "pajin.locator.forensics.artifact",
        "forensics-artifact",
        ForensicSurfaceClass.ARTIFACT,
        "pajin.discovery.forensics_surfaces.ForensicArtifactSurfaceLocator",
    ),
)


class ForensicImmutableArtifactLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered Forensic locator."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: ForensicSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: ForensicSurfaceClass = Field(alias="surfaceClass")

    @model_validator(mode="after")
    def bind_registered_locator_reference(self) -> Self:
        registered = next(
            (
                item
                for item in _registered_forensic_locators()
                if item.locator_id == self.locator_id
            ),
            None,
        )
        if registered is None or (
            self.locator_version,
            self.locator_digest,
            self.locator_kind,
            self.surface_class,
        ) != (
            registered.locator_version,
            registered.locator_digest,
            registered.locator_kind,
            registered.surface_class,
        ):
            raise ValueError("Forensic locator reference differs from code authority")
        return self


class ForensicImmutableArtifactLocatorRegistryRef(StrictModel):
    """Exact reference to the complete FORENSICS-001A locator registry."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    registry_id: Literal["pajin.forensics.immutable-artifact-locators"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")

    @model_validator(mode="after")
    def bind_registered_registry_reference(self) -> Self:
        if (
            self.registry_id,
            self.registry_version,
            self.registry_digest,
        ) != _forensic_locator_registry_identity():
            raise ValueError("Forensic locator registry reference differs from code authority")
        return self


class ForensicImmutableArtifactSurfaceRef(StrictModel):
    """Opaque pointer claim that becomes exact only when bound to a complete Surface."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["forensics.immutable-artifact"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.forensics.immutable-artifact.v1"] = Field(
        alias="locatorSchema"
    )
    locator_registry: ForensicImmutableArtifactLocatorRegistryRef = Field(alias="locatorRegistry")

    @model_validator(mode="after")
    def validate_pointer_shape(self) -> Self:
        if (
            self.surface_id != f"forensics-immutable-artifact-surface_{self.surface_digest}"
            or (
                self.locator_registry.registry_id,
                self.locator_registry.registry_version,
                self.locator_registry.registry_digest,
            )
            != _forensic_locator_registry_identity()
        ):
            raise ValueError(
                "Forensic Surface pointer shape or registry differs from code authority"
            )
        return self


class _NoForensicAuthority(StrictModel):
    """Authority markers that remain literal false throughout FORENSICS-001A."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    source_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="sourceResolutionAuthorized",
    )
    source_acquisition_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAcquisitionAuthorized",
    )
    source_read_authorized: Literal[False] = Field(default=False, alias="sourceReadAuthorized")
    source_mount_authorized: Literal[False] = Field(default=False, alias="sourceMountAuthorized")
    source_copy_authorized: Literal[False] = Field(default=False, alias="sourceCopyAuthorized")
    parser_selection_authorized: Literal[False] = Field(
        default=False,
        alias="parserSelectionAuthorized",
    )
    analysis_authorized: Literal[False] = Field(default=False, alias="analysisAuthorized")
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    lateral_movement_authorized: Literal[False] = Field(
        default=False,
        alias="lateralMovementAuthorized",
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceMutationAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
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
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "source_resolution_authorized",
        "source_acquisition_authorized",
        "source_read_authorized",
        "source_mount_authorized",
        "source_copy_authorized",
        "parser_selection_authorized",
        "analysis_authorized",
        "credential_access_authorized",
        "credential_use_authorized",
        "lateral_movement_authorized",
        "evidence_mutation_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "graph_admission_authorized",
        "finding_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("FORENSICS-001A authority markers must be boolean false")
        return value


class RegisteredForensicImmutableArtifactLocator(_NoForensicAuthority):
    """One code-owned Forensic locator mapping without evidence access authority."""

    api_version: Literal["pajin.dev/forensics-immutable-artifact-locator/v1alpha1"] = Field(
        default=FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredForensicImmutableArtifactLocator"] = (
        "RegisteredForensicImmutableArtifactLocator"
    )
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: ForensicSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: ForensicSurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    provenance_required: Literal[True] = Field(default=True, alias="provenanceRequired")
    provenance_preservation_required: Literal[True] = Field(
        default=True,
        alias="provenancePreservationRequired",
    )
    immutable_source_required: Literal[True] = Field(
        default=True,
        alias="immutableSourceRequired",
    )
    source_root_kind_required: Literal[True] = Field(default=True, alias="sourceRootKindRequired")
    source_root_digest_required: Literal[True] = Field(
        default=True,
        alias="sourceRootDigestRequired",
    )
    source_artifact_record_digest_required: Literal[True] = Field(
        default=True,
        alias="sourceArtifactRecordDigestRequired",
    )
    provenance_record_digest_required: Literal[True] = Field(
        default=True,
        alias="provenanceRecordDigestRequired",
    )
    artifact_digest_required: Literal[True] = Field(default=True, alias="artifactDigestRequired")
    artifact_byte_count_required: Literal[True] = Field(
        default=True,
        alias="artifactByteCountRequired",
    )
    provenance_verified: Literal[False] = Field(default=False, alias="provenanceVerified")
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    registration_only: Literal[True] = Field(default=True, alias="registrationOnly")

    @field_validator(
        "provenance_required",
        "provenance_preservation_required",
        "immutable_source_required",
        "source_root_kind_required",
        "source_root_digest_required",
        "source_artifact_record_digest_required",
        "provenance_record_digest_required",
        "artifact_digest_required",
        "artifact_byte_count_required",
        "provenance_verified",
        "locator_schema_implementation_available",
        "registration_only",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _FORENSIC_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
            )
            or self.domain_classification != _forensics_domain_classification()
            or self.domain_graph_type_set != _forensics_graph_type_set()
        ):
            raise ValueError("Forensic immutable-artifact locator differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"locator_digest"})
        canonical_json_bytes(
            material,
            label="Forensic immutable-artifact locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.forensics-immutable-artifact-locator/v1",
            material,
        )
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("Forensic immutable-artifact locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> ForensicImmutableArtifactLocatorRef:
        """Return the exact locator reference without authority transfer."""

        canonical = _validated_registered_forensic_locator(self)
        return ForensicImmutableArtifactLocatorRef(
            locatorId=canonical.locator_id,
            locatorVersion=canonical.locator_version,
            locatorDigest=canonical.locator_digest,
            locatorKind=canonical.locator_kind,
            surfaceClass=canonical.surface_class,
        )


class ForensicImmutableArtifactLocatorRegistry(_NoForensicAuthority):
    """Complete FORENSICS-001A locator registry without evidence access authority."""

    api_version: Literal["pajin.dev/forensics-immutable-artifact-locator-registry/v1alpha1"] = (
        Field(
            default=FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_REGISTRY_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["ForensicImmutableArtifactLocatorRegistry"] = (
        "ForensicImmutableArtifactLocatorRegistry"
    )
    registry_id: Literal["pajin.forensics.immutable-artifact-locators"] = Field(
        default="pajin.forensics.immutable-artifact-locators",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_api_version: Literal["pajin.dev/security-domain-taxonomy/v1alpha1"] = (
        Field(
            default=SECURITY_DOMAIN_TAXONOMY_API_VERSION,
            alias="securityDomainTaxonomyApiVersion",
        )
    )
    security_domain_taxonomy_digest: _Sha256 = Field(alias="securityDomainTaxonomyDigest")
    multi_domain_graph_semantics_api_version: Literal[
        "pajin.dev/multi-domain-graph-semantics/v1alpha1"
    ] = Field(
        default=MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
        alias="multiDomainGraphSemanticsApiVersion",
    )
    multi_domain_graph_semantics_digest: _Sha256 = Field(alias="multiDomainGraphSemanticsDigest")
    discovery_api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="discoveryApiVersion",
    )
    surface_type: Literal["forensics.immutable-artifact"] = Field(
        default=FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.forensics.immutable-artifact.v1"] = Field(
        default=FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locators: tuple[RegisteredForensicImmutableArtifactLocator, ...] = Field(
        min_length=len(_FORENSIC_LOCATOR_SPECS),
        max_length=len(_FORENSIC_LOCATOR_SPECS),
    )
    discovered_surface_initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="discoveredSurfaceInitialState",
    )
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    discovery_wire_changed: Literal[False] = Field(default=False, alias="discoveryWireChanged")
    attack_surface_wire_changed: Literal[False] = Field(
        default=False,
        alias="attackSurfaceWireChanged",
    )
    domain_semantics_registry_changed: Literal[False] = Field(
        default=False,
        alias="domainSemanticsRegistryChanged",
    )

    @field_validator(
        "registry_only",
        "discovery_wire_changed",
        "attack_surface_wire_changed",
        "domain_semantics_registry_changed",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic locator registry boundary markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        for locator in self.locators:
            _require_known_instance_fields(locator, label="Registered Forensic locator")
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _forensics_domain_classification()
            or self.domain_graph_type_set != _forensics_graph_type_set()
            or self.locators != _registered_forensic_locators()
            or tuple(item.surface_class for item in self.locators) != tuple(ForensicSurfaceClass)
        ):
            raise ValueError("Forensic locator registry differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"registry_digest"})
        canonical_json_bytes(
            material,
            label="Forensic immutable-artifact locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.forensics-immutable-artifact-registry/v1",
            material,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Forensic immutable-artifact registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> ForensicImmutableArtifactLocatorRegistryRef:
        """Return the exact complete registry reference."""

        canonical = _validated_forensic_locator_registry(self)
        return ForensicImmutableArtifactLocatorRegistryRef(
            registryId=canonical.registry_id,
            registryVersion=canonical.registry_version,
            registryDigest=canonical.registry_digest,
        )


class ForensicImmutableArtifactSurface(_NoForensicAuthority):
    """Typed immutable-source knowledge that is neither parsed nor Graph-admitted."""

    api_version: Literal["pajin.dev/forensics-immutable-artifact-surface/v1alpha1"] = Field(
        default=FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicImmutableArtifactSurface"] = "ForensicImmutableArtifactSurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=120)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["forensics.immutable-artifact"] = Field(
        default=FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.forensics.immutable-artifact.v1"] = Field(
        default=FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: ForensicSurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locator_registry: ForensicImmutableArtifactLocatorRegistryRef = Field(alias="locatorRegistry")
    locator: ForensicImmutableArtifactSurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    source_resolved: Literal[False] = Field(default=False, alias="sourceResolved")
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
    artifact_bytes_verified: Literal[False] = Field(default=False, alias="artifactBytesVerified")
    evidence_class_verified: Literal[False] = Field(default=False, alias="evidenceClassVerified")
    provenance_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="provenanceSanitizationVerified",
    )
    provenance_preserved: Literal[False] = Field(default=False, alias="provenancePreserved")
    source_format_verified: Literal[False] = Field(default=False, alias="sourceFormatVerified")
    parser_result_available: Literal[False] = Field(default=False, alias="parserResultAvailable")
    forensic_hypothesis_created: Literal[False] = Field(
        default=False,
        alias="forensicHypothesisCreated",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")

    @field_validator(
        "typed_surface_only",
        "source_resolved",
        "source_seal_verified",
        "source_authenticity_verified",
        "source_immutability_verified",
        "source_artifact_membership_verified",
        "chain_of_custody_verified",
        "artifact_digest_verified",
        "artifact_bytes_verified",
        "evidence_class_verified",
        "provenance_sanitization_verified",
        "provenance_preserved",
        "source_format_verified",
        "parser_result_available",
        "forensic_hypothesis_created",
        "evidence_sealed",
        "graph_admitted",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed Forensic Surface state markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_forensic_immutable_artifact_locator_registry()
        _require_known_instance_fields(
            self.locator_registry,
            label="Forensic locator registry reference",
        )
        canonical_locator = _validated_forensic_locator(self.locator)
        registered = next(
            (item for item in registry.locators if item.locator_kind == canonical_locator.kind),
            None,
        )
        if (
            canonical_locator != self.locator
            or self.domain_classification != _forensics_domain_classification()
            or self.domain_graph_type_set != _forensics_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError("Typed Forensic Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed Forensic immutable-artifact Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.forensics-immutable-artifact-surface/v1",
            material,
        )
        surface_id: _SurfaceId = f"forensics-immutable-artifact-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed Forensic Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed Forensic Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> ForensicImmutableArtifactSurfaceRef:
        """Return a content-addressed inert Forensic Surface reference."""

        canonical = _validated_forensic_surface(self)
        return ForensicImmutableArtifactSurfaceRef(
            surfaceId=canonical.surface_id,
            surfaceDigest=canonical.surface_digest,
            surfaceType=canonical.surface_type,
            locatorSchema=canonical.locator_schema,
            locatorRegistry=canonical.locator_registry,
        )


def registered_forensic_immutable_artifact_locator_registry() -> (
    ForensicImmutableArtifactLocatorRegistry
):
    """Return the FORENSICS-001A registry without source access authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return ForensicImmutableArtifactLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_forensics_domain_classification(),
        domainGraphTypeSet=_forensics_graph_type_set(),
        locators=_registered_forensic_locators(),
    )


@cache
def _forensic_locator_registry_identity() -> tuple[str, str, str]:
    registry = registered_forensic_immutable_artifact_locator_registry()
    return registry.registry_id, registry.registry_version, registry.registry_digest


def resolve_registered_forensic_immutable_artifact_locator(
    reference: ForensicImmutableArtifactLocatorRef,
) -> RegisteredForensicImmutableArtifactLocator:
    """Resolve one exact Forensic locator without transferring authority."""

    try:
        _require_known_instance_fields(reference, label="Forensic locator reference")
        canonical_reference = ForensicImmutableArtifactLocatorRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise ForensicSurfaceRegistryError(
            "Forensic immutable-artifact locator is not registered exactly"
        ) from exc
    if canonical_reference != reference:
        raise ForensicSurfaceRegistryError(
            "Forensic immutable-artifact locator is not registered exactly"
        )
    for locator in registered_forensic_immutable_artifact_locator_registry().locators:
        if locator.reference() == canonical_reference:
            return locator.model_copy(deep=True)
    raise ForensicSurfaceRegistryError(
        "Forensic immutable-artifact locator is not registered exactly"
    )


def resolve_forensic_immutable_artifact_locator_registry(
    reference: ForensicImmutableArtifactLocatorRegistryRef,
) -> ForensicImmutableArtifactLocatorRegistry:
    """Resolve the complete Forensic registry without activating source access."""

    try:
        _require_known_instance_fields(reference, label="Forensic locator registry reference")
        canonical_reference = ForensicImmutableArtifactLocatorRegistryRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise ForensicSurfaceRegistryError(
            "Forensic locator registry is not registered exactly"
        ) from exc
    if canonical_reference != reference:
        raise ForensicSurfaceRegistryError("Forensic locator registry is not registered exactly")
    registry = registered_forensic_immutable_artifact_locator_registry()
    if registry.reference() == canonical_reference:
        return registry.model_copy(deep=True)
    raise ForensicSurfaceRegistryError("Forensic locator registry is not registered exactly")


def typed_forensic_immutable_artifact_surface(
    *,
    locator: ForensicImmutableArtifactSurfaceLocator,
) -> ForensicImmutableArtifactSurface:
    """Type one revalidated locator as inert registered-not-authorized knowledge."""

    canonical_locator = _validated_forensic_locator(locator)
    registry = registered_forensic_immutable_artifact_locator_registry()
    registered = next(
        item for item in registry.locators if item.locator_kind == canonical_locator.kind
    )
    return ForensicImmutableArtifactSurface(
        surfaceClass=registered.surface_class,
        domainClassification=_forensics_domain_classification(),
        domainGraphTypeSet=_forensics_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=canonical_locator,
    )


def bind_forensic_immutable_artifact_surface_reference(
    *,
    reference: ForensicImmutableArtifactSurfaceRef,
    surface: ForensicImmutableArtifactSurface,
) -> ForensicImmutableArtifactSurface:
    """Bind an opaque reference to one complete revalidated Surface."""

    canonical_reference = _validated_forensic_surface_reference(reference)
    canonical_surface = _validated_forensic_surface(surface)
    if canonical_surface.reference() != canonical_reference:
        raise ForensicSurfaceRegistryError(
            "Forensic Surface reference does not identify the supplied complete Surface"
        )
    return canonical_surface.model_copy(deep=True)


def forensic_source_provenance_coordinate(
    *,
    source_root_kind: ForensicSourceRootKind,
    source_root_sha256: str,
    source_artifact_record_sha256: str,
    provenance_record_sha256: str,
    artifact_sha256: str,
    artifact_bytes: int,
) -> ForensicSourceProvenanceCoordinate:
    """Build content-free caller provenance without resolving or verifying its source."""

    return ForensicSourceProvenanceCoordinate(
        sourceRootKind=source_root_kind,
        sourceRootSha256=source_root_sha256,
        sourceArtifactRecordSha256=source_artifact_record_sha256,
        provenanceRecordSha256=provenance_record_sha256,
        artifactSha256=artifact_sha256,
        artifactBytes=artifact_bytes,
    )


def forensic_disk_surface_locator(
    *,
    provenance: ForensicSourceProvenanceCoordinate,
) -> ForensicDiskSurfaceLocator:
    """Build one disk source coordinate without resolving, reading, or mounting it."""

    return ForensicDiskSurfaceLocator(provenance=_validated_forensic_provenance(provenance))


def forensic_memory_surface_locator(
    *,
    provenance: ForensicSourceProvenanceCoordinate,
) -> ForensicMemorySurfaceLocator:
    """Build one memory source coordinate without resolving or reading it."""

    return ForensicMemorySurfaceLocator(provenance=_validated_forensic_provenance(provenance))


def forensic_log_surface_locator(
    *,
    provenance: ForensicSourceProvenanceCoordinate,
) -> ForensicLogSurfaceLocator:
    """Build one log source coordinate without resolving or reading it."""

    return ForensicLogSurfaceLocator(provenance=_validated_forensic_provenance(provenance))


def forensic_artifact_surface_locator(
    *,
    provenance: ForensicSourceProvenanceCoordinate,
) -> ForensicArtifactSurfaceLocator:
    """Build one generic artifact coordinate without resolving or parsing it."""

    return ForensicArtifactSurfaceLocator(provenance=_validated_forensic_provenance(provenance))


@cache
def _registered_forensic_locators() -> tuple[RegisteredForensicImmutableArtifactLocator, ...]:
    return tuple(
        RegisteredForensicImmutableArtifactLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_forensics_domain_classification(),
            domainGraphTypeSet=_forensics_graph_type_set(),
        )
        for spec in _FORENSIC_LOCATOR_SPECS
    )


@cache
def _forensics_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.FORENSICS
    )


@cache
def _forensics_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.FORENSICS
    )


def _validated_forensic_provenance(
    provenance: ForensicSourceProvenanceCoordinate,
) -> ForensicSourceProvenanceCoordinate:
    if not isinstance(provenance, ForensicSourceProvenanceCoordinate):
        raise ValueError("Forensic immutable-source provenance has the wrong model type")
    _require_known_instance_fields(provenance, label="Forensic immutable-source provenance")
    canonical = ForensicSourceProvenanceCoordinate.model_validate(
        provenance.model_dump(mode="json", by_alias=True)
    )
    if canonical != provenance:
        raise ValueError("Forensic immutable-source provenance instance is not exact")
    return canonical


def _validated_forensic_locator(
    locator: ForensicImmutableArtifactSurfaceLocator,
) -> (
    ForensicDiskSurfaceLocator
    | ForensicMemorySurfaceLocator
    | ForensicLogSurfaceLocator
    | ForensicArtifactSurfaceLocator
):
    if not isinstance(
        locator,
        ForensicDiskSurfaceLocator
        | ForensicMemorySurfaceLocator
        | ForensicLogSurfaceLocator
        | ForensicArtifactSurfaceLocator,
    ):
        raise ValueError("Forensic immutable-artifact locator has the wrong model type")
    _require_known_instance_fields(locator, label="Forensic immutable-artifact locator")
    _validated_forensic_provenance(locator.provenance)
    canonical = _FORENSIC_LOCATOR_ADAPTER.validate_python(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Forensic immutable-artifact locator instance is not exact")
    return canonical


def _require_known_instance_fields(model: StrictModel, *, label: str) -> None:
    unexpected = set(model.__dict__) - set(type(model).model_fields)
    if unexpected:
        raise ValueError(f"{label} contains unmodeled instance state")
    for field_name in type(model).model_fields:
        _require_known_instance_value(
            getattr(model, field_name),
            label=f"{label}.{field_name}",
        )


def _require_known_instance_value(value: object, *, label: str) -> None:
    if isinstance(value, StrictModel):
        _require_known_instance_fields(value, label=label)
    elif isinstance(value, tuple | list):
        for index, item in enumerate(value):
            _require_known_instance_value(item, label=f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_known_instance_value(item, label=f"{label}[{key!r}]")


def _validated_registered_forensic_locator(
    locator: RegisteredForensicImmutableArtifactLocator,
) -> RegisteredForensicImmutableArtifactLocator:
    if not isinstance(locator, RegisteredForensicImmutableArtifactLocator):
        raise ValueError("Registered Forensic locator has the wrong model type")
    _require_known_instance_fields(locator, label="Registered Forensic locator")
    canonical = RegisteredForensicImmutableArtifactLocator.model_validate(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Registered Forensic locator instance is not exact")
    return canonical


def _validated_forensic_locator_registry(
    registry: ForensicImmutableArtifactLocatorRegistry,
) -> ForensicImmutableArtifactLocatorRegistry:
    if not isinstance(registry, ForensicImmutableArtifactLocatorRegistry):
        raise ValueError("Forensic locator registry has the wrong model type")
    _require_known_instance_fields(registry, label="Forensic locator registry")
    canonical = ForensicImmutableArtifactLocatorRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    )
    if canonical != registry:
        raise ValueError("Forensic locator registry instance is not exact")
    return canonical


def _validated_forensic_surface(
    surface: ForensicImmutableArtifactSurface,
) -> ForensicImmutableArtifactSurface:
    if not isinstance(surface, ForensicImmutableArtifactSurface):
        raise ValueError("Typed Forensic Surface has the wrong model type")
    _require_known_instance_fields(surface, label="Typed Forensic Surface")
    canonical = ForensicImmutableArtifactSurface.model_validate(
        surface.model_dump(mode="json", by_alias=True)
    )
    if canonical != surface:
        raise ValueError("Typed Forensic Surface instance is not exact")
    return canonical


def _validated_forensic_surface_reference(
    reference: ForensicImmutableArtifactSurfaceRef,
) -> ForensicImmutableArtifactSurfaceRef:
    if not isinstance(reference, ForensicImmutableArtifactSurfaceRef):
        raise ValueError("Forensic Surface reference has the wrong model type")
    _require_known_instance_fields(reference, label="Forensic Surface reference")
    canonical = ForensicImmutableArtifactSurfaceRef.model_validate(
        reference.model_dump(mode="json", by_alias=True)
    )
    if canonical != reference:
        raise ValueError("Forensic Surface reference instance is not exact")
    return canonical


__all__ = [
    "FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_API_VERSION",
    "FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_REGISTRY_API_VERSION",
    "FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_SCHEMA",
    "FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_API_VERSION",
    "FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_TYPE",
    "FORENSICS_SOURCE_PROVENANCE_COORDINATE_API_VERSION",
    "ForensicArtifactSurfaceLocator",
    "ForensicDiskSurfaceLocator",
    "ForensicImmutableArtifactLocatorRef",
    "ForensicImmutableArtifactLocatorRegistry",
    "ForensicImmutableArtifactLocatorRegistryRef",
    "ForensicImmutableArtifactSurface",
    "ForensicImmutableArtifactSurfaceLocator",
    "ForensicImmutableArtifactSurfaceRef",
    "ForensicLogSurfaceLocator",
    "ForensicMemorySurfaceLocator",
    "ForensicSourceProvenanceCoordinate",
    "ForensicSourceRootKind",
    "ForensicSurfaceClass",
    "ForensicSurfaceLocatorKind",
    "ForensicSurfaceRegistryError",
    "RegisteredForensicImmutableArtifactLocator",
    "bind_forensic_immutable_artifact_surface_reference",
    "forensic_artifact_surface_locator",
    "forensic_disk_surface_locator",
    "forensic_log_surface_locator",
    "forensic_memory_surface_locator",
    "forensic_source_provenance_coordinate",
    "registered_forensic_immutable_artifact_locator_registry",
    "resolve_forensic_immutable_artifact_locator_registry",
    "resolve_registered_forensic_immutable_artifact_locator",
    "typed_forensic_immutable_artifact_surface",
]
