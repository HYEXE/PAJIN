"""APP-001A typed Application Surfaces without analysis or execution authority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

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

APPLICATION_ARTIFACT_RUNTIME_LOCATOR_API_VERSION: Literal[
    "pajin.dev/application-artifact-runtime-locator/v1alpha1"
] = "pajin.dev/application-artifact-runtime-locator/v1alpha1"
APPLICATION_ARTIFACT_RUNTIME_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/application-artifact-runtime-locator-registry/v1alpha1"
] = "pajin.dev/application-artifact-runtime-locator-registry/v1alpha1"
APPLICATION_ARTIFACT_RUNTIME_SURFACE_API_VERSION: Literal[
    "pajin.dev/application-artifact-runtime-surface/v1alpha1"
] = "pajin.dev/application-artifact-runtime-surface/v1alpha1"

APPLICATION_ARTIFACT_RUNTIME_SURFACE_TYPE: Literal["application.artifact-runtime"] = (
    "application.artifact-runtime"
)
APPLICATION_ARTIFACT_RUNTIME_LOCATOR_SCHEMA: Literal[
    "pajin.locator.application.artifact-runtime.v1"
] = "pajin.locator.application.artifact-runtime.v1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_Coordinate = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._+-]{0,127}$"),
]
_ExactVersion = Annotated[
    str,
    Field(
        min_length=3,
        max_length=96,
        pattern=r"^[0-9]+(?:\.[0-9a-z]+)+(?:[-+][0-9a-z][0-9a-z.-]*)?$",
    ),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^application-artifact-runtime-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 256 * 1024
_MAX_TYPED_SURFACE_BYTES = 256 * 1024
_MUTABLE_COORDINATE_TOKENS = frozenset(
    {
        "any",
        "auto",
        "current",
        "default",
        "latest",
        "local",
        "stable",
        "unknown",
        "x",
    }
)


class ApplicationSurfaceRegistryError(RuntimeError):
    """Raised when an exact APP-001A registry reference cannot be resolved."""


class ApplicationSurfaceClass(StrEnum):
    """Application knowledge classes that grant no analysis or runtime authority."""

    BINARY = "binary"
    CONFIGURATION = "configuration"
    RUNTIME = "runtime"
    LIBRARY = "library"


class _ContentOnlyApplicationLocator(StrictModel):
    """Negative markers shared by raw-value-free Application locators."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    raw_artifact_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentEmbedded",
    )
    mutable_path_embedded: Literal[False] = Field(
        default=False,
        alias="mutablePathEmbedded",
    )
    runtime_process_state_embedded: Literal[False] = Field(
        default=False,
        alias="runtimeProcessStateEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )

    @field_validator(
        "raw_artifact_content_embedded",
        "mutable_path_embedded",
        "runtime_process_state_embedded",
        "secret_material_embedded",
        "credential_reference_embedded",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application locator security markers must be boolean false")
        return value


class ApplicationBinarySurfaceLocator(_ContentOnlyApplicationLocator):
    """One immutable application binary artifact digest without a path or format claim."""

    kind: Literal["application-binary"] = "application-binary"
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")


class ApplicationConfigurationSurfaceLocator(_ContentOnlyApplicationLocator):
    """One sanitized configuration artifact bound to an exact binary parent."""

    kind: Literal["application-configuration"] = "application-configuration"
    parent: ApplicationBinarySurfaceLocator
    configuration_namespace: _Coordinate = Field(alias="configurationNamespace")
    configuration_id: _Coordinate = Field(alias="configurationId")
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")

    @field_validator("configuration_namespace", "configuration_id", mode="before")
    @classmethod
    def canonicalize_configuration_coordinate(cls, value: object) -> object:
        return _canonical_application_coordinate(
            value, label="Application configuration coordinate"
        )


class ApplicationRuntimeSurfaceLocator(_ContentOnlyApplicationLocator):
    """One declared runtime artifact bound to a binary, never a live process."""

    kind: Literal["application-runtime"] = "application-runtime"
    parent: ApplicationBinarySurfaceLocator
    runtime_family: _Coordinate = Field(alias="runtimeFamily")
    runtime_version: _ExactVersion = Field(alias="runtimeVersion")
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")

    @field_validator("runtime_family", mode="before")
    @classmethod
    def canonicalize_runtime_family(cls, value: object) -> object:
        return _canonical_application_coordinate(value, label="Application runtime family")

    @field_validator("runtime_version", mode="before")
    @classmethod
    def canonicalize_runtime_version(cls, value: object) -> object:
        return _canonical_exact_version(value, label="Application runtime version")


ApplicationLibraryParentLocator = Annotated[
    ApplicationBinarySurfaceLocator | ApplicationRuntimeSurfaceLocator,
    Field(discriminator="kind"),
]


class ApplicationLibrarySurfaceLocator(_ContentOnlyApplicationLocator):
    """One exact library artifact below a binary or declared runtime parent."""

    kind: Literal["application-library"] = "application-library"
    parent: ApplicationLibraryParentLocator
    library_namespace: _Coordinate = Field(alias="libraryNamespace")
    library_id: _Coordinate = Field(alias="libraryId")
    library_version: _ExactVersion = Field(alias="libraryVersion")
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")

    @field_validator("library_namespace", "library_id", mode="before")
    @classmethod
    def canonicalize_library_coordinate(cls, value: object) -> object:
        return _canonical_application_coordinate(value, label="Application library coordinate")

    @field_validator("library_version", mode="before")
    @classmethod
    def canonicalize_library_version(cls, value: object) -> object:
        return _canonical_exact_version(value, label="Application library version")


ApplicationArtifactRuntimeSurfaceLocator = Annotated[
    ApplicationBinarySurfaceLocator
    | ApplicationConfigurationSurfaceLocator
    | ApplicationRuntimeSurfaceLocator
    | ApplicationLibrarySurfaceLocator,
    Field(discriminator="kind"),
]

ApplicationSurfaceLocatorKind = Literal[
    "application-binary",
    "application-configuration",
    "application-runtime",
    "application-library",
]
ApplicationParentRequirement = Literal[
    "none",
    "binary",
    "binary-or-runtime",
]


@dataclass(frozen=True, slots=True)
class _ApplicationLocatorSpec:
    locator_id: str
    locator_kind: ApplicationSurfaceLocatorKind
    surface_class: ApplicationSurfaceClass
    source_model_id: str
    parent_requirement: ApplicationParentRequirement
    artifact_digest_required: bool
    exact_parent_lineage_required: bool
    exact_version_required: bool


_APPLICATION_LOCATOR_SPECS = (
    _ApplicationLocatorSpec(
        "pajin.locator.application.binary",
        "application-binary",
        ApplicationSurfaceClass.BINARY,
        "pajin.discovery.application_surfaces.ApplicationBinarySurfaceLocator",
        "none",
        True,
        False,
        False,
    ),
    _ApplicationLocatorSpec(
        "pajin.locator.application.configuration",
        "application-configuration",
        ApplicationSurfaceClass.CONFIGURATION,
        "pajin.discovery.application_surfaces.ApplicationConfigurationSurfaceLocator",
        "binary",
        True,
        True,
        False,
    ),
    _ApplicationLocatorSpec(
        "pajin.locator.application.runtime",
        "application-runtime",
        ApplicationSurfaceClass.RUNTIME,
        "pajin.discovery.application_surfaces.ApplicationRuntimeSurfaceLocator",
        "binary",
        True,
        True,
        True,
    ),
    _ApplicationLocatorSpec(
        "pajin.locator.application.library",
        "application-library",
        ApplicationSurfaceClass.LIBRARY,
        "pajin.discovery.application_surfaces.ApplicationLibrarySurfaceLocator",
        "binary-or-runtime",
        True,
        True,
        True,
    ),
)


class ApplicationArtifactRuntimeLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered Application locator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: ApplicationSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: ApplicationSurfaceClass = Field(alias="surfaceClass")


class ApplicationArtifactRuntimeLocatorRegistryRef(StrictModel):
    """Exact reference to the complete APP-001A locator registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    registry_id: Literal["pajin.application.artifact-runtime-locators"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class ApplicationArtifactRuntimeSurfaceRef(StrictModel):
    """Exact reference to one inert typed Application Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["application.artifact-runtime"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.application.artifact-runtime.v1"] = Field(
        alias="locatorSchema"
    )
    surface_class: ApplicationSurfaceClass = Field(alias="surfaceClass")
    locator_kind: ApplicationSurfaceLocatorKind = Field(alias="locatorKind")
    locator_registry: ApplicationArtifactRuntimeLocatorRegistryRef = Field(alias="locatorRegistry")


class RegisteredApplicationArtifactRuntimeLocator(StrictModel):
    """One code-owned Application locator mapping without analysis authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-artifact-runtime-locator/v1alpha1"] = Field(
        default=APPLICATION_ARTIFACT_RUNTIME_LOCATOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredApplicationArtifactRuntimeLocator"] = (
        "RegisteredApplicationArtifactRuntimeLocator"
    )
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: ApplicationSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: ApplicationSurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    parent_requirement: ApplicationParentRequirement = Field(alias="parentRequirement")
    artifact_digest_required: bool = Field(alias="artifactDigestRequired")
    exact_parent_lineage_required: bool = Field(alias="exactParentLineageRequired")
    exact_version_required: bool = Field(alias="exactVersionRequired")
    secret_free: Literal[True] = Field(default=True, alias="secretFree")
    mutable_path_allowed: Literal[False] = Field(default=False, alias="mutablePathAllowed")
    live_runtime_state_allowed: Literal[False] = Field(
        default=False,
        alias="liveRuntimeStateAllowed",
    )
    raw_artifact_content_allowed: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentAllowed",
    )
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    registration_only: Literal[True] = Field(default=True, alias="registrationOnly")
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    static_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="staticAnalysisAuthorized",
    )
    dynamic_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicAnalysisAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "artifact_digest_required",
        "exact_parent_lineage_required",
        "exact_version_required",
        "secret_free",
        "mutable_path_allowed",
        "live_runtime_state_allowed",
        "raw_artifact_content_allowed",
        "locator_schema_implementation_available",
        "registration_only",
        "artifact_read_authorized",
        "static_analysis_authorized",
        "dynamic_analysis_authorized",
        "debugger_attach_authorized",
        "network_access_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _APPLICATION_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
                self.parent_requirement,
                self.artifact_digest_required,
                self.exact_parent_lineage_required,
                self.exact_version_required,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
                spec.parent_requirement,
                spec.artifact_digest_required,
                spec.exact_parent_lineage_required,
                spec.exact_version_required,
            )
            or self.domain_classification != _application_domain_classification()
            or self.domain_graph_type_set != _application_graph_type_set()
        ):
            raise ValueError("Application artifact/runtime locator differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"locator_digest"},
        )
        canonical_json_bytes(
            material,
            label="Application artifact/runtime locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.application-artifact-runtime-locator/v1",
            material,
        )
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("Application artifact/runtime locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> ApplicationArtifactRuntimeLocatorRef:
        """Return the exact locator reference without authority transfer."""

        return ApplicationArtifactRuntimeLocatorRef(
            locatorId=self.locator_id,
            locatorVersion=self.locator_version,
            locatorDigest=self.locator_digest,
            locatorKind=self.locator_kind,
            surfaceClass=self.surface_class,
        )


class ApplicationArtifactRuntimeLocatorRegistry(StrictModel):
    """Complete binary/configuration/runtime/library registry without analysis authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-artifact-runtime-locator-registry/v1alpha1"] = (
        Field(
            default=APPLICATION_ARTIFACT_RUNTIME_LOCATOR_REGISTRY_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["ApplicationArtifactRuntimeLocatorRegistry"] = (
        "ApplicationArtifactRuntimeLocatorRegistry"
    )
    registry_id: Literal["pajin.application.artifact-runtime-locators"] = Field(
        default="pajin.application.artifact-runtime-locators",
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
    surface_type: Literal["application.artifact-runtime"] = Field(
        default=APPLICATION_ARTIFACT_RUNTIME_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.application.artifact-runtime.v1"] = Field(
        default=APPLICATION_ARTIFACT_RUNTIME_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locators: tuple[RegisteredApplicationArtifactRuntimeLocator, ...] = Field(
        min_length=len(_APPLICATION_LOCATOR_SPECS),
        max_length=len(_APPLICATION_LOCATOR_SPECS),
    )
    discovered_surface_initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="discoveredSurfaceInitialState",
    )
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    discovery_wire_changed: Literal[False] = Field(
        default=False,
        alias="discoveryWireChanged",
    )
    attack_surface_wire_changed: Literal[False] = Field(
        default=False,
        alias="attackSurfaceWireChanged",
    )
    domain_semantics_registry_changed: Literal[False] = Field(
        default=False,
        alias="domainSemanticsRegistryChanged",
    )
    discovery_authorized: Literal[False] = Field(default=False, alias="discoveryAuthorized")
    artifact_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="artifactResolutionAuthorized",
    )
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    static_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="staticAnalysisAuthorized",
    )
    dynamic_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicAnalysisAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
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
    sandbox_selection_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "registry_only",
        "discovery_wire_changed",
        "attack_surface_wire_changed",
        "domain_semantics_registry_changed",
        "discovery_authorized",
        "artifact_resolution_authorized",
        "artifact_read_authorized",
        "static_analysis_authorized",
        "dynamic_analysis_authorized",
        "credential_access_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "sandbox_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "debugger_attach_authorized",
        "artifact_mutation_authorized",
        "graph_admission_authorized",
        "finding_authority",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application locator registry authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _application_domain_classification()
            or self.domain_graph_type_set != _application_graph_type_set()
            or self.locators != _registered_application_locators()
            or tuple(item.surface_class for item in self.locators) != tuple(ApplicationSurfaceClass)
        ):
            raise ValueError(
                "Application artifact/runtime locator registry differs from code authority"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        canonical_json_bytes(
            material,
            label="Application artifact/runtime locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.application-artifact-runtime-registry/v1",
            material,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Application artifact/runtime locator registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> ApplicationArtifactRuntimeLocatorRegistryRef:
        """Return the exact complete registry reference."""

        return ApplicationArtifactRuntimeLocatorRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )


class ApplicationArtifactRuntimeSurface(StrictModel):
    """Typed Application knowledge that is neither analyzed nor Graph-admitted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/application-artifact-runtime-surface/v1alpha1"] = Field(
        default=APPLICATION_ARTIFACT_RUNTIME_SURFACE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationArtifactRuntimeSurface"] = "ApplicationArtifactRuntimeSurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=110)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["application.artifact-runtime"] = Field(
        default=APPLICATION_ARTIFACT_RUNTIME_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.application.artifact-runtime.v1"] = Field(
        default=APPLICATION_ARTIFACT_RUNTIME_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: ApplicationSurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locator_registry: ApplicationArtifactRuntimeLocatorRegistryRef = Field(alias="locatorRegistry")
    locator: ApplicationArtifactRuntimeSurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    discovery_observed: Literal[False] = Field(default=False, alias="discoveryObserved")
    artifact_resolved: Literal[False] = Field(default=False, alias="artifactResolved")
    artifact_bytes_verified: Literal[False] = Field(
        default=False,
        alias="artifactBytesVerified",
    )
    binary_format_verified: Literal[False] = Field(
        default=False,
        alias="binaryFormatVerified",
    )
    configuration_semantics_verified: Literal[False] = Field(
        default=False,
        alias="configurationSemanticsVerified",
    )
    runtime_environment_verified: Literal[False] = Field(
        default=False,
        alias="runtimeEnvironmentVerified",
    )
    library_dependency_verified: Literal[False] = Field(
        default=False,
        alias="libraryDependencyVerified",
    )
    vulnerability_confirmed: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmed",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    artifact_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="artifactResolutionAuthorized",
    )
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    static_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="staticAnalysisAuthorized",
    )
    dynamic_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicAnalysisAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
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
    sandbox_selection_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "typed_surface_only",
        "discovery_observed",
        "artifact_resolved",
        "artifact_bytes_verified",
        "binary_format_verified",
        "configuration_semantics_verified",
        "runtime_environment_verified",
        "library_dependency_verified",
        "vulnerability_confirmed",
        "evidence_sealed",
        "graph_admitted",
        "artifact_resolution_authorized",
        "artifact_read_authorized",
        "static_analysis_authorized",
        "dynamic_analysis_authorized",
        "credential_access_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "sandbox_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "debugger_attach_authorized",
        "artifact_mutation_authorized",
        "finding_authority",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed Application Surface authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_application_artifact_runtime_locator_registry()
        registered = next(
            (item for item in registry.locators if item.locator_kind == self.locator.kind),
            None,
        )
        if (
            self.domain_classification != _application_domain_classification()
            or self.domain_graph_type_set != _application_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError(
                "Typed Application artifact/runtime Surface differs from code authority"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed Application artifact/runtime Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.application-artifact-runtime-surface/v1",
            material,
        )
        surface_id: _SurfaceId = f"application-artifact-runtime-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed Application Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed Application Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> ApplicationArtifactRuntimeSurfaceRef:
        """Return a content-addressed inert Surface reference."""

        return ApplicationArtifactRuntimeSurfaceRef(
            surfaceId=self.surface_id,
            surfaceDigest=self.surface_digest,
            surfaceType=self.surface_type,
            locatorSchema=self.locator_schema,
            surfaceClass=self.surface_class,
            locatorKind=self.locator.kind,
            locatorRegistry=self.locator_registry,
        )


def registered_application_artifact_runtime_locator_registry() -> (
    ApplicationArtifactRuntimeLocatorRegistry
):
    """Return the APP-001A registry without artifact access or analysis authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return ApplicationArtifactRuntimeLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_application_domain_classification(),
        domainGraphTypeSet=_application_graph_type_set(),
        locators=_registered_application_locators(),
    )


def resolve_registered_application_artifact_runtime_locator(
    reference: ApplicationArtifactRuntimeLocatorRef,
) -> RegisteredApplicationArtifactRuntimeLocator:
    """Resolve one exact Application locator without transferring authority."""

    for locator in registered_application_artifact_runtime_locator_registry().locators:
        if locator.reference() == reference:
            return locator.model_copy(deep=True)
    raise ApplicationSurfaceRegistryError(
        "Application artifact/runtime locator is not registered exactly"
    )


def resolve_application_artifact_runtime_locator_registry(
    reference: ApplicationArtifactRuntimeLocatorRegistryRef,
) -> ApplicationArtifactRuntimeLocatorRegistry:
    """Resolve the complete Application registry without activating analysis behavior."""

    registry = registered_application_artifact_runtime_locator_registry()
    if registry.reference() == reference:
        return registry.model_copy(deep=True)
    raise ApplicationSurfaceRegistryError(
        "Application artifact/runtime locator registry is not registered exactly"
    )


def typed_application_artifact_runtime_surface(
    *,
    locator: ApplicationArtifactRuntimeSurfaceLocator,
) -> ApplicationArtifactRuntimeSurface:
    """Type a locator as inert registered-not-authorized Application knowledge."""

    registry = registered_application_artifact_runtime_locator_registry()
    registered = next(item for item in registry.locators if item.locator_kind == locator.kind)
    return ApplicationArtifactRuntimeSurface(
        surfaceClass=registered.surface_class,
        domainClassification=_application_domain_classification(),
        domainGraphTypeSet=_application_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=locator.model_copy(deep=True),
    )


def application_binary_surface_locator(
    *,
    artifact_sha256: str,
) -> ApplicationBinarySurfaceLocator:
    """Build one immutable binary coordinate without reading or classifying its bytes."""

    return ApplicationBinarySurfaceLocator(artifactSha256=artifact_sha256)


def application_configuration_surface_locator(
    *,
    parent: ApplicationBinarySurfaceLocator,
    configuration_namespace: str,
    configuration_id: str,
    artifact_sha256: str,
) -> ApplicationConfigurationSurfaceLocator:
    """Build one sanitized configuration coordinate below an exact binary."""

    return ApplicationConfigurationSurfaceLocator(
        parent=parent.model_copy(deep=True),
        configurationNamespace=configuration_namespace,
        configurationId=configuration_id,
        artifactSha256=artifact_sha256,
    )


def application_runtime_surface_locator(
    *,
    parent: ApplicationBinarySurfaceLocator,
    runtime_family: str,
    runtime_version: str,
    artifact_sha256: str,
) -> ApplicationRuntimeSurfaceLocator:
    """Build one declared runtime artifact coordinate without invoking it."""

    return ApplicationRuntimeSurfaceLocator(
        parent=parent.model_copy(deep=True),
        runtimeFamily=runtime_family,
        runtimeVersion=runtime_version,
        artifactSha256=artifact_sha256,
    )


def application_library_surface_locator(
    *,
    parent: ApplicationLibraryParentLocator,
    library_namespace: str,
    library_id: str,
    library_version: str,
    artifact_sha256: str,
) -> ApplicationLibrarySurfaceLocator:
    """Build one exact library artifact coordinate without dependency resolution."""

    return ApplicationLibrarySurfaceLocator(
        parent=parent.model_copy(deep=True),
        libraryNamespace=library_namespace,
        libraryId=library_id,
        libraryVersion=library_version,
        artifactSha256=artifact_sha256,
    )


@cache
def _registered_application_locators() -> tuple[RegisteredApplicationArtifactRuntimeLocator, ...]:
    return tuple(
        RegisteredApplicationArtifactRuntimeLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_application_domain_classification(),
            domainGraphTypeSet=_application_graph_type_set(),
            parentRequirement=spec.parent_requirement,
            artifactDigestRequired=spec.artifact_digest_required,
            exactParentLineageRequired=spec.exact_parent_lineage_required,
            exactVersionRequired=spec.exact_version_required,
        )
        for spec in _APPLICATION_LOCATOR_SPECS
    )


@cache
def _application_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.APPLICATION
    )


@cache
def _application_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.APPLICATION
    )


def _canonical_application_coordinate(value: object, *, label: str) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    if "://" in value or any(character in value for character in "/\\?#*"):
        raise ValueError(f"{label} cannot contain path, URL, query, fragment, or wildcard syntax")
    canonical = value.casefold()
    tokens = tuple(filter(None, re.split(r"[._+-]", canonical)))
    if not tokens or any(token in _MUTABLE_COORDINATE_TOKENS for token in tokens):
        raise ValueError(f"{label} must be one explicit stable coordinate")
    return canonical


def _canonical_exact_version(value: object, *, label: str) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    canonical = value.casefold()
    tokens = tuple(filter(None, re.split(r"[._+-]", canonical)))
    if not tokens or any(token in _MUTABLE_COORDINATE_TOKENS for token in tokens):
        raise ValueError(f"{label} must be one exact non-floating version")
    return canonical


__all__ = [
    "APPLICATION_ARTIFACT_RUNTIME_LOCATOR_API_VERSION",
    "APPLICATION_ARTIFACT_RUNTIME_LOCATOR_REGISTRY_API_VERSION",
    "APPLICATION_ARTIFACT_RUNTIME_LOCATOR_SCHEMA",
    "APPLICATION_ARTIFACT_RUNTIME_SURFACE_API_VERSION",
    "APPLICATION_ARTIFACT_RUNTIME_SURFACE_TYPE",
    "ApplicationArtifactRuntimeLocatorRef",
    "ApplicationArtifactRuntimeLocatorRegistry",
    "ApplicationArtifactRuntimeLocatorRegistryRef",
    "ApplicationArtifactRuntimeSurface",
    "ApplicationArtifactRuntimeSurfaceLocator",
    "ApplicationArtifactRuntimeSurfaceRef",
    "ApplicationBinarySurfaceLocator",
    "ApplicationConfigurationSurfaceLocator",
    "ApplicationLibraryParentLocator",
    "ApplicationLibrarySurfaceLocator",
    "ApplicationParentRequirement",
    "ApplicationRuntimeSurfaceLocator",
    "ApplicationSurfaceClass",
    "ApplicationSurfaceLocatorKind",
    "ApplicationSurfaceRegistryError",
    "RegisteredApplicationArtifactRuntimeLocator",
    "application_binary_surface_locator",
    "application_configuration_surface_locator",
    "application_library_surface_locator",
    "application_runtime_surface_locator",
    "registered_application_artifact_runtime_locator_registry",
    "resolve_application_artifact_runtime_locator_registry",
    "resolve_registered_application_artifact_runtime_locator",
    "typed_application_artifact_runtime_surface",
]
