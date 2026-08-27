"""SYS-001A typed System Surfaces without host-access or inspection authority."""

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

SYSTEM_HOST_RESOURCE_LOCATOR_API_VERSION: Literal[
    "pajin.dev/system-host-resource-locator/v1alpha1"
] = "pajin.dev/system-host-resource-locator/v1alpha1"
SYSTEM_HOST_RESOURCE_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/system-host-resource-locator-registry/v1alpha1"
] = "pajin.dev/system-host-resource-locator-registry/v1alpha1"
SYSTEM_HOST_RESOURCE_SURFACE_API_VERSION: Literal[
    "pajin.dev/system-host-resource-surface/v1alpha1"
] = "pajin.dev/system-host-resource-surface/v1alpha1"

SYSTEM_HOST_RESOURCE_SURFACE_TYPE: Literal["system.host-resource"] = "system.host-resource"
SYSTEM_HOST_RESOURCE_LOCATOR_SCHEMA: Literal["pajin.locator.system.host-resource.v1"] = (
    "pajin.locator.system.host-resource.v1"
)

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_HostId = Annotated[
    str,
    Field(min_length=69, max_length=69, pattern=r"^host-[a-f0-9]{64}$"),
]
_Coordinate = Annotated[
    str,
    Field(min_length=2, max_length=100, pattern=r"^[a-z0-9][a-z0-9._-]{1,99}$"),
]
_ServiceId = Annotated[
    str,
    Field(min_length=2, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._@:-]{1,199}$"),
]
_PortableReference = Annotated[str, Field(min_length=1, max_length=512)]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^system-host-resource-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 256 * 1024
_MAX_TYPED_SURFACE_BYTES = 256 * 1024
_MUTABLE_IDENTITY_ALIASES = frozenset(
    {
        "auto",
        "current",
        "default",
        "latest",
        "local",
        "localhost",
        "this-host",
        "unknown",
    }
)
_PORTABLE_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")


class SystemSurfaceRegistryError(RuntimeError):
    """Raised when an exact SYS-001A registry reference cannot be resolved."""


class SystemSurfaceClass(StrEnum):
    """System knowledge classes; values grant no host or inspection authority."""

    HOST = "host"
    PROCESS = "process"
    FILESYSTEM = "filesystem"
    SERVICE = "service"
    CONFIGURATION = "configuration"


class SystemOperatingSystem(StrEnum):
    """Bounded operating-system families without host-attestation claims."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"


class SystemArchitecture(StrEnum):
    """Bounded machine architectures used only as locator dimensions."""

    X86_64 = "x86_64"
    AARCH64 = "aarch64"


class SystemFilesystemEntryKind(StrEnum):
    """Portable non-alias filesystem entry kinds."""

    FILE = "file"
    DIRECTORY = "directory"


class SystemServiceManager(StrEnum):
    """Service-manager namespaces whose stable unit IDs are explicit."""

    SYSTEMD = "systemd"
    WINDOWS_SERVICE = "windows-service"
    LAUNCHD = "launchd"


class _SecretFreeSystemLocator(StrictModel):
    """Negative markers shared by all non-authoritative System locators."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )
    host_local_absolute_path_embedded: Literal[False] = Field(
        default=False,
        alias="hostLocalAbsolutePathEmbedded",
    )
    privilege_claim_embedded: Literal[False] = Field(
        default=False,
        alias="privilegeClaimEmbedded",
    )

    @field_validator(
        "secret_material_embedded",
        "credential_reference_embedded",
        "host_local_absolute_path_embedded",
        "privilege_claim_embedded",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System locator security markers must be booleans")
        return value


class SystemHostSurfaceLocator(_SecretFreeSystemLocator):
    """One pseudonymous deployment-stable host coordinate without host access."""

    kind: Literal["system-host"] = "system-host"
    host_id: _HostId = Field(alias="hostId")
    operating_system: SystemOperatingSystem = Field(alias="operatingSystem")
    architecture: SystemArchitecture

    @field_validator("host_id", mode="before")
    @classmethod
    def canonicalize_host_id(cls, value: object) -> object:
        return _canonical_system_coordinate(value, label="System host ID")


class SystemProcessSurfaceLocator(_SecretFreeSystemLocator):
    """One process-snapshot identity without mutable PID or live-state claims."""

    kind: Literal["system-process"] = "system-process"
    host: SystemHostSurfaceLocator
    process_instance_digest: _Sha256 = Field(alias="processInstanceDigest")
    executable_digest: _Sha256 = Field(alias="executableDigest")


class SystemFilesystemSurfaceLocator(_SecretFreeSystemLocator):
    """One content-bound entry below a logical mount, never an absolute host path."""

    kind: Literal["system-filesystem"] = "system-filesystem"
    host: SystemHostSurfaceLocator
    mount_id: _Coordinate = Field(alias="mountId")
    relative_path: _PortableReference = Field(alias="relativePath")
    entry_kind: SystemFilesystemEntryKind = Field(alias="entryKind")
    content_digest: _Sha256 = Field(alias="contentDigest")

    @field_validator("mount_id", mode="before")
    @classmethod
    def canonicalize_mount_id(cls, value: object) -> object:
        return _canonical_system_coordinate(value, label="System logical mount ID")

    @field_validator("relative_path", mode="before")
    @classmethod
    def require_portable_relative_path(cls, value: object) -> object:
        return _portable_relative_reference(value, label="System filesystem relative path")


class SystemServiceSurfaceLocator(_SecretFreeSystemLocator):
    """One manager-qualified unit identity without display-name or control authority."""

    kind: Literal["system-service"] = "system-service"
    host: SystemHostSurfaceLocator
    service_manager: SystemServiceManager = Field(alias="serviceManager")
    service_id: _ServiceId = Field(alias="serviceId")
    definition_digest: _Sha256 = Field(alias="definitionDigest")

    @field_validator("service_id")
    @classmethod
    def require_stable_service_id(cls, value: str) -> str:
        return _stable_service_identity(value)

    @model_validator(mode="after")
    def bind_manager_specific_identity(self) -> Self:
        if self.service_manager is SystemServiceManager.SYSTEMD and not self.service_id.endswith(
            ".service"
        ):
            raise ValueError("systemd service IDs must be exact .service unit IDs")
        if self.service_manager is SystemServiceManager.WINDOWS_SERVICE:
            object.__setattr__(self, "service_id", self.service_id.casefold())
        return self


SystemConfigurationParentLocator = Annotated[
    SystemHostSurfaceLocator
    | SystemProcessSurfaceLocator
    | SystemFilesystemSurfaceLocator
    | SystemServiceSurfaceLocator,
    Field(discriminator="kind"),
]


class SystemConfigurationSurfaceLocator(_SecretFreeSystemLocator):
    """One sanitized configuration-record identity without raw values or read authority."""

    kind: Literal["system-configuration"] = "system-configuration"
    parent: SystemConfigurationParentLocator
    configuration_namespace: _Coordinate = Field(alias="configurationNamespace")
    configuration_id: _PortableReference = Field(alias="configurationId")
    configuration_digest: _Sha256 = Field(alias="configurationDigest")

    @field_validator("configuration_namespace", mode="before")
    @classmethod
    def canonicalize_configuration_namespace(cls, value: object) -> object:
        return _canonical_system_coordinate(value, label="System configuration namespace")

    @field_validator("configuration_id", mode="before")
    @classmethod
    def require_portable_configuration_id(cls, value: object) -> object:
        return _portable_relative_reference(value, label="System configuration ID")


SystemHostResourceSurfaceLocator = Annotated[
    SystemHostSurfaceLocator
    | SystemProcessSurfaceLocator
    | SystemFilesystemSurfaceLocator
    | SystemServiceSurfaceLocator
    | SystemConfigurationSurfaceLocator,
    Field(discriminator="kind"),
]

SystemSurfaceLocatorKind = Literal[
    "system-host",
    "system-process",
    "system-filesystem",
    "system-service",
    "system-configuration",
]
SystemParentRequirement = Literal[
    "none",
    "host",
    "host-or-process-or-filesystem-or-service",
]


@dataclass(frozen=True, slots=True)
class _SystemLocatorSpec:
    locator_id: str
    locator_kind: SystemSurfaceLocatorKind
    surface_class: SystemSurfaceClass
    source_model_id: str
    parent_requirement: SystemParentRequirement
    content_digest_required: bool
    portable_relative_path_required: bool


_SYSTEM_LOCATOR_SPECS = (
    _SystemLocatorSpec(
        "pajin.locator.system.host",
        "system-host",
        SystemSurfaceClass.HOST,
        "pajin.discovery.system_surfaces.SystemHostSurfaceLocator",
        "none",
        False,
        False,
    ),
    _SystemLocatorSpec(
        "pajin.locator.system.process",
        "system-process",
        SystemSurfaceClass.PROCESS,
        "pajin.discovery.system_surfaces.SystemProcessSurfaceLocator",
        "host",
        True,
        False,
    ),
    _SystemLocatorSpec(
        "pajin.locator.system.filesystem",
        "system-filesystem",
        SystemSurfaceClass.FILESYSTEM,
        "pajin.discovery.system_surfaces.SystemFilesystemSurfaceLocator",
        "host",
        True,
        True,
    ),
    _SystemLocatorSpec(
        "pajin.locator.system.service",
        "system-service",
        SystemSurfaceClass.SERVICE,
        "pajin.discovery.system_surfaces.SystemServiceSurfaceLocator",
        "host",
        True,
        False,
    ),
    _SystemLocatorSpec(
        "pajin.locator.system.configuration",
        "system-configuration",
        SystemSurfaceClass.CONFIGURATION,
        "pajin.discovery.system_surfaces.SystemConfigurationSurfaceLocator",
        "host-or-process-or-filesystem-or-service",
        True,
        False,
    ),
)


class SystemHostResourceLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered System locator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: SystemSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: SystemSurfaceClass = Field(alias="surfaceClass")


class SystemHostResourceLocatorRegistryRef(StrictModel):
    """Exact reference to the complete SYS-001A locator registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    registry_id: Literal["pajin.system.host-resource-locators"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class SystemHostResourceSurfaceRef(StrictModel):
    """Exact reference to one inert typed System Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["system.host-resource"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.system.host-resource.v1"] = Field(alias="locatorSchema")
    surface_class: SystemSurfaceClass = Field(alias="surfaceClass")
    locator_kind: SystemSurfaceLocatorKind = Field(alias="locatorKind")
    locator_registry: SystemHostResourceLocatorRegistryRef = Field(alias="locatorRegistry")


class RegisteredSystemHostResourceLocator(StrictModel):
    """One code-owned System locator mapping without host inspection authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-host-resource-locator/v1alpha1"] = Field(
        default=SYSTEM_HOST_RESOURCE_LOCATOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredSystemHostResourceLocator"] = "RegisteredSystemHostResourceLocator"
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: SystemSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: SystemSurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    parent_requirement: SystemParentRequirement = Field(alias="parentRequirement")
    content_digest_required: bool = Field(alias="contentDigestRequired")
    portable_relative_path_required: bool = Field(alias="portableRelativePathRequired")
    secret_free: Literal[True] = Field(default=True, alias="secretFree")
    mutable_runtime_identifier_allowed: Literal[False] = Field(
        default=False,
        alias="mutableRuntimeIdentifierAllowed",
    )
    host_local_absolute_path_allowed: Literal[False] = Field(
        default=False,
        alias="hostLocalAbsolutePathAllowed",
    )
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    registration_only: Literal[True] = Field(default=True, alias="registrationOnly")
    host_access_authorized: Literal[False] = Field(default=False, alias="hostAccessAuthorized")
    inspection_authorized: Literal[False] = Field(
        default=False,
        alias="inspectionAuthorized",
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
        "content_digest_required",
        "portable_relative_path_required",
        "secret_free",
        "mutable_runtime_identifier_allowed",
        "host_local_absolute_path_allowed",
        "locator_schema_implementation_available",
        "registration_only",
        "host_access_authorized",
        "inspection_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _SYSTEM_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
                self.parent_requirement,
                self.content_digest_required,
                self.portable_relative_path_required,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
                spec.parent_requirement,
                spec.content_digest_required,
                spec.portable_relative_path_required,
            )
            or self.domain_classification != _system_domain_classification()
            or self.domain_graph_type_set != _system_graph_type_set()
        ):
            raise ValueError("System host/resource locator differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"locator_digest"},
        )
        canonical_json_bytes(
            material,
            label="System host/resource locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest("pajin.discovery.system-host-resource-locator/v1", material)
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("System host/resource locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> SystemHostResourceLocatorRef:
        """Return the exact locator reference without authority transfer."""

        return SystemHostResourceLocatorRef(
            locatorId=self.locator_id,
            locatorVersion=self.locator_version,
            locatorDigest=self.locator_digest,
            locatorKind=self.locator_kind,
            surfaceClass=self.surface_class,
        )


class SystemHostResourceLocatorRegistry(StrictModel):
    """Complete host/process/filesystem/service/configuration registry without runtime authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-host-resource-locator-registry/v1alpha1"] = Field(
        default=SYSTEM_HOST_RESOURCE_LOCATOR_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemHostResourceLocatorRegistry"] = "SystemHostResourceLocatorRegistry"
    registry_id: Literal["pajin.system.host-resource-locators"] = Field(
        default="pajin.system.host-resource-locators",
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
    surface_type: Literal["system.host-resource"] = Field(
        default=SYSTEM_HOST_RESOURCE_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.system.host-resource.v1"] = Field(
        default=SYSTEM_HOST_RESOURCE_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locators: tuple[RegisteredSystemHostResourceLocator, ...] = Field(
        min_length=len(_SYSTEM_LOCATOR_SPECS),
        max_length=len(_SYSTEM_LOCATOR_SPECS),
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
    host_access_authorized: Literal[False] = Field(default=False, alias="hostAccessAuthorized")
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
    service_control_authorized: Literal[False] = Field(
        default=False,
        alias="serviceControlAuthorized",
    )
    configuration_read_authorized: Literal[False] = Field(
        default=False,
        alias="configurationReadAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    root_authority_asserted: Literal[False] = Field(
        default=False,
        alias="rootAuthorityAsserted",
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
    authenticated_host_agent_authorized: Literal[False] = Field(
        default=False,
        alias="authenticatedHostAgentAuthorized",
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
    host_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="hostMutationAuthorized",
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
        "registry_only",
        "discovery_wire_changed",
        "attack_surface_wire_changed",
        "domain_semantics_registry_changed",
        "discovery_authorized",
        "host_access_authorized",
        "process_inspection_authorized",
        "filesystem_read_authorized",
        "service_inspection_authorized",
        "service_control_authorized",
        "configuration_read_authorized",
        "credential_use_authorized",
        "root_authority_asserted",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "authenticated_host_agent_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "host_mutation_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("System locator registry authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _system_domain_classification()
            or self.domain_graph_type_set != _system_graph_type_set()
            or self.locators != _registered_system_locators()
            or tuple(item.surface_class for item in self.locators) != tuple(SystemSurfaceClass)
        ):
            raise ValueError("System host/resource locator registry differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        canonical_json_bytes(
            material,
            label="System host/resource locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest("pajin.discovery.system-host-resource-registry/v1", material)
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("System host/resource locator registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> SystemHostResourceLocatorRegistryRef:
        """Return the exact complete registry reference."""

        return SystemHostResourceLocatorRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )


class SystemHostResourceSurface(StrictModel):
    """Typed System knowledge that is neither inspected nor Graph-admitted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/system-host-resource-surface/v1alpha1"] = Field(
        default=SYSTEM_HOST_RESOURCE_SURFACE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemHostResourceSurface"] = "SystemHostResourceSurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=96)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["system.host-resource"] = Field(
        default=SYSTEM_HOST_RESOURCE_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.system.host-resource.v1"] = Field(
        default=SYSTEM_HOST_RESOURCE_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: SystemSurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locator_registry: SystemHostResourceLocatorRegistryRef = Field(alias="locatorRegistry")
    locator: SystemHostResourceSurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    discovery_observed: Literal[False] = Field(default=False, alias="discoveryObserved")
    host_existence_verified: Literal[False] = Field(
        default=False,
        alias="hostExistenceVerified",
    )
    process_running_verified: Literal[False] = Field(
        default=False,
        alias="processRunningVerified",
    )
    filesystem_entry_verified: Literal[False] = Field(
        default=False,
        alias="filesystemEntryVerified",
    )
    service_state_verified: Literal[False] = Field(
        default=False,
        alias="serviceStateVerified",
    )
    configuration_record_verified: Literal[False] = Field(
        default=False,
        alias="configurationRecordVerified",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    host_access_authorized: Literal[False] = Field(default=False, alias="hostAccessAuthorized")
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
    service_control_authorized: Literal[False] = Field(
        default=False,
        alias="serviceControlAuthorized",
    )
    configuration_read_authorized: Literal[False] = Field(
        default=False,
        alias="configurationReadAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    root_authority_asserted: Literal[False] = Field(
        default=False,
        alias="rootAuthorityAsserted",
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
    authenticated_host_agent_authorized: Literal[False] = Field(
        default=False,
        alias="authenticatedHostAgentAuthorized",
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
    host_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="hostMutationAuthorized",
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
        "typed_surface_only",
        "discovery_observed",
        "host_existence_verified",
        "process_running_verified",
        "filesystem_entry_verified",
        "service_state_verified",
        "configuration_record_verified",
        "evidence_sealed",
        "graph_admitted",
        "host_access_authorized",
        "process_inspection_authorized",
        "filesystem_read_authorized",
        "service_inspection_authorized",
        "service_control_authorized",
        "configuration_read_authorized",
        "credential_use_authorized",
        "root_authority_asserted",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "authenticated_host_agent_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "host_mutation_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed System Surface authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_system_host_resource_locator_registry()
        registered = next(
            (item for item in registry.locators if item.locator_kind == self.locator.kind),
            None,
        )
        if (
            self.domain_classification != _system_domain_classification()
            or self.domain_graph_type_set != _system_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError("Typed System host/resource Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed System host/resource Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest("pajin.discovery.system-host-resource-surface/v1", material)
        surface_id: _SurfaceId = f"system-host-resource-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed System Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed System Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> SystemHostResourceSurfaceRef:
        """Return a content-addressed inert Surface reference."""

        return SystemHostResourceSurfaceRef(
            surfaceId=self.surface_id,
            surfaceDigest=self.surface_digest,
            surfaceType=self.surface_type,
            locatorSchema=self.locator_schema,
            surfaceClass=self.surface_class,
            locatorKind=self.locator.kind,
            locatorRegistry=self.locator_registry,
        )


def registered_system_host_resource_locator_registry() -> SystemHostResourceLocatorRegistry:
    """Return the SYS-001A registry without host-access or inspection authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return SystemHostResourceLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_system_domain_classification(),
        domainGraphTypeSet=_system_graph_type_set(),
        locators=_registered_system_locators(),
    )


def resolve_registered_system_host_resource_locator(
    reference: SystemHostResourceLocatorRef,
) -> RegisteredSystemHostResourceLocator:
    """Resolve one exact System locator without transferring authority."""

    for locator in registered_system_host_resource_locator_registry().locators:
        if locator.reference() == reference:
            return locator.model_copy(deep=True)
    raise SystemSurfaceRegistryError("System host/resource locator is not registered exactly")


def resolve_system_host_resource_locator_registry(
    reference: SystemHostResourceLocatorRegistryRef,
) -> SystemHostResourceLocatorRegistry:
    """Resolve the exact complete System registry without activating host behavior."""

    registry = registered_system_host_resource_locator_registry()
    if registry.reference() == reference:
        return registry.model_copy(deep=True)
    raise SystemSurfaceRegistryError(
        "System host/resource locator registry is not registered exactly"
    )


def typed_system_host_resource_surface(
    *,
    locator: SystemHostResourceSurfaceLocator,
) -> SystemHostResourceSurface:
    """Type a locator as inert registered-not-authorized System knowledge."""

    registry = registered_system_host_resource_locator_registry()
    registered = next(item for item in registry.locators if item.locator_kind == locator.kind)
    return SystemHostResourceSurface(
        surfaceClass=registered.surface_class,
        domainClassification=_system_domain_classification(),
        domainGraphTypeSet=_system_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=locator.model_copy(deep=True),
    )


def system_host_surface_locator(
    *,
    host_id: str,
    operating_system: SystemOperatingSystem,
    architecture: SystemArchitecture,
) -> SystemHostSurfaceLocator:
    """Build one pseudonymous stable host locator without host access."""

    return SystemHostSurfaceLocator(
        hostId=host_id,
        operatingSystem=operating_system,
        architecture=architecture,
    )


def system_process_surface_locator(
    *,
    host: SystemHostSurfaceLocator,
    process_instance_digest: str,
    executable_digest: str,
) -> SystemProcessSurfaceLocator:
    """Build one content-bound process locator without accepting a PID."""

    return SystemProcessSurfaceLocator(
        host=host.model_copy(deep=True),
        processInstanceDigest=process_instance_digest,
        executableDigest=executable_digest,
    )


def system_filesystem_surface_locator(
    *,
    host: SystemHostSurfaceLocator,
    mount_id: str,
    relative_path: str,
    entry_kind: SystemFilesystemEntryKind,
    content_digest: str,
) -> SystemFilesystemSurfaceLocator:
    """Build one logical-mount relative filesystem locator without reading it."""

    return SystemFilesystemSurfaceLocator(
        host=host.model_copy(deep=True),
        mountId=mount_id,
        relativePath=relative_path,
        entryKind=entry_kind,
        contentDigest=content_digest,
    )


def system_service_surface_locator(
    *,
    host: SystemHostSurfaceLocator,
    service_manager: SystemServiceManager,
    service_id: str,
    definition_digest: str,
) -> SystemServiceSurfaceLocator:
    """Build one exact service-unit locator without service control."""

    return SystemServiceSurfaceLocator(
        host=host.model_copy(deep=True),
        serviceManager=service_manager,
        serviceId=service_id,
        definitionDigest=definition_digest,
    )


def system_configuration_surface_locator(
    *,
    parent: SystemConfigurationParentLocator,
    configuration_namespace: str,
    configuration_id: str,
    configuration_digest: str,
) -> SystemConfigurationSurfaceLocator:
    """Build one sanitized configuration-record locator without raw configuration values."""

    return SystemConfigurationSurfaceLocator(
        parent=parent.model_copy(deep=True),
        configurationNamespace=configuration_namespace,
        configurationId=configuration_id,
        configurationDigest=configuration_digest,
    )


@cache
def _registered_system_locators() -> tuple[RegisteredSystemHostResourceLocator, ...]:
    return tuple(
        RegisteredSystemHostResourceLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_system_domain_classification(),
            domainGraphTypeSet=_system_graph_type_set(),
            parentRequirement=spec.parent_requirement,
            contentDigestRequired=spec.content_digest_required,
            portableRelativePathRequired=spec.portable_relative_path_required,
        )
        for spec in _SYSTEM_LOCATOR_SPECS
    )


@cache
def _system_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.SYSTEM
    )


@cache
def _system_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.SYSTEM
    )


def _canonical_system_coordinate(value: object, *, label: str) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    canonical = value.lower()
    if canonical in _MUTABLE_IDENTITY_ALIASES:
        raise ValueError(f"{label} must be an explicit stable identifier")
    if "://" in value or any(character in value for character in "/\\?#*"):
        raise ValueError(f"{label} cannot contain path, URL, query, fragment, or wildcard syntax")
    return canonical


def _portable_relative_reference(value: object, *, label: str) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    if (
        value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or any(character in value for character in "\\:?#*")
    ):
        raise ValueError(f"{label} must be one canonical portable relative reference")
    parts = value.split("/")
    if any(
        part in {".", ".."} or _PORTABLE_SEGMENT_PATTERN.fullmatch(part) is None for part in parts
    ):
        raise ValueError(f"{label} contains an ambiguous or non-portable segment")
    return value


def _stable_service_identity(value: str) -> str:
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError("System service ID cannot contain surrounding or control whitespace")
    if value.casefold() in _MUTABLE_IDENTITY_ALIASES:
        raise ValueError("System service ID must be an exact manager unit identifier")
    if "://" in value or any(character in value for character in "/\\?#*"):
        raise ValueError("System service ID cannot contain path, URL, or wildcard syntax")
    return value


__all__ = [
    "SYSTEM_HOST_RESOURCE_LOCATOR_API_VERSION",
    "SYSTEM_HOST_RESOURCE_LOCATOR_REGISTRY_API_VERSION",
    "SYSTEM_HOST_RESOURCE_LOCATOR_SCHEMA",
    "SYSTEM_HOST_RESOURCE_SURFACE_API_VERSION",
    "SYSTEM_HOST_RESOURCE_SURFACE_TYPE",
    "RegisteredSystemHostResourceLocator",
    "SystemArchitecture",
    "SystemConfigurationParentLocator",
    "SystemConfigurationSurfaceLocator",
    "SystemFilesystemEntryKind",
    "SystemFilesystemSurfaceLocator",
    "SystemHostResourceLocatorRef",
    "SystemHostResourceLocatorRegistry",
    "SystemHostResourceLocatorRegistryRef",
    "SystemHostResourceSurface",
    "SystemHostResourceSurfaceLocator",
    "SystemHostResourceSurfaceRef",
    "SystemHostSurfaceLocator",
    "SystemOperatingSystem",
    "SystemParentRequirement",
    "SystemProcessSurfaceLocator",
    "SystemServiceManager",
    "SystemServiceSurfaceLocator",
    "SystemSurfaceClass",
    "SystemSurfaceLocatorKind",
    "SystemSurfaceRegistryError",
    "registered_system_host_resource_locator_registry",
    "resolve_registered_system_host_resource_locator",
    "resolve_system_host_resource_locator_registry",
    "system_configuration_surface_locator",
    "system_filesystem_surface_locator",
    "system_host_surface_locator",
    "system_process_surface_locator",
    "system_service_surface_locator",
    "typed_system_host_resource_surface",
]
