"""NET-001A typed Network host/service Surfaces without scan authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from ipaddress import ip_address
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

NETWORK_HOST_SERVICE_LOCATOR_API_VERSION: Literal[
    "pajin.dev/network-host-service-locator/v1alpha1"
] = "pajin.dev/network-host-service-locator/v1alpha1"
NETWORK_HOST_SERVICE_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/network-host-service-locator-registry/v1alpha1"
] = "pajin.dev/network-host-service-locator-registry/v1alpha1"
NETWORK_HOST_SERVICE_SURFACE_API_VERSION: Literal[
    "pajin.dev/network-host-service-surface/v1alpha1"
] = "pajin.dev/network-host-service-surface/v1alpha1"

NETWORK_HOST_SERVICE_SURFACE_TYPE: Literal["network.host-service"] = "network.host-service"
NETWORK_HOST_SERVICE_LOCATOR_SCHEMA: Literal["pajin.locator.network.host-service.v1"] = (
    "pajin.locator.network.host-service.v1"
)

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_ServiceName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    ),
]
_NetworkPort = Annotated[int, Field(strict=True, ge=1, le=65_535)]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^network-host-service-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 256 * 1024
_MAX_TYPED_SURFACE_BYTES = 128 * 1024


class NetworkSurfaceRegistryError(RuntimeError):
    """Raised when an exact NET-001A registry reference cannot be resolved."""


class NetworkAddressFamily(StrEnum):
    """Explicit host representation family; this does not authorize resolution."""

    DNS_NAME = "dns-name"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class NetworkTransportProtocol(StrEnum):
    """Bounded transport identifiers supported by the first Network locator schema."""

    TCP = "tcp"
    UDP = "udp"


class NetworkSurfaceClass(StrEnum):
    """Network knowledge classes; values grant no discovery or runtime authority."""

    HOST = "host"
    PORT = "port"
    SERVICE = "service"


class NetworkHostSurfaceLocator(StrictModel):
    """Canonical secret-free DNS name or IP literal with an explicit family."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    kind: Literal["network-host"] = "network-host"
    address_family: NetworkAddressFamily = Field(alias="addressFamily")
    host: str = Field(min_length=1, max_length=253)

    @model_validator(mode="after")
    def canonicalize_host(self) -> Self:
        canonical = _canonical_network_host(self.host, self.address_family)
        object.__setattr__(self, "host", canonical)
        return self


class NetworkPortSurfaceLocator(StrictModel):
    """One exact host, transport protocol, and port without service inference."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    kind: Literal["network-port"] = "network-port"
    host: NetworkHostSurfaceLocator
    transport_protocol: NetworkTransportProtocol = Field(alias="transportProtocol")
    port: _NetworkPort


class NetworkServiceSurfaceLocator(StrictModel):
    """One explicitly named service at an exact host/protocol/port coordinate."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    kind: Literal["network-service"] = "network-service"
    host: NetworkHostSurfaceLocator
    transport_protocol: NetworkTransportProtocol = Field(alias="transportProtocol")
    port: _NetworkPort
    service_name: _ServiceName = Field(alias="serviceName")

    @field_validator("service_name", mode="before")
    @classmethod
    def canonicalize_service_name(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        canonical = value.lower()
        if value != value.strip() or canonical in {"auto", "default", "unknown"}:
            raise ValueError("Network service name must be an explicit stable identifier")
        return canonical


NetworkHostServiceSurfaceLocator = Annotated[
    NetworkHostSurfaceLocator | NetworkPortSurfaceLocator | NetworkServiceSurfaceLocator,
    Field(discriminator="kind"),
]

NetworkSurfaceLocatorKind = Literal[
    "network-host",
    "network-port",
    "network-service",
]


@dataclass(frozen=True, slots=True)
class _NetworkLocatorSpec:
    locator_id: str
    locator_kind: NetworkSurfaceLocatorKind
    surface_class: NetworkSurfaceClass
    source_model_id: str
    transport_protocol_required: bool
    port_required: bool
    service_name_required: bool


_NETWORK_LOCATOR_SPECS = (
    _NetworkLocatorSpec(
        "pajin.locator.network.host",
        "network-host",
        NetworkSurfaceClass.HOST,
        "pajin.discovery.network_surfaces.NetworkHostSurfaceLocator",
        False,
        False,
        False,
    ),
    _NetworkLocatorSpec(
        "pajin.locator.network.port",
        "network-port",
        NetworkSurfaceClass.PORT,
        "pajin.discovery.network_surfaces.NetworkPortSurfaceLocator",
        True,
        True,
        False,
    ),
    _NetworkLocatorSpec(
        "pajin.locator.network.service",
        "network-service",
        NetworkSurfaceClass.SERVICE,
        "pajin.discovery.network_surfaces.NetworkServiceSurfaceLocator",
        True,
        True,
        True,
    ),
)


class NetworkHostServiceLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered Network locator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: NetworkSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: NetworkSurfaceClass = Field(alias="surfaceClass")


class NetworkHostServiceLocatorRegistryRef(StrictModel):
    """Exact reference to the complete NET-001A locator registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    registry_id: Literal["pajin.network.host-service-locators"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class NetworkHostServiceSurfaceRef(StrictModel):
    """Exact reference to one inert typed Network Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["network.host-service"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.network.host-service.v1"] = Field(alias="locatorSchema")
    surface_class: NetworkSurfaceClass = Field(alias="surfaceClass")
    locator_kind: NetworkSurfaceLocatorKind = Field(alias="locatorKind")
    locator_registry: NetworkHostServiceLocatorRegistryRef = Field(alias="locatorRegistry")


class RegisteredNetworkHostServiceLocator(StrictModel):
    """One code-owned Network locator mapping with no scan or socket authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-host-service-locator/v1alpha1"] = Field(
        default=NETWORK_HOST_SERVICE_LOCATOR_API_VERSION, alias="apiVersion"
    )
    kind: Literal["RegisteredNetworkHostServiceLocator"] = "RegisteredNetworkHostServiceLocator"
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: NetworkSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: NetworkSurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    transport_protocol_required: bool = Field(alias="transportProtocolRequired")
    port_required: bool = Field(alias="portRequired")
    service_name_required: bool = Field(alias="serviceNameRequired")
    secret_free: Literal[True] = Field(default=True, alias="secretFree")
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    registration_only: Literal[True] = Field(default=True, alias="registrationOnly")
    discovery_authorized: Literal[False] = Field(default=False, alias="discoveryAuthorized")
    service_identification_authorized: Literal[False] = Field(
        default=False,
        alias="serviceIdentificationAuthorized",
    )
    raw_socket_authorized: Literal[False] = Field(
        default=False,
        alias="rawSocketAuthorized",
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
        "transport_protocol_required",
        "port_required",
        "service_name_required",
        "secret_free",
        "locator_schema_implementation_available",
        "registration_only",
        "discovery_authorized",
        "service_identification_authorized",
        "raw_socket_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Network locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _NETWORK_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
                self.transport_protocol_required,
                self.port_required,
                self.service_name_required,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
                spec.transport_protocol_required,
                spec.port_required,
                spec.service_name_required,
            )
            or self.domain_classification != _network_domain_classification()
            or self.domain_graph_type_set != _network_graph_type_set()
        ):
            raise ValueError("Network host/service locator differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"locator_digest"},
        )
        canonical_json_bytes(
            material,
            label="Network host/service locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest("pajin.discovery.network-host-service-locator/v1", material)
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("Network host/service locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> NetworkHostServiceLocatorRef:
        """Return the exact locator reference without authority transfer."""

        return NetworkHostServiceLocatorRef(
            locatorId=self.locator_id,
            locatorVersion=self.locator_version,
            locatorDigest=self.locator_digest,
            locatorKind=self.locator_kind,
            surfaceClass=self.surface_class,
        )


class NetworkHostServiceLocatorRegistry(StrictModel):
    """Complete host/port/service locator registry without Network runtime authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-host-service-locator-registry/v1alpha1"] = Field(
        default=NETWORK_HOST_SERVICE_LOCATOR_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkHostServiceLocatorRegistry"] = "NetworkHostServiceLocatorRegistry"
    registry_id: Literal["pajin.network.host-service-locators"] = Field(
        default="pajin.network.host-service-locators",
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
    surface_type: Literal["network.host-service"] = Field(
        default=NETWORK_HOST_SERVICE_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.network.host-service.v1"] = Field(
        default=NETWORK_HOST_SERVICE_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locators: tuple[RegisteredNetworkHostServiceLocator, ...] = Field(
        min_length=len(_NETWORK_LOCATOR_SPECS),
        max_length=len(_NETWORK_LOCATOR_SPECS),
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
    name_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="nameResolutionAuthorized",
    )
    port_enumeration_authorized: Literal[False] = Field(
        default=False,
        alias="portEnumerationAuthorized",
    )
    service_probe_authorized: Literal[False] = Field(
        default=False,
        alias="serviceProbeAuthorized",
    )
    raw_socket_authorized: Literal[False] = Field(
        default=False,
        alias="rawSocketAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    scanner_selection_authorized: Literal[False] = Field(
        default=False,
        alias="scannerSelectionAuthorized",
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
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
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
        "name_resolution_authorized",
        "port_enumeration_authorized",
        "service_probe_authorized",
        "raw_socket_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "permit_issuance_authorized",
        "scanner_selection_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "credential_access_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Network locator registry authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _network_domain_classification()
            or self.domain_graph_type_set != _network_graph_type_set()
            or self.locators != _registered_network_locators()
            or tuple(item.surface_class for item in self.locators) != tuple(NetworkSurfaceClass)
        ):
            raise ValueError("Network host/service locator registry differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        canonical_json_bytes(
            material,
            label="Network host/service locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest("pajin.discovery.network-host-service-registry/v1", material)
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Network host/service locator registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> NetworkHostServiceLocatorRegistryRef:
        """Return the exact complete registry reference."""

        return NetworkHostServiceLocatorRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )


class NetworkHostServiceSurface(StrictModel):
    """Typed Network knowledge that is neither observed nor Graph-admitted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-host-service-surface/v1alpha1"] = Field(
        default=NETWORK_HOST_SERVICE_SURFACE_API_VERSION, alias="apiVersion"
    )
    kind: Literal["NetworkHostServiceSurface"] = "NetworkHostServiceSurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=93)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["network.host-service"] = Field(
        default=NETWORK_HOST_SERVICE_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.network.host-service.v1"] = Field(
        default=NETWORK_HOST_SERVICE_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: NetworkSurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locator_registry: NetworkHostServiceLocatorRegistryRef = Field(alias="locatorRegistry")
    locator: NetworkHostServiceSurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    discovery_observed: Literal[False] = Field(default=False, alias="discoveryObserved")
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
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
    name_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="nameResolutionAuthorized",
    )
    port_enumeration_authorized: Literal[False] = Field(
        default=False,
        alias="portEnumerationAuthorized",
    )
    service_probe_authorized: Literal[False] = Field(
        default=False,
        alias="serviceProbeAuthorized",
    )
    raw_socket_authorized: Literal[False] = Field(
        default=False,
        alias="rawSocketAuthorized",
    )
    scanner_selection_authorized: Literal[False] = Field(
        default=False,
        alias="scannerSelectionAuthorized",
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
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
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
        "evidence_sealed",
        "graph_admitted",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "name_resolution_authorized",
        "port_enumeration_authorized",
        "service_probe_authorized",
        "raw_socket_authorized",
        "scanner_selection_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "credential_access_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed Network Surface authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_network_host_service_locator_registry()
        registered = next(
            (item for item in registry.locators if item.locator_kind == self.locator.kind),
            None,
        )
        if (
            self.domain_classification != _network_domain_classification()
            or self.domain_graph_type_set != _network_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError("Typed Network host/service Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed Network host/service Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest("pajin.discovery.network-host-service-surface/v1", material)
        surface_id: _SurfaceId = f"network-host-service-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed Network Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed Network Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> NetworkHostServiceSurfaceRef:
        """Return a content-addressed inert Surface reference."""

        return NetworkHostServiceSurfaceRef(
            surfaceId=self.surface_id,
            surfaceDigest=self.surface_digest,
            surfaceType=self.surface_type,
            locatorSchema=self.locator_schema,
            surfaceClass=self.surface_class,
            locatorKind=self.locator.kind,
            locatorRegistry=self.locator_registry,
        )


def registered_network_host_service_locator_registry() -> NetworkHostServiceLocatorRegistry:
    """Return the NET-001A registry without discovery, socket, or execution authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return NetworkHostServiceLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_network_domain_classification(),
        domainGraphTypeSet=_network_graph_type_set(),
        locators=_registered_network_locators(),
    )


def resolve_registered_network_host_service_locator(
    reference: NetworkHostServiceLocatorRef,
) -> RegisteredNetworkHostServiceLocator:
    """Resolve one exact Network locator without transferring authority."""

    for locator in registered_network_host_service_locator_registry().locators:
        if locator.reference() == reference:
            return locator.model_copy(deep=True)
    raise NetworkSurfaceRegistryError("Network host/service locator is not registered exactly")


def resolve_network_host_service_locator_registry(
    reference: NetworkHostServiceLocatorRegistryRef,
) -> NetworkHostServiceLocatorRegistry:
    """Resolve the exact complete Network registry without activating runtime behavior."""

    registry = registered_network_host_service_locator_registry()
    if registry.reference() == reference:
        return registry.model_copy(deep=True)
    raise NetworkSurfaceRegistryError(
        "Network host/service locator registry is not registered exactly"
    )


def typed_network_host_service_surface(
    *,
    locator: NetworkHostServiceSurfaceLocator,
) -> NetworkHostServiceSurface:
    """Type a locator as inert registered-not-authorized Network knowledge."""

    registry = registered_network_host_service_locator_registry()
    registered = next(item for item in registry.locators if item.locator_kind == locator.kind)
    return NetworkHostServiceSurface(
        surfaceClass=registered.surface_class,
        domainClassification=_network_domain_classification(),
        domainGraphTypeSet=_network_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=locator.model_copy(deep=True),
    )


def network_host_surface_locator(
    *,
    address_family: NetworkAddressFamily,
    host: str,
) -> NetworkHostSurfaceLocator:
    """Build one canonical host locator without resolving a DNS name."""

    return NetworkHostSurfaceLocator(addressFamily=address_family, host=host)


def network_port_surface_locator(
    *,
    host: NetworkHostSurfaceLocator,
    transport_protocol: NetworkTransportProtocol,
    port: int,
) -> NetworkPortSurfaceLocator:
    """Build one exact host/protocol/port locator without probing it."""

    return NetworkPortSurfaceLocator(
        host=host.model_copy(deep=True),
        transportProtocol=transport_protocol,
        port=port,
    )


def network_service_surface_locator(
    *,
    host: NetworkHostSurfaceLocator,
    transport_protocol: NetworkTransportProtocol,
    port: int,
    service_name: str,
) -> NetworkServiceSurfaceLocator:
    """Build an explicitly named service locator without verifying the declaration."""

    return NetworkServiceSurfaceLocator(
        host=host.model_copy(deep=True),
        transportProtocol=transport_protocol,
        port=port,
        serviceName=service_name,
    )


@cache
def _registered_network_locators() -> tuple[RegisteredNetworkHostServiceLocator, ...]:
    return tuple(
        RegisteredNetworkHostServiceLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_network_domain_classification(),
            domainGraphTypeSet=_network_graph_type_set(),
            transportProtocolRequired=spec.transport_protocol_required,
            portRequired=spec.port_required,
            serviceNameRequired=spec.service_name_required,
        )
        for spec in _NETWORK_LOCATOR_SPECS
    )


@cache
def _network_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.NETWORK
    )


@cache
def _network_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.NETWORK
    )


def _canonical_network_host(host: str, family: NetworkAddressFamily) -> str:
    if host != host.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in host
    ):
        raise ValueError("Network host cannot contain surrounding or control whitespace")
    if "%" in host or "*" in host:
        raise ValueError("Network host cannot contain a zone identifier or wildcard")

    if family is NetworkAddressFamily.DNS_NAME:
        rooted = host[:-1] if host.endswith(".") else host
        if not rooted or rooted.endswith(".") or ".." in rooted:
            raise ValueError("Network DNS name is not canonical host text")
        try:
            canonical = rooted.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Network DNS name is not valid IDNA text") from exc
        labels = canonical.split(".")
        if len(canonical) > 253 or any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            raise ValueError("Network DNS name is not canonical host text")
        if all(_is_legacy_ip_component(label) for label in labels):
            raise ValueError("Network numeric host must use its explicit address family")
        try:
            ip_address(canonical)
        except ValueError:
            return canonical
        raise ValueError("Network IP literal must use its explicit address family")

    try:
        parsed = ip_address(host)
    except ValueError as exc:
        raise ValueError("Network IP host is not a valid address literal") from exc
    expected_version = 4 if family is NetworkAddressFamily.IPV4 else 6
    if parsed.version != expected_version:
        raise ValueError("Network IP host differs from its explicit address family")
    return parsed.compressed.lower()


def _is_legacy_ip_component(label: str) -> bool:
    if label.isdigit():
        return True
    lowered = label.lower()
    return (
        lowered.startswith("0x")
        and len(lowered) > 2
        and all(character in "0123456789abcdef" for character in lowered[2:])
    )
