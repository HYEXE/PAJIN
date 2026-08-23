"""WEB-001A typed HTTP/API Surface and locator registry without runtime authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import (
    DISCOVERY_API_VERSION,
    HTTPRouteSurfaceLocator,
    HTTPSurfaceLocator,
)
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

WEB_HTTP_OPERATION_LOCATOR_API_VERSION: Literal[
    "pajin.dev/web-http-operation-locator/v1alpha1"
] = "pajin.dev/web-http-operation-locator/v1alpha1"
WEB_HTTP_OPERATION_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/web-http-operation-locator-registry/v1alpha1"
] = "pajin.dev/web-http-operation-locator-registry/v1alpha1"
WEB_HTTP_OPERATION_SURFACE_API_VERSION: Literal[
    "pajin.dev/web-http-operation-surface/v1alpha1"
] = "pajin.dev/web-http-operation-surface/v1alpha1"

WEB_HTTP_OPERATION_SURFACE_TYPE: Literal["web.http-operation"] = "web.http-operation"
WEB_HTTP_OPERATION_LOCATOR_SCHEMA: Literal["pajin.locator.web.http-operation.v1"] = (
    "pajin.locator.web.http-operation.v1"
)

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^web-http-operation-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 256 * 1024
_MAX_TYPED_SURFACE_BYTES = 128 * 1024

WebHTTPOperationLocator = Annotated[
    HTTPSurfaceLocator | HTTPRouteSurfaceLocator,
    Field(discriminator="kind"),
]


class WebSurfaceRegistryError(RuntimeError):
    """Raised when an exact WEB-001A locator registry reference cannot be resolved."""


@dataclass(frozen=True, slots=True)
class _WebLocatorSpec:
    locator_id: str
    locator_kind: Literal["http-endpoint", "http-route"]
    source_model_id: Literal[
        "pajin.discovery.models.HTTPSurfaceLocator",
        "pajin.discovery.models.HTTPRouteSurfaceLocator",
    ]
    uri_template: bool


_WEB_LOCATOR_SPECS = (
    _WebLocatorSpec(
        "pajin.locator.web.http-operation.concrete",
        "http-endpoint",
        "pajin.discovery.models.HTTPSurfaceLocator",
        False,
    ),
    _WebLocatorSpec(
        "pajin.locator.web.http-operation.uri-template",
        "http-route",
        "pajin.discovery.models.HTTPRouteSurfaceLocator",
        True,
    ),
)


class WebHTTPOperationLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered HTTP locator implementation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: Literal["http-endpoint", "http-route"] = Field(alias="locatorKind")


class WebHTTPOperationLocatorRegistryRef(StrictModel):
    """Exact content-addressed reference to the complete WEB-001A locator registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    registry_id: Literal["pajin.web.http-operation-locators"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class WebHTTPOperationSurfaceRef(StrictModel):
    """Exact content-addressed reference to one inert typed Web Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["web.http-operation"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.web.http-operation.v1"] = Field(
        alias="locatorSchema"
    )
    locator_kind: Literal["http-endpoint", "http-route"] = Field(alias="locatorKind")
    locator_registry: WebHTTPOperationLocatorRegistryRef = Field(
        alias="locatorRegistry"
    )


class RegisteredWebHTTPOperationLocator(StrictModel):
    """One exact existing HTTP locator implementation with no discovery authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-http-operation-locator/v1alpha1"] = Field(
        default=WEB_HTTP_OPERATION_LOCATOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredWebHTTPOperationLocator"] = (
        "RegisteredWebHTTPOperationLocator"
    )
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: Literal["http-endpoint", "http-route"] = Field(alias="locatorKind")
    source_model_id: Literal[
        "pajin.discovery.models.HTTPSurfaceLocator",
        "pajin.discovery.models.HTTPRouteSurfaceLocator",
    ] = Field(alias="sourceModelId")
    discovery_api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="discoveryApiVersion",
    )
    surface_type: Literal["web.http-operation"] = Field(
        default=WEB_HTTP_OPERATION_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.web.http-operation.v1"] = Field(
        default=WEB_HTTP_OPERATION_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(
        alias="domainGraphTypeSet"
    )
    uri_template: bool = Field(alias="uriTemplate")
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    locator_registration_only: Literal[True] = Field(
        default=True,
        alias="locatorRegistrationOnly",
    )
    discovery_authorized: Literal[False] = Field(
        default=False,
        alias="discoveryAuthorized",
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
        "uri_template",
        "locator_schema_implementation_available",
        "locator_registration_only",
        "discovery_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Web locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _WEB_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.source_model_id,
                self.uri_template,
            )
            != (spec.locator_kind, spec.source_model_id, spec.uri_template)
            or self.domain_classification != _web_domain_classification()
            or self.domain_graph_type_set != _web_graph_type_set()
        ):
            raise ValueError("Web HTTP operation locator differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"locator_digest"},
        )
        canonical_json_bytes(
            material,
            label="Web HTTP operation locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest("pajin.discovery.web-http-operation-locator/v1", material)
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("Web HTTP operation locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> WebHTTPOperationLocatorRef:
        """Return an exact content-addressed reference to this locator implementation."""

        return WebHTTPOperationLocatorRef(
            locatorId=self.locator_id,
            locatorVersion=self.locator_version,
            locatorDigest=self.locator_digest,
            locatorKind=self.locator_kind,
        )


class WebHTTPOperationLocatorRegistry(StrictModel):
    """Complete typed Web locator registry that grants no runtime authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/web-http-operation-locator-registry/v1alpha1"
    ] = Field(
        default=WEB_HTTP_OPERATION_LOCATOR_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebHTTPOperationLocatorRegistry"] = (
        "WebHTTPOperationLocatorRegistry"
    )
    registry_id: Literal["pajin.web.http-operation-locators"] = Field(
        default="pajin.web.http-operation-locators",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_api_version: Literal[
        "pajin.dev/security-domain-taxonomy/v1alpha1"
    ] = Field(
        default=SECURITY_DOMAIN_TAXONOMY_API_VERSION,
        alias="securityDomainTaxonomyApiVersion",
    )
    security_domain_taxonomy_digest: _Sha256 = Field(
        alias="securityDomainTaxonomyDigest"
    )
    multi_domain_graph_semantics_api_version: Literal[
        "pajin.dev/multi-domain-graph-semantics/v1alpha1"
    ] = Field(
        default=MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
        alias="multiDomainGraphSemanticsApiVersion",
    )
    multi_domain_graph_semantics_digest: _Sha256 = Field(
        alias="multiDomainGraphSemanticsDigest"
    )
    discovery_api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="discoveryApiVersion",
    )
    surface_type: Literal["web.http-operation"] = Field(
        default=WEB_HTTP_OPERATION_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.web.http-operation.v1"] = Field(
        default=WEB_HTTP_OPERATION_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(
        alias="domainGraphTypeSet"
    )
    locators: tuple[RegisteredWebHTTPOperationLocator, ...] = Field(
        min_length=2,
        max_length=2,
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
    domain_semantics_registry_changed: Literal[False] = Field(
        default=False,
        alias="domainSemanticsRegistryChanged",
    )
    attack_surface_wire_changed: Literal[False] = Field(
        default=False,
        alias="attackSurfaceWireChanged",
    )
    discovery_authorized: Literal[False] = Field(
        default=False,
        alias="discoveryAuthorized",
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
        "domain_semantics_registry_changed",
        "attack_surface_wire_changed",
        "discovery_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "permit_issuance_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Web locator registry authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _web_domain_classification()
            or self.domain_graph_type_set != _web_graph_type_set()
            or self.locators != _registered_web_locators()
        ):
            raise ValueError("Web HTTP operation locator registry differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        canonical_json_bytes(
            material,
            label="Web HTTP operation locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest("pajin.discovery.web-http-operation-registry/v1", material)
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Web HTTP operation locator registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> WebHTTPOperationLocatorRegistryRef:
        """Return the exact complete registry reference."""

        return WebHTTPOperationLocatorRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )


class WebHTTPOperationSurface(StrictModel):
    """Typed Web knowledge record that is not an observed or admitted AttackSurface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-http-operation-surface/v1alpha1"] = Field(
        default=WEB_HTTP_OPERATION_SURFACE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebHTTPOperationSurface"] = "WebHTTPOperationSurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=91)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["web.http-operation"] = Field(
        default=WEB_HTTP_OPERATION_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.web.http-operation.v1"] = Field(
        default=WEB_HTTP_OPERATION_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(
        alias="domainGraphTypeSet"
    )
    locator_registry: WebHTTPOperationLocatorRegistryRef = Field(
        alias="locatorRegistry"
    )
    locator: WebHTTPOperationLocator
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
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed Web Surface authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_web_http_operation_locator_registry()
        expected_model_id = (
            "pajin.discovery.models.HTTPSurfaceLocator"
            if isinstance(self.locator, HTTPSurfaceLocator)
            else "pajin.discovery.models.HTTPRouteSurfaceLocator"
        )
        registered_locator = next(
            (item for item in registry.locators if item.locator_kind == self.locator.kind),
            None,
        )
        if (
            self.domain_classification != _web_domain_classification()
            or self.domain_graph_type_set != _web_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered_locator is None
            or registered_locator.source_model_id != expected_model_id
        ):
            raise ValueError("Typed Web HTTP operation Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed Web HTTP operation Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest("pajin.discovery.web-http-operation-surface/v1", material)
        surface_id: _SurfaceId = f"web-http-operation-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed Web HTTP operation Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed Web HTTP operation Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> WebHTTPOperationSurfaceRef:
        """Return the exact inert Surface reference without transferring authority."""

        return WebHTTPOperationSurfaceRef(
            surfaceId=self.surface_id,
            surfaceDigest=self.surface_digest,
            surfaceType=self.surface_type,
            locatorSchema=self.locator_schema,
            locatorKind=self.locator.kind,
            locatorRegistry=self.locator_registry,
        )


def registered_web_http_operation_locator_registry() -> WebHTTPOperationLocatorRegistry:
    """Return the complete WEB-001A registry without discovery or execution authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return WebHTTPOperationLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_web_domain_classification(),
        domainGraphTypeSet=_web_graph_type_set(),
        locators=_registered_web_locators(),
    )


def resolve_registered_web_http_operation_locator(
    reference: WebHTTPOperationLocatorRef,
) -> RegisteredWebHTTPOperationLocator:
    """Resolve one exact registered locator implementation without authority transfer."""

    for locator in registered_web_http_operation_locator_registry().locators:
        if locator.reference() == reference:
            return locator.model_copy(deep=True)
    raise WebSurfaceRegistryError("Web HTTP operation locator is not registered exactly")


def resolve_web_http_operation_locator_registry(
    reference: WebHTTPOperationLocatorRegistryRef,
) -> WebHTTPOperationLocatorRegistry:
    """Resolve the exact complete registry without activating any runtime path."""

    registry = registered_web_http_operation_locator_registry()
    if registry.reference() == reference:
        return registry.model_copy(deep=True)
    raise WebSurfaceRegistryError("Web HTTP operation locator registry is not registered exactly")


def typed_web_http_operation_surface(
    *,
    locator: HTTPSurfaceLocator | HTTPRouteSurfaceLocator,
) -> WebHTTPOperationSurface:
    """Type one existing locator as inert registered-not-authorized Web knowledge."""

    registry = registered_web_http_operation_locator_registry()
    return WebHTTPOperationSurface(
        domainClassification=_web_domain_classification(),
        domainGraphTypeSet=_web_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=locator.model_copy(deep=True),
    )


def _registered_web_locators() -> tuple[RegisteredWebHTTPOperationLocator, ...]:
    return tuple(
        RegisteredWebHTTPOperationLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            sourceModelId=spec.source_model_id,
            domainClassification=_web_domain_classification(),
            domainGraphTypeSet=_web_graph_type_set(),
            uriTemplate=spec.uri_template,
        )
        for spec in _WEB_LOCATOR_SPECS
    )


def _web_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.WEB
    )


def _web_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.WEB
    )
