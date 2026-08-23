from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    DISCOVERY_API_VERSION,
    WEB_HTTP_OPERATION_LOCATOR_SCHEMA,
    WEB_HTTP_OPERATION_SURFACE_TYPE,
    AttackSurface,
    HTTPRouteSurfaceLocator,
    HTTPSurfaceLocator,
    RegisteredWebHTTPOperationLocator,
    WebHTTPOperationLocatorRegistry,
    WebHTTPOperationSurface,
    WebHTTPOperationSurfaceRef,
    WebSurfaceRegistryError,
    http_route_surface_locator,
    http_surface_locator,
    registered_web_http_operation_locator_registry,
    resolve_registered_web_http_operation_locator,
    resolve_web_http_operation_locator_registry,
    typed_web_http_operation_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "domainSemanticsRegistryChanged",
    "attackSurfaceWireChanged",
    "discoveryAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "permitIssuanceAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "graphAdmissionAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_SURFACE_FALSE_ALIASES = (
    "discoveryObserved",
    "evidenceSealed",
    "graphAdmitted",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)


def _endpoint() -> HTTPSurfaceLocator:
    return http_surface_locator(url="https://api.example.test/v1/users", method="get")


def _route() -> HTTPRouteSurfaceLocator:
    return http_route_surface_locator(
        base_url="https://api.example.test/v1/",
        path_template="/users/{user_id}",
        method="post",
        request_content_types=("application/json",),
        response_content_types=("application/json",),
    )


def test_registry_binds_exact_domain_semantics_and_existing_locator_models() -> None:
    registry = registered_web_http_operation_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    web_type_set = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.WEB
    )

    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert registry.discovery_api_version == DISCOVERY_API_VERSION
    assert registry.surface_type == WEB_HTTP_OPERATION_SURFACE_TYPE
    assert registry.locator_schema == WEB_HTTP_OPERATION_LOCATOR_SCHEMA
    assert registry.domain_classification.domain is SecurityDomain.WEB
    assert registry.domain_graph_type_set == web_type_set.reference()
    assert web_type_set.surface_type == WEB_HTTP_OPERATION_SURFACE_TYPE
    assert web_type_set.locator_schema == WEB_HTTP_OPERATION_LOCATOR_SCHEMA
    assert tuple(
        (item.locator_kind, item.source_model_id, item.uri_template)
        for item in registry.locators
    ) == (
        (
            "http-endpoint",
            "pajin.discovery.models.HTTPSurfaceLocator",
            False,
        ),
        (
            "http-route",
            "pajin.discovery.models.HTTPRouteSurfaceLocator",
            True,
        ),
    )
    assert registry.discovered_surface_initial_state == "registered-not-authorized"
    assert registry.registry_only is True
    assert len(registry.registry_digest) == 64
    assert WebHTTPOperationLocatorRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    ) == registry


def test_locator_and_complete_registry_resolution_require_exact_references() -> None:
    registry = registered_web_http_operation_locator_registry()

    for source in registry.locators:
        resolved = resolve_registered_web_http_operation_locator(source.reference())
        assert resolved == source
        assert resolved is not source

    resolved_registry = resolve_web_http_operation_locator_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_reference_resolution_rejects_digest_kind_and_registry_substitution() -> None:
    registry = registered_web_http_operation_locator_registry()
    source = registry.locators[0]

    with pytest.raises(WebSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_web_http_operation_locator(
            source.reference().model_copy(update={"locator_digest": "0" * 64})
        )
    with pytest.raises(WebSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_web_http_operation_locator(
            source.reference().model_copy(update={"locator_kind": "http-route"})
        )
    with pytest.raises(WebSurfaceRegistryError, match="not registered exactly"):
        resolve_web_http_operation_locator_registry(
            registry.reference().model_copy(update={"registry_digest": "0" * 64})
        )


def test_concrete_endpoint_becomes_stable_inert_typed_web_surface() -> None:
    locator = _endpoint()
    surface = typed_web_http_operation_surface(locator=locator)

    assert surface.locator == HTTPSurfaceLocator(
        url="https://api.example.test/v1/users",
        method="GET",
    )
    assert surface.locator is not locator
    assert surface.initial_state == "registered-not-authorized"
    assert surface.typed_surface_only is True
    assert surface.surface_id == f"web-http-operation-surface_{surface.surface_digest}"
    assert surface.reference() == WebHTTPOperationSurfaceRef(
        surfaceId=surface.surface_id,
        surfaceDigest=surface.surface_digest,
        surfaceType=surface.surface_type,
        locatorSchema=surface.locator_schema,
        locatorKind="http-endpoint",
        locatorRegistry=surface.locator_registry,
    )
    assert WebHTTPOperationSurface.model_validate(
        surface.model_dump(mode="json", by_alias=True)
    ) == surface


def test_uri_template_route_reuses_existing_canonical_validation() -> None:
    locator = _route()
    surface = typed_web_http_operation_surface(locator=locator)

    assert surface.locator == HTTPRouteSurfaceLocator(
        base_url="https://api.example.test/v1",
        path_template="/users/{user_id}",
        method="POST",
        request_content_types=("application/json",),
        response_content_types=("application/json",),
    )
    assert surface.locator.kind == "http-route"
    assert surface.surface_id != typed_web_http_operation_surface(locator=_endpoint()).surface_id

    payload = surface.model_dump(mode="json", by_alias=True)
    payload["locator"]["path_template"] = "/users/{user_id}/{user_id}"
    payload["surfaceId"] = ""
    payload["surfaceDigest"] = ""
    with pytest.raises(ValidationError, match="parameter names must be unique"):
        WebHTTPOperationSurface.model_validate(payload)


def test_registry_and_typed_surface_carry_explicit_non_authority_markers() -> None:
    registry = registered_web_http_operation_locator_registry()
    surface = typed_web_http_operation_surface(locator=_endpoint())
    registry_payload = registry.model_dump(mode="json", by_alias=True)
    surface_payload = surface.model_dump(mode="json", by_alias=True)

    assert all(registry_payload[alias] is False for alias in _REGISTRY_FALSE_ALIASES)
    assert all(surface_payload[alias] is False for alias in _SURFACE_FALSE_ALIASES)
    assert {
        "campaign_profile",
        "capability",
        "scope",
        "approval",
        "permit",
        "tool",
        "worker",
        "request",
        "observation",
        "evidence",
    }.isdisjoint(WebHTTPOperationSurface.model_fields)


def test_web_registry_does_not_change_existing_discovery_or_attack_surface_wire() -> None:
    registry = registered_web_http_operation_locator_registry()

    assert registry.discovery_wire_changed is False
    assert registry.attack_surface_wire_changed is False
    assert registry.domain_semantics_registry_changed is False
    assert "domain_classification" not in HTTPSurfaceLocator.model_fields
    assert "domain_classification" not in HTTPRouteSurfaceLocator.model_fields
    assert "surface_type" not in AttackSurface.model_fields
    assert "locator_schema" not in AttackSurface.model_fields


@pytest.mark.parametrize(
    ("path", "value", "match"),
    (
        (
            ("locators", 0, "sourceModelId"),
            "pajin.discovery.models.HTTPRouteSurfaceLocator",
            "code authority",
        ),
        (("locators", 0, "locatorDigest"), "0" * 64, "Digest differs"),
        (("locators",), "reverse", "code authority"),
        (("domainClassification", "domain"), "network", "code authority"),
        (("multiDomainGraphSemanticsDigest",), "0" * 64, "code authority"),
        (("registryDigest",), "0" * 64, "Digest differs"),
    ),
)
def test_registry_rejects_locator_order_identity_domain_and_digest_drift(
    path: tuple[str | int, ...],
    value: str,
    match: str,
) -> None:
    payload = deepcopy(
        registered_web_http_operation_locator_registry().model_dump(
            mode="json",
            by_alias=True,
        )
    )
    if path == ("locators",):
        payload["locators"].reverse()
    else:
        target = payload
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = value

    with pytest.raises(ValidationError, match=match):
        WebHTTPOperationLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
def test_registry_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_web_http_operation_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        WebHTTPOperationLocatorRegistry.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        WebHTTPOperationLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
def test_typed_surface_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = typed_web_http_operation_surface(locator=_route()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        WebHTTPOperationSurface.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        WebHTTPOperationSurface.model_validate(payload)


def test_typed_surface_rejects_registry_domain_identity_digest_and_injected_authority() -> None:
    original = typed_web_http_operation_surface(locator=_endpoint()).model_dump(
        mode="json",
        by_alias=True,
    )
    mutations = (
        ("locatorRegistry", "registryDigest", "0" * 64),
        ("domainClassification", "domain", "network"),
        (None, "surfaceDigest", "0" * 64),
        (None, "surfaceId", "web-http-operation-surface_" + "0" * 64),
        (None, "capability", {"capabilityId": "unregistered"}),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            WebHTTPOperationSurface.model_validate(payload)


def test_locator_definition_rejects_uri_template_coercion_and_injected_tool_mapping() -> None:
    definition = registered_web_http_operation_locator_registry().locators[0]
    payload = definition.model_dump(mode="json", by_alias=True)
    payload["uriTemplate"] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        RegisteredWebHTTPOperationLocator.model_validate(payload)

    payload = definition.model_dump(mode="json", by_alias=True)
    payload["toolId"] = "scanner"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredWebHTTPOperationLocator.model_validate(payload)
