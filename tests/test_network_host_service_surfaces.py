from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    NETWORK_HOST_SERVICE_LOCATOR_SCHEMA,
    NETWORK_HOST_SERVICE_SURFACE_TYPE,
    AttackSurface,
    NetworkAddressFamily,
    NetworkHostServiceLocatorRegistry,
    NetworkHostServiceSurface,
    NetworkHostServiceSurfaceLocator,
    NetworkHostServiceSurfaceRef,
    NetworkHostSurfaceLocator,
    NetworkPortSurfaceLocator,
    NetworkServiceSurfaceLocator,
    NetworkSurfaceClass,
    NetworkSurfaceRegistryError,
    NetworkTransportProtocol,
    RegisteredNetworkHostServiceLocator,
    SurfaceLocator,
    network_host_surface_locator,
    network_port_surface_locator,
    network_service_surface_locator,
    registered_network_host_service_locator_registry,
    resolve_network_host_service_locator_registry,
    resolve_registered_network_host_service_locator,
    typed_network_host_service_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_NETWORK_LOCATOR_ADAPTER = TypeAdapter(NetworkHostServiceSurfaceLocator)
_DISCOVERY_LOCATOR_ADAPTER = TypeAdapter(SurfaceLocator)

_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "attackSurfaceWireChanged",
    "domainSemanticsRegistryChanged",
    "discoveryAuthorized",
    "nameResolutionAuthorized",
    "portEnumerationAuthorized",
    "serviceProbeAuthorized",
    "rawSocketAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "permitIssuanceAuthorized",
    "scannerSelectionAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "credentialAccessAuthorized",
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
    "nameResolutionAuthorized",
    "portEnumerationAuthorized",
    "serviceProbeAuthorized",
    "rawSocketAuthorized",
    "scannerSelectionAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "credentialAccessAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)


def _dns_host() -> NetworkHostSurfaceLocator:
    return network_host_surface_locator(
        address_family=NetworkAddressFamily.DNS_NAME,
        host="service.example.test",
    )


def _port() -> NetworkPortSurfaceLocator:
    return network_port_surface_locator(
        host=_dns_host(),
        transport_protocol=NetworkTransportProtocol.TCP,
        port=443,
    )


def _service() -> NetworkServiceSurfaceLocator:
    return network_service_surface_locator(
        host=_dns_host(),
        transport_protocol=NetworkTransportProtocol.TCP,
        port=443,
        service_name="HTTPS",
    )


def test_registry_binds_exact_network_semantics_and_locator_classes() -> None:
    registry = registered_network_host_service_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    network_type_set = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.NETWORK
    )

    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert registry.surface_type == NETWORK_HOST_SERVICE_SURFACE_TYPE
    assert registry.locator_schema == NETWORK_HOST_SERVICE_LOCATOR_SCHEMA
    assert registry.domain_classification.domain is SecurityDomain.NETWORK
    assert registry.domain_graph_type_set == network_type_set.reference()
    assert network_type_set.surface_type == NETWORK_HOST_SERVICE_SURFACE_TYPE
    assert network_type_set.locator_schema == NETWORK_HOST_SERVICE_LOCATOR_SCHEMA
    assert tuple(
        (
            item.surface_class.value,
            item.locator_kind,
            item.transport_protocol_required,
            item.port_required,
            item.service_name_required,
        )
        for item in registry.locators
    ) == (
        ("host", "network-host", False, False, False),
        ("port", "network-port", True, True, False),
        ("service", "network-service", True, True, True),
    )
    assert tuple(item.surface_class for item in registry.locators) == tuple(NetworkSurfaceClass)
    assert registry.discovered_surface_initial_state == "registered-not-authorized"
    assert registry.registry_only is True
    assert len(registry.registry_digest) == 64
    assert (
        NetworkHostServiceLocatorRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        == registry
    )


def test_locator_and_complete_registry_resolution_require_exact_references() -> None:
    registry = registered_network_host_service_locator_registry()

    for source in registry.locators:
        resolved = resolve_registered_network_host_service_locator(source.reference())
        assert resolved == source
        assert resolved is not source

    resolved_registry = resolve_network_host_service_locator_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_resolution_rejects_digest_class_and_registry_substitution() -> None:
    registry = registered_network_host_service_locator_registry()
    source = registry.locators[0]

    with pytest.raises(NetworkSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_network_host_service_locator(
            source.reference().model_copy(update={"locator_digest": "0" * 64})
        )
    with pytest.raises(NetworkSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_network_host_service_locator(
            source.reference().model_copy(update={"surface_class": NetworkSurfaceClass.SERVICE})
        )
    with pytest.raises(NetworkSurfaceRegistryError, match="not registered exactly"):
        resolve_network_host_service_locator_registry(
            registry.reference().model_copy(update={"registry_digest": "0" * 64})
        )


def test_host_locator_canonicalizes_dns_ipv4_and_ipv6_without_resolution() -> None:
    dns = network_host_surface_locator(
        address_family=NetworkAddressFamily.DNS_NAME,
        host="BÜCHER.Example.",
    )
    ipv4 = network_host_surface_locator(
        address_family=NetworkAddressFamily.IPV4,
        host="192.0.2.10",
    )
    ipv6 = network_host_surface_locator(
        address_family=NetworkAddressFamily.IPV6,
        host="2001:0DB8:0:0::1",
    )

    assert dns.host == "xn--bcher-kva.example"
    assert ipv4.host == "192.0.2.10"
    assert ipv6.host == "2001:db8::1"
    assert (
        NetworkHostSurfaceLocator.model_validate(dns.model_dump(mode="json", by_alias=True)) == dns
    )


@pytest.mark.parametrize(
    ("family", "host", "match"),
    (
        (NetworkAddressFamily.DNS_NAME, "https://example.test", "canonical host text"),
        (NetworkAddressFamily.DNS_NAME, "user@example.test", "canonical host text"),
        (NetworkAddressFamily.DNS_NAME, "*.example.test", "zone identifier or wildcard"),
        (NetworkAddressFamily.DNS_NAME, "example..test", "canonical host text"),
        (NetworkAddressFamily.DNS_NAME, "192.0.2.10", "explicit address family"),
        (NetworkAddressFamily.DNS_NAME, "192.0.2.010", "explicit address family"),
        (NetworkAddressFamily.DNS_NAME, "0x7f.0.0.1", "explicit address family"),
        (NetworkAddressFamily.IPV4, "2001:db8::1", "explicit address family"),
        (NetworkAddressFamily.IPV6, "192.0.2.10", "explicit address family"),
        (NetworkAddressFamily.IPV6, "fe80::1%eth0", "zone identifier or wildcard"),
        (NetworkAddressFamily.IPV4, "127.0.0.1 ", "surrounding or control"),
    ),
)
def test_host_locator_rejects_ambiguous_or_cross_family_identity(
    family: NetworkAddressFamily,
    host: str,
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        NetworkHostSurfaceLocator(addressFamily=family, host=host)


def test_port_and_service_locators_are_exact_and_do_not_infer_each_other() -> None:
    port = _port()
    service = _service()

    assert port.host == _dns_host()
    assert port.host is not _dns_host()
    assert port.transport_protocol is NetworkTransportProtocol.TCP
    assert port.port == 443
    assert "service_name" not in NetworkPortSurfaceLocator.model_fields
    assert service.service_name == "https"
    assert service.host == port.host
    assert service.transport_protocol == port.transport_protocol
    assert service.port == port.port


@pytest.mark.parametrize("port", (0, 65_536, True, "443"))
def test_port_locators_reject_out_of_range_and_coerced_ports(port: object) -> None:
    payload = _port().model_dump(mode="json", by_alias=True)
    payload["port"] = port
    with pytest.raises(ValidationError):
        NetworkPortSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    "service_name",
    ("unknown", "auto", "default", " ssh ", "ssh/tcp", "ssh.", "ssh..tls"),
)
def test_service_locator_requires_explicit_bounded_service_name(
    service_name: str,
) -> None:
    payload = _service().model_dump(mode="json", by_alias=True)
    payload["serviceName"] = service_name
    with pytest.raises(ValidationError):
        NetworkServiceSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("locator", "expected_class"),
    (
        (_dns_host(), NetworkSurfaceClass.HOST),
        (_port(), NetworkSurfaceClass.PORT),
        (_service(), NetworkSurfaceClass.SERVICE),
    ),
)
def test_each_locator_becomes_a_stable_inert_typed_network_surface(
    locator: NetworkHostServiceSurfaceLocator,
    expected_class: NetworkSurfaceClass,
) -> None:
    surface = typed_network_host_service_surface(locator=locator)

    assert surface.locator == locator
    assert surface.locator is not locator
    assert surface.surface_class is expected_class
    assert surface.initial_state == "registered-not-authorized"
    assert surface.typed_surface_only is True
    assert surface.surface_id == f"network-host-service-surface_{surface.surface_digest}"
    assert surface.reference() == NetworkHostServiceSurfaceRef(
        surfaceId=surface.surface_id,
        surfaceDigest=surface.surface_digest,
        surfaceType=surface.surface_type,
        locatorSchema=surface.locator_schema,
        surfaceClass=expected_class,
        locatorKind=locator.kind,
        locatorRegistry=surface.locator_registry,
    )
    assert (
        NetworkHostServiceSurface.model_validate(surface.model_dump(mode="json", by_alias=True))
        == surface
    )
    assert (
        _NETWORK_LOCATOR_ADAPTER.validate_python(locator.model_dump(mode="json", by_alias=True))
        == locator
    )


def test_host_port_and_service_surface_identities_remain_distinct() -> None:
    surface_ids = {
        typed_network_host_service_surface(locator=locator).surface_id
        for locator in (_dns_host(), _port(), _service())
    }

    assert len(surface_ids) == 3


def test_network_models_do_not_change_existing_discovery_or_attack_surface_wire() -> None:
    registry = registered_network_host_service_locator_registry()

    assert registry.discovery_wire_changed is False
    assert registry.attack_surface_wire_changed is False
    assert registry.domain_semantics_registry_changed is False
    assert "network-host" not in str(SurfaceLocator)
    assert "domain_classification" not in NetworkHostSurfaceLocator.model_fields
    assert "surface_type" not in AttackSurface.model_fields
    assert "locator_schema" not in AttackSurface.model_fields

    with pytest.raises(ValidationError):
        _DISCOVERY_LOCATOR_ADAPTER.validate_python(_port().model_dump(mode="json", by_alias=True))


def test_registry_and_surface_carry_explicit_non_authority_markers() -> None:
    registry_payload = registered_network_host_service_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    surface_payload = typed_network_host_service_surface(locator=_service()).model_dump(
        mode="json",
        by_alias=True,
    )

    assert all(registry_payload[alias] is False for alias in _REGISTRY_FALSE_ALIASES)
    assert all(surface_payload[alias] is False for alias in _SURFACE_FALSE_ALIASES)
    assert {
        "campaign_profile",
        "scope",
        "capability",
        "approval",
        "permit",
        "scanner",
        "tool",
        "worker",
        "request",
        "observation",
        "evidence",
        "credential",
        "secret",
        "banner",
    }.isdisjoint(NetworkHostServiceSurface.model_fields)


@pytest.mark.parametrize(
    ("path", "value", "match"),
    (
        (("locators", 0, "surfaceClass"), "service", "code authority"),
        (("locators", 0, "sourceModelId"), "pajin.fake.Host", "code authority"),
        (("locators", 0, "locatorDigest"), "0" * 64, "Digest differs"),
        (("locators",), "reverse", "code authority"),
        (("domainClassification", "domain"), "web", "code authority"),
        (("multiDomainGraphSemanticsDigest",), "0" * 64, "code authority"),
        (("registryDigest",), "0" * 64, "Digest differs"),
    ),
)
def test_registry_rejects_identity_order_domain_and_digest_drift(
    path: tuple[str | int, ...],
    value: str,
    match: str,
) -> None:
    payload = deepcopy(
        registered_network_host_service_locator_registry().model_dump(
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
        NetworkHostServiceLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
def test_registry_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_network_host_service_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        NetworkHostServiceLocatorRegistry.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        NetworkHostServiceLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
def test_typed_surface_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
) -> None:
    payload = typed_network_host_service_surface(locator=_service()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        NetworkHostServiceSurface.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        NetworkHostServiceSurface.model_validate(payload)


def test_typed_surface_rejects_registry_domain_identity_digest_and_authority_injection() -> None:
    original = typed_network_host_service_surface(locator=_service()).model_dump(
        mode="json",
        by_alias=True,
    )
    mutations = (
        ("locatorRegistry", "registryDigest", "0" * 64),
        ("domainClassification", "domain", "web"),
        (None, "surfaceClass", "host"),
        (None, "surfaceDigest", "0" * 64),
        (None, "surfaceId", "network-host-service-surface_" + "0" * 64),
        (None, "scope", {"targets": ["service.example.test"]}),
        (None, "credential", {"secretId": "ambient"}),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            NetworkHostServiceSurface.model_validate(payload)


def test_locator_definition_rejects_boolean_coercion_and_injected_scanner_mapping() -> None:
    definition = registered_network_host_service_locator_registry().locators[0]
    payload = definition.model_dump(mode="json", by_alias=True)
    payload["transportProtocolRequired"] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        RegisteredNetworkHostServiceLocator.model_validate(payload)

    payload = definition.model_dump(mode="json", by_alias=True)
    payload["scannerId"] = "broad-port-scanner"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredNetworkHostServiceLocator.model_validate(payload)
