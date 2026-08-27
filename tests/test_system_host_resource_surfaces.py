from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    SYSTEM_HOST_RESOURCE_LOCATOR_SCHEMA,
    SYSTEM_HOST_RESOURCE_SURFACE_TYPE,
    AttackSurface,
    RegisteredSystemHostResourceLocator,
    SurfaceLocator,
    SystemArchitecture,
    SystemConfigurationSurfaceLocator,
    SystemFilesystemEntryKind,
    SystemFilesystemSurfaceLocator,
    SystemHostResourceLocatorRegistry,
    SystemHostResourceSurface,
    SystemHostResourceSurfaceLocator,
    SystemHostResourceSurfaceRef,
    SystemHostSurfaceLocator,
    SystemOperatingSystem,
    SystemProcessSurfaceLocator,
    SystemServiceManager,
    SystemServiceSurfaceLocator,
    SystemSurfaceClass,
    SystemSurfaceRegistryError,
    registered_system_host_resource_locator_registry,
    resolve_registered_system_host_resource_locator,
    resolve_system_host_resource_locator_registry,
    system_configuration_surface_locator,
    system_filesystem_surface_locator,
    system_host_surface_locator,
    system_process_surface_locator,
    system_service_surface_locator,
    typed_system_host_resource_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_SYSTEM_LOCATOR_ADAPTER = TypeAdapter(SystemHostResourceSurfaceLocator)
_DISCOVERY_LOCATOR_ADAPTER = TypeAdapter(SurfaceLocator)

_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "attackSurfaceWireChanged",
    "domainSemanticsRegistryChanged",
    "discoveryAuthorized",
    "hostAccessAuthorized",
    "processInspectionAuthorized",
    "filesystemReadAuthorized",
    "serviceInspectionAuthorized",
    "serviceControlAuthorized",
    "configurationReadAuthorized",
    "credentialUseAuthorized",
    "rootAuthorityAsserted",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "authenticatedHostAgentAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "hostMutationAuthorized",
    "graphAdmissionAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_SURFACE_FALSE_ALIASES = (
    "discoveryObserved",
    "hostExistenceVerified",
    "processRunningVerified",
    "filesystemEntryVerified",
    "serviceStateVerified",
    "configurationRecordVerified",
    "evidenceSealed",
    "graphAdmitted",
    "hostAccessAuthorized",
    "processInspectionAuthorized",
    "filesystemReadAuthorized",
    "serviceInspectionAuthorized",
    "serviceControlAuthorized",
    "configurationReadAuthorized",
    "credentialUseAuthorized",
    "rootAuthorityAsserted",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "authenticatedHostAgentAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "hostMutationAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_LOCATOR_SECURITY_ALIASES = (
    "secretMaterialEmbedded",
    "credentialReferenceEmbedded",
    "hostLocalAbsolutePathEmbedded",
    "privilegeClaimEmbedded",
)


def _host(host_id: str = "host-" + "1" * 64) -> SystemHostSurfaceLocator:
    return system_host_surface_locator(
        host_id=host_id,
        operating_system=SystemOperatingSystem.LINUX,
        architecture=SystemArchitecture.X86_64,
    )


def _process(host: SystemHostSurfaceLocator | None = None) -> SystemProcessSurfaceLocator:
    return system_process_surface_locator(
        host=host or _host(),
        process_instance_digest="a" * 64,
        executable_digest="b" * 64,
    )


def _filesystem(host: SystemHostSurfaceLocator | None = None) -> SystemFilesystemSurfaceLocator:
    return system_filesystem_surface_locator(
        host=host or _host(),
        mount_id="system-root",
        relative_path="etc/ssh/sshd_config",
        entry_kind=SystemFilesystemEntryKind.FILE,
        content_digest="c" * 64,
    )


def _service(host: SystemHostSurfaceLocator | None = None) -> SystemServiceSurfaceLocator:
    return system_service_surface_locator(
        host=host or _host(),
        service_manager=SystemServiceManager.SYSTEMD,
        service_id="sshd.service",
        definition_digest="d" * 64,
    )


def _configuration(
    parent: (
        SystemHostSurfaceLocator
        | SystemProcessSurfaceLocator
        | SystemFilesystemSurfaceLocator
        | SystemServiceSurfaceLocator
        | None
    ) = None,
) -> SystemConfigurationSurfaceLocator:
    return system_configuration_surface_locator(
        parent=parent or _service(),
        configuration_namespace="systemd",
        configuration_id="sshd/service-hardening",
        configuration_digest="e" * 64,
    )


def _locators() -> tuple[SystemHostResourceSurfaceLocator, ...]:
    return (_host(), _process(), _filesystem(), _service(), _configuration())


def test_registry_binds_exact_system_semantics_and_locator_classes() -> None:
    registry = registered_system_host_resource_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    system_type_set = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.SYSTEM
    )

    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert registry.surface_type == SYSTEM_HOST_RESOURCE_SURFACE_TYPE
    assert registry.locator_schema == SYSTEM_HOST_RESOURCE_LOCATOR_SCHEMA
    assert registry.domain_classification.domain is SecurityDomain.SYSTEM
    assert registry.domain_graph_type_set == system_type_set.reference()
    assert system_type_set.surface_type == SYSTEM_HOST_RESOURCE_SURFACE_TYPE
    assert system_type_set.locator_schema == SYSTEM_HOST_RESOURCE_LOCATOR_SCHEMA
    assert tuple(
        (
            item.surface_class.value,
            item.locator_kind,
            item.parent_requirement,
            item.content_digest_required,
            item.portable_relative_path_required,
        )
        for item in registry.locators
    ) == (
        ("host", "system-host", "none", False, False),
        ("process", "system-process", "host", True, False),
        ("filesystem", "system-filesystem", "host", True, True),
        ("service", "system-service", "host", True, False),
        (
            "configuration",
            "system-configuration",
            "host-or-process-or-filesystem-or-service",
            True,
            False,
        ),
    )
    assert tuple(item.surface_class for item in registry.locators) == tuple(SystemSurfaceClass)
    assert registry.discovered_surface_initial_state == "registered-not-authorized"
    assert registry.registry_only is True
    assert len(registry.registry_digest) == 64
    assert (
        SystemHostResourceLocatorRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        == registry
    )


def test_locator_and_complete_registry_resolution_require_exact_references() -> None:
    registry = registered_system_host_resource_locator_registry()

    for source in registry.locators:
        resolved = resolve_registered_system_host_resource_locator(source.reference())
        assert resolved == source
        assert resolved is not source

    resolved_registry = resolve_system_host_resource_locator_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_resolution_rejects_digest_class_and_registry_substitution() -> None:
    registry = registered_system_host_resource_locator_registry()
    source = registry.locators[0]

    with pytest.raises(SystemSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_system_host_resource_locator(
            source.reference().model_copy(update={"locator_digest": "0" * 64})
        )
    with pytest.raises(SystemSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_system_host_resource_locator(
            source.reference().model_copy(update={"surface_class": SystemSurfaceClass.SERVICE})
        )
    with pytest.raises(SystemSurfaceRegistryError, match="not registered exactly"):
        resolve_system_host_resource_locator_registry(
            registry.reference().model_copy(update={"registry_digest": "0" * 64})
        )


def test_host_id_canonicalizes_without_access_or_attestation() -> None:
    host = system_host_surface_locator(
        host_id="HOST-" + "A" * 64,
        operating_system=SystemOperatingSystem.WINDOWS,
        architecture=SystemArchitecture.AARCH64,
    )

    assert host.host_id == "host-" + "a" * 64
    assert host.operating_system is SystemOperatingSystem.WINDOWS
    assert host.architecture is SystemArchitecture.AARCH64
    assert (
        SystemHostSurfaceLocator.model_validate(host.model_dump(mode="json", by_alias=True)) == host
    )


@pytest.mark.parametrize(
    "host_id",
    (
        "local",
        "localhost",
        "current",
        "this-host",
        "host-security-0001",
        " host-" + "1" * 64,
        "host/" + "1" * 64,
        "host-" + "1" * 63 + "*",
        "https://host.example.test",
    ),
)
def test_host_id_rejects_mutable_local_path_or_active_aliases(host_id: str) -> None:
    payload = _host().model_dump(mode="json", by_alias=True)
    payload["hostId"] = host_id

    with pytest.raises(ValidationError):
        SystemHostSurfaceLocator.model_validate(payload)


def test_process_identity_uses_exact_host_and_digests_without_pid() -> None:
    process = _process()
    other_host = _host("host-" + "2" * 64)
    other_process = _process(other_host)

    assert process.host == _host()
    assert process.process_instance_digest == "a" * 64
    assert process.executable_digest == "b" * 64
    assert "pid" not in SystemProcessSurfaceLocator.model_fields
    assert "executable_path" not in SystemProcessSurfaceLocator.model_fields
    assert (
        typed_system_host_resource_surface(locator=process).surface_id
        != typed_system_host_resource_surface(locator=other_process).surface_id
    )

    payload = process.model_dump(mode="json", by_alias=True)
    payload["pid"] = 1234
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SystemProcessSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    "relative_path",
    (
        "/etc/ssh/sshd_config",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "../etc/passwd",
        "etc/../passwd",
        "etc/./passwd",
        "etc//passwd",
        "etc/passwd/",
        "etc/pass*",
        "etc/passwd?version=1",
    ),
)
def test_filesystem_rejects_absolute_ambiguous_or_active_paths(relative_path: str) -> None:
    payload = _filesystem().model_dump(mode="json", by_alias=True)
    payload["relativePath"] = relative_path

    with pytest.raises(ValidationError):
        SystemFilesystemSurfaceLocator.model_validate(payload)


def test_filesystem_locator_is_logical_mount_relative_and_content_bound() -> None:
    filesystem = _filesystem()

    assert filesystem.host == _host()
    assert filesystem.mount_id == "system-root"
    assert filesystem.relative_path == "etc/ssh/sshd_config"
    assert filesystem.entry_kind is SystemFilesystemEntryKind.FILE
    assert filesystem.content_digest == "c" * 64
    assert "absolute_path" not in SystemFilesystemSurfaceLocator.model_fields

    payload = filesystem.model_dump(mode="json", by_alias=True)
    payload["absolutePath"] = "/etc/ssh/sshd_config"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SystemFilesystemSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("manager", "service_id"),
    (
        (SystemServiceManager.SYSTEMD, "sshd"),
        (SystemServiceManager.SYSTEMD, "current"),
        (SystemServiceManager.SYSTEMD, "/etc/systemd/system/sshd.service"),
        (SystemServiceManager.WINDOWS_SERVICE, "C:\\service.exe"),
        (SystemServiceManager.LAUNCHD, "com.example.*"),
    ),
)
def test_service_rejects_display_alias_path_or_non_unit_identity(
    manager: SystemServiceManager,
    service_id: str,
) -> None:
    payload = _service().model_dump(mode="json", by_alias=True)
    payload["serviceManager"] = manager.value
    payload["serviceId"] = service_id

    with pytest.raises(ValidationError):
        SystemServiceSurfaceLocator.model_validate(payload)


def test_service_locator_is_manager_qualified_without_display_name_or_control() -> None:
    service = _service()
    windows_service = system_service_surface_locator(
        host=_host(),
        service_manager=SystemServiceManager.WINDOWS_SERVICE,
        service_id="OpenSSH-Service",
        definition_digest="f" * 64,
    )

    assert service.host == _host()
    assert service.service_manager is SystemServiceManager.SYSTEMD
    assert service.service_id == "sshd.service"
    assert service.definition_digest == "d" * 64
    assert windows_service.service_id == "openssh-service"
    assert "display_name" not in SystemServiceSurfaceLocator.model_fields

    payload = service.model_dump(mode="json", by_alias=True)
    payload["displayName"] = "OpenSSH Server"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SystemServiceSurfaceLocator.model_validate(payload)


def test_configuration_accepts_only_exact_sanitized_parent_lineage() -> None:
    parents = (_host(), _process(), _filesystem(), _service())
    surfaces = tuple(
        typed_system_host_resource_surface(locator=_configuration(parent)) for parent in parents
    )

    assert len({surface.surface_id for surface in surfaces}) == len(parents)
    for parent, surface in zip(parents, surfaces, strict=True):
        locator = surface.locator
        assert isinstance(locator, SystemConfigurationSurfaceLocator)
        assert locator.parent == parent
        assert locator.configuration_namespace == "systemd"
        assert locator.configuration_id == "sshd/service-hardening"
        assert locator.configuration_digest == "e" * 64

    payload = _configuration().model_dump(mode="json", by_alias=True)
    payload["rawValue"] = "PermitRootLogin yes"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SystemConfigurationSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("locator", "expected_class"),
    tuple(zip(_locators(), tuple(SystemSurfaceClass), strict=True)),
)
def test_each_locator_becomes_a_stable_inert_typed_system_surface(
    locator: SystemHostResourceSurfaceLocator,
    expected_class: SystemSurfaceClass,
) -> None:
    surface = typed_system_host_resource_surface(locator=locator)

    assert surface.locator == locator
    assert surface.locator is not locator
    assert surface.surface_class is expected_class
    assert surface.initial_state == "registered-not-authorized"
    assert surface.typed_surface_only is True
    assert surface.surface_id == f"system-host-resource-surface_{surface.surface_digest}"
    assert surface.reference() == SystemHostResourceSurfaceRef(
        surfaceId=surface.surface_id,
        surfaceDigest=surface.surface_digest,
        surfaceType=surface.surface_type,
        locatorSchema=surface.locator_schema,
        surfaceClass=expected_class,
        locatorKind=locator.kind,
        locatorRegistry=surface.locator_registry,
    )
    assert (
        SystemHostResourceSurface.model_validate(surface.model_dump(mode="json", by_alias=True))
        == surface
    )
    assert (
        _SYSTEM_LOCATOR_ADAPTER.validate_python(locator.model_dump(mode="json", by_alias=True))
        == locator
    )


def test_system_models_do_not_change_existing_discovery_or_attack_surface_wire() -> None:
    registry = registered_system_host_resource_locator_registry()

    assert registry.discovery_wire_changed is False
    assert registry.attack_surface_wire_changed is False
    assert registry.domain_semantics_registry_changed is False
    assert "system-host" not in str(SurfaceLocator)
    assert "domain_classification" not in SystemHostSurfaceLocator.model_fields
    assert "surface_type" not in AttackSurface.model_fields
    assert "locator_schema" not in AttackSurface.model_fields

    with pytest.raises(ValidationError):
        _DISCOVERY_LOCATOR_ADAPTER.validate_python(
            _filesystem().model_dump(mode="json", by_alias=True)
        )


def test_registry_and_surface_carry_explicit_non_authority_markers() -> None:
    registry_payload = registered_system_host_resource_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    surface_payload = typed_system_host_resource_surface(locator=_configuration()).model_dump(
        mode="json",
        by_alias=True,
    )

    assert all(registry_payload[alias] is False for alias in _REGISTRY_FALSE_ALIASES)
    assert all(surface_payload[alias] is False for alias in _SURFACE_FALSE_ALIASES)
    assert {
        "campaign_profile",
        "scope_authority",
        "capability",
        "approval",
        "permit",
        "tool",
        "worker",
        "request",
        "observation",
        "evidence",
        "credential",
        "secret",
        "raw_configuration",
        "absolute_path",
        "pid",
    }.isdisjoint(SystemHostResourceSurface.model_fields)


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
        registered_system_host_resource_locator_registry().model_dump(
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
        SystemHostResourceLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
def test_registry_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_system_host_resource_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        SystemHostResourceLocatorRegistry.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        SystemHostResourceLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
def test_typed_surface_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = typed_system_host_resource_surface(locator=_configuration()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        SystemHostResourceSurface.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        SystemHostResourceSurface.model_validate(payload)


def test_typed_surface_rejects_registry_domain_identity_digest_and_authority_injection() -> None:
    original = typed_system_host_resource_surface(locator=_configuration()).model_dump(
        mode="json",
        by_alias=True,
    )
    mutations = (
        ("locatorRegistry", "registryDigest", "0" * 64),
        ("domainClassification", "domain", "web"),
        (None, "surfaceClass", "host"),
        (None, "surfaceDigest", "0" * 64),
        (None, "surfaceId", "system-host-resource-surface_" + "0" * 64),
        (None, "hostAccess", {"agentId": "host-agent"}),
        (None, "credential", {"token": "redacted"}),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            SystemHostResourceSurface.model_validate(payload)


def test_locator_definition_rejects_boolean_coercion_and_host_agent_mapping() -> None:
    definition = registered_system_host_resource_locator_registry().locators[0]
    payload = definition.model_dump(mode="json", by_alias=True)
    payload["contentDigestRequired"] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        RegisteredSystemHostResourceLocator.model_validate(payload)

    payload = definition.model_dump(mode="json", by_alias=True)
    payload["hostAgentId"] = "local-root-agent"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredSystemHostResourceLocator.model_validate(payload)


@pytest.mark.parametrize("locator", _locators())
@pytest.mark.parametrize("alias", _LOCATOR_SECURITY_ALIASES)
def test_locators_reject_security_marker_escalation_and_secret_field_injection(
    locator: SystemHostResourceSurfaceLocator,
    alias: str,
) -> None:
    payload = locator.model_dump(mode="json", by_alias=True)
    payload[alias] = True
    with pytest.raises(ValidationError):
        _SYSTEM_LOCATOR_ADAPTER.validate_python(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        _SYSTEM_LOCATOR_ADAPTER.validate_python(payload)

    payload = locator.model_dump(mode="json", by_alias=True)
    payload["password"] = "redacted"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _SYSTEM_LOCATOR_ADAPTER.validate_python(payload)
