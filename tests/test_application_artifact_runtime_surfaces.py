from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    APPLICATION_ARTIFACT_RUNTIME_LOCATOR_SCHEMA,
    APPLICATION_ARTIFACT_RUNTIME_SURFACE_TYPE,
    ApplicationArtifactRuntimeLocatorRegistry,
    ApplicationArtifactRuntimeSurface,
    ApplicationArtifactRuntimeSurfaceLocator,
    ApplicationArtifactRuntimeSurfaceRef,
    ApplicationBinarySurfaceLocator,
    ApplicationConfigurationSurfaceLocator,
    ApplicationLibrarySurfaceLocator,
    ApplicationRuntimeSurfaceLocator,
    ApplicationSurfaceClass,
    ApplicationSurfaceRegistryError,
    AttackSurface,
    RegisteredApplicationArtifactRuntimeLocator,
    SurfaceLocator,
    application_binary_surface_locator,
    application_configuration_surface_locator,
    application_library_surface_locator,
    application_runtime_surface_locator,
    registered_application_artifact_runtime_locator_registry,
    resolve_application_artifact_runtime_locator_registry,
    resolve_registered_application_artifact_runtime_locator,
    typed_application_artifact_runtime_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_APPLICATION_LOCATOR_ADAPTER = TypeAdapter(ApplicationArtifactRuntimeSurfaceLocator)
_DISCOVERY_LOCATOR_ADAPTER = TypeAdapter(SurfaceLocator)

_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "attackSurfaceWireChanged",
    "domainSemanticsRegistryChanged",
    "discoveryAuthorized",
    "artifactResolutionAuthorized",
    "artifactReadAuthorized",
    "staticAnalysisAuthorized",
    "dynamicAnalysisAuthorized",
    "credentialAccessAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "sandboxSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "debuggerAttachAuthorized",
    "artifactMutationAuthorized",
    "graphAdmissionAuthorized",
    "findingAuthority",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_SURFACE_FALSE_ALIASES = (
    "discoveryObserved",
    "artifactResolved",
    "artifactBytesVerified",
    "binaryFormatVerified",
    "configurationSemanticsVerified",
    "runtimeEnvironmentVerified",
    "libraryDependencyVerified",
    "vulnerabilityConfirmed",
    "evidenceSealed",
    "graphAdmitted",
    "artifactResolutionAuthorized",
    "artifactReadAuthorized",
    "staticAnalysisAuthorized",
    "dynamicAnalysisAuthorized",
    "credentialAccessAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "sandboxSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "debuggerAttachAuthorized",
    "artifactMutationAuthorized",
    "findingAuthority",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_LOCATOR_SECURITY_ALIASES = (
    "rawArtifactContentEmbedded",
    "mutablePathEmbedded",
    "runtimeProcessStateEmbedded",
    "secretMaterialEmbedded",
    "credentialReferenceEmbedded",
)


def _binary(digest: str = "1" * 64) -> ApplicationBinarySurfaceLocator:
    return application_binary_surface_locator(artifact_sha256=digest)


def _configuration(
    parent: ApplicationBinarySurfaceLocator | None = None,
) -> ApplicationConfigurationSurfaceLocator:
    return application_configuration_surface_locator(
        parent=parent or _binary(),
        configuration_namespace="pajin.app",
        configuration_id="production",
        artifact_sha256="2" * 64,
    )


def _runtime(
    parent: ApplicationBinarySurfaceLocator | None = None,
) -> ApplicationRuntimeSurfaceLocator:
    return application_runtime_surface_locator(
        parent=parent or _binary(),
        runtime_family="python",
        runtime_version="3.12.7",
        artifact_sha256="3" * 64,
    )


def _library(
    parent: ApplicationBinarySurfaceLocator | ApplicationRuntimeSurfaceLocator | None = None,
) -> ApplicationLibrarySurfaceLocator:
    return application_library_surface_locator(
        parent=parent or _runtime(),
        library_namespace="pypi",
        library_id="pydantic",
        library_version="2.11.7",
        artifact_sha256="4" * 64,
    )


def _locators() -> tuple[ApplicationArtifactRuntimeSurfaceLocator, ...]:
    return (_binary(), _configuration(), _runtime(), _library())


def test_registry_binds_exact_application_semantics_and_locator_classes() -> None:
    registry = registered_application_artifact_runtime_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    application_type_set = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.APPLICATION
    )

    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert registry.surface_type == APPLICATION_ARTIFACT_RUNTIME_SURFACE_TYPE
    assert registry.locator_schema == APPLICATION_ARTIFACT_RUNTIME_LOCATOR_SCHEMA
    assert registry.domain_classification.domain is SecurityDomain.APPLICATION
    assert registry.domain_graph_type_set == application_type_set.reference()
    assert application_type_set.surface_type == APPLICATION_ARTIFACT_RUNTIME_SURFACE_TYPE
    assert application_type_set.locator_schema == APPLICATION_ARTIFACT_RUNTIME_LOCATOR_SCHEMA
    assert tuple(
        (
            item.surface_class.value,
            item.locator_kind,
            item.parent_requirement,
            item.artifact_digest_required,
            item.exact_parent_lineage_required,
            item.exact_version_required,
        )
        for item in registry.locators
    ) == (
        ("binary", "application-binary", "none", True, False, False),
        (
            "configuration",
            "application-configuration",
            "binary",
            True,
            True,
            False,
        ),
        ("runtime", "application-runtime", "binary", True, True, True),
        ("library", "application-library", "binary-or-runtime", True, True, True),
    )
    assert tuple(item.surface_class for item in registry.locators) == tuple(ApplicationSurfaceClass)
    assert tuple(item.source_model_id for item in registry.locators) == tuple(
        f"{model.__module__}.{model.__qualname__}"
        for model in (
            ApplicationBinarySurfaceLocator,
            ApplicationConfigurationSurfaceLocator,
            ApplicationRuntimeSurfaceLocator,
            ApplicationLibrarySurfaceLocator,
        )
    )
    assert registry.discovered_surface_initial_state == "registered-not-authorized"
    assert registry.registry_only is True
    assert len(registry.registry_digest) == 64
    assert (
        ApplicationArtifactRuntimeLocatorRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        == registry
    )


def test_locator_and_complete_registry_resolution_require_exact_references() -> None:
    registry = registered_application_artifact_runtime_locator_registry()

    for source in registry.locators:
        resolved = resolve_registered_application_artifact_runtime_locator(source.reference())
        assert resolved == source
        assert resolved is not source

    resolved_registry = resolve_application_artifact_runtime_locator_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_resolution_rejects_digest_class_and_registry_substitution() -> None:
    registry = registered_application_artifact_runtime_locator_registry()
    source = registry.locators[0]

    with pytest.raises(ApplicationSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_application_artifact_runtime_locator(
            source.reference().model_copy(update={"locator_digest": "0" * 64})
        )
    with pytest.raises(ApplicationSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_application_artifact_runtime_locator(
            source.reference().model_copy(update={"surface_class": ApplicationSurfaceClass.RUNTIME})
        )
    with pytest.raises(ApplicationSurfaceRegistryError, match="not registered exactly"):
        resolve_application_artifact_runtime_locator_registry(
            registry.reference().model_copy(update={"registry_digest": "0" * 64})
        )


def test_binary_identity_is_digest_only_without_path_or_format_claims() -> None:
    binary = _binary()

    assert binary.artifact_sha256 == "1" * 64
    assert {
        "path",
        "file_path",
        "artifact_name",
        "binary_format",
        "content",
    }.isdisjoint(ApplicationBinarySurfaceLocator.model_fields)
    assert (
        ApplicationBinarySurfaceLocator.model_validate(
            binary.model_dump(mode="json", by_alias=True)
        )
        == binary
    )

    payload = binary.model_dump(mode="json", by_alias=True)
    payload["path"] = "C:\\apps\\pajin.exe"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ApplicationBinarySurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    "digest",
    (
        "A" * 64,
        "1" * 63,
        "1" * 65,
        "g" * 64,
        "sha256:" + "1" * 64,
    ),
)
def test_binary_rejects_noncanonical_or_malformed_artifact_digest(digest: str) -> None:
    with pytest.raises(ValidationError):
        application_binary_surface_locator(artifact_sha256=digest)


def test_configuration_is_content_bound_to_exact_binary_lineage() -> None:
    configuration = application_configuration_surface_locator(
        parent=_binary(),
        configuration_namespace="PAJIN.APP",
        configuration_id="Production",
        artifact_sha256="2" * 64,
    )
    other_configuration = _configuration(_binary("9" * 64))

    assert configuration.configuration_namespace == "pajin.app"
    assert configuration.configuration_id == "production"
    assert configuration.parent == _binary()
    assert configuration.artifact_sha256 == "2" * 64
    assert (
        typed_application_artifact_runtime_surface(locator=configuration).surface_id
        != typed_application_artifact_runtime_surface(locator=other_configuration).surface_id
    )

    payload = configuration.model_dump(mode="json", by_alias=True)
    payload["rawValue"] = "debug=true"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ApplicationConfigurationSurfaceLocator.model_validate(payload)

    payload = configuration.model_dump(mode="json", by_alias=True)
    payload["configurationId"] = "file:pajin.toml"
    with pytest.raises(ValidationError):
        ApplicationConfigurationSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    "coordinate",
    (
        " latest ",
        "latest",
        "current",
        "pajin/config",
        "C:\\pajin\\config.toml",
        "https://config.example.test/app",
        "pajin?environment=production",
        "pajin#production",
        "pajin*",
    ),
)
def test_configuration_rejects_mutable_path_url_or_wildcard_coordinates(
    coordinate: str,
) -> None:
    payload = _configuration().model_dump(mode="json", by_alias=True)
    payload["configurationId"] = coordinate

    with pytest.raises(ValidationError):
        ApplicationConfigurationSurfaceLocator.model_validate(payload)


def test_runtime_is_a_declared_artifact_coordinate_not_live_process_state() -> None:
    runtime = application_runtime_surface_locator(
        parent=_binary(),
        runtime_family="Python",
        runtime_version="3.12.7-RC.1",
        artifact_sha256="3" * 64,
    )

    assert runtime.parent == _binary()
    assert runtime.runtime_family == "python"
    assert runtime.runtime_version == "3.12.7-rc.1"
    assert runtime.artifact_sha256 == "3" * 64
    assert {
        "pid",
        "process_id",
        "executable_path",
        "environment",
        "running",
    }.isdisjoint(ApplicationRuntimeSurfaceLocator.model_fields)

    payload = runtime.model_dump(mode="json", by_alias=True)
    payload["processId"] = 1234
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ApplicationRuntimeSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    "version",
    (
        "latest",
        "stable",
        "3",
        "3.latest",
        "3.x",
        "3.12.*",
        "^3.12",
        ">=3.12",
        " 3.12.7",
        "3.12.7 ",
        "v3.12.7",
        "3/12/7",
    ),
)
def test_runtime_rejects_floating_range_or_noncanonical_versions(version: str) -> None:
    payload = _runtime().model_dump(mode="json", by_alias=True)
    payload["runtimeVersion"] = version

    with pytest.raises(ValidationError):
        ApplicationRuntimeSurfaceLocator.model_validate(payload)


def test_library_accepts_binary_or_runtime_parent_with_exact_lineage() -> None:
    binary_library = _library(_binary())
    runtime_library = _library(_runtime())
    other_runtime_library = _library(_runtime(_binary("9" * 64)))

    assert isinstance(binary_library.parent, ApplicationBinarySurfaceLocator)
    assert isinstance(runtime_library.parent, ApplicationRuntimeSurfaceLocator)
    assert runtime_library.library_namespace == "pypi"
    assert runtime_library.library_id == "pydantic"
    assert runtime_library.library_version == "2.11.7"
    assert runtime_library.artifact_sha256 == "4" * 64
    assert (
        len(
            {
                typed_application_artifact_runtime_surface(locator=binary_library).surface_id,
                typed_application_artifact_runtime_surface(locator=runtime_library).surface_id,
                typed_application_artifact_runtime_surface(
                    locator=other_runtime_library
                ).surface_id,
            }
        )
        == 3
    )


@pytest.mark.parametrize(
    "version",
    (
        "latest",
        "2",
        "2.x",
        "2.11.*",
        "~2.11",
        ">=2.11",
        "2.11 || 3.0",
    ),
)
def test_library_rejects_floating_or_range_versions(version: str) -> None:
    payload = _library().model_dump(mode="json", by_alias=True)
    payload["libraryVersion"] = version

    with pytest.raises(ValidationError):
        ApplicationLibrarySurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("libraryNamespace", "https://pypi.org"),
        ("libraryNamespace", "current"),
        ("libraryId", "pypi/pydantic"),
        ("libraryId", "pydantic?download=1"),
        ("libraryId", "pydantic*"),
    ),
)
def test_library_rejects_repository_path_or_mutable_coordinates(
    field: str,
    value: str,
) -> None:
    payload = _library().model_dump(mode="json", by_alias=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        ApplicationLibrarySurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("locator", "expected_class"),
    tuple(zip(_locators(), tuple(ApplicationSurfaceClass), strict=True)),
)
def test_each_locator_becomes_a_stable_inert_typed_application_surface(
    locator: ApplicationArtifactRuntimeSurfaceLocator,
    expected_class: ApplicationSurfaceClass,
) -> None:
    surface = typed_application_artifact_runtime_surface(locator=locator)

    assert surface.locator == locator
    assert surface.locator is not locator
    assert surface.surface_class is expected_class
    assert surface.initial_state == "registered-not-authorized"
    assert surface.typed_surface_only is True
    assert surface.surface_id == (f"application-artifact-runtime-surface_{surface.surface_digest}")
    assert surface.reference() == ApplicationArtifactRuntimeSurfaceRef(
        surfaceId=surface.surface_id,
        surfaceDigest=surface.surface_digest,
        surfaceType=surface.surface_type,
        locatorSchema=surface.locator_schema,
        surfaceClass=expected_class,
        locatorKind=locator.kind,
        locatorRegistry=surface.locator_registry,
    )
    assert (
        ApplicationArtifactRuntimeSurface.model_validate(
            surface.model_dump(mode="json", by_alias=True)
        )
        == surface
    )
    assert (
        _APPLICATION_LOCATOR_ADAPTER.validate_python(locator.model_dump(mode="json", by_alias=True))
        == locator
    )


def test_application_models_do_not_change_discovery_or_attack_surface_wire() -> None:
    registry = registered_application_artifact_runtime_locator_registry()

    assert registry.discovery_wire_changed is False
    assert registry.attack_surface_wire_changed is False
    assert registry.domain_semantics_registry_changed is False
    assert "application-binary" not in str(SurfaceLocator)
    assert "domain_classification" not in ApplicationBinarySurfaceLocator.model_fields
    assert "surface_type" not in AttackSurface.model_fields
    assert "locator_schema" not in AttackSurface.model_fields

    with pytest.raises(ValidationError):
        _DISCOVERY_LOCATOR_ADAPTER.validate_python(_binary().model_dump(mode="json", by_alias=True))


def test_registry_and_surface_carry_explicit_non_authority_markers() -> None:
    registry_payload = registered_application_artifact_runtime_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    surface_payload = typed_application_artifact_runtime_surface(locator=_library()).model_dump(
        mode="json", by_alias=True
    )

    assert all(registry_payload[alias] is False for alias in _REGISTRY_FALSE_ALIASES)
    assert all(surface_payload[alias] is False for alias in _SURFACE_FALSE_ALIASES)
    assert {
        "campaign_profile",
        "scope_authority",
        "capability",
        "approval",
        "permit",
        "sandbox",
        "worker",
        "request",
        "observation",
        "evidence",
        "credential",
        "secret",
        "artifact_content",
        "process_state",
        "network",
        "debugger",
    }.isdisjoint(ApplicationArtifactRuntimeSurface.model_fields)


@pytest.mark.parametrize(
    ("path", "value", "match"),
    (
        (("locators", 0, "surfaceClass"), "runtime", "code authority"),
        (("locators", 0, "sourceModelId"), "pajin.fake.Binary", "code authority"),
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
        registered_application_artifact_runtime_locator_registry().model_dump(
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
        ApplicationArtifactRuntimeLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
def test_registry_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_application_artifact_runtime_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        ApplicationArtifactRuntimeLocatorRegistry.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        ApplicationArtifactRuntimeLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
def test_typed_surface_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
) -> None:
    payload = typed_application_artifact_runtime_surface(locator=_library()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        ApplicationArtifactRuntimeSurface.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        ApplicationArtifactRuntimeSurface.model_validate(payload)


def test_typed_surface_rejects_registry_domain_identity_digest_and_authority_injection() -> None:
    original = typed_application_artifact_runtime_surface(locator=_library()).model_dump(
        mode="json",
        by_alias=True,
    )
    mutations = (
        ("locatorRegistry", "registryDigest", "0" * 64),
        ("domainClassification", "domain", "web"),
        (None, "surfaceClass", "binary"),
        (None, "surfaceDigest", "0" * 64),
        (None, "surfaceId", "application-artifact-runtime-surface_" + "0" * 64),
        (None, "artifactPath", "C:\\apps\\pajin.exe"),
        (None, "credential", {"token": "redacted"}),
        (None, "analysisRequest", {"engine": "static"}),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            ApplicationArtifactRuntimeSurface.model_validate(payload)


def test_locator_definition_rejects_boolean_coercion_and_execution_mapping() -> None:
    definition = registered_application_artifact_runtime_locator_registry().locators[0]
    payload = definition.model_dump(mode="json", by_alias=True)
    payload["artifactDigestRequired"] = 1
    with pytest.raises(ValidationError, match="must be booleans"):
        RegisteredApplicationArtifactRuntimeLocator.model_validate(payload)

    payload = definition.model_dump(mode="json", by_alias=True)
    payload["sandboxId"] = "application-static-analysis"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredApplicationArtifactRuntimeLocator.model_validate(payload)


@pytest.mark.parametrize("locator", _locators())
@pytest.mark.parametrize("alias", _LOCATOR_SECURITY_ALIASES)
def test_locators_reject_security_marker_escalation_and_secret_field_injection(
    locator: ApplicationArtifactRuntimeSurfaceLocator,
    alias: str,
) -> None:
    payload = locator.model_dump(mode="json", by_alias=True)
    payload[alias] = True
    with pytest.raises(ValidationError):
        _APPLICATION_LOCATOR_ADAPTER.validate_python(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be boolean false"):
        _APPLICATION_LOCATOR_ADAPTER.validate_python(payload)

    payload = locator.model_dump(mode="json", by_alias=True)
    payload["password"] = "redacted"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _APPLICATION_LOCATOR_ADAPTER.validate_python(payload)
