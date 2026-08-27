from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import cast

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    MOBILE_APPLICATION_RUNTIME_LOCATOR_SCHEMA,
    MOBILE_APPLICATION_RUNTIME_SURFACE_TYPE,
    AttackSurface,
    MobileAPKSurfaceLocator,
    MobileApplicationRuntimeLocatorRegistry,
    MobileApplicationRuntimeSurface,
    MobileApplicationRuntimeSurfaceLocator,
    MobileApplicationRuntimeSurfaceRef,
    MobileApplicationSurfaceLocator,
    MobileAuthenticationKind,
    MobileAuthenticationSurfaceLocator,
    MobileDeepLinkKind,
    MobileDeepLinkSurfaceLocator,
    MobileIPASurfaceLocator,
    MobilePlatform,
    MobileRuntimeDeclarationKind,
    MobileRuntimeSurfaceLocator,
    MobileStorageKind,
    MobileStorageSurfaceLocator,
    MobileSurfaceClass,
    MobileSurfaceRegistryError,
    MobileTLSPolicyKind,
    MobileTLSPolicySurfaceLocator,
    RegisteredMobileApplicationRuntimeLocator,
    SurfaceLocator,
    mobile_apk_surface_locator,
    mobile_application_surface_locator,
    mobile_authentication_surface_locator,
    mobile_deep_link_surface_locator,
    mobile_ipa_surface_locator,
    mobile_runtime_surface_locator,
    mobile_storage_surface_locator,
    mobile_tls_policy_surface_locator,
    registered_mobile_application_runtime_locator_registry,
    resolve_mobile_application_runtime_locator_registry,
    resolve_registered_mobile_application_runtime_locator,
    typed_mobile_application_runtime_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_MOBILE_LOCATOR_ADAPTER: TypeAdapter[MobileApplicationRuntimeSurfaceLocator] = TypeAdapter(
    MobileApplicationRuntimeSurfaceLocator
)
_DISCOVERY_LOCATOR_ADAPTER: TypeAdapter[SurfaceLocator] = TypeAdapter(SurfaceLocator)

_AUTHORITY_FALSE_ALIASES = (
    "artifactResolutionAuthorized",
    "packageReadAuthorized",
    "staticAnalysisAuthorized",
    "sandboxSelectionAuthorized",
    "emulatorSelectionAuthorized",
    "deviceSelectionAuthorized",
    "deviceAccessAuthorized",
    "instrumentationAuthorized",
    "dynamicAnalysisAuthorized",
    "networkAccessAuthorized",
    "tlsValidationAuthorized",
    "authenticationInvocationAuthorized",
    "credentialAccessAuthorized",
    "storageReadAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "graphAdmissionAuthorized",
    "findingAuthority",
    "packageMutationAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "attackSurfaceWireChanged",
    "domainSemanticsRegistryChanged",
    *_AUTHORITY_FALSE_ALIASES,
)
_SURFACE_FALSE_ALIASES = (
    "discoveryObserved",
    "packageResolved",
    "packageBytesVerified",
    "packageFormatVerified",
    "manifestVerified",
    "applicationIdentityVerified",
    "signingIdentityVerified",
    "runtimeDeclarationVerified",
    "storageDeclarationVerified",
    "deepLinkDeclarationVerified",
    "tlsPolicyVerified",
    "authenticationFlowVerified",
    "deviceIdentityVerified",
    "emulatorIdentityVerified",
    "appInstalled",
    "vulnerabilityConfirmed",
    "evidenceSealed",
    "graphAdmitted",
    *_AUTHORITY_FALSE_ALIASES,
)
_LOCATOR_SECURITY_ALIASES = (
    "packageBytesEmbedded",
    "manifestEmbedded",
    "signingMaterialEmbedded",
    "rawSecurityConfigurationEmbedded",
    "secretMaterialEmbedded",
    "credentialReferenceEmbedded",
    "deviceStateEmbedded",
    "deviceLocalPathEmbedded",
)


def _apk(digest: str = "1" * 64) -> MobileAPKSurfaceLocator:
    return mobile_apk_surface_locator(artifact_sha256=digest)


def _ipa(digest: str = "2" * 64) -> MobileIPASurfaceLocator:
    return mobile_ipa_surface_locator(artifact_sha256=digest)


def _android_app(
    parent: MobileAPKSurfaceLocator | None = None,
) -> MobileApplicationSurfaceLocator:
    return mobile_application_surface_locator(
        parent=parent or _apk(),
        application_id="dev.pajin.mobile",
    )


def _ios_app(
    parent: MobileIPASurfaceLocator | None = None,
) -> MobileApplicationSurfaceLocator:
    return mobile_application_surface_locator(
        parent=parent or _ipa(),
        application_id="dev.pajin.mobile-ios",
    )


def _runtime(
    parent: MobileApplicationSurfaceLocator | None = None,
) -> MobileRuntimeSurfaceLocator:
    return mobile_runtime_surface_locator(
        parent=parent or _android_app(),
        runtime_family=MobilePlatform.ANDROID,
        declaration_kind=MobileRuntimeDeclarationKind.TARGET,
        runtime_version="34",
    )


def _storage(
    parent: MobileApplicationSurfaceLocator | None = None,
) -> MobileStorageSurfaceLocator:
    return mobile_storage_surface_locator(
        parent=parent or _android_app(),
        storage_kind=MobileStorageKind.PREFERENCES,
        storage_id="session-cache",
        declaration_sha256="3" * 64,
    )


def _deeplink(
    parent: MobileApplicationSurfaceLocator | None = None,
) -> MobileDeepLinkSurfaceLocator:
    return mobile_deep_link_surface_locator(
        parent=parent or _android_app(),
        link_kind=MobileDeepLinkKind.ANDROID_APP_LINK,
        scheme="https",
        host="app.example.test",
        route_id="account-view",
        declaration_sha256="4" * 64,
    )


def _tls(
    parent: MobileApplicationSurfaceLocator | None = None,
) -> MobileTLSPolicySurfaceLocator:
    return mobile_tls_policy_surface_locator(
        parent=parent or _android_app(),
        policy_kind=MobileTLSPolicyKind.ANDROID_NETWORK_SECURITY_CONFIG,
        policy_id="primary-network-policy",
        declaration_sha256="5" * 64,
    )


def _auth(
    parent: MobileApplicationSurfaceLocator | None = None,
) -> MobileAuthenticationSurfaceLocator:
    return mobile_authentication_surface_locator(
        parent=parent or _android_app(),
        authentication_kind=MobileAuthenticationKind.FEDERATED,
        flow_id="primary-login",
        declaration_sha256="6" * 64,
    )


def _locators() -> tuple[MobileApplicationRuntimeSurfaceLocator, ...]:
    return (_apk(), _ipa(), _android_app(), _runtime(), _storage(), _deeplink(), _tls(), _auth())


def _set_nested_value(
    payload: dict[str, object],
    path: tuple[str | int, ...],
    value: object,
) -> None:
    target: object = payload
    for component in path[:-1]:
        if isinstance(component, str) and isinstance(target, dict):  # noqa: SIM114
            target = target[component]
        elif isinstance(component, int) and isinstance(target, list):
            target = target[component]
        else:
            raise AssertionError("invalid test mutation path")
    final = path[-1]
    if isinstance(final, str) and isinstance(target, dict):  # noqa: SIM114
        target[final] = value
    elif isinstance(final, int) and isinstance(target, list):
        target[final] = value
    else:
        raise AssertionError("invalid test mutation target")


def test_registry_binds_exact_mobile_semantics_and_eight_locator_classes() -> None:
    registry = registered_mobile_application_runtime_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    mobile_type_set = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.MOBILE
    )

    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert registry.surface_type == MOBILE_APPLICATION_RUNTIME_SURFACE_TYPE
    assert registry.locator_schema == MOBILE_APPLICATION_RUNTIME_LOCATOR_SCHEMA
    assert registry.domain_classification.domain is SecurityDomain.MOBILE
    assert registry.domain_graph_type_set == mobile_type_set.reference()
    assert mobile_type_set.surface_type == MOBILE_APPLICATION_RUNTIME_SURFACE_TYPE
    assert mobile_type_set.locator_schema == MOBILE_APPLICATION_RUNTIME_LOCATOR_SCHEMA
    assert tuple(
        (
            item.surface_class.value,
            item.locator_kind,
            item.parent_requirement,
            item.platform_requirement,
            item.declaration_digest_required,
            item.exact_version_required,
        )
        for item in registry.locators
    ) == (
        ("apk", "mobile-apk-package", "application-binary", "android", False, False),
        ("ipa", "mobile-ipa-package", "application-binary", "ios", False, False),
        ("application", "mobile-application", "mobile-package", "from-parent", False, False),
        ("runtime", "mobile-runtime", "mobile-application", "from-parent", False, True),
        ("storage", "mobile-storage", "mobile-application", "from-parent", True, False),
        ("deeplink", "mobile-deeplink", "mobile-application", "from-parent", True, False),
        ("tls", "mobile-tls-policy", "mobile-application", "from-parent", True, False),
        ("auth", "mobile-authentication", "mobile-application", "from-parent", True, False),
    )
    assert tuple(item.surface_class for item in registry.locators) == tuple(MobileSurfaceClass)
    assert (
        MobileApplicationRuntimeLocatorRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        == registry
    )


def test_exact_locator_and_registry_resolution_require_content_addressed_references() -> None:
    registry = registered_mobile_application_runtime_locator_registry()

    for source in registry.locators:
        resolved = resolve_registered_mobile_application_runtime_locator(source.reference())
        assert resolved == source
        assert resolved is not source

    resolved_registry = resolve_mobile_application_runtime_locator_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry

    with pytest.raises(MobileSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_mobile_application_runtime_locator(
            registry.locators[0].reference().model_copy(update={"locator_digest": "0" * 64})
        )
    with pytest.raises(MobileSurfaceRegistryError, match="not registered exactly"):
        resolve_mobile_application_runtime_locator_registry(
            registry.reference().model_copy(update={"registry_digest": "0" * 64})
        )


def test_apk_and_ipa_reuse_exact_application_binary_without_format_claims() -> None:
    apk = _apk()
    ipa = _ipa()

    assert apk.application_artifact.artifact_sha256 == "1" * 64
    assert ipa.application_artifact.artifact_sha256 == "2" * 64
    assert apk.application_artifact.kind == "application-binary"
    assert ipa.application_artifact.kind == "application-binary"
    assert {
        "path",
        "archive_entry",
        "manifest",
        "signing_certificate",
        "package_format_verified",
    }.isdisjoint(MobileAPKSurfaceLocator.model_fields)

    for digest in ("A" * 64, "1" * 63, "g" * 64, "sha256:" + "1" * 64):
        with pytest.raises(ValidationError):
            mobile_apk_surface_locator(artifact_sha256=digest)


@pytest.mark.parametrize(
    ("factory", "application_id"),
    (
        (_apk, "dev.pajin.mobile-app"),
        (_apk, "dev.1pajin.mobile"),
        (_ipa, "dev.pajin.mobile_ios"),
        (_ipa, "dev..pajin"),
        (_ipa, "dev/pajin/mobile"),
    ),
)
def test_application_id_is_exact_and_platform_grammar_bound(
    factory: Callable[[], MobileAPKSurfaceLocator | MobileIPASurfaceLocator],
    application_id: str,
) -> None:
    with pytest.raises(ValidationError):
        mobile_application_surface_locator(parent=factory(), application_id=application_id)


def test_application_id_accepts_platform_case_rules_and_canonicalizes_ios() -> None:
    android = mobile_application_surface_locator(
        parent=_apk(),
        application_id="Dev.Pajin.Mobile_2",
    )
    ios_upper = mobile_application_surface_locator(
        parent=_ipa(),
        application_id="Dev.Pajin.Mobile-App",
    )
    ios_lower = mobile_application_surface_locator(
        parent=_ipa(),
        application_id="dev.pajin.mobile-app",
    )

    assert android.application_id == "Dev.Pajin.Mobile_2"
    assert ios_upper.application_id == "dev.pajin.mobile-app"
    assert ios_upper == ios_lower
    assert (
        typed_mobile_application_runtime_surface(locator=ios_upper).surface_id
        == typed_mobile_application_runtime_surface(locator=ios_lower).surface_id
    )


def test_parent_lineage_and_platform_substitution_change_surface_identity() -> None:
    android = _android_app()
    other_binary = _android_app(_apk("9" * 64))
    other_app = mobile_application_surface_locator(
        parent=_apk(),
        application_id="dev.pajin.other",
    )
    ios = _ios_app()

    assert (
        typed_mobile_application_runtime_surface(locator=android).surface_id
        != typed_mobile_application_runtime_surface(locator=other_binary).surface_id
    )
    assert (
        typed_mobile_application_runtime_surface(locator=_storage(android)).surface_id
        != typed_mobile_application_runtime_surface(locator=_storage(other_app)).surface_id
    )
    assert (
        typed_mobile_application_runtime_surface(locator=android).surface_id
        != typed_mobile_application_runtime_surface(locator=ios).surface_id
    )

    shared_digest = "a" * 64
    apk_application = mobile_application_surface_locator(
        parent=_apk(shared_digest),
        application_id="dev.pajin.mobile",
    )
    ipa_application = mobile_application_surface_locator(
        parent=_ipa(shared_digest),
        application_id="dev.pajin.mobile",
    )
    assert apk_application.application_id == ipa_application.application_id
    assert (
        typed_mobile_application_runtime_surface(locator=apk_application).surface_id
        != typed_mobile_application_runtime_surface(locator=ipa_application).surface_id
    )


@pytest.mark.parametrize(
    "version",
    (
        "latest",
        "current",
        "default",
        "*",
        "x",
        "17.x",
        "17.alpha",
        "34.foo",
        "17.5-beta",
        "17..5",
        "17.",
        "034",
        "017.05",
        ">=17",
        "^17",
        "~17",
        "v17",
    ),
)
def test_runtime_rejects_floating_range_or_prefixed_versions(version: str) -> None:
    with pytest.raises(ValidationError):
        mobile_runtime_surface_locator(
            parent=_android_app(),
            runtime_family=MobilePlatform.ANDROID,
            declaration_kind=MobileRuntimeDeclarationKind.MINIMUM_SUPPORTED,
            runtime_version=version,
        )


def test_runtime_accepts_android_api_and_ios_version_but_rejects_platform_mismatch() -> None:
    assert _runtime().runtime_version == "34"
    ios_runtime = mobile_runtime_surface_locator(
        parent=_ios_app(),
        runtime_family=MobilePlatform.IOS,
        declaration_kind=MobileRuntimeDeclarationKind.MINIMUM_SUPPORTED,
        runtime_version="17.5",
    )
    assert ios_runtime.runtime_version == "17.5"

    apk_app = _android_app()
    with pytest.raises(ValidationError, match="numeric API level"):
        mobile_runtime_surface_locator(
            parent=apk_app,
            runtime_family=MobilePlatform.ANDROID,
            declaration_kind=MobileRuntimeDeclarationKind.TARGET,
            runtime_version="34.1",
        )
    with pytest.raises(ValidationError, match="package platform"):
        mobile_runtime_surface_locator(
            parent=apk_app,
            runtime_family=MobilePlatform.IOS,
            declaration_kind=MobileRuntimeDeclarationKind.TARGET,
            runtime_version="17.5",
        )
    assert apk_app.parent.kind == "mobile-apk-package"


@pytest.mark.parametrize(
    "storage_id",
    (
        "latest",
        "../preferences",
        "/data/data/dev.pajin.mobile/prefs",
        "C:\\mobile\\prefs",
        "https://storage.example.test",
        "prefs?user=1",
        "prefs#token",
        "prefs*",
    ),
)
def test_storage_rejects_mutable_path_url_and_raw_value_coordinates(storage_id: str) -> None:
    payload = _storage().model_dump(mode="json", by_alias=True)
    payload["storageId"] = storage_id
    with pytest.raises(ValidationError):
        MobileStorageSurfaceLocator.model_validate(payload)

    payload = _storage().model_dump(mode="json", by_alias=True)
    payload["rawValue"] = "session=redacted"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MobileStorageSurfaceLocator.model_validate(payload)


def test_deep_link_canonicalizes_only_scheme_and_host_not_a_full_uri() -> None:
    link = mobile_deep_link_surface_locator(
        parent=_android_app(),
        link_kind=MobileDeepLinkKind.ANDROID_APP_LINK,
        scheme="HTTPS",
        host="Exämple.Test",
        port=8443,
        route_id="Account-View",
        declaration_sha256="4" * 64,
    )

    assert link.scheme == "https"
    assert link.host == "xn--exmple-cua.test"
    assert link.port == 8443
    assert link.route_id == "account-view"
    assert {
        "url",
        "path",
        "path_pattern",
        "query",
        "fragment",
        "userinfo",
    }.isdisjoint(MobileDeepLinkSurfaceLocator.model_fields)


def test_deep_link_uses_nontransitional_idna_and_accepts_one_character_scheme() -> None:
    unicode_host = mobile_deep_link_surface_locator(
        parent=_android_app(),
        link_kind=MobileDeepLinkKind.ANDROID_APP_LINK,
        scheme="https",
        host="faß.de",
        port=None,
        route_id="unicode-host",
        declaration_sha256="4" * 64,
    )
    ascii_host = mobile_deep_link_surface_locator(
        parent=_android_app(),
        link_kind=MobileDeepLinkKind.ANDROID_APP_LINK,
        scheme="https",
        host="fass.de",
        port=None,
        route_id="ascii-host",
        declaration_sha256="4" * 64,
    )
    custom = mobile_deep_link_surface_locator(
        parent=_android_app(),
        link_kind=MobileDeepLinkKind.CUSTOM_SCHEME,
        scheme="x",
        host=None,
        port=None,
        route_id="single-letter-scheme",
        declaration_sha256="4" * 64,
    )

    assert unicode_host.host == "xn--fa-hia.de"
    assert unicode_host.host != ascii_host.host
    assert custom.scheme == "x"


@pytest.mark.parametrize(
    "host",
    ("xn--a.com", "xn--abc.com", "\u200dexample.com", "\U0001f600.com"),
)
def test_deep_link_rejects_malformed_or_disallowed_idna(host: str) -> None:
    payload = _deeplink().model_dump(mode="json", by_alias=True)
    payload["host"] = host
    with pytest.raises(ValidationError, match="valid IDNA"):
        MobileDeepLinkSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("scheme", "https://app.example.test"),
        ("scheme", "https:"),
        ("host", "user@app.example.test"),
        ("host", "app.example.test?token=redacted"),
        ("host", "*.example.test"),
        ("host", "app.example.test%2fadmin"),
        ("routeId", "../admin"),
        ("routeId", "account?token=redacted"),
        ("routeId", "account#fragment"),
    ),
)
def test_deep_link_rejects_uri_smuggling(field: str, value: str) -> None:
    payload = _deeplink().model_dump(mode="json", by_alias=True)
    payload[field] = value
    with pytest.raises(ValidationError):
        MobileDeepLinkSurfaceLocator.model_validate(payload)


def test_deep_link_kind_and_tls_policy_are_package_platform_bound() -> None:
    with pytest.raises(ValidationError, match="package platform"):
        mobile_deep_link_surface_locator(
            parent=_ios_app(),
            link_kind=MobileDeepLinkKind.ANDROID_APP_LINK,
            scheme="https",
            host="app.example.test",
            route_id="account-view",
            declaration_sha256="4" * 64,
        )
    with pytest.raises(ValidationError, match="package platform"):
        mobile_tls_policy_surface_locator(
            parent=_android_app(),
            policy_kind=MobileTLSPolicyKind.IOS_APP_TRANSPORT_SECURITY,
            policy_id="ats-primary",
            declaration_sha256="5" * 64,
        )
    with pytest.raises(ValidationError, match="require an HTTP scheme"):
        mobile_deep_link_surface_locator(
            parent=_ios_app(),
            link_kind=MobileDeepLinkKind.IOS_UNIVERSAL_LINK,
            scheme="pajin",
            host="app.example.test",
            route_id="account-view",
            declaration_sha256="4" * 64,
        )
    with pytest.raises(ValidationError, match="port requires an exact host"):
        mobile_deep_link_surface_locator(
            parent=_android_app(),
            link_kind=MobileDeepLinkKind.CUSTOM_SCHEME,
            scheme="pajin",
            port=8443,
            route_id="account-view",
            declaration_sha256="4" * 64,
        )


@pytest.mark.parametrize(
    ("model", "locator", "field", "value"),
    (
        (MobileTLSPolicySurfaceLocator, _tls(), "certificate", "redacted"),
        (MobileTLSPolicySurfaceLocator, _tls(), "privateKey", "redacted"),
        (MobileTLSPolicySurfaceLocator, _tls(), "rawPin", "redacted"),
        (MobileAuthenticationSurfaceLocator, _auth(), "clientSecret", "redacted"),
        (MobileAuthenticationSurfaceLocator, _auth(), "accessToken", "redacted"),
        (MobileAuthenticationSurfaceLocator, _auth(), "redirectUrl", "https://example.test"),
    ),
)
def test_tls_and_authentication_reject_sensitive_or_endpoint_fields(
    model: type[MobileTLSPolicySurfaceLocator] | type[MobileAuthenticationSurfaceLocator],
    locator: MobileTLSPolicySurfaceLocator | MobileAuthenticationSurfaceLocator,
    field: str,
    value: str,
) -> None:
    payload = locator.model_dump(mode="json", by_alias=True)
    payload[field] = value
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model.model_validate(payload)


def test_declaration_digest_rejects_noncanonical_sha256() -> None:
    payload = _storage().model_dump(mode="json", by_alias=True)
    payload["declarationSha256"] = "A" * 64
    with pytest.raises(ValidationError):
        MobileStorageSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("locator", "expected_class"),
    tuple(zip(_locators(), tuple(MobileSurfaceClass), strict=True)),
)
def test_each_locator_becomes_a_stable_inert_typed_mobile_surface(
    locator: MobileApplicationRuntimeSurfaceLocator,
    expected_class: MobileSurfaceClass,
) -> None:
    surface = typed_mobile_application_runtime_surface(locator=locator)

    assert surface.locator == locator
    assert surface.locator is not locator
    assert surface.surface_class is expected_class
    assert surface.initial_state == "registered-not-authorized"
    assert surface.typed_surface_only is True
    assert surface.surface_id == f"mobile-application-runtime-surface_{surface.surface_digest}"
    assert surface.reference() == MobileApplicationRuntimeSurfaceRef(
        surfaceId=surface.surface_id,
        surfaceDigest=surface.surface_digest,
        surfaceType=surface.surface_type,
        locatorSchema=surface.locator_schema,
        surfaceClass=expected_class,
        locatorKind=locator.kind,
        locatorRegistry=surface.locator_registry,
    )
    assert (
        MobileApplicationRuntimeSurface.model_validate(
            surface.model_dump(mode="json", by_alias=True)
        )
        == surface
    )
    assert (
        _MOBILE_LOCATOR_ADAPTER.validate_python(locator.model_dump(mode="json", by_alias=True))
        == locator
    )


def test_mobile_models_do_not_change_discovery_or_attack_surface_wire() -> None:
    registry = registered_mobile_application_runtime_locator_registry()

    assert registry.discovery_wire_changed is False
    assert registry.attack_surface_wire_changed is False
    assert registry.domain_semantics_registry_changed is False
    assert "mobile-apk-package" not in str(SurfaceLocator)
    assert "domain_classification" not in MobileAPKSurfaceLocator.model_fields
    assert "surface_type" not in AttackSurface.model_fields
    assert "locator_schema" not in AttackSurface.model_fields

    for locator in _locators():
        with pytest.raises(ValidationError):
            _DISCOVERY_LOCATOR_ADAPTER.validate_python(
                locator.model_dump(mode="json", by_alias=True)
            )


def test_registry_surface_and_locators_carry_explicit_non_authority_markers() -> None:
    registry_payload = registered_mobile_application_runtime_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    surface_payload = typed_mobile_application_runtime_surface(locator=_auth()).model_dump(
        mode="json",
        by_alias=True,
    )

    assert all(registry_payload[alias] is False for alias in _REGISTRY_FALSE_ALIASES)
    assert all(surface_payload[alias] is False for alias in _SURFACE_FALSE_ALIASES)
    for locator in _locators():
        payload = locator.model_dump(mode="json", by_alias=True)
        assert all(payload[alias] is False for alias in _LOCATOR_SECURITY_ALIASES)
    assert {
        "device_id",
        "emulator_id",
        "pid",
        "command",
        "package_path",
        "manifest",
        "credential",
        "secret",
        "certificate",
        "signing_key",
        "request_url",
        "scope",
        "capability",
        "approval",
        "permit",
        "worker",
        "observation",
        "evidence",
    }.isdisjoint(MobileApplicationRuntimeSurface.model_fields)


@pytest.mark.parametrize(
    ("path", "value", "match"),
    (
        (("locators", 0, "surfaceClass"), "runtime", "code authority"),
        (("locators", 0, "sourceModelId"), "pajin.fake.Mobile", "code authority"),
        (("locators", 0, "locatorDigest"), "0" * 64, "Digest differs"),
        (("locators",), "reverse", "code authority"),
        (("domainClassification", "domain"), "web", "code authority"),
        (("multiDomainGraphSemanticsDigest",), "0" * 64, "code authority"),
        (("registryDigest",), "0" * 64, "Digest differs"),
    ),
)
def test_registry_rejects_class_order_domain_model_and_digest_drift(
    path: tuple[str | int, ...],
    value: str,
    match: str,
) -> None:
    payload = cast(
        dict[str, object],
        deepcopy(
            registered_mobile_application_runtime_locator_registry().model_dump(
                mode="json",
                by_alias=True,
            )
        ),
    )
    if path == ("locators",):
        locators = payload["locators"]
        assert isinstance(locators, list)
        locators.reverse()
    else:
        _set_nested_value(payload, path, value)

    with pytest.raises(ValidationError, match=match):
        MobileApplicationRuntimeLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_registry_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = registered_mobile_application_runtime_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    with pytest.raises(ValidationError):
        MobileApplicationRuntimeLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_surface_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = typed_mobile_application_runtime_surface(locator=_auth()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    with pytest.raises(ValidationError):
        MobileApplicationRuntimeSurface.model_validate(payload)


@pytest.mark.parametrize("locator", _locators())
@pytest.mark.parametrize("alias", _LOCATOR_SECURITY_ALIASES)
def test_locators_reject_security_marker_escalation_and_boolean_coercion(
    locator: MobileApplicationRuntimeSurfaceLocator,
    alias: str,
) -> None:
    payload = locator.model_dump(mode="json", by_alias=True)
    payload[alias] = True
    with pytest.raises(ValidationError):
        _MOBILE_LOCATOR_ADAPTER.validate_python(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be boolean false"):
        _MOBILE_LOCATOR_ADAPTER.validate_python(payload)


def test_public_boundaries_revalidate_forged_pydantic_instances() -> None:
    forged_binary = _apk().application_artifact.model_copy(update={"artifact_sha256": "A" * 64})
    with pytest.raises(ValidationError):
        MobileAPKSurfaceLocator(applicationArtifact=forged_binary)

    forged_package = _apk().model_copy(update={"application_artifact": forged_binary})
    with pytest.raises(ValidationError):
        mobile_application_surface_locator(
            parent=forged_package,
            application_id="dev.pajin.mobile",
        )

    forged_package_extra = _apk().model_copy(update={"device_id": "emulator-01"})
    with pytest.raises(ValueError, match="unmodeled instance state"):
        mobile_application_surface_locator(
            parent=forged_package_extra,
            application_id="dev.pajin.mobile",
        )

    forged_application = _android_app().model_copy(update={"application_id": "../invalid"})
    with pytest.raises(ValidationError):
        mobile_storage_surface_locator(
            parent=forged_application,
            storage_kind=MobileStorageKind.FILE,
            storage_id="primary",
            declaration_sha256="3" * 64,
        )

    forged_runtime = _runtime().model_copy(update={"runtime_version": "latest"})
    with pytest.raises(ValidationError):
        typed_mobile_application_runtime_surface(locator=forged_runtime)

    forged_auth_extra = _auth().model_copy(update={"client_secret": "redacted"})
    with pytest.raises(ValueError, match="unmodeled instance state"):
        typed_mobile_application_runtime_surface(locator=forged_auth_extra)


def test_references_revalidate_sources_and_bind_exact_identity() -> None:
    registry = registered_mobile_application_runtime_locator_registry()
    surface = typed_mobile_application_runtime_surface(locator=_auth())

    forged_registered = registry.locators[-1].model_copy(
        update={"surface_class": MobileSurfaceClass.APK}
    )
    with pytest.raises(ValueError):
        forged_registered.reference()

    forged_registry = registry.model_copy(update={"registry_digest": "0" * 64})
    with pytest.raises(ValueError):
        forged_registry.reference()

    forged_surface = surface.model_copy(update={"surface_class": MobileSurfaceClass.APK})
    with pytest.raises(ValueError):
        forged_surface.reference()

    reference_payload = surface.reference().model_dump(mode="json", by_alias=True)

    digest_mismatch = deepcopy(reference_payload)
    digest_mismatch["surfaceDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="differs from code authority"):
        MobileApplicationRuntimeSurfaceRef.model_validate(digest_mismatch)

    class_mismatch = deepcopy(reference_payload)
    class_mismatch["surfaceClass"] = MobileSurfaceClass.APK.value
    with pytest.raises(ValidationError, match="differs from code authority"):
        MobileApplicationRuntimeSurfaceRef.model_validate(class_mismatch)

    registry_mismatch = deepcopy(reference_payload)
    registry_mismatch["locatorRegistry"]["registryDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="differs from code authority"):
        MobileApplicationRuntimeSurfaceRef.model_validate(registry_mismatch)


def test_surface_rejects_identity_digest_and_sensitive_field_injection() -> None:
    original = typed_mobile_application_runtime_surface(locator=_auth()).model_dump(
        mode="json",
        by_alias=True,
    )
    mutations = (
        ("locatorRegistry", "registryDigest", "0" * 64),
        ("domainClassification", "domain", "web"),
        (None, "surfaceClass", "apk"),
        (None, "surfaceDigest", "0" * 64),
        (None, "surfaceId", "mobile-application-runtime-surface_" + "0" * 64),
        (None, "deviceId", "device-01"),
        (None, "packagePath", "C:\\mobile\\app.apk"),
        (None, "clientSecret", "redacted"),
        (None, "analysisRequest", {"engine": "mobile-static"}),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            MobileApplicationRuntimeSurface.model_validate(payload)


def test_locator_definition_rejects_boolean_coercion_and_execution_mapping() -> None:
    definition = registered_mobile_application_runtime_locator_registry().locators[0]
    payload = definition.model_dump(mode="json", by_alias=True)
    payload["declarationDigestRequired"] = 1
    with pytest.raises(ValidationError, match="must be booleans"):
        RegisteredMobileApplicationRuntimeLocator.model_validate(payload)

    payload = definition.model_dump(mode="json", by_alias=True)
    payload["deviceId"] = "emulator-01"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredMobileApplicationRuntimeLocator.model_validate(payload)
