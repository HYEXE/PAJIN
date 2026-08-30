from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_SCHEMA,
    CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_TYPE,
    AttackSurface,
    CryptographicCiphertextSurfaceLocator,
    CryptographicConfigurationSurfaceLocator,
    CryptographicKeyUsageKind,
    CryptographicKeyUsageSurfaceLocator,
    CryptographicProtocolSurfaceLocator,
    CryptographyProtocolKeyArtifactLocatorRegistry,
    CryptographyProtocolKeyArtifactSurface,
    CryptographyProtocolKeyArtifactSurfaceLocator,
    CryptographyProtocolKeyArtifactSurfaceRef,
    CryptographySurfaceClass,
    CryptographySurfaceRegistryError,
    RegisteredCryptographyProtocolKeyArtifactLocator,
    SurfaceLocator,
    cryptographic_ciphertext_surface_locator,
    cryptographic_configuration_surface_locator,
    cryptographic_key_usage_surface_locator,
    cryptographic_protocol_surface_locator,
    registered_cryptography_protocol_key_artifact_locator_registry,
    resolve_cryptography_protocol_key_artifact_locator_registry,
    resolve_registered_cryptography_protocol_key_artifact_locator,
    typed_cryptography_protocol_key_artifact_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_CRYPTOGRAPHY_LOCATOR_ADAPTER: TypeAdapter[CryptographyProtocolKeyArtifactSurfaceLocator] = (
    TypeAdapter(CryptographyProtocolKeyArtifactSurfaceLocator)
)
_DISCOVERY_LOCATOR_ADAPTER: TypeAdapter[SurfaceLocator] = TypeAdapter(SurfaceLocator)

_AUTHORITY_FALSE_ALIASES = (
    "artifactResolutionAuthorized",
    "artifactReadAuthorized",
    "offlineAnalysisAuthorized",
    "keyMaterialAccessAuthorized",
    "keyUseAuthorized",
    "cryptographicOperationAuthorized",
    "protocolNegotiationAuthorized",
    "oracleInvocationAuthorized",
    "recomputationAuthorized",
    "credentialAccessAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "graphAdmissionAuthorized",
    "findingAuthority",
    "artifactMutationAuthorized",
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
    "protocolDeclarationVerified",
    "keyUsageDeclarationVerified",
    "ciphertextResolved",
    "ciphertextBytesVerified",
    "configurationDeclarationVerified",
    "declarationSanitizationVerified",
    "algorithmVerified",
    "keyIdentityVerified",
    "misuseConfirmed",
    "evidenceSealed",
    "graphAdmitted",
    *_AUTHORITY_FALSE_ALIASES,
)
_LOCATOR_SECURITY_ALIASES = (
    "rawKeyMaterialEmbedded",
    "keyReferenceEmbedded",
    "rawCiphertextEmbedded",
    "rawPlaintextEmbedded",
    "rawConfigurationEmbedded",
    "rawParameterMaterialEmbedded",
    "secretMaterialEmbedded",
    "credentialReferenceEmbedded",
    "mutablePathEmbedded",
    "oracleResultEmbedded",
)


def _protocol(digest: str = "1" * 64) -> CryptographicProtocolSurfaceLocator:
    return cryptographic_protocol_surface_locator(
        protocol_namespace="ietf",
        protocol_id="tls-1.3",
        declaration_sha256=digest,
    )


def _key_usage(
    parent: CryptographicProtocolSurfaceLocator | None = None,
) -> CryptographicKeyUsageSurfaceLocator:
    return cryptographic_key_usage_surface_locator(
        parent=parent or _protocol(),
        usage_kind=CryptographicKeyUsageKind.ENCRYPTION,
        declaration_sha256="2" * 64,
    )


def _ciphertext(
    parent: CryptographicProtocolSurfaceLocator | None = None,
) -> CryptographicCiphertextSurfaceLocator:
    return cryptographic_ciphertext_surface_locator(
        parent=parent or _protocol(),
        artifact_sha256="3" * 64,
    )


def _configuration(
    parent: CryptographicProtocolSurfaceLocator | None = None,
) -> CryptographicConfigurationSurfaceLocator:
    return cryptographic_configuration_surface_locator(
        parent=parent or _protocol(),
        configuration_namespace="transport-security",
        configuration_id="primary-profile",
        declaration_sha256="4" * 64,
    )


def _locators() -> tuple[CryptographyProtocolKeyArtifactSurfaceLocator, ...]:
    return (_protocol(), _key_usage(), _ciphertext(), _configuration())


def _set_nested_value(
    payload: dict[str, object],
    path: tuple[str, ...],
    value: object,
) -> None:
    target = payload
    for component in path[:-1]:
        child = target[component]
        if not isinstance(child, dict):
            raise AssertionError("invalid test mutation path")
        target = child
    target[path[-1]] = value


def test_registry_binds_exact_cryptography_semantics_and_four_locator_classes() -> None:
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    cryptography_domain = next(
        item for item in taxonomy.domains if item.domain is SecurityDomain.CRYPTOGRAPHY
    )
    cryptography_semantics = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    )

    assert registry.surface_type == CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_TYPE
    assert registry.locator_schema == CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_SCHEMA
    assert registry.domain_classification == cryptography_domain.reference()
    assert registry.domain_graph_type_set == cryptography_semantics.reference()
    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert tuple(item.surface_class for item in registry.locators) == tuple(
        CryptographySurfaceClass
    )
    assert tuple(item.locator_kind for item in registry.locators) == (
        "cryptography-protocol",
        "cryptography-key-usage",
        "cryptography-ciphertext",
        "cryptography-configuration",
    )
    assert tuple(item.parent_requirement for item in registry.locators) == (
        "none",
        "cryptography-protocol",
        "cryptography-protocol",
        "cryptography-protocol",
    )
    assert tuple(item.declaration_digest_required for item in registry.locators) == (
        True,
        True,
        False,
        True,
    )
    assert tuple(item.artifact_digest_required for item in registry.locators) == (
        False,
        False,
        True,
        False,
    )
    assert all(not item.declaration_sanitization_verified for item in registry.locators)
    assert len(registry.registry_digest) == 64
    assert registry.registry_digest == (
        registered_cryptography_protocol_key_artifact_locator_registry().registry_digest
    )


def test_locator_and_registry_resolution_require_exact_content_references() -> None:
    registry = registered_cryptography_protocol_key_artifact_locator_registry()

    for locator in registry.locators:
        resolved = resolve_registered_cryptography_protocol_key_artifact_locator(
            locator.reference()
        )
        assert resolved == locator
        assert resolved is not locator

    resolved_registry = resolve_cryptography_protocol_key_artifact_locator_registry(
        registry.reference()
    )
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_resolution_rejects_forged_reference_state() -> None:
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    locator_reference = (
        registry.locators[0].reference().model_copy(update={"locator_digest": "0" * 64})
    )
    registry_reference = registry.reference().model_copy(update={"registry_digest": "0" * 64})

    with pytest.raises(CryptographySurfaceRegistryError):
        resolve_registered_cryptography_protocol_key_artifact_locator(locator_reference)
    with pytest.raises(CryptographySurfaceRegistryError):
        resolve_cryptography_protocol_key_artifact_locator_registry(registry_reference)


def test_protocol_coordinates_are_canonical_stable_and_content_bound() -> None:
    locator = cryptographic_protocol_surface_locator(
        protocol_namespace="IETF",
        protocol_id="TLS-1.3",
        declaration_sha256="1" * 64,
    )
    changed = _protocol("9" * 64)

    assert locator.protocol_namespace == "ietf"
    assert locator.protocol_id == "tls-1.3"
    assert locator.declaration_sha256 == "1" * 64
    assert (
        typed_cryptography_protocol_key_artifact_surface(locator=locator).surface_digest
        != typed_cryptography_protocol_key_artifact_surface(locator=changed).surface_digest
    )


@pytest.mark.parametrize(
    "coordinate",
    (
        "latest",
        "tls.latest",
        "tls/*",
        "../tls",
        "https://example.test/tls",
        "tls?version=1",
        "tls#profile",
        "tls@host",
        " tls",
        "tls\n",
        "tls%2fprofile",
        "IETF\u212a",
        "IETF\u017f",
        "IETF\u00df",
        "tls.",
        "tls..1",
        "tls--1",
        "ietf+",
    ),
)
def test_protocol_rejects_mutable_or_operational_coordinates(coordinate: str) -> None:
    with pytest.raises(ValidationError):
        cryptographic_protocol_surface_locator(
            protocol_namespace=coordinate,
            protocol_id="tls-1.3",
            declaration_sha256="1" * 64,
        )


@pytest.mark.parametrize("digest", ("A" * 64, "1" * 63, "g" * 64))
def test_all_content_digests_require_canonical_lowercase_sha256(digest: str) -> None:
    with pytest.raises(ValidationError):
        cryptographic_protocol_surface_locator(
            protocol_namespace="ietf",
            protocol_id="tls-1.3",
            declaration_sha256=digest,
        )
    with pytest.raises(ValidationError):
        cryptographic_ciphertext_surface_locator(
            parent=_protocol(),
            artifact_sha256=digest,
        )
    with pytest.raises(ValidationError):
        cryptographic_key_usage_surface_locator(
            parent=_protocol(),
            usage_kind=CryptographicKeyUsageKind.ENCRYPTION,
            declaration_sha256=digest,
        )
    with pytest.raises(ValidationError):
        cryptographic_configuration_surface_locator(
            parent=_protocol(),
            configuration_namespace="transport-security",
            configuration_id="primary-profile",
            declaration_sha256=digest,
        )


def test_key_usage_is_a_declaration_without_key_identity_or_use_authority() -> None:
    locator = _key_usage()
    payload = locator.model_dump(mode="json", by_alias=True)

    assert locator.parent == _protocol()
    assert locator.usage_kind is CryptographicKeyUsageKind.ENCRYPTION
    assert "usageId" not in payload
    assert not any(
        token in key.casefold()
        for key in payload
        for token in ("fingerprint", "privatekey", "publickey", "kms", "pkcs11")
    )
    assert "keyUseAuthorized" not in payload


@pytest.mark.parametrize(
    "field,value",
    (
        ("rawKey", "secret"),
        ("privateKey", "secret"),
        ("publicKey", "public-material"),
        ("keyFingerprint", "a" * 64),
        ("keyId", "production-key"),
        ("keyAlias", "primary"),
        ("kmsArn", "arn:example:kms:key/1"),
        ("pkcs11Uri", "pkcs11:object=key"),
        ("credentialLease", "lease-1"),
    ),
)
def test_key_usage_rejects_key_material_identity_or_credential_fields(
    field: str,
    value: str,
) -> None:
    payload = _key_usage().model_dump(mode="json", by_alias=True)
    payload[field] = value
    with pytest.raises(ValidationError):
        CryptographicKeyUsageSurfaceLocator.model_validate(payload)


def test_ciphertext_is_digest_only_without_bytes_plaintext_or_key_association() -> None:
    locator = _ciphertext()
    payload = locator.model_dump(mode="json", by_alias=True)

    assert locator.parent == _protocol()
    assert locator.artifact_sha256 == "3" * 64
    assert set(payload) == {
        "rawKeyMaterialEmbedded",
        "keyReferenceEmbedded",
        "rawCiphertextEmbedded",
        "rawPlaintextEmbedded",
        "rawConfigurationEmbedded",
        "rawParameterMaterialEmbedded",
        "secretMaterialEmbedded",
        "credentialReferenceEmbedded",
        "mutablePathEmbedded",
        "oracleResultEmbedded",
        "parent",
        "kind",
        "artifactSha256",
    }


@pytest.mark.parametrize(
    "field,value",
    (
        ("ciphertext", "deadbeef"),
        ("ciphertextHex", "deadbeef"),
        ("ciphertextBase64", "3q2+7w=="),
        ("plaintext", "secret"),
        ("plaintextSha256", "a" * 64),
        ("nonce", "00"),
        ("iv", "00"),
        ("tag", "00"),
        ("aad", "header"),
        ("path", "C:/secret.bin"),
        ("uri", "https://example.test/ciphertext"),
    ),
)
def test_ciphertext_rejects_raw_or_operational_fields(field: str, value: str) -> None:
    payload = _ciphertext().model_dump(mode="json", by_alias=True)
    payload[field] = value
    with pytest.raises(ValidationError):
        CryptographicCiphertextSurfaceLocator.model_validate(payload)


def test_configuration_is_sanitized_and_protocol_parent_bound() -> None:
    locator = cryptographic_configuration_surface_locator(
        parent=_protocol(),
        configuration_namespace="TRANSPORT-SECURITY",
        configuration_id="PRIMARY-PROFILE",
        declaration_sha256="4" * 64,
    )
    assert locator.configuration_namespace == "transport-security"
    assert locator.configuration_id == "primary-profile"
    assert locator.parent == _protocol()


@pytest.mark.parametrize(
    "field,value",
    (
        ("rawConfiguration", {"minimumBits": 128}),
        ("configurationValue", "secret"),
        ("environment", {"KEY": "secret"}),
        ("parameter", "nonce"),
        ("secretReference", "secret-1"),
        ("path", "/etc/crypto.conf"),
        ("endpoint", "https://example.test"),
    ),
)
def test_configuration_rejects_raw_value_path_or_secret_fields(
    field: str,
    value: object,
) -> None:
    payload = _configuration().model_dump(mode="json", by_alias=True)
    payload[field] = value
    with pytest.raises(ValidationError):
        CryptographicConfigurationSurfaceLocator.model_validate(payload)


def test_protocol_parent_substitution_changes_each_child_surface_identity() -> None:
    first_parent = _protocol("1" * 64)
    second_parent = _protocol("9" * 64)
    first_children: tuple[CryptographyProtocolKeyArtifactSurfaceLocator, ...] = (
        _key_usage(first_parent),
        _ciphertext(first_parent),
        _configuration(first_parent),
    )
    second_children: tuple[CryptographyProtocolKeyArtifactSurfaceLocator, ...] = (
        _key_usage(second_parent),
        _ciphertext(second_parent),
        _configuration(second_parent),
    )

    for first, second in zip(first_children, second_children, strict=True):
        assert (
            typed_cryptography_protocol_key_artifact_surface(locator=first).surface_digest
            != typed_cryptography_protocol_key_artifact_surface(locator=second).surface_digest
        )


@pytest.mark.parametrize("locator", _locators())
def test_each_locator_becomes_a_stable_inert_typed_cryptography_surface(
    locator: CryptographyProtocolKeyArtifactSurfaceLocator,
) -> None:
    first = typed_cryptography_protocol_key_artifact_surface(locator=locator)
    second = typed_cryptography_protocol_key_artifact_surface(locator=locator)
    reference = first.reference()

    assert first == second
    assert first.surface_digest == second.surface_digest
    assert first.surface_id == f"cryptography-protocol-key-artifact-surface_{first.surface_digest}"
    assert first.initial_state == "registered-not-authorized"
    assert reference.surface_id == first.surface_id
    assert reference.surface_digest == first.surface_digest
    assert reference.locator_kind == locator.kind


def test_cryptography_models_do_not_change_legacy_discovery_or_attack_surface_wire() -> None:
    locator = _protocol()
    with pytest.raises(ValidationError):
        _DISCOVERY_LOCATOR_ADAPTER.validate_python(locator.model_dump(mode="json", by_alias=True))

    assert "domainClassification" not in AttackSurface.model_json_schema()["properties"]
    assert "cryptography-protocol" not in str(_DISCOVERY_LOCATOR_ADAPTER.json_schema())


def test_registry_surface_and_locators_carry_explicit_non_authority_markers() -> None:
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    registry_payload = registry.model_dump(mode="json", by_alias=True)

    assert registry_payload["registryOnly"] is True
    assert registry_payload["discoveredSurfaceInitialState"] == "registered-not-authorized"
    for alias in _REGISTRY_FALSE_ALIASES:
        assert registry_payload[alias] is False

    for locator in _locators():
        payload = locator.model_dump(mode="json", by_alias=True)
        for alias in _LOCATOR_SECURITY_ALIASES:
            assert payload[alias] is False

        surface_payload = typed_cryptography_protocol_key_artifact_surface(
            locator=locator
        ).model_dump(mode="json", by_alias=True)
        assert surface_payload["typedSurfaceOnly"] is True
        for alias in _SURFACE_FALSE_ALIASES:
            assert surface_payload[alias] is False


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_registry_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = registered_cryptography_protocol_key_artifact_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    with pytest.raises(ValidationError):
        CryptographyProtocolKeyArtifactLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_surface_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = typed_cryptography_protocol_key_artifact_surface(locator=_protocol()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    with pytest.raises(ValidationError):
        CryptographyProtocolKeyArtifactSurface.model_validate(payload)


@pytest.mark.parametrize("alias", _LOCATOR_SECURITY_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_locators_reject_security_marker_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = _protocol().model_dump(mode="json", by_alias=True)
    payload[alias] = value
    with pytest.raises(ValidationError):
        CryptographicProtocolSurfaceLocator.model_validate(payload)


def test_registry_rejects_order_domain_model_and_digest_drift() -> None:
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    payload = registry.model_dump(mode="json", by_alias=True)

    reordered = deepcopy(payload)
    reordered["locators"] = list(reversed(reordered["locators"]))
    with pytest.raises(ValidationError):
        CryptographyProtocolKeyArtifactLocatorRegistry.model_validate(reordered)

    changed_domain = deepcopy(payload)
    changed_domain["domainClassification"]["domain"] = "application"
    with pytest.raises(ValidationError):
        CryptographyProtocolKeyArtifactLocatorRegistry.model_validate(changed_domain)

    changed_model = deepcopy(payload)
    changed_model["locators"][0]["sourceModelId"] = "pajin.discovery.fake.Model"
    with pytest.raises(ValidationError):
        CryptographyProtocolKeyArtifactLocatorRegistry.model_validate(changed_model)

    changed_digest = deepcopy(payload)
    changed_digest["registryDigest"] = "0" * 64
    with pytest.raises(ValidationError):
        CryptographyProtocolKeyArtifactLocatorRegistry.model_validate(changed_digest)


def test_surface_rejects_identity_class_registry_and_sensitive_field_injection() -> None:
    surface = typed_cryptography_protocol_key_artifact_surface(locator=_protocol())
    payload = surface.model_dump(mode="json", by_alias=True)

    for path, value in (
        (("surfaceId",), "cryptography-protocol-key-artifact-surface_" + "0" * 64),
        (("surfaceDigest",), "0" * 64),
        (("surfaceClass",), "ciphertext"),
        (("locatorRegistry", "registryDigest"), "0" * 64),
        (("domainClassification", "domain"), "application"),
    ):
        changed = deepcopy(payload)
        _set_nested_value(changed, path, value)
        with pytest.raises(ValidationError):
            CryptographyProtocolKeyArtifactSurface.model_validate(changed)

    for field in ("plaintext", "keyMaterial", "credentialReference", "workerJob"):
        changed = deepcopy(payload)
        changed[field] = "forbidden"
        with pytest.raises(ValidationError):
            CryptographyProtocolKeyArtifactSurface.model_validate(changed)


def test_public_boundaries_revalidate_forged_pydantic_instances() -> None:
    forged_parent = _protocol().model_copy(update={"protocol_id": "https://invalid.test"})
    with pytest.raises((ValidationError, ValueError)):
        cryptographic_key_usage_surface_locator(
            parent=forged_parent,
            usage_kind=CryptographicKeyUsageKind.ENCRYPTION,
            declaration_sha256="2" * 64,
        )

    forged_child = _key_usage().model_copy(update={"declaration_sha256": "A" * 64})
    with pytest.raises((ValidationError, ValueError)):
        typed_cryptography_protocol_key_artifact_surface(locator=forged_child)

    forged_surface = typed_cryptography_protocol_key_artifact_surface(
        locator=_protocol()
    ).model_copy(update={"surface_class": CryptographySurfaceClass.CIPHERTEXT})
    with pytest.raises((ValidationError, ValueError)):
        forged_surface.reference()

    forged_registry = registered_cryptography_protocol_key_artifact_locator_registry().model_copy(
        update={
            "locators": tuple(
                reversed(registered_cryptography_protocol_key_artifact_locator_registry().locators)
            )
        }
    )
    with pytest.raises((ValidationError, ValueError)):
        forged_registry.reference()


@pytest.mark.parametrize("forged_parent", ({"kind": "cryptography-protocol"}, 1, None))
def test_public_boundary_rejects_forged_parent_types_with_controlled_error(
    forged_parent: object,
) -> None:
    forged_child = _key_usage().model_copy(update={"parent": forged_parent})

    with pytest.raises(ValueError):
        typed_cryptography_protocol_key_artifact_surface(locator=forged_child)


def test_public_boundaries_reject_unmodeled_instance_state() -> None:
    protocol = _protocol()
    object.__setattr__(protocol, "hidden_key_reference", "forbidden")

    with pytest.raises(ValueError, match="unmodeled instance state"):
        cryptographic_ciphertext_surface_locator(
            parent=protocol,
            artifact_sha256="3" * 64,
        )


def test_surface_reference_revalidates_exact_sources_and_identity() -> None:
    surface = typed_cryptography_protocol_key_artifact_surface(locator=_configuration())
    reference = surface.reference()
    payload = reference.model_dump(mode="json", by_alias=True)

    assert CryptographyProtocolKeyArtifactSurfaceRef.model_validate(payload) == reference

    payload["surfaceId"] = "cryptography-protocol-key-artifact-surface_" + "0" * 64
    with pytest.raises(ValidationError):
        CryptographyProtocolKeyArtifactSurfaceRef.model_validate(payload)


def test_registered_locator_definition_rejects_boolean_coercion_and_execution_mapping() -> None:
    locator = registered_cryptography_protocol_key_artifact_locator_registry().locators[0]
    payload = locator.model_dump(mode="json", by_alias=True)

    for field, value in (
        ("secretFree", 1),
        ("declarationSanitizationVerified", True),
        ("registrationOnly", "true"),
        ("declarationDigestRequired", 1),
        ("executionAuthorized", True),
    ):
        changed = deepcopy(payload)
        changed[field] = value
        with pytest.raises(ValidationError):
            RegisteredCryptographyProtocolKeyArtifactLocator.model_validate(changed)

    payload["capabilityId"] = "pajin.ctf.crypto-single-byte-xor"
    with pytest.raises(ValidationError):
        RegisteredCryptographyProtocolKeyArtifactLocator.model_validate(payload)


def test_crypto_surface_registry_does_not_claim_general_ctf_runtime_reuse() -> None:
    payload = registered_cryptography_protocol_key_artifact_locator_registry().model_dump_json(
        by_alias=True
    )
    assert "single-byte-xor" not in payload
    assert "ctf-crypto" not in payload
    assert "artifact.invalid" not in payload
