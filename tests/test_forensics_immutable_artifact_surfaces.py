from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_SCHEMA,
    FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_TYPE,
    AttackSurface,
    ForensicArtifactSurfaceLocator,
    ForensicDiskSurfaceLocator,
    ForensicImmutableArtifactLocatorRegistry,
    ForensicImmutableArtifactSurface,
    ForensicImmutableArtifactSurfaceLocator,
    ForensicImmutableArtifactSurfaceRef,
    ForensicLogSurfaceLocator,
    ForensicMemorySurfaceLocator,
    ForensicSourceProvenanceCoordinate,
    ForensicSourceRootKind,
    ForensicSurfaceClass,
    ForensicSurfaceRegistryError,
    RegisteredForensicImmutableArtifactLocator,
    SurfaceLocator,
    bind_forensic_immutable_artifact_surface_reference,
    forensic_artifact_surface_locator,
    forensic_disk_surface_locator,
    forensic_log_surface_locator,
    forensic_memory_surface_locator,
    forensic_source_provenance_coordinate,
    registered_forensic_immutable_artifact_locator_registry,
    resolve_forensic_immutable_artifact_locator_registry,
    resolve_registered_forensic_immutable_artifact_locator,
    typed_forensic_immutable_artifact_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_FORENSIC_LOCATOR_ADAPTER: TypeAdapter[ForensicImmutableArtifactSurfaceLocator] = TypeAdapter(
    ForensicImmutableArtifactSurfaceLocator
)
_DISCOVERY_LOCATOR_ADAPTER: TypeAdapter[SurfaceLocator] = TypeAdapter(SurfaceLocator)

_AUTHORITY_FALSE_ALIASES = (
    "sourceResolutionAuthorized",
    "sourceAcquisitionAuthorized",
    "sourceReadAuthorized",
    "sourceMountAuthorized",
    "sourceCopyAuthorized",
    "parserSelectionAuthorized",
    "analysisAuthorized",
    "credentialAccessAuthorized",
    "credentialUseAuthorized",
    "lateralMovementAuthorized",
    "evidenceMutationAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "graphAdmissionAuthorized",
    "findingAuthority",
    "executionAuthorized",
)
_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "attackSurfaceWireChanged",
    "domainSemanticsRegistryChanged",
    *_AUTHORITY_FALSE_ALIASES,
)
_SURFACE_FALSE_ALIASES = (
    "sourceResolved",
    "sourceSealVerified",
    "sourceAuthenticityVerified",
    "sourceImmutabilityVerified",
    "sourceArtifactMembershipVerified",
    "chainOfCustodyVerified",
    "artifactDigestVerified",
    "artifactBytesVerified",
    "evidenceClassVerified",
    "provenanceSanitizationVerified",
    "provenancePreserved",
    "sourceFormatVerified",
    "parserResultAvailable",
    "forensicHypothesisCreated",
    "evidenceSealed",
    "graphAdmitted",
    *_AUTHORITY_FALSE_ALIASES,
)
_PROVENANCE_SECURITY_ALIASES = (
    "rawSourceBytesEmbedded",
    "rawDiskContentEmbedded",
    "rawMemoryContentEmbedded",
    "rawLogContentEmbedded",
    "rawArtifactContentEmbedded",
    "rawProvenanceRecordEmbedded",
    "mutablePathEmbedded",
    "sourceUriEmbedded",
    "secretMaterialEmbedded",
    "credentialMaterialEmbedded",
    "credentialReferenceEmbedded",
    "parserOutputEmbedded",
)


def _provenance(
    *,
    source_root_sha256: str = "1" * 64,
    source_artifact_record_sha256: str = "2" * 64,
    provenance_record_sha256: str = "3" * 64,
    artifact_sha256: str = "4" * 64,
    artifact_bytes: int = 0,
) -> ForensicSourceProvenanceCoordinate:
    return forensic_source_provenance_coordinate(
        source_root_kind=ForensicSourceRootKind.PAJIN_RUN_INTEGRITY_V1,
        source_root_sha256=source_root_sha256,
        source_artifact_record_sha256=source_artifact_record_sha256,
        provenance_record_sha256=provenance_record_sha256,
        artifact_sha256=artifact_sha256,
        artifact_bytes=artifact_bytes,
    )


def _disk(
    provenance: ForensicSourceProvenanceCoordinate | None = None,
) -> ForensicDiskSurfaceLocator:
    return forensic_disk_surface_locator(provenance=provenance or _provenance())


def _memory(
    provenance: ForensicSourceProvenanceCoordinate | None = None,
) -> ForensicMemorySurfaceLocator:
    return forensic_memory_surface_locator(provenance=provenance or _provenance())


def _log(
    provenance: ForensicSourceProvenanceCoordinate | None = None,
) -> ForensicLogSurfaceLocator:
    return forensic_log_surface_locator(provenance=provenance or _provenance())


def _artifact(
    provenance: ForensicSourceProvenanceCoordinate | None = None,
) -> ForensicArtifactSurfaceLocator:
    return forensic_artifact_surface_locator(provenance=provenance or _provenance())


def _locators() -> tuple[ForensicImmutableArtifactSurfaceLocator, ...]:
    return (_disk(), _memory(), _log(), _artifact())


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


def test_registry_binds_exact_forensics_semantics_and_four_sibling_classes() -> None:
    registry = registered_forensic_immutable_artifact_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    forensics_domain = next(
        item for item in taxonomy.domains if item.domain is SecurityDomain.FORENSICS
    )
    forensics_semantics = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.FORENSICS
    )

    assert registry.surface_type == FORENSICS_IMMUTABLE_ARTIFACT_SURFACE_TYPE
    assert registry.locator_schema == FORENSICS_IMMUTABLE_ARTIFACT_LOCATOR_SCHEMA
    assert registry.domain_classification == forensics_domain.reference()
    assert registry.domain_graph_type_set == forensics_semantics.reference()
    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert tuple(item.surface_class for item in registry.locators) == tuple(ForensicSurfaceClass)
    assert tuple(item.locator_kind for item in registry.locators) == (
        "forensics-disk",
        "forensics-memory",
        "forensics-log",
        "forensics-artifact",
    )
    assert all(item.provenance_required for item in registry.locators)
    assert all(item.provenance_preservation_required for item in registry.locators)
    assert all(item.immutable_source_required for item in registry.locators)
    assert all(item.source_root_kind_required for item in registry.locators)
    assert all(item.source_root_digest_required for item in registry.locators)
    assert all(item.source_artifact_record_digest_required for item in registry.locators)
    assert all(item.provenance_record_digest_required for item in registry.locators)
    assert all(item.artifact_digest_required for item in registry.locators)
    assert all(item.artifact_byte_count_required for item in registry.locators)
    assert all(not item.provenance_verified for item in registry.locators)
    assert len(registry.registry_digest) == 64


def test_locator_and_registry_resolution_require_exact_content_references() -> None:
    registry = registered_forensic_immutable_artifact_locator_registry()

    for locator in registry.locators:
        resolved = resolve_registered_forensic_immutable_artifact_locator(locator.reference())
        assert resolved == locator
        assert resolved is not locator

    resolved_registry = resolve_forensic_immutable_artifact_locator_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_resolution_rejects_forged_reference_state() -> None:
    registry = registered_forensic_immutable_artifact_locator_registry()
    locator_reference = (
        registry.locators[0].reference().model_copy(update={"locator_digest": "0" * 64})
    )
    registry_reference = registry.reference().model_copy(update={"registry_digest": "0" * 64})

    with pytest.raises(ForensicSurfaceRegistryError):
        resolve_registered_forensic_immutable_artifact_locator(locator_reference)
    with pytest.raises(ForensicSurfaceRegistryError):
        resolve_forensic_immutable_artifact_locator_registry(registry_reference)


def test_provenance_coordinate_is_content_free_and_source_root_bound() -> None:
    provenance = _provenance(artifact_bytes=2**63 - 1)
    payload = provenance.model_dump(mode="json", by_alias=True)

    assert provenance.source_root_kind is ForensicSourceRootKind.PAJIN_RUN_INTEGRITY_V1
    assert provenance.source_root_sha256 == "1" * 64
    assert provenance.source_artifact_record_sha256 == "2" * 64
    assert provenance.provenance_record_sha256 == "3" * 64
    assert provenance.artifact_sha256 == "4" * 64
    assert provenance.artifact_bytes == 2**63 - 1
    assert set(payload) == {
        "apiVersion",
        "kind",
        "sourceRootKind",
        "sourceRootSha256",
        "sourceArtifactRecordSha256",
        "provenanceRecordSha256",
        "artifactSha256",
        "artifactBytes",
        *_PROVENANCE_SECURITY_ALIASES,
    }


@pytest.mark.parametrize(
    "field",
    (
        "sourceRootSha256",
        "sourceArtifactRecordSha256",
        "provenanceRecordSha256",
        "artifactSha256",
    ),
)
@pytest.mark.parametrize("digest", ("A" * 64, "1" * 63, "1" * 65, "g" * 64, "sha256:" + "1" * 64))
def test_all_provenance_digests_require_canonical_lowercase_sha256(
    field: str,
    digest: str,
) -> None:
    payload = _provenance().model_dump(mode="json", by_alias=True)
    payload[field] = digest
    with pytest.raises(ValidationError):
        ForensicSourceProvenanceCoordinate.model_validate(payload)


@pytest.mark.parametrize("value", (-1, 2**63, True, False, 1.0, "1"))
def test_artifact_byte_count_requires_bounded_json_integer(value: object) -> None:
    payload = _provenance().model_dump(mode="json", by_alias=True)
    payload["artifactBytes"] = value
    with pytest.raises(ValidationError):
        ForensicSourceProvenanceCoordinate.model_validate(payload)


@pytest.mark.parametrize(
    "field,value",
    (
        ("path", "C:/evidence/image.dd"),
        ("uri", "file:///evidence/image.dd"),
        ("objectKey", "case/evidence/image.dd"),
        ("fileName", "image.dd"),
        ("hostName", "workstation-1"),
        ("deviceSerial", "serial-1"),
        ("caseId", "case-1"),
        ("operator", "analyst"),
        ("capturedAt", "2026-08-28T00:00:00Z"),
        ("parser", "parser-1"),
        ("rawBytes", "AA=="),
        ("rawProvenance", {"operator": "analyst"}),
        ("password", "secret"),
        ("token", "secret"),
        ("credentialReference", "credential-1"),
        ("secretReference", "secret-1"),
    ),
)
def test_provenance_rejects_operational_private_or_sensitive_fields(
    field: str,
    value: object,
) -> None:
    payload = _provenance().model_dump(mode="json", by_alias=True)
    payload[field] = value
    with pytest.raises(ValidationError):
        ForensicSourceProvenanceCoordinate.model_validate(payload)


def test_each_provenance_dimension_and_class_changes_surface_identity() -> None:
    baseline = typed_forensic_immutable_artifact_surface(locator=_disk())
    changed_provenance = (
        _provenance(source_root_sha256="9" * 64),
        _provenance(source_artifact_record_sha256="9" * 64),
        _provenance(provenance_record_sha256="9" * 64),
        _provenance(artifact_sha256="9" * 64),
        _provenance(artifact_bytes=1),
    )

    for provenance in changed_provenance:
        assert (
            typed_forensic_immutable_artifact_surface(locator=_disk(provenance)).surface_digest
            != baseline.surface_digest
        )

    assert typed_forensic_immutable_artifact_surface(locator=_memory()).surface_digest != (
        baseline.surface_digest
    )


@pytest.mark.parametrize("locator", _locators())
def test_each_locator_becomes_a_stable_inert_typed_forensic_surface(
    locator: ForensicImmutableArtifactSurfaceLocator,
) -> None:
    first = typed_forensic_immutable_artifact_surface(locator=locator)
    second = typed_forensic_immutable_artifact_surface(locator=locator)
    reference = first.reference()

    assert first == second
    assert first.locator is not locator
    assert first.locator.provenance is not locator.provenance
    assert first.surface_id == f"forensics-immutable-artifact-surface_{first.surface_digest}"
    assert first.initial_state == "registered-not-authorized"
    assert reference.surface_id == first.surface_id
    assert reference.surface_digest == first.surface_digest
    bound = bind_forensic_immutable_artifact_surface_reference(
        reference=reference,
        surface=first,
    )
    assert bound == first
    assert bound is not first


def test_forensic_models_do_not_change_legacy_discovery_or_attack_surface_wire() -> None:
    locator = _disk()
    with pytest.raises(ValidationError):
        _DISCOVERY_LOCATOR_ADAPTER.validate_python(locator.model_dump(mode="json", by_alias=True))

    assert "domainClassification" not in AttackSurface.model_json_schema()["properties"]
    assert "forensics-disk" not in str(_DISCOVERY_LOCATOR_ADAPTER.json_schema())


def test_registry_surface_and_provenance_carry_explicit_non_authority_markers() -> None:
    registry = registered_forensic_immutable_artifact_locator_registry()
    registry_payload = registry.model_dump(mode="json", by_alias=True)

    assert registry_payload["registryOnly"] is True
    assert registry_payload["discoveredSurfaceInitialState"] == "registered-not-authorized"
    for alias in _REGISTRY_FALSE_ALIASES:
        assert registry_payload[alias] is False

    for locator in _locators():
        provenance_payload = locator.provenance.model_dump(mode="json", by_alias=True)
        for alias in _PROVENANCE_SECURITY_ALIASES:
            assert provenance_payload[alias] is False

        surface_payload = typed_forensic_immutable_artifact_surface(locator=locator).model_dump(
            mode="json",
            by_alias=True,
        )
        assert surface_payload["typedSurfaceOnly"] is True
        for alias in _SURFACE_FALSE_ALIASES:
            assert surface_payload[alias] is False


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_registry_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = registered_forensic_immutable_artifact_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    with pytest.raises(ValidationError):
        ForensicImmutableArtifactLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_surface_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = typed_forensic_immutable_artifact_surface(locator=_disk()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    with pytest.raises(ValidationError):
        ForensicImmutableArtifactSurface.model_validate(payload)


@pytest.mark.parametrize("alias", _PROVENANCE_SECURITY_ALIASES)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_provenance_rejects_security_marker_escalation_and_boolean_coercion(
    alias: str,
    value: object,
) -> None:
    payload = _provenance().model_dump(mode="json", by_alias=True)
    payload[alias] = value
    with pytest.raises(ValidationError):
        ForensicSourceProvenanceCoordinate.model_validate(payload)


def test_registry_rejects_order_domain_model_and_digest_drift() -> None:
    registry = registered_forensic_immutable_artifact_locator_registry()
    payload = registry.model_dump(mode="json", by_alias=True)

    reordered = deepcopy(payload)
    reordered["locators"] = list(reversed(reordered["locators"]))
    with pytest.raises(ValidationError):
        ForensicImmutableArtifactLocatorRegistry.model_validate(reordered)

    changed_domain = deepcopy(payload)
    changed_domain["domainClassification"]["domain"] = "application"
    with pytest.raises(ValidationError):
        ForensicImmutableArtifactLocatorRegistry.model_validate(changed_domain)

    changed_model = deepcopy(payload)
    changed_model["locators"][0]["sourceModelId"] = "pajin.discovery.fake.Model"
    with pytest.raises(ValidationError):
        ForensicImmutableArtifactLocatorRegistry.model_validate(changed_model)

    changed_digest = deepcopy(payload)
    changed_digest["registryDigest"] = "0" * 64
    with pytest.raises(ValidationError):
        ForensicImmutableArtifactLocatorRegistry.model_validate(changed_digest)


def test_surface_rejects_identity_class_registry_and_sensitive_field_injection() -> None:
    surface = typed_forensic_immutable_artifact_surface(locator=_disk())
    payload = surface.model_dump(mode="json", by_alias=True)

    for path, value in (
        (("surfaceId",), "forensics-immutable-artifact-surface_" + "0" * 64),
        (("surfaceDigest",), "0" * 64),
        (("surfaceClass",), "memory"),
        (("locatorRegistry", "registryDigest"), "0" * 64),
        (("domainClassification", "domain"), "application"),
    ):
        changed = deepcopy(payload)
        _set_nested_value(changed, path, value)
        with pytest.raises(ValidationError):
            ForensicImmutableArtifactSurface.model_validate(changed)

    for field in (
        "rawEvidence",
        "credentialMaterial",
        "secretMaterial",
        "parserResult",
        "workerJob",
    ):
        changed = deepcopy(payload)
        changed[field] = "forbidden"
        with pytest.raises(ValidationError):
            ForensicImmutableArtifactSurface.model_validate(changed)


def test_public_boundaries_revalidate_forged_pydantic_instances() -> None:
    forged_provenance = _provenance().model_copy(update={"artifact_sha256": "A" * 64})
    with pytest.raises((ValidationError, ValueError)):
        forensic_disk_surface_locator(provenance=forged_provenance)

    forged_locator = _disk().model_copy(update={"kind": "forensics-memory"})
    with pytest.raises((ValidationError, ValueError)):
        typed_forensic_immutable_artifact_surface(locator=forged_locator)

    forged_surface = typed_forensic_immutable_artifact_surface(locator=_disk()).model_copy(
        update={"surface_class": ForensicSurfaceClass.MEMORY}
    )
    with pytest.raises((ValidationError, ValueError)):
        forged_surface.reference()

    registry = registered_forensic_immutable_artifact_locator_registry()
    forged_registry = registry.model_copy(update={"locators": tuple(reversed(registry.locators))})
    with pytest.raises((ValidationError, ValueError)):
        forged_registry.reference()


@pytest.mark.parametrize("forged_provenance", ({"kind": "wrong"}, 1, None))
def test_public_boundary_rejects_forged_provenance_types_with_controlled_error(
    forged_provenance: object,
) -> None:
    forged_locator = _disk().model_copy(update={"provenance": forged_provenance})
    with pytest.raises(ValueError):
        typed_forensic_immutable_artifact_surface(locator=forged_locator)


def test_public_boundaries_reject_unmodeled_nested_instance_state() -> None:
    provenance = _provenance()
    object.__setattr__(provenance, "hidden_credential_reference", "forbidden")

    with pytest.raises(ValueError, match="unmodeled instance state"):
        forensic_artifact_surface_locator(provenance=provenance)


def test_surface_reference_is_opaque_until_bound_to_complete_surface() -> None:
    surface = typed_forensic_immutable_artifact_surface(locator=_artifact())
    reference = surface.reference()
    payload = reference.model_dump(mode="json", by_alias=True)

    assert ForensicImmutableArtifactSurfaceRef.model_validate(payload) == reference
    assert "surfaceClass" not in payload
    assert "locatorKind" not in payload

    substituted = deepcopy(payload)
    substituted["surfaceDigest"] = "0" * 64
    substituted["surfaceId"] = "forensics-immutable-artifact-surface_" + "0" * 64
    structurally_valid_pointer = ForensicImmutableArtifactSurfaceRef.model_validate(substituted)
    with pytest.raises(ForensicSurfaceRegistryError):
        bind_forensic_immutable_artifact_surface_reference(
            reference=structurally_valid_pointer,
            surface=surface,
        )

    paired_class_claim = deepcopy(payload)
    paired_class_claim["surfaceClass"] = "memory"
    paired_class_claim["locatorKind"] = "forensics-memory"
    with pytest.raises(ValidationError):
        ForensicImmutableArtifactSurfaceRef.model_validate(paired_class_claim)

    other_surface = typed_forensic_immutable_artifact_surface(locator=_memory())
    with pytest.raises(ForensicSurfaceRegistryError):
        bind_forensic_immutable_artifact_surface_reference(
            reference=reference,
            surface=other_surface,
        )

    hidden_state_pointer = surface.reference()
    object.__setattr__(hidden_state_pointer, "unmodeled_surface_class", "artifact")
    with pytest.raises(ValueError, match="unmodeled instance state"):
        bind_forensic_immutable_artifact_surface_reference(
            reference=hidden_state_pointer,
            surface=surface,
        )


def test_registered_locator_rejects_boolean_coercion_and_execution_mapping() -> None:
    locator = registered_forensic_immutable_artifact_locator_registry().locators[0]
    payload = locator.model_dump(mode="json", by_alias=True)

    for field, value in (
        ("provenanceRequired", 1),
        ("provenancePreservationRequired", "true"),
        ("immutableSourceRequired", 1),
        ("sourceRootKindRequired", "true"),
        ("sourceRootDigestRequired", 1),
        ("sourceArtifactRecordDigestRequired", "true"),
        ("provenanceRecordDigestRequired", 1),
        ("artifactDigestRequired", "true"),
        ("artifactByteCountRequired", 1),
        ("provenanceVerified", True),
        ("registrationOnly", "true"),
        ("executionAuthorized", True),
    ):
        changed = deepcopy(payload)
        changed[field] = value
        with pytest.raises(ValidationError):
            RegisteredForensicImmutableArtifactLocator.model_validate(changed)

    payload["capabilityId"] = "pajin.forensics.parser"
    with pytest.raises(ValidationError):
        RegisteredForensicImmutableArtifactLocator.model_validate(payload)


def test_public_registry_and_resolver_results_are_detached_from_cached_authority() -> None:
    first = registered_forensic_immutable_artifact_locator_registry()
    second = registered_forensic_immutable_artifact_locator_registry()
    assert first == second
    assert first is not second
    assert first.locators[0] is not second.locators[0]

    resolved_first = resolve_registered_forensic_immutable_artifact_locator(
        first.locators[0].reference()
    )
    resolved_second = resolve_registered_forensic_immutable_artifact_locator(
        first.locators[0].reference()
    )
    assert resolved_first == resolved_second
    assert resolved_first is not resolved_second


def test_source_root_kind_is_code_owned_and_does_not_accept_generic_external_roots() -> None:
    payload = _provenance().model_dump(mode="json", by_alias=True)
    for kind in ("external", "object-store", "local-file", "latest"):
        changed = deepcopy(payload)
        changed["sourceRootKind"] = kind
        with pytest.raises(ValidationError):
            ForensicSourceProvenanceCoordinate.model_validate(changed)


def test_registry_does_not_claim_parser_worker_graph_or_credential_runtime_reuse() -> None:
    payload = registered_forensic_immutable_artifact_locator_registry().model_dump_json(
        by_alias=True
    )
    assert "PreparedCapabilityAction" not in payload
    assert "forensics.analysis-observation" not in payload
    assert "credentialLease" not in payload
    assert "parserExecutable" not in payload
    assert "workerBoundary" not in payload
