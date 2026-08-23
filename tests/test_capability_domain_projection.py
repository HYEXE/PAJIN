from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityDefinition,
    CapabilityDefinitionRegistry,
    CapabilityDomainClassificationRef,
    CapabilityDomainInventoryProjection,
    CapabilityDomainProjectionError,
    ExistingModeCapabilityBundle,
    RegisteredCapabilityDomainClassification,
    existing_mode_capability_bundle,
    registered_capability_domain_inventory_projection,
    resolve_registered_capability_domain_classification,
)
from pajin.capabilities.pentest_recon import (
    PentestReconCapabilityBundle,
    pentest_recon_capability_bundle,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import MockAgentProbe

_TRUE_MARKERS = (
    "projectionOnly",
    "explicitMappingReviewed",
    "completeCodeAuthoritySetVerified",
    "signedReleaseRequiredForExecution",
    "currentActivationRequiredForExecution",
)
_FALSE_MARKERS = (
    "releaseBound",
    "activationBound",
    "legacyCapabilityDomainInterpreted",
    "surfaceMetadataInferred",
    "toolMetadataInferred",
    "profileMappingAvailable",
    "capabilityActivationAuthorized",
    "scopeExpansionAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "graphAdmissionAuthorized",
    "findingConfirmationAuthorized",
    "runtimeSupportAssertedByProjection",
    "executionAuthorized",
)
_INVENTORY_TRUE_MARKERS = (
    "projectionOnly",
    "exactCodeBackedInventoryVerified",
)
_INVENTORY_FALSE_MARKERS = (
    "releaseInventoryBound",
    "activationInventoryBound",
    "profileMappingAvailable",
    "capabilityActivationAuthorized",
    "scopeExpansionAuthorized",
    "permitIssuanceAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "runtimeSupportAssertedByProjection",
    "executionAuthorized",
)


def _tools(*, include_mcp: bool = True) -> ToolRegistry:
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
        HTTPGetTool(),
    ):
        tools.register(tool)
    if include_mcp:
        tools.register(demo_mcp_tool())
    return tools


@pytest.fixture
def source_bundles() -> tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle]:
    tools = _tools()
    return (
        existing_mode_capability_bundle(tools, include_registered_mcp=True),
        pentest_recon_capability_bundle(tools),
    )


def _projection(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> CapabilityDomainInventoryProjection:
    existing, pentest = source_bundles
    return registered_capability_domain_inventory_projection(
        existing_bundle=existing,
        pentest_recon_bundle=pentest,
    )


def test_projection_binds_exact_current_cap001_cap002_inventory(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    projection = _projection(source_bundles)
    taxonomy = registered_security_domain_taxonomy()

    assert (
        projection.security_domain_taxonomy_id,
        projection.security_domain_taxonomy_version,
        projection.security_domain_taxonomy_digest,
    ) == (taxonomy.taxonomy_id, taxonomy.taxonomy_version, taxonomy.taxonomy_digest)
    assert projection.classified_capability_count == 9
    assert projection.classified_domain_count == 3
    assert projection.unclassified_capability_count == 0
    assert len(projection.bindings) == 9
    assert len(projection.projection_digest) == 64
    assert CapabilityDomainInventoryProjection.model_validate(
        projection.model_dump(mode="json", by_alias=True)
    ) == projection

    existing, pentest = source_bundles
    source_refs = {
        item.reference()
        for item in (*existing.capabilities(), *pentest.authorities.capabilities())
    }
    assert {item.code_backed_capability for item in projection.bindings} == source_refs


def test_projection_registers_explicit_domain_and_surface_mappings(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    projection = _projection(source_bundles)
    actual = {
        item.capability.capability_id: (
            item.domain_classification.domain,
            item.reviewed_surface_types,
        )
        for item in projection.bindings
    }

    assert actual == {
        "pajin.ai.kisa.indirect-tool-hijacking": (SecurityDomain.AI, ("mock-agent",)),
        "pajin.ai.kisa.jailbreak-policy-bypass": (
            SecurityDomain.AI,
            ("ai-chat-api", "rag-chat-api"),
        ),
        "pajin.ai.kisa.memory-poisoning-persistence": (
            SecurityDomain.AI,
            ("ai-chat-api", "rag-chat-api"),
        ),
        "pajin.ai.kisa.system-prompt-disclosure": (
            SecurityDomain.AI,
            ("ai-chat-api", "rag-chat-api"),
        ),
        "pajin.ai.mcp.instruction-hijacking-inspection": (
            SecurityDomain.AI,
            ("mock-mcp",),
        ),
        "pajin.bug-bounty.boolean-sqli-lab": (
            SecurityDomain.WEB,
            ("bug-bounty-api",),
        ),
        "pajin.ctf.crypto-single-byte-xor": (
            SecurityDomain.CRYPTOGRAPHY,
            ("ctf-crypto",),
        ),
        "pajin.ctf.web-exposed-backup-config": (
            SecurityDomain.WEB,
            ("ctf-web",),
        ),
        "pajin.pentest.http-get-recon": (
            SecurityDomain.WEB,
            ("http-endpoint",),
        ),
    }


def test_projection_cannot_be_derived_from_legacy_domain_namespace(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    existing, pentest = source_bundles
    definitions = (*existing.definitions.definitions(), *pentest.definitions.definitions())
    legacy = {item.capability_id: item.domain for item in definitions}
    classified = {
        item.capability.capability_id: item.domain_classification.domain
        for item in _projection(source_bundles).bindings
    }

    assert legacy["pajin.ctf.crypto-single-byte-xor"] == "ctf"
    assert legacy["pajin.ctf.web-exposed-backup-config"] == "ctf"
    assert classified["pajin.ctf.crypto-single-byte-xor"] is SecurityDomain.CRYPTOGRAPHY
    assert classified["pajin.ctf.web-exposed-backup-config"] is SecurityDomain.WEB
    assert "domain" in CapabilityDefinition.model_fields
    assert "legacy_capability_domain" not in RegisteredCapabilityDomainClassification.model_fields


def test_projection_records_no_release_activation_profile_or_execution_mapping(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    projection = _projection(source_bundles)
    inventory_payload = projection.model_dump(mode="json", by_alias=True)
    forbidden_fields = {
        "release",
        "activation",
        "profile",
        "tool",
        "worker",
        "scope",
        "permit",
    }

    assert forbidden_fields.isdisjoint(CapabilityDomainInventoryProjection.model_fields)
    assert all(inventory_payload[alias] is True for alias in _INVENTORY_TRUE_MARKERS)
    assert all(inventory_payload[alias] is False for alias in _INVENTORY_FALSE_MARKERS)
    for binding in projection.bindings:
        payload = binding.model_dump(mode="json", by_alias=True)
        assert forbidden_fields.isdisjoint(RegisteredCapabilityDomainClassification.model_fields)
        assert all(payload[alias] is True for alias in _TRUE_MARKERS)
        assert all(payload[alias] is False for alias in _FALSE_MARKERS)


@pytest.mark.parametrize("index", range(9))
def test_exact_classification_resolution_grants_no_authority(
    index: int,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    source = _projection(source_bundles).bindings[index]
    existing, pentest = source_bundles
    resolved = resolve_registered_capability_domain_classification(
        source.reference(),
        existing_bundle=existing,
        pentest_recon_bundle=pentest,
    )

    assert resolved == source
    assert resolved is not source
    assert resolved.capability_activation_authorized is False
    assert resolved.execution_authorized is False


def test_exact_resolution_rejects_reference_substitution(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    projection = _projection(source_bundles)
    source = projection.bindings[0].reference()
    existing, pentest = source_bundles
    wrong_digest = source.model_copy(update={"classification_digest": "0" * 64})
    wrong_domain = source.model_copy(
        update={"domain_classification": projection.bindings[-1].domain_classification}
    )

    for reference in (wrong_digest, wrong_domain):
        with pytest.raises(CapabilityDomainProjectionError, match="not registered exactly"):
            resolve_registered_capability_domain_classification(
                reference,
                existing_bundle=existing,
                pentest_recon_bundle=pentest,
            )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("classificationId", "latest"),
        ("classificationDigest", "not-a-digest"),
        ("capability", {"capabilityId": "unknown"}),
    ),
)
def test_classification_reference_rejects_invalid_identity(
    field: str,
    value: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).bindings[0].reference().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        CapabilityDomainClassificationRef.model_validate(payload)


def test_projection_rejects_incomplete_base_inventory() -> None:
    tools = _tools(include_mcp=False)
    with pytest.raises(CapabilityDomainProjectionError, match="reviewed exact inventory"):
        registered_capability_domain_inventory_projection(
            existing_bundle=existing_mode_capability_bundle(tools),
            pentest_recon_bundle=pentest_recon_capability_bundle(tools),
        )


def test_projection_rejects_cap001_source_drift(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    existing, pentest = source_bundles
    definitions = list(existing.definitions.definitions())
    payload = definitions[0].model_dump(mode="json", by_alias=True)
    payload["supportedSurfaceTypes"] = ["mock-agent", "network-host"]
    payload["capabilityDigest"] = ""
    definitions[0] = CapabilityDefinition.model_validate(payload)
    drifted = ExistingModeCapabilityBundle(
        definitions=CapabilityDefinitionRegistry(definitions),
        authorities=existing.authorities,
    )

    with pytest.raises(CapabilityDomainProjectionError, match="CAP-001/CAP-002"):
        registered_capability_domain_inventory_projection(
            existing_bundle=drifted,
            pentest_recon_bundle=pentest,
        )


@pytest.mark.parametrize("alias", _TRUE_MARKERS)
@pytest.mark.parametrize("value", (False, 1, "true"))
def test_classification_true_markers_are_exact(
    alias: str,
    value: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).bindings[0].model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["classificationId"] = ""
    payload["classificationDigest"] = ""

    with pytest.raises(ValidationError):
        RegisteredCapabilityDomainClassification.model_validate(payload)


@pytest.mark.parametrize("alias", _FALSE_MARKERS)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_classification_false_markers_fail_closed(
    alias: str,
    value: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).bindings[0].model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["classificationId"] = ""
    payload["classificationDigest"] = ""

    with pytest.raises(ValidationError):
        RegisteredCapabilityDomainClassification.model_validate(payload)


@pytest.mark.parametrize("alias", _INVENTORY_TRUE_MARKERS)
@pytest.mark.parametrize("value", (False, 1, "true"))
def test_inventory_true_markers_are_exact(
    alias: str,
    value: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["projectionDigest"] = ""

    with pytest.raises(ValidationError):
        CapabilityDomainInventoryProjection.model_validate(payload)


@pytest.mark.parametrize("alias", _INVENTORY_FALSE_MARKERS)
@pytest.mark.parametrize("value", (True, 0, "false"))
def test_inventory_false_markers_fail_closed(
    alias: str,
    value: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["projectionDigest"] = ""

    with pytest.raises(ValidationError):
        CapabilityDomainInventoryProjection.model_validate(payload)


@pytest.mark.parametrize(
    ("alias", "value"),
    (
        ("release", {"releaseId": "capability-release_any"}),
        ("activation", {"activationSetId": "activation:any"}),
        ("profile", "pentest"),
        ("toolId", "http.get"),
        ("workerId", "worker:any"),
        ("scope", {"targets": ["example.test"]}),
        ("permitId", "permit:any"),
    ),
)
def test_classification_rejects_injected_authority_mapping(
    alias: str,
    value: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).bindings[0].model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["classificationId"] = ""
    payload["classificationDigest"] = ""

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredCapabilityDomainClassification.model_validate(payload)


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("projectionDigest",), "0" * 64),
        (("securityDomainTaxonomyDigest",), "1" * 64),
        (("bindings",), "reverse"),
        (("bindings", 0, "capability", "capabilityDigest"), "0" * 64),
        (("bindings", 0, "codeBackedCapability", "authoritySetDigest"), "0" * 64),
        (("bindings", 0, "domainClassification"), "next-domain"),
        (("bindings", 0, "reviewedSurfaceTypes"), ["network-host"]),
        (("classifiedCapabilityCount",), 8),
        (("classifiedDomainCount",), 9),
        (("unclassifiedCapabilityCount",), 1),
    ),
)
def test_projection_rejects_identity_or_mapping_substitution(
    path: tuple[str | int, ...],
    replacement: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).model_dump(mode="json", by_alias=True)
    if replacement == "reverse":
        replacement = list(reversed(payload["bindings"]))
    elif replacement == "next-domain":
        replacement = deepcopy(payload["bindings"][-1]["domainClassification"])
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    if path != ("projectionDigest",):
        payload["projectionDigest"] = ""
    if path[:2] == ("bindings", 0):
        payload["bindings"][0]["classificationId"] = ""
        payload["bindings"][0]["classificationDigest"] = ""
    if path[:3] == ("bindings", 0, "codeBackedCapability"):
        payload["bindings"][0]["codeBackedCapability"]["authoritySetId"] = (
            "capability-authority-set_" + "0" * 64
        )

    with pytest.raises(ValidationError):
        CapabilityDomainInventoryProjection.model_validate(payload)


@pytest.mark.parametrize(
    ("alias", "value"),
    (
        ("classifiedCapabilityCount", True),
        ("classifiedCapabilityCount", "9"),
        ("classifiedDomainCount", True),
        ("unclassifiedCapabilityCount", "0"),
    ),
)
def test_inventory_counts_reject_boolean_and_string_coercion(
    alias: str,
    value: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> None:
    payload = _projection(source_bundles).model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["projectionDigest"] = ""

    with pytest.raises(ValidationError):
        CapabilityDomainInventoryProjection.model_validate(payload)
