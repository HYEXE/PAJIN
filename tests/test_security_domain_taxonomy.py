from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.capabilities.existing import existing_mode_capability_registrations
from pajin.capabilities.pentest_recon import registered_pentest_recon_capability_definition
from pajin.domain.security_domain import (
    RegisteredSecurityDomain,
    SecurityDomain,
    SecurityDomainClassificationRef,
    SecurityDomainTaxonomy,
    SecurityDomainTaxonomyError,
    registered_security_domain_taxonomy,
    resolve_registered_security_domain,
)

_DOMAIN_AUTHORITY_ALIASES = (
    "campaignProfileSelectionAuthorized",
    "capabilityRegistrationAuthorized",
    "capabilityActivationAuthorized",
    "scopeExpansionAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "filesystemAccessAuthorized",
    "credentialUseAuthorized",
    "graphAdmissionAuthorized",
    "findingConfirmationAuthorized",
    "executionAuthorized",
)


def test_registered_taxonomy_is_exact_content_addressed_classification_only() -> None:
    taxonomy = registered_security_domain_taxonomy()

    assert tuple(classification.domain for classification in taxonomy.domains) == tuple(
        SecurityDomain
    )
    assert tuple(domain.value for domain in SecurityDomain) == (
        "web",
        "network",
        "system",
        "application",
        "mobile",
        "cloud",
        "ai",
        "cryptography",
        "forensics",
    )
    assert taxonomy.classification_only is True
    assert taxonomy.profile_orthogonal is True
    assert taxonomy.profile_mapping_available is False
    assert taxonomy.legacy_capability_domain_reinterpreted is False
    assert taxonomy.runtime_support_asserted is False
    assert taxonomy.execution_authorized is False
    assert len(taxonomy.taxonomy_digest) == 64
    assert len({item.classification_digest for item in taxonomy.domains}) == 9
    assert SecurityDomainTaxonomy.model_validate(
        taxonomy.model_dump(mode="json", by_alias=True)
    ) == taxonomy


def test_every_domain_carries_explicit_false_authority_markers() -> None:
    taxonomy = registered_security_domain_taxonomy()

    for classification in taxonomy.domains:
        payload = classification.model_dump(mode="json", by_alias=True)
        assert classification.classification_only is True
        assert classification.profile_orthogonal is True
        assert all(payload[alias] is False for alias in _DOMAIN_AUTHORITY_ALIASES)


@pytest.mark.parametrize("domain", tuple(SecurityDomain))
def test_exact_reference_resolution_grants_no_mapping_or_execution(
    domain: SecurityDomain,
) -> None:
    source = next(
        item for item in registered_security_domain_taxonomy().domains if item.domain is domain
    )
    resolved = resolve_registered_security_domain(source.reference())

    assert resolved == source
    assert resolved is not source
    assert resolved.execution_authorized is False
    assert {
        "profile_id",
        "capability_id",
        "tool_id",
        "worker_id",
        "scope",
        "permit",
    }.isdisjoint(RegisteredSecurityDomain.model_fields)


def test_exact_resolution_rejects_reference_substitution() -> None:
    source = registered_security_domain_taxonomy().domains[0]
    wrong_digest = source.reference().model_copy(
        update={"classification_digest": "0" * 64}
    )
    wrong_domain = source.reference().model_copy(update={"domain": SecurityDomain.NETWORK})

    with pytest.raises(SecurityDomainTaxonomyError, match="not registered exactly"):
        resolve_registered_security_domain(wrong_digest)
    with pytest.raises(SecurityDomainTaxonomyError, match="not registered exactly"):
        resolve_registered_security_domain(wrong_domain)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("domain", "database"),
        ("classificationVersion", "latest"),
        ("classificationVersion", "2.0.0"),
        ("classificationDigest", "not-a-digest"),
    ),
)
def test_classification_reference_rejects_unknown_or_implicit_identity(
    field: str,
    value: object,
) -> None:
    payload = registered_security_domain_taxonomy().domains[0].reference().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        SecurityDomainClassificationRef.model_validate(payload)


def test_taxonomy_rejects_membership_reordering_and_digest_drift() -> None:
    payload = registered_security_domain_taxonomy().model_dump(mode="json", by_alias=True)

    reordered = deepcopy(payload)
    reordered["domains"] = list(reversed(reordered["domains"]))
    reordered["taxonomyDigest"] = ""
    with pytest.raises(ValidationError, match="differs from code authority"):
        SecurityDomainTaxonomy.model_validate(reordered)

    changed_digest = deepcopy(payload)
    changed_digest["taxonomyDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="Digest differs"):
        SecurityDomainTaxonomy.model_validate(changed_digest)

    changed_name = deepcopy(payload)
    changed_name["domains"][0]["displayName"] = "Browser"
    changed_name["domains"][0]["classificationDigest"] = ""
    changed_name["taxonomyDigest"] = ""
    with pytest.raises(ValidationError, match="identity differs"):
        SecurityDomainTaxonomy.model_validate(changed_name)


@pytest.mark.parametrize("alias", _DOMAIN_AUTHORITY_ALIASES)
@pytest.mark.parametrize("escalated", (True, 1, "false"))
def test_domain_authority_markers_fail_closed(alias: str, escalated: object) -> None:
    payload = registered_security_domain_taxonomy().domains[0].model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = escalated
    payload["classificationDigest"] = ""

    with pytest.raises(ValidationError):
        RegisteredSecurityDomain.model_validate(payload)


@pytest.mark.parametrize(
    ("alias", "escalated"),
    (
        ("profileMappingAvailable", True),
        ("legacyCapabilityDomainReinterpreted", True),
        ("runtimeSupportAsserted", True),
        ("executionAuthorized", True),
        ("classificationOnly", 1),
        ("profileOrthogonal", "true"),
    ),
)
def test_taxonomy_level_authority_and_support_claims_fail_closed(
    alias: str,
    escalated: object,
) -> None:
    payload = registered_security_domain_taxonomy().model_dump(mode="json", by_alias=True)
    payload[alias] = escalated
    payload["taxonomyDigest"] = ""

    with pytest.raises(ValidationError):
        SecurityDomainTaxonomy.model_validate(payload)


@pytest.mark.parametrize(
    ("alias", "value"),
    (
        ("profileId", "pajin.profile.pentest"),
        ("capabilityId", "pajin.discovery.read-surface"),
        ("toolId", "http.get"),
        ("workerId", "worker:any"),
        ("scope", {"targets": ["example.test"]}),
    ),
)
def test_classification_rejects_authority_mapping_fields(alias: str, value: object) -> None:
    payload = registered_security_domain_taxonomy().domains[0].model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    payload["classificationDigest"] = ""

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredSecurityDomain.model_validate(payload)


def test_legacy_capability_domain_namespaces_remain_unchanged() -> None:
    before = tuple(
        (item.capability_id, item.capability_version, item.domain)
        for item in existing_mode_capability_registrations(include_registered_mcp=True)
    )
    pentest_before = registered_pentest_recon_capability_definition()

    registered_security_domain_taxonomy()

    after = tuple(
        (item.capability_id, item.capability_version, item.domain)
        for item in existing_mode_capability_registrations(include_registered_mcp=True)
    )
    pentest_after = registered_pentest_recon_capability_definition()
    assert after == before
    assert {item[2] for item in after} == {"ai-redteam", "bug-bounty", "ctf"}
    assert pentest_before == pentest_after
    assert pentest_after.domain == "pentest"
    assert pentest_after.capability_digest == pentest_before.capability_digest
