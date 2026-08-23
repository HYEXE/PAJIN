"""DOMAIN-001 code-owned, non-authoritative Security Domain taxonomy."""

from __future__ import annotations

import json
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import StrictModel

SECURITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/security-domain-classification/v1alpha1"
] = "pajin.dev/security-domain-classification/v1alpha1"
SECURITY_DOMAIN_TAXONOMY_API_VERSION: Literal[
    "pajin.dev/security-domain-taxonomy/v1alpha1"
] = "pajin.dev/security-domain-taxonomy/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CLASSIFICATION_BYTES = 64 * 1024
_MAX_TAXONOMY_BYTES = 1024 * 1024


class SecurityDomainTaxonomyError(RuntimeError):
    """Raised when an exact Security Domain classification cannot be resolved."""


class SecurityDomain(StrEnum):
    """Stable Security Domain values that classify subject matter only."""

    WEB = "web"
    NETWORK = "network"
    SYSTEM = "system"
    APPLICATION = "application"
    MOBILE = "mobile"
    CLOUD = "cloud"
    AI = "ai"
    CRYPTOGRAPHY = "cryptography"
    FORENSICS = "forensics"


_DOMAIN_SPECS = (
    (SecurityDomain.WEB, "Web"),
    (SecurityDomain.NETWORK, "Network"),
    (SecurityDomain.SYSTEM, "System"),
    (SecurityDomain.APPLICATION, "Application"),
    (SecurityDomain.MOBILE, "Mobile"),
    (SecurityDomain.CLOUD, "Cloud"),
    (SecurityDomain.AI, "AI"),
    (SecurityDomain.CRYPTOGRAPHY, "Cryptography"),
    (SecurityDomain.FORENSICS, "Digital Forensics"),
)


def _security_domain_digest(domain: str, value: object, *, max_bytes: int) -> str:
    """Return a bounded domain-separated digest for one taxonomy object."""

    try:
        domain_bytes = domain.encode("ascii")
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError("Security Domain metadata is not canonical UTF-8 JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError("Security Domain metadata exceeds the canonical byte limit")
    return sha256(
        b"PAJIN-SECURITY-DOMAIN\0"
        + len(domain_bytes).to_bytes(4, "big")
        + domain_bytes
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).hexdigest()


class SecurityDomainClassificationRef(StrictModel):
    """Exact content-addressed reference to one registered classification."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    classification_id: _Identifier = Field(alias="classificationId")
    classification_version: Literal["1.0.0"] = Field(alias="classificationVersion")
    classification_digest: _Sha256 = Field(alias="classificationDigest")
    domain: SecurityDomain


class RegisteredSecurityDomain(StrictModel):
    """One immutable classification carrying no Profile or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/security-domain-classification/v1alpha1"] = Field(
        default=SECURITY_DOMAIN_CLASSIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredSecurityDomain"] = "RegisteredSecurityDomain"
    classification_id: _Identifier = Field(alias="classificationId")
    classification_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="classificationVersion",
    )
    classification_digest: str = Field(default="", alias="classificationDigest", max_length=64)
    domain: SecurityDomain
    display_name: str = Field(alias="displayName", min_length=1, max_length=100)
    classification_only: Literal[True] = Field(default=True, alias="classificationOnly")
    profile_orthogonal: Literal[True] = Field(default=True, alias="profileOrthogonal")
    campaign_profile_selection_authorized: Literal[False] = Field(
        default=False,
        alias="campaignProfileSelectionAuthorized",
    )
    capability_registration_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityRegistrationAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
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
    filesystem_access_authorized: Literal[False] = Field(
        default=False,
        alias="filesystemAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "classification_only",
        "profile_orthogonal",
        "campaign_profile_selection_authorized",
        "capability_registration_authorized",
        "capability_activation_authorized",
        "scope_expansion_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "filesystem_access_authorized",
        "credential_use_authorized",
        "graph_admission_authorized",
        "finding_confirmation_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Security Domain authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        expected_id = f"pajin.security-domain.{self.domain.value}"
        if (
            self.classification_id != expected_id
            or self.display_name != dict(_DOMAIN_SPECS)[self.domain]
        ):
            raise ValueError("Security Domain classification identity differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_digest"},
        )
        digest = _security_domain_digest(
            "pajin.domain.security-domain-classification/v1",
            material,
            max_bytes=_MAX_CLASSIFICATION_BYTES,
        )
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Security Domain classification Digest differs")
        object.__setattr__(self, "classification_digest", digest)
        return self

    def reference(self) -> SecurityDomainClassificationRef:
        """Return the exact content-addressed classification reference."""

        return SecurityDomainClassificationRef(
            classificationId=self.classification_id,
            classificationVersion=self.classification_version,
            classificationDigest=self.classification_digest,
            domain=self.domain,
        )


class SecurityDomainTaxonomy(StrictModel):
    """Exact nine-domain catalog with no runtime-support or authority claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/security-domain-taxonomy/v1alpha1"] = Field(
        default=SECURITY_DOMAIN_TAXONOMY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SecurityDomainTaxonomy"] = "SecurityDomainTaxonomy"
    taxonomy_id: Literal["pajin.security-domain-taxonomy.core"] = Field(
        default="pajin.security-domain-taxonomy.core",
        alias="taxonomyId",
    )
    taxonomy_version: Literal["1.0.0"] = Field(default="1.0.0", alias="taxonomyVersion")
    taxonomy_digest: str = Field(default="", alias="taxonomyDigest", max_length=64)
    domains: tuple[RegisteredSecurityDomain, ...] = Field(min_length=9, max_length=9)
    classification_only: Literal[True] = Field(default=True, alias="classificationOnly")
    profile_orthogonal: Literal[True] = Field(default=True, alias="profileOrthogonal")
    profile_mapping_available: Literal[False] = Field(
        default=False,
        alias="profileMappingAvailable",
    )
    legacy_capability_domain_reinterpreted: Literal[False] = Field(
        default=False,
        alias="legacyCapabilityDomainReinterpreted",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "classification_only",
        "profile_orthogonal",
        "profile_mapping_available",
        "legacy_capability_domain_reinterpreted",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Security Domain taxonomy markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_taxonomy(self) -> Self:
        if self.domains != _registered_security_domains():
            raise ValueError("Security Domain taxonomy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"taxonomy_digest"},
        )
        digest = _security_domain_digest(
            "pajin.domain.security-domain-taxonomy/v1",
            material,
            max_bytes=_MAX_TAXONOMY_BYTES,
        )
        if self.taxonomy_digest and self.taxonomy_digest != digest:
            raise ValueError("Security Domain taxonomy Digest differs")
        object.__setattr__(self, "taxonomy_digest", digest)
        return self


def registered_security_domain_taxonomy() -> SecurityDomainTaxonomy:
    """Return the exact DOMAIN-001 taxonomy without selecting runtime behavior."""

    return SecurityDomainTaxonomy(domains=_registered_security_domains())


def resolve_registered_security_domain(
    reference: SecurityDomainClassificationRef,
) -> RegisteredSecurityDomain:
    """Resolve an exact classification without inferring Profile or Capability mappings."""

    for classification in registered_security_domain_taxonomy().domains:
        if classification.reference() == reference:
            return classification.model_copy(deep=True)
    raise SecurityDomainTaxonomyError("Security Domain classification is not registered exactly")


def _registered_security_domains() -> tuple[RegisteredSecurityDomain, ...]:
    return tuple(
        RegisteredSecurityDomain(
            classificationId=f"pajin.security-domain.{domain.value}",
            domain=domain,
            displayName=display_name,
        )
        for domain, display_name in _DOMAIN_SPECS
    )
