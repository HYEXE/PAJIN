"""DOMAIN-003 non-authoritative projection over exact CAP-001/CAP-002 inventory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.capabilities.authorities import CapabilityAuthorityError, CodeBackedCapabilityRef
from pajin.capabilities.existing import ExistingModeCapabilityBundle
from pajin.capabilities.models import (
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    capability_definition_digest,
)
from pajin.capabilities.pentest_recon import PentestReconCapabilityBundle
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)

CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/capability-domain-classification/v1alpha1"
] = "pajin.dev/capability-domain-classification/v1alpha1"
CAPABILITY_DOMAIN_INVENTORY_PROJECTION_API_VERSION: Literal[
    "pajin.dev/capability-domain-inventory-projection/v1alpha1"
] = "pajin.dev/capability-domain-inventory-projection/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_CLASSIFICATION_ID_PATTERN = r"^capability-domain-classification_[a-f0-9]{64}$"
_EXPECTED_CAPABILITY_COUNT = 9
_EXPECTED_DOMAIN_COUNT = 3


class CapabilityDomainProjectionError(RuntimeError):
    """Raised when the exact code-backed source inventory cannot be projected."""


@dataclass(frozen=True, slots=True)
class _CapabilityDomainSpec:
    capability_id: str
    capability_version: str
    capability_digest: str
    authority_set_digest: str
    domain: SecurityDomain
    reviewed_surface_types: tuple[str, ...]

    def capability_reference(self) -> CapabilityDefinitionRef:
        return CapabilityDefinitionRef(
            capabilityId=self.capability_id,
            capabilityVersion=self.capability_version,
            capabilityDigest=self.capability_digest,
        )

    def code_backed_reference(self) -> CodeBackedCapabilityRef:
        return CodeBackedCapabilityRef(
            capability=self.capability_reference(),
            authoritySetId=f"capability-authority-set_{self.authority_set_digest}",
            authoritySetDigest=self.authority_set_digest,
        )


_CAPABILITY_DOMAIN_SPECS = (
    _CapabilityDomainSpec(
        "pajin.ai.kisa.indirect-tool-hijacking",
        "1.0.0",
        "e63226ffc242d1632d361d39f33ed6d3bbdd89c4ac52c5073b95a0b17581a9a0",
        "ea81b33e846081d30f5282411d915f50b626d6a2e8e994b8ee63d1925be7de67",
        SecurityDomain.AI,
        ("mock-agent",),
    ),
    _CapabilityDomainSpec(
        "pajin.ai.kisa.jailbreak-policy-bypass",
        "1.0.0",
        "2f54a9fe6688bf529f2b234fe0a5c3cc73d73d9a8ec8b77ce5b213bc1fef4d9c",
        "95b0467757569a58ae136a15c0f01913cd82f4e3ac438df7606124697a9dc3a2",
        SecurityDomain.AI,
        ("ai-chat-api", "rag-chat-api"),
    ),
    _CapabilityDomainSpec(
        "pajin.ai.kisa.memory-poisoning-persistence",
        "1.1.0",
        "bef0e8ea7d4dad7e5dfd80dd6aeaf2d62d7219ce54ce67574168c8bbad4995b2",
        "e61a3be501451566a957e0fa78079fe7d9c1f5588d579a4f45306ba73c005624",
        SecurityDomain.AI,
        ("ai-chat-api", "rag-chat-api"),
    ),
    _CapabilityDomainSpec(
        "pajin.ai.kisa.system-prompt-disclosure",
        "1.0.0",
        "ab4977d8fe16775eda5cb7a49f63c1c91d5b85d7359760b48b7dc954494155b7",
        "4f2eecf579f82680e7756b96fbeeea78fabc9522cf1538b2e8eaf7682ee79ad5",
        SecurityDomain.AI,
        ("ai-chat-api", "rag-chat-api"),
    ),
    _CapabilityDomainSpec(
        "pajin.ai.mcp.instruction-hijacking-inspection",
        "1.0.0",
        "127d47cad70d24bbb640dfaacc6851737631b1c1cd3d72862a450a4419849167",
        "697ac4814e8d40f321bbce90c785f5f72fae670503d4faeb50ab7b175f4520d0",
        SecurityDomain.AI,
        ("mock-mcp",),
    ),
    _CapabilityDomainSpec(
        "pajin.bug-bounty.boolean-sqli-lab",
        "1.0.0",
        "7316c7ae0ce073c5818891f3196bea4a94124dac3fb53b51037fcfcfa4e79186",
        "5e460ae39f6960ffa6e99e1db7ff817f55ceb10ca1472ccbff635998d2091efa",
        SecurityDomain.WEB,
        ("bug-bounty-api",),
    ),
    _CapabilityDomainSpec(
        "pajin.ctf.crypto-single-byte-xor",
        "1.0.0",
        "8fabdcf49b9ea2f5ac0178849762202c08ee2294d2c9c5d2ff5c37e76a0bc75b",
        "a07090c6950af1851e832f8bacad51c7f43ff7ad4e223bab124a1c17e8d08c0f",
        SecurityDomain.CRYPTOGRAPHY,
        ("ctf-crypto",),
    ),
    _CapabilityDomainSpec(
        "pajin.ctf.web-exposed-backup-config",
        "1.0.0",
        "ab62da6e95f87de9dc084d9f585b679ee328fa3db17e3882fd1a2a5b595348f1",
        "3e7eabb0419959f3efe72d60f36281ecf8e0b9b4a6d86a09fb55fae8307746c7",
        SecurityDomain.WEB,
        ("ctf-web",),
    ),
    _CapabilityDomainSpec(
        "pajin.pentest.http-get-recon",
        "1.0.0",
        "05797f25d9592de906ec0a32de81889b95b79576057595f389bca54aa23ee707",
        "7bcc380f312f17184c2b6155a3f8c8d3820c006696d2295f50e0a4c868410af8",
        SecurityDomain.WEB,
        ("http-endpoint",),
    ),
)


class CapabilityDomainClassificationRef(StrictModel):
    """Exact content-addressed reference to one inventory classification."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    classification_id: str = Field(
        alias="classificationId",
        pattern=_CLASSIFICATION_ID_PATTERN,
    )
    classification_digest: _Sha256 = Field(alias="classificationDigest")
    capability: CapabilityDefinitionRef
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )


class RegisteredCapabilityDomainClassification(StrictModel):
    """Reviewed Domain metadata over one exact CAP-001/CAP-002 identity."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/capability-domain-classification/v1alpha1"
    ] = Field(
        default=CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredCapabilityDomainClassification"] = (
        "RegisteredCapabilityDomainClassification"
    )
    classification_id: str = Field(default="", alias="classificationId", max_length=97)
    classification_digest: str = Field(
        default="",
        alias="classificationDigest",
        max_length=64,
    )
    capability: CapabilityDefinitionRef
    code_backed_capability: CodeBackedCapabilityRef = Field(alias="codeBackedCapability")
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    reviewed_surface_types: tuple[str, ...] = Field(
        alias="reviewedSurfaceTypes",
        min_length=1,
        max_length=100,
    )
    mapping_basis: Literal["explicit-code-reviewed-capability-and-surface-set"] = Field(
        default="explicit-code-reviewed-capability-and-surface-set",
        alias="mappingBasis",
    )
    projection_only: Literal[True] = Field(default=True, alias="projectionOnly")
    explicit_mapping_reviewed: Literal[True] = Field(
        default=True,
        alias="explicitMappingReviewed",
    )
    complete_code_authority_set_verified: Literal[True] = Field(
        default=True,
        alias="completeCodeAuthoritySetVerified",
    )
    signed_release_required_for_execution: Literal[True] = Field(
        default=True,
        alias="signedReleaseRequiredForExecution",
    )
    current_activation_required_for_execution: Literal[True] = Field(
        default=True,
        alias="currentActivationRequiredForExecution",
    )
    release_bound: Literal[False] = Field(default=False, alias="releaseBound")
    activation_bound: Literal[False] = Field(default=False, alias="activationBound")
    legacy_capability_domain_interpreted: Literal[False] = Field(
        default=False,
        alias="legacyCapabilityDomainInterpreted",
    )
    surface_metadata_inferred: Literal[False] = Field(
        default=False,
        alias="surfaceMetadataInferred",
    )
    tool_metadata_inferred: Literal[False] = Field(
        default=False,
        alias="toolMetadataInferred",
    )
    profile_mapping_available: Literal[False] = Field(
        default=False,
        alias="profileMappingAvailable",
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
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    runtime_support_asserted_by_projection: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAssertedByProjection",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "projection_only",
        "explicit_mapping_reviewed",
        "complete_code_authority_set_verified",
        "signed_release_required_for_execution",
        "current_activation_required_for_execution",
        "release_bound",
        "activation_bound",
        "legacy_capability_domain_interpreted",
        "surface_metadata_inferred",
        "tool_metadata_inferred",
        "profile_mapping_available",
        "capability_activation_authorized",
        "scope_expansion_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "graph_admission_authorized",
        "finding_confirmation_authorized",
        "runtime_support_asserted_by_projection",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Capability Domain projection markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        spec = _capability_domain_spec(self.capability)
        if (
            self.capability != spec.capability_reference()
            or self.code_backed_capability != spec.code_backed_reference()
            or self.code_backed_capability.capability != self.capability
            or self.domain_classification != _domain_classification(spec.domain)
            or self.reviewed_surface_types != spec.reviewed_surface_types
            or self.reviewed_surface_types != tuple(sorted(set(self.reviewed_surface_types)))
        ):
            raise ValueError("Capability Domain classification differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("Capability Domain classification ID differs")
        object.__setattr__(self, "classification_digest", digest)
        object.__setattr__(self, "classification_id", classification_id)
        return self

    def reference(self) -> CapabilityDomainClassificationRef:
        """Return an exact detached classification reference."""

        return CapabilityDomainClassificationRef(
            classificationId=self.classification_id,
            classificationDigest=self.classification_digest,
            capability=self.capability,
            domainClassification=self.domain_classification,
        )


class CapabilityDomainInventoryProjection(StrictModel):
    """Exact current code-backed inventory with classification but no authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/capability-domain-inventory-projection/v1alpha1"
    ] = Field(
        default=CAPABILITY_DOMAIN_INVENTORY_PROJECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityDomainInventoryProjection"] = (
        "CapabilityDomainInventoryProjection"
    )
    projection_id: Literal["pajin.capability-domain-inventory.current"] = Field(
        default="pajin.capability-domain-inventory.current",
        alias="projectionId",
    )
    projection_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="projectionVersion",
    )
    projection_digest: str = Field(default="", alias="projectionDigest", max_length=64)
    security_domain_taxonomy_id: Literal["pajin.security-domain-taxonomy.core"] = Field(
        alias="securityDomainTaxonomyId"
    )
    security_domain_taxonomy_version: Literal["1.0.0"] = Field(
        alias="securityDomainTaxonomyVersion"
    )
    security_domain_taxonomy_digest: _Sha256 = Field(alias="securityDomainTaxonomyDigest")
    bindings: tuple[RegisteredCapabilityDomainClassification, ...] = Field(
        min_length=_EXPECTED_CAPABILITY_COUNT,
        max_length=_EXPECTED_CAPABILITY_COUNT,
    )
    classified_capability_count: Literal[9] = Field(
        default=9,
        alias="classifiedCapabilityCount",
    )
    classified_domain_count: Literal[3] = Field(default=3, alias="classifiedDomainCount")
    unclassified_capability_count: Literal[0] = Field(
        default=0,
        alias="unclassifiedCapabilityCount",
    )
    projection_only: Literal[True] = Field(default=True, alias="projectionOnly")
    exact_code_backed_inventory_verified: Literal[True] = Field(
        default=True,
        alias="exactCodeBackedInventoryVerified",
    )
    release_inventory_bound: Literal[False] = Field(
        default=False,
        alias="releaseInventoryBound",
    )
    activation_inventory_bound: Literal[False] = Field(
        default=False,
        alias="activationInventoryBound",
    )
    profile_mapping_available: Literal[False] = Field(
        default=False,
        alias="profileMappingAvailable",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
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
    runtime_support_asserted_by_projection: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAssertedByProjection",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "projection_only",
        "exact_code_backed_inventory_verified",
        "release_inventory_bound",
        "activation_inventory_bound",
        "profile_mapping_available",
        "capability_activation_authorized",
        "scope_expansion_authorized",
        "permit_issuance_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "runtime_support_asserted_by_projection",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Capability Domain inventory markers must be booleans")
        return value

    @field_validator(
        "classified_capability_count",
        "classified_domain_count",
        "unclassified_capability_count",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Capability Domain inventory counts must be integers")
        return value

    @model_validator(mode="after")
    def bind_projection_identity(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        if (
            (
                self.security_domain_taxonomy_id,
                self.security_domain_taxonomy_version,
                self.security_domain_taxonomy_digest,
            )
            != (taxonomy.taxonomy_id, taxonomy.taxonomy_version, taxonomy.taxonomy_digest)
            or self.bindings != _registered_classifications()
            or len({item.domain_classification.domain for item in self.bindings})
            != _EXPECTED_DOMAIN_COUNT
        ):
            raise ValueError("Capability Domain inventory projection differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"projection_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.domain-inventory-projection/v1",
            material,
        )
        if self.projection_digest and self.projection_digest != digest:
            raise ValueError("Capability Domain inventory projection digest differs")
        object.__setattr__(self, "projection_digest", digest)
        return self


def registered_capability_domain_inventory_projection(
    *,
    existing_bundle: ExistingModeCapabilityBundle,
    pentest_recon_bundle: PentestReconCapabilityBundle,
) -> CapabilityDomainInventoryProjection:
    """Project the exact current CAP-001/CAP-002 inventory without activation authority."""

    _verify_source_inventory(existing_bundle, pentest_recon_bundle)
    taxonomy = registered_security_domain_taxonomy()
    return CapabilityDomainInventoryProjection(
        securityDomainTaxonomyId=taxonomy.taxonomy_id,
        securityDomainTaxonomyVersion=taxonomy.taxonomy_version,
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        bindings=_registered_classifications(),
    )


def resolve_registered_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
    *,
    existing_bundle: ExistingModeCapabilityBundle,
    pentest_recon_bundle: PentestReconCapabilityBundle,
) -> RegisteredCapabilityDomainClassification:
    """Resolve exact inventory metadata without resolving a release or activation."""

    projection = registered_capability_domain_inventory_projection(
        existing_bundle=existing_bundle,
        pentest_recon_bundle=pentest_recon_bundle,
    )
    for classification in projection.bindings:
        if classification.reference() == reference:
            return classification.model_copy(deep=True)
    raise CapabilityDomainProjectionError(
        "Capability Domain classification is not registered exactly"
    )


def _registered_classifications() -> tuple[RegisteredCapabilityDomainClassification, ...]:
    return tuple(
        RegisteredCapabilityDomainClassification(
            capability=spec.capability_reference(),
            codeBackedCapability=spec.code_backed_reference(),
            domainClassification=_domain_classification(spec.domain),
            reviewedSurfaceTypes=spec.reviewed_surface_types,
        )
        for spec in _CAPABILITY_DOMAIN_SPECS
    )


def _verify_source_inventory(
    existing_bundle: ExistingModeCapabilityBundle,
    pentest_recon_bundle: PentestReconCapabilityBundle,
) -> None:
    if not isinstance(existing_bundle, ExistingModeCapabilityBundle):
        raise TypeError("Capability Domain projection requires an existing Mode bundle")
    if not isinstance(pentest_recon_bundle, PentestReconCapabilityBundle):
        raise TypeError("Capability Domain projection requires a Pentest Recon bundle")
    try:
        existing_manifests = existing_bundle.capabilities()
        pentest_manifests = pentest_recon_bundle.authorities.capabilities()
        if len(pentest_manifests) != 1:
            raise CapabilityDomainProjectionError(
                "Pentest Recon Capability authority inventory differs"
            )
        observed: list[
            tuple[CapabilityDefinitionRef, CodeBackedCapabilityRef, tuple[str, ...]]
        ] = []
        for manifest in existing_manifests:
            definition = existing_bundle.definitions.resolve(manifest.capability)
            observed.append(
                (
                    definition.reference(),
                    manifest.reference(),
                    definition.supported_surface_types,
                )
            )
        for manifest in pentest_manifests:
            definition = pentest_recon_bundle.definitions.resolve(manifest.capability)
            observed.append(
                (
                    definition.reference(),
                    manifest.reference(),
                    definition.supported_surface_types,
                )
            )
    except (CapabilityAuthorityError, CapabilityDefinitionError) as exc:
        raise CapabilityDomainProjectionError(
            "Capability Domain source inventory failed exact CAP-001/CAP-002 verification"
        ) from exc
    expected = [
        (
            spec.capability_reference(),
            spec.code_backed_reference(),
            spec.reviewed_surface_types,
        )
        for spec in _CAPABILITY_DOMAIN_SPECS
    ]
    if sorted(observed, key=_observed_key) != expected:
        raise CapabilityDomainProjectionError(
            "Capability Domain source inventory differs from the reviewed exact inventory"
        )


def _observed_key(
    item: tuple[CapabilityDefinitionRef, CodeBackedCapabilityRef, tuple[str, ...]],
) -> tuple[str, str]:
    return item[0].capability_id, item[0].capability_version


def _capability_domain_spec(reference: CapabilityDefinitionRef) -> _CapabilityDomainSpec:
    for spec in _CAPABILITY_DOMAIN_SPECS:
        if (
            spec.capability_id,
            spec.capability_version,
        ) == (reference.capability_id, reference.capability_version):
            return spec
    raise ValueError("Capability Domain classification is not code registered")


def _domain_classification(domain: SecurityDomain) -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(item.reference() for item in taxonomy.domains if item.domain is domain)
