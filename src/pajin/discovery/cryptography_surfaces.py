"""CRYPTO-001A typed Cryptography Surfaces without key-use or analysis authority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, TypeAdapter, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import DISCOVERY_API_VERSION
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SECURITY_DOMAIN_TAXONOMY_API_VERSION,
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)
from pajin.graph.domain_semantics import (
    MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
    SecurityDomainGraphTypeSetRef,
    registered_multi_domain_graph_semantics,
)

CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_API_VERSION: Literal[
    "pajin.dev/cryptography-protocol-key-artifact-locator/v1alpha1"
] = "pajin.dev/cryptography-protocol-key-artifact-locator/v1alpha1"
CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/cryptography-protocol-key-artifact-locator-registry/v1alpha1"
] = "pajin.dev/cryptography-protocol-key-artifact-locator-registry/v1alpha1"
CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_API_VERSION: Literal[
    "pajin.dev/cryptography-protocol-key-artifact-surface/v1alpha1"
] = "pajin.dev/cryptography-protocol-key-artifact-surface/v1alpha1"

CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_TYPE: Literal["cryptography.protocol-key-artifact"] = (
    "cryptography.protocol-key-artifact"
)
CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_SCHEMA: Literal[
    "pajin.locator.cryptography.protocol-key-artifact.v1"
] = "pajin.locator.cryptography.protocol-key-artifact.v1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"),
]
_Coordinate = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._+-][a-z0-9]+)*$",
    ),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^cryptography-protocol-key-artifact-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 512 * 1024
_MAX_TYPED_SURFACE_BYTES = 512 * 1024
_MUTABLE_COORDINATE_TOKENS = frozenset(
    {
        "any",
        "auto",
        "current",
        "default",
        "latest",
        "local",
        "stable",
        "unknown",
        "x",
    }
)


class CryptographySurfaceRegistryError(RuntimeError):
    """Raised when an exact CRYPTO-001A registry reference cannot be resolved."""


class CryptographySurfaceClass(StrEnum):
    """Cryptography knowledge classes that grant no key-use or analysis authority."""

    PROTOCOL = "protocol"
    KEY_USAGE = "key-usage"
    CIPHERTEXT = "ciphertext"
    CONFIGURATION = "configuration"


class CryptographicKeyUsageKind(StrEnum):
    """Bounded declared key-use purposes, never permission to perform the operation."""

    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNATURE_GENERATION = "signature-generation"
    SIGNATURE_VERIFICATION = "signature-verification"
    KEY_AGREEMENT = "key-agreement"
    KEY_DERIVATION = "key-derivation"
    MAC_GENERATION = "mac-generation"
    MAC_VERIFICATION = "mac-verification"
    KEY_WRAPPING = "key-wrapping"
    KEY_UNWRAPPING = "key-unwrapping"


class _SecretFreeCryptographyLocator(StrictModel):
    """Negative markers shared by content-free Cryptography locators."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    raw_key_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawKeyMaterialEmbedded",
    )
    key_reference_embedded: Literal[False] = Field(
        default=False,
        alias="keyReferenceEmbedded",
    )
    raw_ciphertext_embedded: Literal[False] = Field(
        default=False,
        alias="rawCiphertextEmbedded",
    )
    raw_plaintext_embedded: Literal[False] = Field(
        default=False,
        alias="rawPlaintextEmbedded",
    )
    raw_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawConfigurationEmbedded",
    )
    raw_parameter_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawParameterMaterialEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )
    mutable_path_embedded: Literal[False] = Field(
        default=False,
        alias="mutablePathEmbedded",
    )
    oracle_result_embedded: Literal[False] = Field(
        default=False,
        alias="oracleResultEmbedded",
    )

    @field_validator(
        "raw_key_material_embedded",
        "key_reference_embedded",
        "raw_ciphertext_embedded",
        "raw_plaintext_embedded",
        "raw_configuration_embedded",
        "raw_parameter_material_embedded",
        "secret_material_embedded",
        "credential_reference_embedded",
        "mutable_path_embedded",
        "oracle_result_embedded",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cryptography locator security markers must be boolean false")
        return value


class CryptographicProtocolSurfaceLocator(_SecretFreeCryptographyLocator):
    """One caller-declared protocol coordinate with no negotiation or runtime claim."""

    kind: Literal["cryptography-protocol"] = "cryptography-protocol"
    protocol_namespace: _Coordinate = Field(alias="protocolNamespace")
    protocol_id: _Coordinate = Field(alias="protocolId")
    declaration_sha256: _Sha256 = Field(alias="declarationSha256")

    @field_validator("protocol_namespace", "protocol_id", mode="before")
    @classmethod
    def canonicalize_protocol_coordinate(cls, value: object) -> object:
        return _canonical_cryptography_coordinate(value, label="Cryptographic protocol coordinate")


class _CryptographicProtocolChildLocator(_SecretFreeCryptographyLocator):
    """Base for declarations below one exact Cryptographic protocol root."""

    parent: CryptographicProtocolSurfaceLocator

    @model_validator(mode="after")
    def require_exact_protocol_parent(self) -> Self:
        _validated_cryptographic_protocol(self.parent)
        return self


class CryptographicKeyUsageSurfaceLocator(_CryptographicProtocolChildLocator):
    """One sanitized key-use declaration without key identity, reference, or material."""

    kind: Literal["cryptography-key-usage"] = "cryptography-key-usage"
    usage_kind: CryptographicKeyUsageKind = Field(alias="usageKind")
    declaration_sha256: _Sha256 = Field(alias="declarationSha256")


class CryptographicCiphertextSurfaceLocator(_CryptographicProtocolChildLocator):
    """One ciphertext content coordinate without bytes, path, key association, or plaintext."""

    kind: Literal["cryptography-ciphertext"] = "cryptography-ciphertext"
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")


class CryptographicConfigurationSurfaceLocator(_CryptographicProtocolChildLocator):
    """One sanitized configuration declaration without paths, values, or parameters."""

    kind: Literal["cryptography-configuration"] = "cryptography-configuration"
    configuration_namespace: _Coordinate = Field(alias="configurationNamespace")
    configuration_id: _Coordinate = Field(alias="configurationId")
    declaration_sha256: _Sha256 = Field(alias="declarationSha256")

    @field_validator("configuration_namespace", "configuration_id", mode="before")
    @classmethod
    def canonicalize_configuration_coordinate(cls, value: object) -> object:
        return _canonical_cryptography_coordinate(
            value,
            label="Cryptographic configuration coordinate",
        )


CryptographyProtocolKeyArtifactSurfaceLocator = Annotated[
    CryptographicProtocolSurfaceLocator
    | CryptographicKeyUsageSurfaceLocator
    | CryptographicCiphertextSurfaceLocator
    | CryptographicConfigurationSurfaceLocator,
    Field(discriminator="kind"),
]
_CRYPTOGRAPHY_LOCATOR_ADAPTER: TypeAdapter[CryptographyProtocolKeyArtifactSurfaceLocator] = (
    TypeAdapter(CryptographyProtocolKeyArtifactSurfaceLocator)
)

CryptographySurfaceLocatorKind = Literal[
    "cryptography-protocol",
    "cryptography-key-usage",
    "cryptography-ciphertext",
    "cryptography-configuration",
]
CryptographyParentRequirement = Literal["none", "cryptography-protocol"]


@dataclass(frozen=True, slots=True)
class _CryptographyLocatorSpec:
    locator_id: str
    locator_kind: CryptographySurfaceLocatorKind
    surface_class: CryptographySurfaceClass
    source_model_id: str
    parent_requirement: CryptographyParentRequirement
    declaration_digest_required: bool
    artifact_digest_required: bool


_CRYPTOGRAPHY_LOCATOR_SPECS = (
    _CryptographyLocatorSpec(
        "pajin.locator.cryptography.protocol",
        "cryptography-protocol",
        CryptographySurfaceClass.PROTOCOL,
        "pajin.discovery.cryptography_surfaces.CryptographicProtocolSurfaceLocator",
        "none",
        True,
        False,
    ),
    _CryptographyLocatorSpec(
        "pajin.locator.cryptography.key-usage",
        "cryptography-key-usage",
        CryptographySurfaceClass.KEY_USAGE,
        "pajin.discovery.cryptography_surfaces.CryptographicKeyUsageSurfaceLocator",
        "cryptography-protocol",
        True,
        False,
    ),
    _CryptographyLocatorSpec(
        "pajin.locator.cryptography.ciphertext",
        "cryptography-ciphertext",
        CryptographySurfaceClass.CIPHERTEXT,
        "pajin.discovery.cryptography_surfaces.CryptographicCiphertextSurfaceLocator",
        "cryptography-protocol",
        False,
        True,
    ),
    _CryptographyLocatorSpec(
        "pajin.locator.cryptography.configuration",
        "cryptography-configuration",
        CryptographySurfaceClass.CONFIGURATION,
        "pajin.discovery.cryptography_surfaces.CryptographicConfigurationSurfaceLocator",
        "cryptography-protocol",
        True,
        False,
    ),
)


class CryptographyProtocolKeyArtifactLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered Cryptography locator."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: CryptographySurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: CryptographySurfaceClass = Field(alias="surfaceClass")

    @model_validator(mode="after")
    def bind_registered_locator_reference(self) -> Self:
        registered = next(
            (
                item
                for item in _registered_cryptography_locators()
                if item.locator_id == self.locator_id
            ),
            None,
        )
        if registered is None or (
            self.locator_version,
            self.locator_digest,
            self.locator_kind,
            self.surface_class,
        ) != (
            registered.locator_version,
            registered.locator_digest,
            registered.locator_kind,
            registered.surface_class,
        ):
            raise ValueError("Cryptography locator reference differs from code authority")
        return self


class CryptographyProtocolKeyArtifactLocatorRegistryRef(StrictModel):
    """Exact reference to the complete CRYPTO-001A locator registry."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    registry_id: Literal["pajin.cryptography.protocol-key-artifact-locators"] = Field(
        alias="registryId"
    )
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")

    @model_validator(mode="after")
    def bind_registered_registry_reference(self) -> Self:
        if (
            self.registry_id,
            self.registry_version,
            self.registry_digest,
        ) != _cryptography_locator_registry_identity():
            raise ValueError("Cryptography locator registry reference differs from code authority")
        return self


class CryptographyProtocolKeyArtifactSurfaceRef(StrictModel):
    """Exact reference to one inert typed Cryptography Surface."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["cryptography.protocol-key-artifact"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.cryptography.protocol-key-artifact.v1"] = Field(
        alias="locatorSchema"
    )
    surface_class: CryptographySurfaceClass = Field(alias="surfaceClass")
    locator_kind: CryptographySurfaceLocatorKind = Field(alias="locatorKind")
    locator_registry: CryptographyProtocolKeyArtifactLocatorRegistryRef = Field(
        alias="locatorRegistry"
    )

    @model_validator(mode="after")
    def bind_surface_reference(self) -> Self:
        registered = next(
            (
                item
                for item in _registered_cryptography_locators()
                if item.locator_kind == self.locator_kind
            ),
            None,
        )
        if (
            self.surface_id != f"cryptography-protocol-key-artifact-surface_{self.surface_digest}"
            or registered is None
            or registered.surface_class is not self.surface_class
            or (
                self.locator_registry.registry_id,
                self.locator_registry.registry_version,
                self.locator_registry.registry_digest,
            )
            != _cryptography_locator_registry_identity()
        ):
            raise ValueError("Cryptography Surface reference differs from code authority")
        return self


class _NoCryptographyAuthority(StrictModel):
    """Authority markers that remain literal false throughout CRYPTO-001A."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    artifact_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="artifactResolutionAuthorized",
    )
    artifact_read_authorized: Literal[False] = Field(
        default=False,
        alias="artifactReadAuthorized",
    )
    offline_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="offlineAnalysisAuthorized",
    )
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    key_use_authorized: Literal[False] = Field(default=False, alias="keyUseAuthorized")
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="oracleInvocationAuthorized",
    )
    recomputation_authorized: Literal[False] = Field(
        default=False,
        alias="recomputationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
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
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "artifact_resolution_authorized",
        "artifact_read_authorized",
        "offline_analysis_authorized",
        "key_material_access_authorized",
        "key_use_authorized",
        "cryptographic_operation_authorized",
        "protocol_negotiation_authorized",
        "oracle_invocation_authorized",
        "recomputation_authorized",
        "credential_access_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "graph_admission_authorized",
        "finding_authority",
        "artifact_mutation_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CRYPTO-001A authority markers must be boolean false")
        return value


class RegisteredCryptographyProtocolKeyArtifactLocator(_NoCryptographyAuthority):
    """One code-owned Cryptography locator mapping without key-use authority."""

    api_version: Literal["pajin.dev/cryptography-protocol-key-artifact-locator/v1alpha1"] = Field(
        default=CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredCryptographyProtocolKeyArtifactLocator"] = (
        "RegisteredCryptographyProtocolKeyArtifactLocator"
    )
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: CryptographySurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: CryptographySurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    parent_requirement: CryptographyParentRequirement = Field(alias="parentRequirement")
    declaration_digest_required: bool = Field(alias="declarationDigestRequired")
    artifact_digest_required: bool = Field(alias="artifactDigestRequired")
    secret_free: Literal[True] = Field(default=True, alias="secretFree")
    declaration_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="declarationSanitizationVerified",
    )
    full_parent_lineage_required: Literal[True] = Field(
        default=True,
        alias="fullParentLineageRequired",
    )
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    registration_only: Literal[True] = Field(default=True, alias="registrationOnly")

    @field_validator(
        "declaration_digest_required",
        "artifact_digest_required",
        "secret_free",
        "declaration_sanitization_verified",
        "full_parent_lineage_required",
        "locator_schema_implementation_available",
        "registration_only",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptography locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _CRYPTOGRAPHY_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
                self.parent_requirement,
                self.declaration_digest_required,
                self.artifact_digest_required,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
                spec.parent_requirement,
                spec.declaration_digest_required,
                spec.artifact_digest_required,
            )
            or self.domain_classification != _cryptography_domain_classification()
            or self.domain_graph_type_set != _cryptography_graph_type_set()
        ):
            raise ValueError(
                "Cryptography protocol/key/artifact locator differs from code authority"
            )
        material = self.model_dump(mode="json", by_alias=True, exclude={"locator_digest"})
        canonical_json_bytes(
            material,
            label="Cryptography protocol/key/artifact locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.cryptography-protocol-key-artifact-locator/v1",
            material,
        )
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("Cryptography protocol/key/artifact locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> CryptographyProtocolKeyArtifactLocatorRef:
        """Return the exact locator reference without authority transfer."""

        canonical = _validated_registered_cryptography_locator(self)
        return CryptographyProtocolKeyArtifactLocatorRef(
            locatorId=canonical.locator_id,
            locatorVersion=canonical.locator_version,
            locatorDigest=canonical.locator_digest,
            locatorKind=canonical.locator_kind,
            surfaceClass=canonical.surface_class,
        )


class CryptographyProtocolKeyArtifactLocatorRegistry(_NoCryptographyAuthority):
    """Complete CRYPTO-001A locator registry without analysis or key-use authority."""

    api_version: Literal[
        "pajin.dev/cryptography-protocol-key-artifact-locator-registry/v1alpha1"
    ] = Field(
        default=CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographyProtocolKeyArtifactLocatorRegistry"] = (
        "CryptographyProtocolKeyArtifactLocatorRegistry"
    )
    registry_id: Literal["pajin.cryptography.protocol-key-artifact-locators"] = Field(
        default="pajin.cryptography.protocol-key-artifact-locators",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_api_version: Literal["pajin.dev/security-domain-taxonomy/v1alpha1"] = (
        Field(
            default=SECURITY_DOMAIN_TAXONOMY_API_VERSION,
            alias="securityDomainTaxonomyApiVersion",
        )
    )
    security_domain_taxonomy_digest: _Sha256 = Field(alias="securityDomainTaxonomyDigest")
    multi_domain_graph_semantics_api_version: Literal[
        "pajin.dev/multi-domain-graph-semantics/v1alpha1"
    ] = Field(
        default=MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
        alias="multiDomainGraphSemanticsApiVersion",
    )
    multi_domain_graph_semantics_digest: _Sha256 = Field(alias="multiDomainGraphSemanticsDigest")
    discovery_api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="discoveryApiVersion",
    )
    surface_type: Literal["cryptography.protocol-key-artifact"] = Field(
        default=CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.cryptography.protocol-key-artifact.v1"] = Field(
        default=CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locators: tuple[RegisteredCryptographyProtocolKeyArtifactLocator, ...] = Field(
        min_length=len(_CRYPTOGRAPHY_LOCATOR_SPECS),
        max_length=len(_CRYPTOGRAPHY_LOCATOR_SPECS),
    )
    discovered_surface_initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="discoveredSurfaceInitialState",
    )
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    discovery_wire_changed: Literal[False] = Field(
        default=False,
        alias="discoveryWireChanged",
    )
    attack_surface_wire_changed: Literal[False] = Field(
        default=False,
        alias="attackSurfaceWireChanged",
    )
    domain_semantics_registry_changed: Literal[False] = Field(
        default=False,
        alias="domainSemanticsRegistryChanged",
    )

    @field_validator(
        "registry_only",
        "discovery_wire_changed",
        "attack_surface_wire_changed",
        "domain_semantics_registry_changed",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptography locator registry boundary markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        for locator in self.locators:
            _require_known_instance_fields(locator, label="Registered Cryptography locator")
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _cryptography_domain_classification()
            or self.domain_graph_type_set != _cryptography_graph_type_set()
            or self.locators != _registered_cryptography_locators()
            or tuple(item.surface_class for item in self.locators)
            != tuple(CryptographySurfaceClass)
        ):
            raise ValueError("Cryptography locator registry differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"registry_digest"})
        canonical_json_bytes(
            material,
            label="Cryptography protocol/key/artifact locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.cryptography-protocol-key-artifact-registry/v1",
            material,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Cryptography protocol/key/artifact registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> CryptographyProtocolKeyArtifactLocatorRegistryRef:
        """Return the exact complete registry reference."""

        canonical = _validated_cryptography_locator_registry(self)
        return CryptographyProtocolKeyArtifactLocatorRegistryRef(
            registryId=canonical.registry_id,
            registryVersion=canonical.registry_version,
            registryDigest=canonical.registry_digest,
        )


class CryptographyProtocolKeyArtifactSurface(_NoCryptographyAuthority):
    """Typed Cryptography knowledge that is neither analyzed nor Graph-admitted."""

    api_version: Literal["pajin.dev/cryptography-protocol-key-artifact-surface/v1alpha1"] = Field(
        default=CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographyProtocolKeyArtifactSurface"] = (
        "CryptographyProtocolKeyArtifactSurface"
    )
    surface_id: str = Field(default="", alias="surfaceId", max_length=120)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["cryptography.protocol-key-artifact"] = Field(
        default=CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.cryptography.protocol-key-artifact.v1"] = Field(
        default=CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: CryptographySurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locator_registry: CryptographyProtocolKeyArtifactLocatorRegistryRef = Field(
        alias="locatorRegistry"
    )
    locator: CryptographyProtocolKeyArtifactSurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    discovery_observed: Literal[False] = Field(default=False, alias="discoveryObserved")
    protocol_declaration_verified: Literal[False] = Field(
        default=False,
        alias="protocolDeclarationVerified",
    )
    key_usage_declaration_verified: Literal[False] = Field(
        default=False,
        alias="keyUsageDeclarationVerified",
    )
    ciphertext_resolved: Literal[False] = Field(default=False, alias="ciphertextResolved")
    ciphertext_bytes_verified: Literal[False] = Field(
        default=False,
        alias="ciphertextBytesVerified",
    )
    configuration_declaration_verified: Literal[False] = Field(
        default=False,
        alias="configurationDeclarationVerified",
    )
    declaration_sanitization_verified: Literal[False] = Field(
        default=False,
        alias="declarationSanitizationVerified",
    )
    algorithm_verified: Literal[False] = Field(default=False, alias="algorithmVerified")
    key_identity_verified: Literal[False] = Field(default=False, alias="keyIdentityVerified")
    misuse_confirmed: Literal[False] = Field(default=False, alias="misuseConfirmed")
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")

    @field_validator(
        "typed_surface_only",
        "discovery_observed",
        "protocol_declaration_verified",
        "key_usage_declaration_verified",
        "ciphertext_resolved",
        "ciphertext_bytes_verified",
        "configuration_declaration_verified",
        "declaration_sanitization_verified",
        "algorithm_verified",
        "key_identity_verified",
        "misuse_confirmed",
        "evidence_sealed",
        "graph_admitted",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed Cryptography Surface state markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_cryptography_protocol_key_artifact_locator_registry()
        _require_known_instance_fields(
            self.locator_registry,
            label="Cryptography locator registry reference",
        )
        canonical_locator = _validated_cryptography_locator(self.locator)
        registered = next(
            (item for item in registry.locators if item.locator_kind == canonical_locator.kind),
            None,
        )
        if (
            canonical_locator != self.locator
            or self.domain_classification != _cryptography_domain_classification()
            or self.domain_graph_type_set != _cryptography_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError("Typed Cryptography Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed Cryptography protocol/key/artifact Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.cryptography-protocol-key-artifact-surface/v1",
            material,
        )
        surface_id: _SurfaceId = f"cryptography-protocol-key-artifact-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed Cryptography Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed Cryptography Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> CryptographyProtocolKeyArtifactSurfaceRef:
        """Return a content-addressed inert Cryptography Surface reference."""

        canonical = _validated_cryptography_surface(self)
        return CryptographyProtocolKeyArtifactSurfaceRef(
            surfaceId=canonical.surface_id,
            surfaceDigest=canonical.surface_digest,
            surfaceType=canonical.surface_type,
            locatorSchema=canonical.locator_schema,
            surfaceClass=canonical.surface_class,
            locatorKind=canonical.locator.kind,
            locatorRegistry=canonical.locator_registry,
        )


def registered_cryptography_protocol_key_artifact_locator_registry() -> (
    CryptographyProtocolKeyArtifactLocatorRegistry
):
    """Return the CRYPTO-001A registry without analysis or key-use authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return CryptographyProtocolKeyArtifactLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_cryptography_domain_classification(),
        domainGraphTypeSet=_cryptography_graph_type_set(),
        locators=_registered_cryptography_locators(),
    )


@cache
def _cryptography_locator_registry_identity() -> tuple[str, str, str]:
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    return registry.registry_id, registry.registry_version, registry.registry_digest


def resolve_registered_cryptography_protocol_key_artifact_locator(
    reference: CryptographyProtocolKeyArtifactLocatorRef,
) -> RegisteredCryptographyProtocolKeyArtifactLocator:
    """Resolve one exact Cryptography locator without transferring authority."""

    try:
        _require_known_instance_fields(reference, label="Cryptography locator reference")
        canonical_reference = CryptographyProtocolKeyArtifactLocatorRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise CryptographySurfaceRegistryError(
            "Cryptography protocol/key/artifact locator is not registered exactly"
        ) from exc
    if canonical_reference != reference:
        raise CryptographySurfaceRegistryError(
            "Cryptography protocol/key/artifact locator is not registered exactly"
        )
    for locator in registered_cryptography_protocol_key_artifact_locator_registry().locators:
        if locator.reference() == canonical_reference:
            return locator.model_copy(deep=True)
    raise CryptographySurfaceRegistryError(
        "Cryptography protocol/key/artifact locator is not registered exactly"
    )


def resolve_cryptography_protocol_key_artifact_locator_registry(
    reference: CryptographyProtocolKeyArtifactLocatorRegistryRef,
) -> CryptographyProtocolKeyArtifactLocatorRegistry:
    """Resolve the complete Cryptography registry without activating analysis behavior."""

    try:
        _require_known_instance_fields(reference, label="Cryptography locator registry reference")
        canonical_reference = CryptographyProtocolKeyArtifactLocatorRegistryRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise CryptographySurfaceRegistryError(
            "Cryptography locator registry is not registered exactly"
        ) from exc
    if canonical_reference != reference:
        raise CryptographySurfaceRegistryError(
            "Cryptography locator registry is not registered exactly"
        )
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    if registry.reference() == canonical_reference:
        return registry.model_copy(deep=True)
    raise CryptographySurfaceRegistryError(
        "Cryptography locator registry is not registered exactly"
    )


def typed_cryptography_protocol_key_artifact_surface(
    *,
    locator: CryptographyProtocolKeyArtifactSurfaceLocator,
) -> CryptographyProtocolKeyArtifactSurface:
    """Type a revalidated locator as inert registered-not-authorized Cryptography knowledge."""

    canonical_locator = _validated_cryptography_locator(locator)
    registry = registered_cryptography_protocol_key_artifact_locator_registry()
    registered = next(
        item for item in registry.locators if item.locator_kind == canonical_locator.kind
    )
    return CryptographyProtocolKeyArtifactSurface(
        surfaceClass=registered.surface_class,
        domainClassification=_cryptography_domain_classification(),
        domainGraphTypeSet=_cryptography_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=canonical_locator,
    )


def cryptographic_protocol_surface_locator(
    *,
    protocol_namespace: str,
    protocol_id: str,
    declaration_sha256: str,
) -> CryptographicProtocolSurfaceLocator:
    """Build one sanitized protocol declaration without negotiation or runtime state."""

    return CryptographicProtocolSurfaceLocator(
        protocolNamespace=protocol_namespace,
        protocolId=protocol_id,
        declarationSha256=declaration_sha256,
    )


def cryptographic_key_usage_surface_locator(
    *,
    parent: CryptographicProtocolSurfaceLocator,
    usage_kind: CryptographicKeyUsageKind,
    declaration_sha256: str,
) -> CryptographicKeyUsageSurfaceLocator:
    """Build one sanitized use declaration without key identity, reference, or material."""

    return CryptographicKeyUsageSurfaceLocator(
        parent=_validated_cryptographic_protocol(parent),
        usageKind=usage_kind,
        declarationSha256=declaration_sha256,
    )


def cryptographic_ciphertext_surface_locator(
    *,
    parent: CryptographicProtocolSurfaceLocator,
    artifact_sha256: str,
) -> CryptographicCiphertextSurfaceLocator:
    """Build one ciphertext digest coordinate without reading or resolving bytes."""

    return CryptographicCiphertextSurfaceLocator(
        parent=_validated_cryptographic_protocol(parent),
        artifactSha256=artifact_sha256,
    )


def cryptographic_configuration_surface_locator(
    *,
    parent: CryptographicProtocolSurfaceLocator,
    configuration_namespace: str,
    configuration_id: str,
    declaration_sha256: str,
) -> CryptographicConfigurationSurfaceLocator:
    """Build one sanitized configuration declaration without paths or raw values."""

    return CryptographicConfigurationSurfaceLocator(
        parent=_validated_cryptographic_protocol(parent),
        configurationNamespace=configuration_namespace,
        configurationId=configuration_id,
        declarationSha256=declaration_sha256,
    )


@cache
def _registered_cryptography_locators() -> tuple[
    RegisteredCryptographyProtocolKeyArtifactLocator, ...
]:
    return tuple(
        RegisteredCryptographyProtocolKeyArtifactLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_cryptography_domain_classification(),
            domainGraphTypeSet=_cryptography_graph_type_set(),
            parentRequirement=spec.parent_requirement,
            declarationDigestRequired=spec.declaration_digest_required,
            artifactDigestRequired=spec.artifact_digest_required,
        )
        for spec in _CRYPTOGRAPHY_LOCATOR_SPECS
    )


@cache
def _cryptography_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.CRYPTOGRAPHY
    )


@cache
def _cryptography_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    )


def _validated_cryptographic_protocol(
    locator: CryptographicProtocolSurfaceLocator,
) -> CryptographicProtocolSurfaceLocator:
    if not isinstance(locator, CryptographicProtocolSurfaceLocator):
        raise ValueError("Cryptographic protocol parent has the wrong model type")
    _require_known_instance_fields(locator, label="Cryptographic protocol locator")
    canonical = CryptographicProtocolSurfaceLocator.model_validate(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Cryptographic protocol locator instance is not exact")
    return canonical


def _validated_cryptography_locator(
    locator: CryptographyProtocolKeyArtifactSurfaceLocator,
) -> (
    CryptographicProtocolSurfaceLocator
    | CryptographicKeyUsageSurfaceLocator
    | CryptographicCiphertextSurfaceLocator
    | CryptographicConfigurationSurfaceLocator
):
    if not isinstance(
        locator,
        CryptographicProtocolSurfaceLocator
        | CryptographicKeyUsageSurfaceLocator
        | CryptographicCiphertextSurfaceLocator
        | CryptographicConfigurationSurfaceLocator,
    ):
        raise ValueError("Cryptography protocol/key/artifact locator has the wrong model type")
    _require_known_instance_fields(locator, label="Cryptography protocol/key/artifact locator")
    if not isinstance(locator, CryptographicProtocolSurfaceLocator):
        _validated_cryptographic_protocol(locator.parent)
    canonical = _CRYPTOGRAPHY_LOCATOR_ADAPTER.validate_python(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Cryptography protocol/key/artifact locator instance is not exact")
    return canonical


def _require_known_instance_fields(model: StrictModel, *, label: str) -> None:
    unexpected = set(model.__dict__) - set(type(model).model_fields)
    if unexpected:
        raise ValueError(f"{label} contains unmodeled instance state")
    for field_name in type(model).model_fields:
        _require_known_instance_value(
            getattr(model, field_name),
            label=f"{label}.{field_name}",
        )


def _require_known_instance_value(value: object, *, label: str) -> None:
    if isinstance(value, StrictModel):
        _require_known_instance_fields(value, label=label)
    elif isinstance(value, tuple | list):
        for index, item in enumerate(value):
            _require_known_instance_value(item, label=f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_known_instance_value(item, label=f"{label}[{key!r}]")


def _validated_registered_cryptography_locator(
    locator: RegisteredCryptographyProtocolKeyArtifactLocator,
) -> RegisteredCryptographyProtocolKeyArtifactLocator:
    if not isinstance(locator, RegisteredCryptographyProtocolKeyArtifactLocator):
        raise ValueError("Registered Cryptography locator has the wrong model type")
    _require_known_instance_fields(locator, label="Registered Cryptography locator")
    canonical = RegisteredCryptographyProtocolKeyArtifactLocator.model_validate(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Registered Cryptography locator instance is not exact")
    return canonical


def _validated_cryptography_locator_registry(
    registry: CryptographyProtocolKeyArtifactLocatorRegistry,
) -> CryptographyProtocolKeyArtifactLocatorRegistry:
    if not isinstance(registry, CryptographyProtocolKeyArtifactLocatorRegistry):
        raise ValueError("Cryptography locator registry has the wrong model type")
    _require_known_instance_fields(registry, label="Cryptography locator registry")
    canonical = CryptographyProtocolKeyArtifactLocatorRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    )
    if canonical != registry:
        raise ValueError("Cryptography locator registry instance is not exact")
    return canonical


def _validated_cryptography_surface(
    surface: CryptographyProtocolKeyArtifactSurface,
) -> CryptographyProtocolKeyArtifactSurface:
    if not isinstance(surface, CryptographyProtocolKeyArtifactSurface):
        raise ValueError("Typed Cryptography Surface has the wrong model type")
    _require_known_instance_fields(surface, label="Typed Cryptography Surface")
    canonical = CryptographyProtocolKeyArtifactSurface.model_validate(
        surface.model_dump(mode="json", by_alias=True)
    )
    if canonical != surface:
        raise ValueError("Typed Cryptography Surface instance is not exact")
    return canonical


def _canonical_cryptography_coordinate(value: object, *, label: str) -> object:
    if not isinstance(value, str):
        return value
    if not value.isascii():
        raise ValueError(f"{label} must contain ASCII characters only")
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    if "://" in value or any(character in value for character in "/\\?#*@:%"):
        raise ValueError(f"{label} cannot contain path, URL, authority, or wildcard syntax")
    canonical = value.casefold()
    tokens = tuple(filter(None, re.split(r"[._+-]", canonical)))
    if not tokens or any(token in _MUTABLE_COORDINATE_TOKENS for token in tokens):
        raise ValueError(f"{label} must be one explicit stable coordinate")
    return canonical


__all__ = [
    "CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_API_VERSION",
    "CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_REGISTRY_API_VERSION",
    "CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_LOCATOR_SCHEMA",
    "CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_API_VERSION",
    "CRYPTOGRAPHY_PROTOCOL_KEY_ARTIFACT_SURFACE_TYPE",
    "CryptographicCiphertextSurfaceLocator",
    "CryptographicConfigurationSurfaceLocator",
    "CryptographicKeyUsageKind",
    "CryptographicKeyUsageSurfaceLocator",
    "CryptographicProtocolSurfaceLocator",
    "CryptographyParentRequirement",
    "CryptographyProtocolKeyArtifactLocatorRef",
    "CryptographyProtocolKeyArtifactLocatorRegistry",
    "CryptographyProtocolKeyArtifactLocatorRegistryRef",
    "CryptographyProtocolKeyArtifactSurface",
    "CryptographyProtocolKeyArtifactSurfaceLocator",
    "CryptographyProtocolKeyArtifactSurfaceRef",
    "CryptographySurfaceClass",
    "CryptographySurfaceLocatorKind",
    "CryptographySurfaceRegistryError",
    "RegisteredCryptographyProtocolKeyArtifactLocator",
    "cryptographic_ciphertext_surface_locator",
    "cryptographic_configuration_surface_locator",
    "cryptographic_key_usage_surface_locator",
    "cryptographic_protocol_surface_locator",
    "registered_cryptography_protocol_key_artifact_locator_registry",
    "resolve_cryptography_protocol_key_artifact_locator_registry",
    "resolve_registered_cryptography_protocol_key_artifact_locator",
    "typed_cryptography_protocol_key_artifact_surface",
]
