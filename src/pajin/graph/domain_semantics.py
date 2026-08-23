"""DOMAIN-002 additive multi-domain semantics over the existing Canonical Graph."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)
from pajin.graph.admission import GRAPH_ADMISSION_EVENT_API_VERSION, GraphAdmissionAuthority
from pajin.graph.models import (
    GRAPH_EDGE_API_VERSION,
    GRAPH_NODE_API_VERSION,
    GRAPH_PROPOSAL_API_VERSION,
    GraphNodeKind,
    GraphRelation,
    graph_digest,
)

SECURITY_DOMAIN_GRAPH_TYPE_SET_API_VERSION: Literal[
    "pajin.dev/security-domain-graph-type-set/v1alpha1"
] = "pajin.dev/security-domain-graph-type-set/v1alpha1"
MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION: Literal[
    "pajin.dev/multi-domain-graph-semantics/v1alpha1"
] = "pajin.dev/multi-domain-graph-semantics/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_TYPE_SET_BYTES = 128 * 1024
_MAX_REGISTRY_BYTES = 2 * 1024 * 1024


class MultiDomainGraphSemanticsError(RuntimeError):
    """Raised when exact registered multi-domain Graph semantics cannot be resolved."""


_RELATION_SPECS = (
    (GraphRelation.MOTIVATES, GraphNodeKind.SURFACE, GraphNodeKind.HYPOTHESIS),
    (GraphRelation.TESTED_BY, GraphNodeKind.HYPOTHESIS, GraphNodeKind.ACTION),
    (GraphRelation.PRODUCES, GraphNodeKind.ACTION, GraphNodeKind.OBSERVATION),
    (GraphRelation.SUPPORTED_BY, GraphNodeKind.OBSERVATION, GraphNodeKind.EVIDENCE),
    (GraphRelation.SUPPORTS, GraphNodeKind.OBSERVATION, GraphNodeKind.HYPOTHESIS),
    (GraphRelation.CONTRADICTS, GraphNodeKind.OBSERVATION, GraphNodeKind.HYPOTHESIS),
    (GraphRelation.DISCOVERS, GraphNodeKind.OBSERVATION, GraphNodeKind.SURFACE),
    (GraphRelation.ENABLES, GraphNodeKind.OBSERVATION, GraphNodeKind.HYPOTHESIS),
)

_TYPE_SET_SPECS = (
    (
        SecurityDomain.WEB,
        "web.http-operation",
        "pajin.locator.web.http-operation.v1",
        "web.security-property",
        "web.protocol-observation",
    ),
    (
        SecurityDomain.NETWORK,
        "network.host-service",
        "pajin.locator.network.host-service.v1",
        "network.exposure",
        "network.protocol-observation",
    ),
    (
        SecurityDomain.SYSTEM,
        "system.host-resource",
        "pajin.locator.system.host-resource.v1",
        "system.security-configuration",
        "system.host-observation",
    ),
    (
        SecurityDomain.APPLICATION,
        "application.artifact-runtime",
        "pajin.locator.application.artifact-runtime.v1",
        "application.vulnerability",
        "application.analysis-observation",
    ),
    (
        SecurityDomain.MOBILE,
        "mobile.application-runtime",
        "pajin.locator.mobile.application-runtime.v1",
        "mobile.security-property",
        "mobile.analysis-observation",
    ),
    (
        SecurityDomain.CLOUD,
        "cloud.account-resource",
        "pajin.locator.cloud.account-resource.v1",
        "cloud.policy-exposure",
        "cloud.api-observation",
    ),
    (
        SecurityDomain.AI,
        "ai.model-rag-agent-tool",
        "pajin.locator.ai.model-rag-agent-tool.v1",
        "ai.security-property",
        "ai.behavior-observation",
    ),
    (
        SecurityDomain.CRYPTOGRAPHY,
        "cryptography.protocol-key-artifact",
        "pajin.locator.cryptography.protocol-key-artifact.v1",
        "cryptography.misuse-weakness",
        "cryptography.analysis-observation",
    ),
    (
        SecurityDomain.FORENSICS,
        "forensics.immutable-artifact",
        "pajin.locator.forensics.immutable-artifact.v1",
        "forensics.forensic-proposition",
        "forensics.analysis-observation",
    ),
)


class CanonicalGraphRelationSemantic(StrictModel):
    """One existing Canonical Graph relation and its fixed endpoint kinds."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    relation: GraphRelation
    source_kind: GraphNodeKind = Field(alias="sourceKind")
    target_kind: GraphNodeKind = Field(alias="targetKind")

    @model_validator(mode="after")
    def require_existing_relation_semantics(self) -> Self:
        expected = next(
            (item for item in _RELATION_SPECS if item[0] is self.relation),
            None,
        )
        if expected is None or (self.source_kind, self.target_kind) != expected[1:]:
            raise ValueError("Canonical Graph relation endpoints differ from Graph v1")
        return self


class SecurityDomainGraphTypeSetRef(StrictModel):
    """Exact content-addressed reference to one Domain Graph semantic type-set."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    type_set_id: _Identifier = Field(alias="typeSetId")
    type_set_version: Literal["1.0.0"] = Field(alias="typeSetVersion")
    type_set_digest: _Sha256 = Field(alias="typeSetDigest")
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )


class RegisteredSecurityDomainGraphTypeSet(StrictModel):
    """Non-executable Surface, locator, Hypothesis, and Observation semantic IDs."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/security-domain-graph-type-set/v1alpha1"] = Field(
        default=SECURITY_DOMAIN_GRAPH_TYPE_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredSecurityDomainGraphTypeSet"] = (
        "RegisteredSecurityDomainGraphTypeSet"
    )
    type_set_id: _Identifier = Field(alias="typeSetId")
    type_set_version: Literal["1.0.0"] = Field(default="1.0.0", alias="typeSetVersion")
    type_set_digest: str = Field(default="", alias="typeSetDigest", max_length=64)
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    surface_type: _Identifier = Field(alias="surfaceType")
    locator_schema: _Identifier = Field(alias="locatorSchema")
    hypothesis_type: _Identifier = Field(alias="hypothesisType")
    observation_type: _Identifier = Field(alias="observationType")
    semantics_only: Literal[True] = Field(default=True, alias="semanticsOnly")
    locator_schema_implementation_available: Literal[False] = Field(
        default=False,
        alias="locatorSchemaImplementationAvailable",
    )
    graph_producer_registered: Literal[False] = Field(
        default=False,
        alias="graphProducerRegistered",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "semantics_only",
        "locator_schema_implementation_available",
        "graph_producer_registered",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Domain Graph semantic markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_type_set_identity(self) -> Self:
        domain = self.domain_classification.domain
        expected = _type_set_spec(domain)
        expected_classification = _domain_classification(domain)
        if (
            self.domain_classification != expected_classification
            or self.type_set_id != f"pajin.graph-semantics.{domain.value}"
            or (
                self.surface_type,
                self.locator_schema,
                self.hypothesis_type,
                self.observation_type,
            )
            != expected[1:]
        ):
            raise ValueError("Security Domain Graph type-set differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"type_set_digest"},
        )
        digest = graph_digest(
            "pajin.graph.security-domain-type-set/v1",
            material,
            max_bytes=_MAX_TYPE_SET_BYTES,
        )
        if self.type_set_digest and self.type_set_digest != digest:
            raise ValueError("Security Domain Graph type-set Digest differs")
        object.__setattr__(self, "type_set_digest", digest)
        return self

    def reference(self) -> SecurityDomainGraphTypeSetRef:
        """Return the exact content-addressed type-set reference."""

        return SecurityDomainGraphTypeSetRef(
            typeSetId=self.type_set_id,
            typeSetVersion=self.type_set_version,
            typeSetDigest=self.type_set_digest,
            domainClassification=self.domain_classification,
        )


class MultiDomainGraphSemanticsRegistry(StrictModel):
    """Exact DOMAIN-002 semantics bound to Graph v1 and its existing single writer."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/multi-domain-graph-semantics/v1alpha1"] = Field(
        default=MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MultiDomainGraphSemanticsRegistry"] = (
        "MultiDomainGraphSemanticsRegistry"
    )
    registry_id: Literal["pajin.multi-domain-graph-semantics.core"] = Field(
        default="pajin.multi-domain-graph-semantics.core",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_id: Literal["pajin.security-domain-taxonomy.core"] = Field(
        alias="securityDomainTaxonomyId"
    )
    security_domain_taxonomy_version: Literal["1.0.0"] = Field(
        alias="securityDomainTaxonomyVersion"
    )
    security_domain_taxonomy_digest: _Sha256 = Field(alias="securityDomainTaxonomyDigest")
    graph_node_api_version: Literal["pajin.dev/canonical-graph-node/v1alpha1"] = Field(
        default=GRAPH_NODE_API_VERSION,
        alias="graphNodeApiVersion",
    )
    graph_edge_api_version: Literal["pajin.dev/canonical-graph-edge/v1alpha1"] = Field(
        default=GRAPH_EDGE_API_VERSION,
        alias="graphEdgeApiVersion",
    )
    graph_proposal_api_version: Literal["pajin.dev/canonical-graph-proposal/v1alpha1"] = Field(
        default=GRAPH_PROPOSAL_API_VERSION,
        alias="graphProposalApiVersion",
    )
    graph_admission_event_api_version: Literal[
        "pajin.dev/graph-admission-event/v1alpha1"
    ] = Field(
        default=GRAPH_ADMISSION_EVENT_API_VERSION,
        alias="graphAdmissionEventApiVersion",
    )
    graph_node_kinds: tuple[GraphNodeKind, ...] = Field(
        alias="graphNodeKinds",
        min_length=6,
        max_length=6,
    )
    graph_relations: tuple[CanonicalGraphRelationSemantic, ...] = Field(
        alias="graphRelations",
        min_length=8,
        max_length=8,
    )
    domain_type_sets: tuple[RegisteredSecurityDomainGraphTypeSet, ...] = Field(
        alias="domainTypeSets",
        min_length=9,
        max_length=9,
    )
    graph_writer_id: Literal["pajin.graph.admission.GraphAdmissionAuthority"] = Field(
        default="pajin.graph.admission.GraphAdmissionAuthority",
        alias="graphWriterId",
    )
    graph_writer_count: Literal[1] = Field(default=1, alias="graphWriterCount")
    domain_ledger_count: Literal[0] = Field(default=0, alias="domainLedgerCount")
    discovered_surface_initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="discoveredSurfaceInitialState",
    )
    semantics_only: Literal[True] = Field(default=True, alias="semanticsOnly")
    canonical_graph_schema_changed: Literal[False] = Field(
        default=False,
        alias="canonicalGraphSchemaChanged",
    )
    domain_specific_ledger_created: Literal[False] = Field(
        default=False,
        alias="domainSpecificLedgerCreated",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    source_authority_transfer_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAuthorityTransferAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("graph_writer_count", "domain_ledger_count", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Domain Graph writer and ledger counts must be integers")
        return value

    @field_validator(
        "semantics_only",
        "canonical_graph_schema_changed",
        "domain_specific_ledger_created",
        "graph_admission_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "permit_issuance_authorized",
        "source_authority_transfer_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Multi-domain Graph semantic markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_existing_graph_and_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        if (
            (
                self.security_domain_taxonomy_id,
                self.security_domain_taxonomy_version,
                self.security_domain_taxonomy_digest,
            )
            != (taxonomy.taxonomy_id, taxonomy.taxonomy_version, taxonomy.taxonomy_digest)
            or self.graph_node_kinds != tuple(GraphNodeKind)
            or self.graph_relations != _registered_relation_semantics()
            or self.domain_type_sets != _registered_domain_type_sets()
            or self.graph_writer_id != _graph_writer_id()
        ):
            raise ValueError("Multi-domain Graph semantics differ from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        digest = graph_digest(
            "pajin.graph.multi-domain-semantics/v1",
            material,
            max_bytes=_MAX_REGISTRY_BYTES,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Multi-domain Graph semantics registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self


def registered_multi_domain_graph_semantics() -> MultiDomainGraphSemanticsRegistry:
    """Return DOMAIN-002 semantics without Graph admission or execution authority."""

    taxonomy = registered_security_domain_taxonomy()
    return MultiDomainGraphSemanticsRegistry(
        securityDomainTaxonomyId=taxonomy.taxonomy_id,
        securityDomainTaxonomyVersion=taxonomy.taxonomy_version,
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        graphNodeKinds=tuple(GraphNodeKind),
        graphRelations=_registered_relation_semantics(),
        domainTypeSets=_registered_domain_type_sets(),
    )


def resolve_registered_security_domain_graph_type_set(
    reference: SecurityDomainGraphTypeSetRef,
) -> RegisteredSecurityDomainGraphTypeSet:
    """Resolve one exact semantic type-set without granting Graph or runtime authority."""

    for type_set in registered_multi_domain_graph_semantics().domain_type_sets:
        if type_set.reference() == reference:
            return type_set.model_copy(deep=True)
    raise MultiDomainGraphSemanticsError(
        "Security Domain Graph semantic type-set is not registered exactly"
    )


def _registered_relation_semantics() -> tuple[CanonicalGraphRelationSemantic, ...]:
    return tuple(
        CanonicalGraphRelationSemantic(
            relation=relation,
            sourceKind=source_kind,
            targetKind=target_kind,
        )
        for relation, source_kind, target_kind in _RELATION_SPECS
    )


def _registered_domain_type_sets() -> tuple[RegisteredSecurityDomainGraphTypeSet, ...]:
    return tuple(
        RegisteredSecurityDomainGraphTypeSet(
            typeSetId=f"pajin.graph-semantics.{domain.value}",
            domainClassification=_domain_classification(domain),
            surfaceType=surface_type,
            locatorSchema=locator_schema,
            hypothesisType=hypothesis_type,
            observationType=observation_type,
        )
        for (
            domain,
            surface_type,
            locator_schema,
            hypothesis_type,
            observation_type,
        ) in _TYPE_SET_SPECS
    )


def _domain_classification(domain: SecurityDomain) -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(item.reference() for item in taxonomy.domains if item.domain is domain)


def _type_set_spec(
    domain: SecurityDomain,
) -> tuple[SecurityDomain, str, str, str, str]:
    return next(item for item in _TYPE_SET_SPECS if item[0] is domain)


def _graph_writer_id() -> str:
    return f"{GraphAdmissionAuthority.__module__}.{GraphAdmissionAuthority.__qualname__}"
