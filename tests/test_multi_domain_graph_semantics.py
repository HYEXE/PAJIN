from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.admission import GRAPH_ADMISSION_EVENT_API_VERSION, GraphAdmissionAuthority
from pajin.graph.domain_semantics import (
    CanonicalGraphRelationSemantic,
    MultiDomainGraphSemanticsError,
    MultiDomainGraphSemanticsRegistry,
    RegisteredSecurityDomainGraphTypeSet,
    SecurityDomainGraphTypeSetRef,
    registered_multi_domain_graph_semantics,
    resolve_registered_security_domain_graph_type_set,
)
from pajin.graph.models import (
    GRAPH_EDGE_API_VERSION,
    GRAPH_NODE_API_VERSION,
    GRAPH_PROPOSAL_API_VERSION,
    GraphEdge,
    GraphHypothesis,
    GraphNodeKind,
    GraphNodeRef,
    GraphObservation,
    GraphRelation,
    GraphSurface,
)

_REGISTRY_AUTHORITY_ALIASES = (
    "canonicalGraphSchemaChanged",
    "domainSpecificLedgerCreated",
    "graphAdmissionAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "permitIssuanceAuthorized",
    "sourceAuthorityTransferAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_TYPE_SET_FALSE_ALIASES = (
    "locatorSchemaImplementationAvailable",
    "graphProducerRegistered",
    "graphAdmissionAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)


def _node_ref(tag: str, kind: GraphNodeKind) -> GraphNodeRef:
    return GraphNodeRef(
        campaignId="domain-semantics",
        nodeId="graph-node_" + sha256(tag.encode()).hexdigest(),
        kind=kind,
    )


def test_registry_reuses_exact_graph_v1_vocabulary_and_single_writer() -> None:
    registry = registered_multi_domain_graph_semantics()
    taxonomy = registered_security_domain_taxonomy()

    assert (
        registry.security_domain_taxonomy_id,
        registry.security_domain_taxonomy_version,
        registry.security_domain_taxonomy_digest,
    ) == (taxonomy.taxonomy_id, taxonomy.taxonomy_version, taxonomy.taxonomy_digest)
    assert registry.graph_node_api_version == GRAPH_NODE_API_VERSION
    assert registry.graph_edge_api_version == GRAPH_EDGE_API_VERSION
    assert registry.graph_proposal_api_version == GRAPH_PROPOSAL_API_VERSION
    assert registry.graph_admission_event_api_version == GRAPH_ADMISSION_EVENT_API_VERSION
    assert registry.graph_node_kinds == tuple(GraphNodeKind)
    assert tuple(item.relation for item in registry.graph_relations) == tuple(GraphRelation)
    assert registry.graph_writer_id == (
        f"{GraphAdmissionAuthority.__module__}.{GraphAdmissionAuthority.__qualname__}"
    )
    assert registry.graph_writer_count == 1
    assert registry.domain_ledger_count == 0
    assert registry.discovered_surface_initial_state == "registered-not-authorized"
    assert registry.semantics_only is True
    assert len(registry.registry_digest) == 64
    assert MultiDomainGraphSemanticsRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    ) == registry


def test_registered_relation_endpoints_match_graph_edge_validation() -> None:
    registry = registered_multi_domain_graph_semantics()

    for index, semantic in enumerate(registry.graph_relations):
        edge = GraphEdge(
            campaignId="domain-semantics",
            relation=semantic.relation,
            source=_node_ref(f"source-{index}", semantic.source_kind),
            target=_node_ref(f"target-{index}", semantic.target_kind),
            authorityId="pajin.graph.admission.test",
            authorityDigest=sha256(b"graph-admission-test").hexdigest(),
        )
        assert edge.relation is semantic.relation


def test_nine_domain_type_sets_are_exact_semantics_without_runtime_claims() -> None:
    registry = registered_multi_domain_graph_semantics()

    assert tuple(
        item.domain_classification.domain for item in registry.domain_type_sets
    ) == tuple(SecurityDomain)
    assert tuple(
        (
            item.surface_type,
            item.locator_schema,
            item.hypothesis_type,
            item.observation_type,
        )
        for item in registry.domain_type_sets
    ) == (
        (
            "web.http-operation",
            "pajin.locator.web.http-operation.v1",
            "web.security-property",
            "web.protocol-observation",
        ),
        (
            "network.host-service",
            "pajin.locator.network.host-service.v1",
            "network.exposure",
            "network.protocol-observation",
        ),
        (
            "system.host-resource",
            "pajin.locator.system.host-resource.v1",
            "system.security-configuration",
            "system.host-observation",
        ),
        (
            "application.artifact-runtime",
            "pajin.locator.application.artifact-runtime.v1",
            "application.vulnerability",
            "application.analysis-observation",
        ),
        (
            "mobile.application-runtime",
            "pajin.locator.mobile.application-runtime.v1",
            "mobile.security-property",
            "mobile.analysis-observation",
        ),
        (
            "cloud.account-resource",
            "pajin.locator.cloud.account-resource.v1",
            "cloud.policy-exposure",
            "cloud.api-observation",
        ),
        (
            "ai.model-rag-agent-tool",
            "pajin.locator.ai.model-rag-agent-tool.v1",
            "ai.security-property",
            "ai.behavior-observation",
        ),
        (
            "cryptography.protocol-key-artifact",
            "pajin.locator.cryptography.protocol-key-artifact.v1",
            "cryptography.misuse-weakness",
            "cryptography.analysis-observation",
        ),
        (
            "forensics.immutable-artifact",
            "pajin.locator.forensics.immutable-artifact.v1",
            "forensics.forensic-proposition",
            "forensics.analysis-observation",
        ),
    )
    assert len({item.type_set_digest for item in registry.domain_type_sets}) == 9
    for item in registry.domain_type_sets:
        payload = item.model_dump(mode="json", by_alias=True)
        assert item.semantics_only is True
        assert all(payload[alias] is False for alias in _TYPE_SET_FALSE_ALIASES)
    registry_payload = registry.model_dump(mode="json", by_alias=True)
    assert all(registry_payload[alias] is False for alias in _REGISTRY_AUTHORITY_ALIASES)


@pytest.mark.parametrize("domain", tuple(SecurityDomain))
def test_exact_type_set_resolution_grants_no_graph_or_execution_authority(
    domain: SecurityDomain,
) -> None:
    source = next(
        item
        for item in registered_multi_domain_graph_semantics().domain_type_sets
        if item.domain_classification.domain is domain
    )
    resolved = resolve_registered_security_domain_graph_type_set(source.reference())

    assert resolved == source
    assert resolved is not source
    assert resolved.graph_admission_authorized is False
    assert resolved.execution_authorized is False
    assert {
        "profile_id",
        "capability_id",
        "tool_id",
        "worker_id",
        "scope",
        "permit",
    }.isdisjoint(RegisteredSecurityDomainGraphTypeSet.model_fields)


def test_exact_type_set_resolution_rejects_digest_and_domain_substitution() -> None:
    registry = registered_multi_domain_graph_semantics()
    source = registry.domain_type_sets[0]
    wrong_digest = source.reference().model_copy(update={"type_set_digest": "0" * 64})
    wrong_domain = source.reference().model_copy(
        update={"domain_classification": registry.domain_type_sets[1].domain_classification}
    )

    with pytest.raises(MultiDomainGraphSemanticsError, match="not registered exactly"):
        resolve_registered_security_domain_graph_type_set(wrong_digest)
    with pytest.raises(MultiDomainGraphSemanticsError, match="not registered exactly"):
        resolve_registered_security_domain_graph_type_set(wrong_domain)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("typeSetVersion", "latest"),
        ("typeSetVersion", "2.0.0"),
        ("typeSetDigest", "not-a-digest"),
    ),
)
def test_type_set_reference_rejects_implicit_or_unknown_identity(
    field: str,
    value: object,
) -> None:
    payload = registered_multi_domain_graph_semantics().domain_type_sets[0].reference().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        SecurityDomainGraphTypeSetRef.model_validate(payload)


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("registryDigest",), "0" * 64),
        (("securityDomainTaxonomyDigest",), "1" * 64),
        (("graphNodeApiVersion",), "pajin.dev/canonical-graph-node/v2"),
        (("graphNodeKinds",), "reverse"),
        (("graphRelations",), "reverse"),
        (("graphRelations", 0, "sourceKind"), "Observation"),
        (("domainTypeSets",), "reverse"),
        (("domainTypeSets", 0, "surfaceType"), "cloud.account-resource"),
        (("domainTypeSets", 0, "domainClassification"), "next-domain"),
        (("graphWriterId",), "pajin.graph.domain.WebGraphWriter"),
        (("discoveredSurfaceInitialState",), "authorized"),
    ),
)
def test_registry_rejects_graph_or_domain_semantic_substitution(
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    payload = registered_multi_domain_graph_semantics().model_dump(mode="json", by_alias=True)
    if replacement == "reverse":
        replacement = list(reversed(payload[path[0]]))
    elif replacement == "next-domain":
        replacement = deepcopy(payload["domainTypeSets"][1]["domainClassification"])
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    if path != ("registryDigest",):
        payload["registryDigest"] = ""
    if path[:2] == ("domainTypeSets", 0):
        payload["domainTypeSets"][0]["typeSetDigest"] = ""

    with pytest.raises(ValidationError):
        MultiDomainGraphSemanticsRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_AUTHORITY_ALIASES)
@pytest.mark.parametrize("escalated", (True, 1, "false"))
def test_registry_authority_markers_fail_closed(alias: str, escalated: object) -> None:
    payload = registered_multi_domain_graph_semantics().model_dump(mode="json", by_alias=True)
    payload[alias] = escalated
    payload["registryDigest"] = ""

    with pytest.raises(ValidationError):
        MultiDomainGraphSemanticsRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _TYPE_SET_FALSE_ALIASES)
@pytest.mark.parametrize("escalated", (True, 0, "false"))
def test_type_set_authority_and_implementation_markers_fail_closed(
    alias: str,
    escalated: object,
) -> None:
    payload = registered_multi_domain_graph_semantics().domain_type_sets[0].model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = escalated
    payload["typeSetDigest"] = ""

    with pytest.raises(ValidationError):
        RegisteredSecurityDomainGraphTypeSet.model_validate(payload)


@pytest.mark.parametrize("value", (False, 1, "true"))
def test_type_set_semantics_only_marker_is_exact(value: object) -> None:
    payload = registered_multi_domain_graph_semantics().domain_type_sets[0].model_dump(
        mode="json",
        by_alias=True,
    )
    payload["semanticsOnly"] = value
    payload["typeSetDigest"] = ""

    with pytest.raises(ValidationError):
        RegisteredSecurityDomainGraphTypeSet.model_validate(payload)


@pytest.mark.parametrize("value", (False, 1, "true"))
def test_registry_semantics_only_marker_is_exact(value: object) -> None:
    payload = registered_multi_domain_graph_semantics().model_dump(mode="json", by_alias=True)
    payload["semanticsOnly"] = value
    payload["registryDigest"] = ""

    with pytest.raises(ValidationError):
        MultiDomainGraphSemanticsRegistry.model_validate(payload)


@pytest.mark.parametrize(
    ("alias", "value"),
    (
        ("profileId", "pajin.profile.pentest"),
        ("capabilityId", "pajin.discovery.read-surface"),
        ("toolId", "http.get"),
        ("workerId", "worker:any"),
        ("scope", {"targets": ["example.test"]}),
        ("permitId", "permit:any"),
    ),
)
def test_type_set_rejects_authority_mapping_fields(alias: str, value: object) -> None:
    payload = registered_multi_domain_graph_semantics().domain_type_sets[0].model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = value
    payload["typeSetDigest"] = ""

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredSecurityDomainGraphTypeSet.model_validate(payload)


@pytest.mark.parametrize(
    ("alias", "value"),
    (
        ("graphWriterCount", 2),
        ("domainLedgerCount", 1),
        ("graphWriterCount", True),
        ("domainLedgerCount", "0"),
    ),
)
def test_registry_rejects_parallel_writer_or_domain_ledger(alias: str, value: object) -> None:
    payload = registered_multi_domain_graph_semantics().model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["registryDigest"] = ""

    with pytest.raises(ValidationError):
        MultiDomainGraphSemanticsRegistry.model_validate(payload)


def test_domain_semantics_do_not_change_existing_graph_node_identity() -> None:
    before = GraphSurface(
        campaignId="domain-semantics",
        targetId="target.web",
        surfaceType="http-endpoint",
        locatorSchema="pajin.discovery.http-endpoint.v1",
        locatorDigest=sha256(b"https://example.test/|GET").hexdigest(),
        origin="operator",
    )

    registered_multi_domain_graph_semantics()

    after = GraphSurface.model_validate(before.model_dump(mode="json", by_alias=True))
    assert after == before
    assert after.node_id == before.node_id
    assert "domain" not in GraphSurface.model_fields
    assert "domain" not in GraphHypothesis.model_fields
    assert "domain" not in GraphObservation.model_fields


def test_relation_semantic_rejects_reversed_endpoint_kinds() -> None:
    with pytest.raises(ValidationError, match="endpoints differ"):
        CanonicalGraphRelationSemantic(
            relation=GraphRelation.DISCOVERS,
            sourceKind=GraphNodeKind.SURFACE,
            targetKind=GraphNodeKind.OBSERVATION,
        )
