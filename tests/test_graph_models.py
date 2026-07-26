from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.graph import (
    CampaignFactPayload,
    CampaignFactProposal,
    CampaignFactValidationState,
    GraphAction,
    GraphActionStatus,
    GraphAuthorityKind,
    GraphCampaignFact,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphNode,
    GraphNodeKind,
    GraphObservation,
    GraphProposalLineage,
    GraphRelation,
    GraphSurface,
    ObservationProposal,
    SurfaceProposal,
    graph_node_ref,
    parse_graph_node,
    parse_graph_proposal,
)

NOW = datetime(2026, 7, 26, 4, 0, tzinfo=UTC)
CAMPAIGN = "graph-lab"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def _surface(*, campaign: str = CAMPAIGN) -> GraphSurface:
    return GraphSurface(
        campaignId=campaign,
        targetId="hybrid-target",
        surfaceType="http-endpoint",
        locatorSchema="pajin.discovery.http-surface.v1",
        locatorDigest=DIGEST_A,
        origin=GraphContentOrigin.TRUSTED_CORE,
    )


def _hypothesis(*, campaign: str = CAMPAIGN) -> GraphHypothesis:
    return GraphHypothesis(
        campaignId=campaign,
        hypothesisType="rag-indirect-prompt-injection",
        statement="Uploaded content may alter a RAG-backed agent decision.",
        expectedObservable="The agent requests a privileged MCP Tool after retrieval.",
        producerId="pajin.graph.test-hypothesis-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_B,
        origin=GraphContentOrigin.AGENT_DERIVED,
        confidence=0.7,
    )


def _action(*, campaign: str = CAMPAIGN) -> GraphAction:
    return GraphAction(
        campaignId=campaign,
        requestId="tool_graph_1",
        requestDigest=DIGEST_B,
        authorityKind=GraphAuthorityKind.CAPABILITY_GRANT,
        authorityId="grant_graph_1",
        authorityDigest=DIGEST_C,
        capabilityId="capability:rag-search",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_D,
        toolId="rag.search",
        targetDigest=DIGEST_E,
        status=GraphActionStatus.SUCCEEDED,
        executedAt=NOW,
    )


def _observation(
    *,
    campaign: str = CAMPAIGN,
    relation: str = "tool-authorization-requested",
    value_digest: str = DIGEST_C,
    summary: str = "The RAG response caused a privileged Tool request.",
) -> GraphObservation:
    return GraphObservation(
        campaignId=campaign,
        observationType=relation,
        summary=summary,
        valueDigest=value_digest,
        producerId="pajin.graph.test-observation-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_D,
        origin=GraphContentOrigin.TARGET_DERIVED,
        confidence=0.9,
        observedAt=NOW + timedelta(seconds=1),
    )


def _evidence(*, campaign: str = CAMPAIGN) -> GraphEvidence:
    return GraphEvidence(
        campaignId=campaign,
        reference="evidence/tool_graph_1.json",
        sha256=DIGEST_E,
        mediaType="application/json",
        sourceRootDigest=DIGEST_F,
        dataClassification="internal",
    )


def _fact(
    *,
    campaign: str = CAMPAIGN,
    value_digest: str = DIGEST_A,
    statement: str = "The target exposes a RAG-backed MCP integration.",
) -> GraphCampaignFact:
    return GraphCampaignFact(
        campaignId=campaign,
        factKey="target.rag-mcp-integration",
        statement=statement,
        valueDigest=value_digest,
        validationState=CampaignFactValidationState.ADMITTED,
        producerId="pajin.graph.test-fact-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_B,
        origin=GraphContentOrigin.AGENT_DERIVED,
        recordedAt=NOW + timedelta(seconds=2),
    )


def _fact_payload(
    *,
    value_digest: str = DIGEST_A,
    statement: str = "The target exposes a RAG-backed MCP integration.",
) -> CampaignFactPayload:
    return CampaignFactPayload(
        factKey="target.rag-mcp-integration",
        statement=statement,
        valueDigest=value_digest,
        producerId="pajin.graph.test-fact-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_B,
        origin=GraphContentOrigin.AGENT_DERIVED,
        recordedAt=NOW + timedelta(seconds=2),
    )


def _edge(
    relation: GraphRelation,
    source: GraphNode,
    target: GraphNode,
) -> GraphEdge:
    return GraphEdge(
        campaignId=CAMPAIGN,
        relation=relation,
        source=graph_node_ref(source),
        target=graph_node_ref(target),
        authorityId="pajin.graph.test-edge-authority",
        authorityDigest=DIGEST_F,
    )


def _lineage(
    *,
    campaign: str = CAMPAIGN,
    evidence: list[GraphEvidenceBinding] | None = None,
    action_permit_id: str | None = None,
    action_permit_digest: str | None = None,
) -> GraphProposalLineage:
    return GraphProposalLineage(
        campaignId=campaign,
        runId="run:graph:1",
        agentId="agent:graph-specialist",
        taskId="task:graph:1",
        requestId="tool_graph_1",
        requestDigest=DIGEST_B,
        capabilityGrantId="grant_graph_1",
        capabilityGrantDigest=DIGEST_C,
        capabilityId="capability:rag-search",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_D,
        actionPermitId=action_permit_id,
        actionPermitDigest=action_permit_digest,
        sourceRootDigest=DIGEST_F,
        evidence=evidence
        or [
            GraphEvidenceBinding(
                reference="evidence/tool_graph_1.json",
                sha256=DIGEST_E,
            )
        ],
        producedAt=NOW + timedelta(seconds=3),
    )


def _observation_proposal() -> ObservationProposal:
    action = _action()
    observation = _observation()
    evidence = _evidence()
    edges = sorted(
        [
            _edge(GraphRelation.PRODUCES, action, observation),
            _edge(GraphRelation.SUPPORTED_BY, observation, evidence),
        ],
        key=lambda item: item.edge_id,
    )
    return ObservationProposal(
        proposalId="proposal:observation:1",
        producerId=observation.producer_id,
        producerVersion=observation.producer_version,
        producerDigest=observation.producer_digest,
        lineage=_lineage(),
        action=action,
        observation=observation,
        evidenceNodes=[evidence],
        edges=edges,
    )


def test_minimum_graph_nodes_have_stable_typed_canonical_identities() -> None:
    nodes: list[GraphNode] = [
        _surface(),
        _hypothesis(),
        _action(),
        _observation(),
        _evidence(),
        _fact(),
    ]

    assert {node.kind for node in nodes} == {
        "Surface",
        "Hypothesis",
        "Action",
        "Observation",
        "Evidence",
        "CampaignFact",
    }
    for node in nodes:
        assert node.node_id.startswith("graph-node_")
        assert parse_graph_node(node.model_dump(mode="json", by_alias=True)) == node

    raw = _observation().model_dump(mode="json")
    raw["summary"] = "A caller changed admitted semantic content."
    with pytest.raises(ValidationError, match="differs from canonical identity"):
        GraphObservation.model_validate(raw)


@pytest.mark.parametrize(
    ("relation", "source_factory", "target_factory"),
    [
        (GraphRelation.MOTIVATES, _surface, _hypothesis),
        (GraphRelation.TESTED_BY, _hypothesis, _action),
        (GraphRelation.PRODUCES, _action, _observation),
        (GraphRelation.SUPPORTED_BY, _observation, _evidence),
        (GraphRelation.SUPPORTS, _observation, _hypothesis),
        (GraphRelation.CONTRADICTS, _observation, _hypothesis),
        (GraphRelation.DISCOVERS, _observation, _surface),
        (GraphRelation.ENABLES, _observation, _hypothesis),
    ],
)
def test_every_minimum_relation_enforces_exact_endpoint_kinds(
    relation: GraphRelation,
    source_factory: object,
    target_factory: object,
) -> None:
    assert callable(source_factory)
    assert callable(target_factory)
    source = source_factory()
    target = target_factory()
    edge = _edge(relation, source, target)

    assert edge.edge_id.startswith("graph-edge_")
    assert edge.source.kind is GraphNodeKind(source.kind)
    assert edge.target.kind is GraphNodeKind(target.kind)

    raw = edge.model_dump(mode="json")
    raw["source"], raw["target"] = raw["target"], raw["source"]
    raw["edge_id"] = ""
    with pytest.raises(ValidationError, match="invalid endpoint kinds"):
        GraphEdge.model_validate(raw)


def test_edge_rejects_cross_campaign_endpoint_and_canonical_id_tampering() -> None:
    edge = _edge(GraphRelation.MOTIVATES, _surface(), _hypothesis())
    raw = edge.model_dump(mode="json")
    raw["source"]["campaign_id"] = "foreign-campaign"
    raw["edge_id"] = ""
    with pytest.raises(ValidationError, match="another Campaign"):
        GraphEdge.model_validate(raw)

    raw = edge.model_dump(mode="json")
    raw["authority_digest"] = DIGEST_A
    with pytest.raises(ValidationError, match="differs from canonical identity"):
        GraphEdge.model_validate(raw)


def test_observation_proposal_binds_action_evidence_and_full_lineage() -> None:
    proposal = _observation_proposal()

    assert proposal.digest() == proposal.digest()
    assert parse_graph_proposal(
        proposal.model_dump(mode="json", by_alias=True)
    ) == proposal
    assert proposal.edges[0].edge_id < proposal.edges[1].edge_id

    changed = _observation_proposal().model_copy(
        update={
            "proposal_id": "proposal:observation:retry",
        }
    )
    assert changed.digest() != proposal.digest()


def test_observation_proposal_rejects_missing_action_or_mismatched_evidence() -> None:
    proposal = _observation_proposal()
    raw = proposal.model_dump(mode="json")
    remaining = [
        edge
        for edge in raw["edges"]
        if edge["relation"] != GraphRelation.PRODUCES.value
    ]
    extra = _edge(
        GraphRelation.SUPPORTS,
        proposal.observation,
        _hypothesis(),
    ).model_dump(mode="json")
    raw["edges"] = sorted([*remaining, extra], key=lambda item: item["edge_id"])
    with pytest.raises(ValidationError, match="requires one Action produces"):
        ObservationProposal.model_validate(raw)

    raw = proposal.model_dump(mode="json")
    raw["lineage"]["evidence"][0]["sha256"] = DIGEST_A
    with pytest.raises(ValidationError, match="differs from its lineage"):
        ObservationProposal.model_validate(raw)

    raw = proposal.model_dump(mode="json")
    raw["evidence_nodes"][0]["source_root_digest"] = DIGEST_A
    raw["evidence_nodes"][0]["node_id"] = ""
    with pytest.raises(ValidationError, match="another source root"):
        ObservationProposal.model_validate(raw)

    raw = proposal.model_dump(mode="json")
    raw["action"]["request_digest"] = DIGEST_A
    raw["action"]["node_id"] = ""
    with pytest.raises(ValidationError, match="differs from its request lineage"):
        ObservationProposal.model_validate(raw)


def test_surface_proposal_allows_seed_or_exact_discovers_edge_only() -> None:
    surface = _surface()
    seed = SurfaceProposal(
        proposalId="proposal:surface:seed",
        producerId="pajin.graph.test-surface-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_A,
        lineage=_lineage(),
        surface=surface,
    )
    assert seed.edges == []

    observation = _observation()
    discovery = SurfaceProposal(
        proposalId="proposal:surface:discovered",
        producerId="pajin.graph.test-surface-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_A,
        lineage=_lineage(),
        surface=surface,
        edges=[_edge(GraphRelation.DISCOVERS, observation, surface)],
    )
    assert discovery.edges[0].target.node_id == surface.node_id

    with pytest.raises(ValidationError, match="unrelated edge"):
        SurfaceProposal(
            proposalId="proposal:surface:invalid",
            producerId="pajin.graph.test-surface-producer",
            producerVersion="1.0.0",
            producerDigest=DIGEST_A,
            lineage=_lineage(),
            surface=surface,
            edges=[_edge(GraphRelation.MOTIVATES, surface, _hypothesis())],
        )


def test_contradictions_coexist_as_distinct_nodes_and_edges() -> None:
    hypothesis = _hypothesis()
    supporting = _observation(
        value_digest=DIGEST_A,
        summary="The privileged Tool request was observed.",
    )
    contradicting = _observation(
        value_digest=DIGEST_B,
        summary="A separate fresh session did not request the privileged Tool.",
    )

    assert supporting.node_id != contradicting.node_id
    supports = _edge(GraphRelation.SUPPORTS, supporting, hypothesis)
    contradicts = _edge(GraphRelation.CONTRADICTS, contradicting, hypothesis)
    assert supports.edge_id != contradicts.edge_id
    assert {supports.relation, contradicts.relation} == {
        GraphRelation.SUPPORTS,
        GraphRelation.CONTRADICTS,
    }


def test_campaign_fact_proposal_is_typed_but_not_a_direct_graph_write() -> None:
    proposal = CampaignFactProposal(
        proposalId="proposal:fact:1",
        producerId="pajin.graph.test-fact-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_B,
        lineage=_lineage(),
        fact=_fact_payload(),
    )
    parsed = parse_graph_proposal(
        proposal.model_dump(mode="json", by_alias=True)
    )
    assert isinstance(parsed, CampaignFactProposal)
    assert "validation_state" not in type(parsed.fact).model_fields

    raw = proposal.model_dump(mode="json")
    raw["fact"]["validationState"] = CampaignFactValidationState.ADMITTED.value
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CampaignFactProposal.model_validate(raw)

    raw = proposal.model_dump(mode="json")
    raw["fact"]["recorded_at"] = (NOW + timedelta(seconds=4)).isoformat()
    with pytest.raises(ValidationError, match="predates its Fact"):
        CampaignFactProposal.model_validate(raw)


def test_proposal_lineage_rejects_partial_permit_unsafe_path_and_unknown_input() -> None:
    with pytest.raises(ValidationError, match="provided together"):
        _lineage(action_permit_id="permit:1")

    with pytest.raises(ValidationError, match="forward slashes"):
        _lineage(
            evidence=[
                GraphEvidenceBinding(
                    reference=r"evidence\result.json",
                    sha256=DIGEST_A,
                )
            ]
        )

    raw = _observation_proposal().model_dump(mode="json")
    raw["canonicalWrite"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_graph_proposal(raw)


def test_graph_timestamps_require_explicit_timezone() -> None:
    raw = _action().model_dump(mode="json")
    raw["node_id"] = ""
    raw["executed_at"] = "2026-07-26T04:00:00"

    with pytest.raises(ValidationError, match="explicit UTC offset"):
        GraphAction.model_validate(raw)
