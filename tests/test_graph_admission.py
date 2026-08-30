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
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphAdmissionReason,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphEdge,
    GraphEventLogError,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphNodeKind,
    GraphObservation,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSurface,
    InMemoryGraphEventLog,
    ObservationProposal,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_node_ref,
)

NOW = datetime(2026, 7, 26, 6, 0, tzinfo=UTC)
CAMPAIGN = "graph-lab"
PRODUCER_ID = "pajin.graph.test-producer"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def _lineage(
    *,
    campaign: str = CAMPAIGN,
    source_root_digest: str = DIGEST_F,
) -> GraphProposalLineage:
    return GraphProposalLineage(
        campaignId=campaign,
        runId="run:graph:admission:1",
        agentId="agent:graph-specialist",
        taskId="task:graph:admission:1",
        requestId="tool_graph_admission_1",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:graph:1",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="capability:graph-observe",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=source_root_digest,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/graph-admission.json",
                sha256=DIGEST_D,
            )
        ],
        producedAt=NOW + timedelta(seconds=2),
    )


def _surface_proposal(
    *,
    proposal_id: str = "proposal:surface:1",
    campaign: str = CAMPAIGN,
    locator_digest: str = DIGEST_A,
    producer_id: str = PRODUCER_ID,
    producer_version: str = "1.0.0",
    lineage: GraphProposalLineage | None = None,
) -> SurfaceProposal:
    return SurfaceProposal(
        proposalId=proposal_id,
        producerId=producer_id,
        producerVersion=producer_version,
        producerDigest=DIGEST_E,
        lineage=lineage or _lineage(campaign=campaign),
        surface=GraphSurface(
            campaignId=campaign,
            targetId="target:hybrid",
            surfaceType="http-endpoint",
            locatorSchema="pajin.discovery.http-surface.v1",
            locatorDigest=locator_digest,
            origin=GraphContentOrigin.TRUSTED_CORE,
        ),
    )


def _observation_proposal() -> ObservationProposal:
    lineage = _lineage()
    action = GraphAction(
        campaignId=CAMPAIGN,
        requestId=lineage.request_id,
        requestDigest=lineage.request_digest,
        authorityKind=GraphAuthorityKind.CAPABILITY_GRANT,
        authorityId=lineage.capability_grant_id,
        authorityDigest=lineage.capability_grant_digest,
        capabilityId=lineage.capability_id,
        capabilityVersion=lineage.capability_version,
        capabilityDigest=lineage.capability_digest,
        toolId="graph.observe",
        targetDigest=DIGEST_D,
        status=GraphActionStatus.SUCCEEDED,
        executedAt=NOW,
    )
    observation = GraphObservation(
        campaignId=CAMPAIGN,
        observationType="surface-confirmed",
        summary="The registered action confirmed the target surface.",
        valueDigest=DIGEST_A,
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_E,
        origin=GraphContentOrigin.TARGET_DERIVED,
        confidence=0.9,
        observedAt=NOW + timedelta(seconds=1),
    )
    evidence = GraphEvidence(
        campaignId=CAMPAIGN,
        reference=lineage.evidence[0].reference,
        sha256=lineage.evidence[0].sha256,
        sourceRootDigest=lineage.source_root_digest,
        dataClassification="internal",
    )
    edges = [
        GraphEdge(
            campaignId=CAMPAIGN,
            relation=GraphRelation.PRODUCES,
            source=graph_node_ref(action),
            target=graph_node_ref(observation),
            authorityId="pajin.graph.admission-authority",
            authorityDigest=DIGEST_A,
        ),
        GraphEdge(
            campaignId=CAMPAIGN,
            relation=GraphRelation.SUPPORTED_BY,
            source=graph_node_ref(observation),
            target=graph_node_ref(evidence),
            authorityId="pajin.graph.admission-authority",
            authorityDigest=DIGEST_A,
        ),
    ]
    return ObservationProposal(
        proposalId="proposal:observation:1",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_E,
        lineage=lineage,
        action=action,
        observation=observation,
        evidenceNodes=[evidence],
        edges=sorted(edges, key=lambda item: item.edge_id),
    )


def _fact_proposal(
    *,
    proposal_id: str = "proposal:fact:1",
    outer_producer_id: str = PRODUCER_ID,
) -> CampaignFactProposal:
    return CampaignFactProposal(
        proposalId=proposal_id,
        producerId=outer_producer_id,
        producerVersion="1.0.0",
        producerDigest=DIGEST_E,
        lineage=_lineage(),
        fact=CampaignFactPayload(
            factKey="target.graph-admission",
            statement="The target has a verified graph admission surface.",
            valueDigest=DIGEST_A,
            producerId=PRODUCER_ID,
            producerVersion="1.0.0",
            producerDigest=DIGEST_E,
            origin=GraphContentOrigin.AGENT_DERIVED,
            recordedAt=NOW + timedelta(seconds=1),
        ),
    )


def _discovered_surface_proposal(observation: GraphObservation) -> SurfaceProposal:
    proposal = _surface_proposal(proposal_id="proposal:surface:discovered")
    edge = GraphEdge(
        campaignId=CAMPAIGN,
        relation=GraphRelation.DISCOVERS,
        source=graph_node_ref(observation),
        target=graph_node_ref(proposal.surface),
        authorityId="pajin.graph.admission-authority",
        authorityDigest=DIGEST_A,
    )
    return SurfaceProposal(
        proposalId=proposal.proposal_id,
        producerId=proposal.producer_id,
        producerVersion=proposal.producer_version,
        producerDigest=proposal.producer_digest,
        lineage=proposal.lineage,
        surface=proposal.surface,
        edges=[edge],
    )


def _authority(
    proposals: list[SurfaceProposal | ObservationProposal | CampaignFactProposal],
    *,
    registrations: list[GraphProducerRegistration] | None = None,
) -> tuple[GraphAdmissionAuthority, InMemoryGraphEventLog]:
    lineages = TrustedGraphLineageRegistry(proposal.lineage for proposal in proposals)
    producers = GraphProducerRegistry(
        registrations
        or [
            GraphProducerRegistration(
                producerId=PRODUCER_ID,
                producerVersion="1.0.0",
                producerDigest=DIGEST_E,
                allowedProposalKinds=(
                    GraphProposalKind.CAMPAIGN_FACT,
                    GraphProposalKind.OBSERVATION,
                    GraphProposalKind.SURFACE,
                ),
            )
        ]
    )
    event_log = InMemoryGraphEventLog()
    authority = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id="pajin.graph.admission-authority",
        authority_digest=DIGEST_A,
        producers=producers,
        lineage_verifier=lineages,
        event_log=event_log,
        clock=lambda: NOW + timedelta(seconds=3),
    )
    return authority, event_log


def test_admission_materializes_observation_action_evidence_and_fact() -> None:
    observation = _observation_proposal()
    fact = _fact_proposal()
    authority, event_log = _authority([observation, fact])

    observed = authority.submit(observation)
    admitted_fact = authority.submit(fact)

    assert observed.event.decision is GraphAdmissionDecision.ADMITTED
    assert {node.kind for node in observed.event.admitted_nodes} == {
        GraphNodeKind.ACTION,
        GraphNodeKind.OBSERVATION,
        GraphNodeKind.EVIDENCE,
    }
    assert len(observed.event.admitted_edges) == 2
    assert admitted_fact.event.admitted_nodes[0].kind == GraphNodeKind.CAMPAIGN_FACT
    assert (
        admitted_fact.event.admitted_nodes[0].validation_state
        is CampaignFactValidationState.ADMITTED
    )
    assert admitted_fact.event.previous_event_digest == observed.event.event_digest
    assert [event.sequence for event in event_log.events()] == [1, 2]


def test_exact_retry_is_idempotent_and_same_id_new_digest_is_audited_once() -> None:
    first = _surface_proposal()
    equivocation = _surface_proposal(locator_digest=DIGEST_B)
    authority, event_log = _authority([first])

    accepted = authority.submit(first)
    retry = authority.submit(first)
    rejected = authority.submit(equivocation)
    rejected_retry = authority.submit(equivocation)

    assert accepted.idempotent is False
    assert retry.idempotent is True
    assert retry.event.event_id == accepted.event.event_id
    assert rejected.event.reason is GraphAdmissionReason.PROPOSAL_EQUIVOCATION
    assert rejected.event.previous_event_digest == accepted.event.event_digest
    assert rejected_retry.idempotent is True
    assert rejected_retry.event.event_id == rejected.event.event_id
    assert len(event_log.events()) == 2


def test_edges_must_resolve_to_this_attempt_or_prior_admitted_nodes() -> None:
    observation = _observation_proposal()
    discovered = _discovered_surface_proposal(observation.observation)
    authority, _ = _authority([discovered])

    rejected = authority.submit(discovered)

    assert rejected.event.reason is GraphAdmissionReason.DANGLING_EDGE

    authority, event_log = _authority([observation, discovered])
    assert authority.submit(observation).event.decision is GraphAdmissionDecision.ADMITTED
    accepted = authority.submit(discovered)
    assert accepted.event.decision is GraphAdmissionDecision.ADMITTED
    assert len(event_log.events()) == 2


@pytest.mark.parametrize(
    ("proposal", "reason"),
    [
        (
            _surface_proposal(producer_id="pajin.graph.unknown-producer"),
            GraphAdmissionReason.PRODUCER_NOT_REGISTERED,
        ),
        (
            _surface_proposal(producer_version="2.0.0"),
            GraphAdmissionReason.PRODUCER_CONTRACT_MISMATCH,
        ),
        (
            _surface_proposal(campaign="foreign-campaign"),
            GraphAdmissionReason.FOREIGN_CAMPAIGN,
        ),
        (
            _fact_proposal(outer_producer_id="pajin.graph.outer-producer"),
            GraphAdmissionReason.PRODUCER_NOT_REGISTERED,
        ),
    ],
)
def test_admission_rejects_untrusted_producer_and_campaign_contracts(
    proposal: SurfaceProposal | CampaignFactProposal,
    reason: GraphAdmissionReason,
) -> None:
    registrations = [
        GraphProducerRegistration(
            producerId=PRODUCER_ID,
            producerVersion="1.0.0",
            producerDigest=DIGEST_E,
            allowedProposalKinds=(
                GraphProposalKind.CAMPAIGN_FACT,
                GraphProposalKind.SURFACE,
            ),
        )
    ]
    authority, event_log = _authority([proposal], registrations=registrations)

    result = authority.submit(proposal)

    assert result.event.decision is GraphAdmissionDecision.REJECTED
    assert result.event.reason is reason
    assert result.event.admitted_nodes == []
    assert result.event.campaign_id == CAMPAIGN
    assert result.event.proposal_campaign_id == proposal.lineage.campaign_id
    assert len(event_log.events()) == 1


def test_admission_rejects_payload_mismatch_kind_denial_and_unregistered_lineage() -> None:
    fact = _fact_proposal(outer_producer_id="pajin.graph.outer-producer")
    registrations = [
        GraphProducerRegistration(
            producerId="pajin.graph.outer-producer",
            producerVersion="1.0.0",
            producerDigest=DIGEST_E,
            allowedProposalKinds=(GraphProposalKind.CAMPAIGN_FACT,),
        )
    ]
    authority, _ = _authority([fact], registrations=registrations)
    assert authority.submit(fact).event.reason is GraphAdmissionReason.PRODUCER_PAYLOAD_MISMATCH

    surface = _surface_proposal(proposal_id="proposal:surface:kind-denied")
    denied_registration = [
        GraphProducerRegistration(
            producerId=PRODUCER_ID,
            producerVersion="1.0.0",
            producerDigest=DIGEST_E,
            allowedProposalKinds=(GraphProposalKind.CAMPAIGN_FACT,),
        )
    ]
    authority, _ = _authority([surface], registrations=denied_registration)
    assert authority.submit(surface).event.reason is GraphAdmissionReason.PROPOSAL_KIND_NOT_ALLOWED

    untrusted_lineage = _surface_proposal(
        proposal_id="proposal:surface:untrusted-lineage",
        lineage=_lineage(source_root_digest=DIGEST_A),
    )
    trusted = _surface_proposal(proposal_id="proposal:surface:trusted-lineage")
    authority, _ = _authority([trusted])
    assert (
        authority.submit(untrusted_lineage).event.reason
        is GraphAdmissionReason.LINEAGE_VERIFICATION_FAILED
    )


def test_event_log_revalidates_mutated_events_and_rejects_stale_append() -> None:
    proposal = _surface_proposal()
    authority, event_log = _authority([proposal])
    accepted = authority.submit(proposal)
    verification_log = InMemoryGraphEventLog()
    writer = verification_log.claim_writer(
        "pajin.graph.admission-authority",
        DIGEST_A,
    )
    verification_log.append(accepted.event, writer=writer)

    mutated = accepted.event.model_copy(update={"reason": GraphAdmissionReason.DANGLING_EDGE})
    with pytest.raises(ValidationError, match="decision and reason"):
        verification_log.append(mutated, writer=writer)

    tampered = accepted.event.model_dump(mode="json")
    tampered["producer_version"] = "2.0.0"
    with pytest.raises(ValidationError, match="digest differs"):
        GraphAdmissionEvent.model_validate(tampered)

    raw = accepted.event.model_dump(mode="json")
    raw.update(
        {
            "event_id": "",
            "event_digest": "",
            "sequence": 3,
            "proposal_id": "proposal:surface:stale",
            "proposal_digest": DIGEST_B,
        }
    )
    stale = GraphAdmissionEvent.model_validate(raw)
    with pytest.raises(GraphEventLogError, match="sequence or predecessor"):
        verification_log.append(stale, writer=writer)

    with pytest.raises(GraphEventLogError, match="already claimed"):
        verification_log.claim_writer("pajin.graph.second-authority", DIGEST_B)

    with pytest.raises(GraphEventLogError, match="write authority"):
        event_log.append(accepted.event, writer=object())

    exported = verification_log.events()
    exported[0].reason = GraphAdmissionReason.DANGLING_EDGE
    assert verification_log.events()[0].reason is GraphAdmissionReason.ADMITTED


def test_event_log_rejects_unauthorized_fact_state_and_dangling_material() -> None:
    fact = _fact_proposal()
    authority, _ = _authority([fact])
    admitted_fact = authority.submit(fact)
    raw = admitted_fact.event.model_dump(mode="json")
    raw["event_id"] = ""
    raw["event_digest"] = ""
    raw["admitted_nodes"][0]["node_id"] = ""
    raw["admitted_nodes"][0]["validation_state"] = CampaignFactValidationState.CORROBORATED.value
    with pytest.raises(ValidationError, match="unauthorized state"):
        GraphAdmissionEvent.model_validate(raw)

    surface = _surface_proposal()
    authority, _ = _authority([surface])
    accepted_surface = authority.submit(surface)
    raw = accepted_surface.event.model_dump(mode="json")
    raw["event_id"] = ""
    raw["event_digest"] = ""
    observation = _observation_proposal().observation
    raw["admitted_edges"] = [
        GraphEdge(
            campaignId=CAMPAIGN,
            relation=GraphRelation.DISCOVERS,
            source=graph_node_ref(observation),
            target=graph_node_ref(surface.surface),
            authorityId="pajin.graph.admission-authority",
            authorityDigest=DIGEST_A,
        ).model_dump(mode="json")
    ]
    dangling = GraphAdmissionEvent.model_validate(raw)
    event_log = InMemoryGraphEventLog()
    writer = event_log.claim_writer("pajin.graph.admission-authority", DIGEST_A)
    with pytest.raises(GraphEventLogError, match="dangling edge"):
        event_log.append(dangling, writer=writer)


def test_authority_revalidates_mutated_proposal_objects_before_admission() -> None:
    proposal = _surface_proposal()
    authority, event_log = _authority([proposal])
    proposal.surface.campaign_id = "foreign-campaign"

    with pytest.raises(ValidationError, match="canonical identity"):
        authority.submit(proposal)

    assert event_log.events() == ()


def test_permit_only_observation_lineage_is_admitted_without_fabricated_grant() -> None:
    base = _observation_proposal()
    lineage_payload = base.lineage.model_dump(mode="json", by_alias=True)
    lineage_payload.pop("capabilityGrantId")
    lineage_payload.pop("capabilityGrantDigest")
    lineage_payload.update(
        {
            "actionPermitId": "action-permit:graph:1",
            "actionPermitDigest": DIGEST_B,
        }
    )
    lineage = GraphProposalLineage.model_validate(lineage_payload)
    action = GraphAction(
        campaignId=CAMPAIGN,
        requestId=lineage.request_id,
        requestDigest=lineage.request_digest,
        authorityKind=GraphAuthorityKind.ACTION_PERMIT,
        authorityId=lineage.action_permit_id,
        authorityDigest=lineage.action_permit_digest,
        capabilityId=lineage.capability_id,
        capabilityVersion=lineage.capability_version,
        capabilityDigest=lineage.capability_digest,
        toolId=base.action.tool_id,
        targetDigest=base.action.target_digest,
        status=base.action.status,
        executedAt=base.action.executed_at,
    )
    edges = [
        GraphEdge(
            campaignId=CAMPAIGN,
            relation=GraphRelation.PRODUCES,
            source=graph_node_ref(action),
            target=graph_node_ref(base.observation),
            authorityId="pajin.graph.admission-authority",
            authorityDigest=DIGEST_A,
        ),
        GraphEdge(
            campaignId=CAMPAIGN,
            relation=GraphRelation.SUPPORTED_BY,
            source=graph_node_ref(base.observation),
            target=graph_node_ref(base.evidence_nodes[0]),
            authorityId="pajin.graph.admission-authority",
            authorityDigest=DIGEST_A,
        ),
    ]
    proposal = ObservationProposal(
        proposalId="proposal:observation:permit-only",
        producerId=base.producer_id,
        producerVersion=base.producer_version,
        producerDigest=base.producer_digest,
        lineage=lineage,
        action=action,
        observation=base.observation,
        evidenceNodes=base.evidence_nodes,
        edges=sorted(edges, key=lambda item: item.edge_id),
    )
    authority, _ = _authority([proposal])

    result = authority.submit(proposal)

    assert result.event.decision is GraphAdmissionDecision.ADMITTED
    assert result.event.capability_grant_id is None
    assert result.event.capability_grant_digest is None
    assert result.event.action_permit_id == "action-permit:graph:1"


def test_expected_event_head_rejects_stale_proposal_inside_writer_lock() -> None:
    proposal = _surface_proposal(
        proposal_id="proposal:surface:stale-snapshot",
    )
    authority, event_log = _authority([proposal])

    result = authority.submit_if_current(
        proposal,
        expected_event_log_head_digest=DIGEST_A,
    )

    assert result.event.decision is GraphAdmissionDecision.REJECTED
    assert result.event.reason is GraphAdmissionReason.STALE_SNAPSHOT
    assert len(event_log.events()) == 1


def test_graph_lineage_rejects_missing_or_partial_execution_authority() -> None:
    payload = _lineage().model_dump(mode="json", by_alias=True)
    payload.pop("capabilityGrantId")
    payload.pop("capabilityGrantDigest")
    with pytest.raises(ValidationError, match="Capability Grant or Action Permit"):
        GraphProposalLineage.model_validate(payload)

    payload["actionPermitId"] = "action-permit:graph:partial"
    with pytest.raises(ValidationError, match="provided together"):
        GraphProposalLineage.model_validate(payload)

    source_payload = _lineage().model_dump(mode="json", by_alias=True)
    source_payload.pop("capabilityGrantId")
    source_payload.pop("capabilityGrantDigest")
    source_payload.pop("capabilityId")
    source_payload.pop("capabilityVersion")
    source_payload.pop("capabilityDigest")
    source_payload["sourceAuthorityId"] = "source:graph:sealed"
    with pytest.raises(ValidationError, match="source authority ID and digest"):
        GraphProposalLineage.model_validate(source_payload)

    source_payload["sourceAuthorityDigest"] = DIGEST_C
    source_payload["actionPermitId"] = "action-permit:graph:forged"
    source_payload["actionPermitDigest"] = DIGEST_D
    with pytest.raises(
        ValidationError,
        match="cannot claim Capability or Permit authority",
    ):
        GraphProposalLineage.model_validate(source_payload)


def test_graph_admission_event_rejects_partial_or_mixed_sealed_source_authority() -> None:
    proposal = _surface_proposal()
    authority, _ = _authority([proposal])
    legacy_event = authority.submit(proposal).event
    legacy_wire = legacy_event.model_dump(mode="json", by_alias=True)

    assert legacy_event.event_digest == (
        "c7c9a31f70e27f8a507449d84cda16077cb93dd922bfe3215063abaa07a0f924"
    )
    assert "sourceAuthorityId" not in legacy_wire
    assert "sourceAuthorityDigest" not in legacy_wire

    partial = dict(legacy_wire)
    partial["eventId"] = ""
    partial["eventDigest"] = ""
    partial["sourceAuthorityId"] = "source:graph:sealed"
    with pytest.raises(ValidationError, match="source authority binding is incomplete"):
        GraphAdmissionEvent.model_validate(partial)

    mixed = dict(legacy_wire)
    mixed["eventId"] = ""
    mixed["eventDigest"] = ""
    mixed["sourceAuthorityId"] = "source:graph:sealed"
    mixed["sourceAuthorityDigest"] = DIGEST_B
    with pytest.raises(
        ValidationError,
        match="cannot claim Capability or Permit authority",
    ):
        GraphAdmissionEvent.model_validate(mixed)
