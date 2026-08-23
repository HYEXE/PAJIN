from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.domain.security_domain import SecurityDomain
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionReason,
    GraphProducerRegistration,
    GraphProducerRegistry,
    InMemoryGraphEventLog,
    TrustedGraphLineageRegistry,
)
from pajin.graph.cross_domain_admission import (
    CrossDomainGraphAdmissionCandidate,
    CrossDomainGraphAdmissionError,
    CrossDomainGraphAdmissionGate,
    cross_domain_graph_producer_registration,
    registered_cross_domain_graph_producer_contract,
)
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics
from pajin.graph.models import (
    GraphAction,
    GraphActionStatus,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphNodeKind,
    GraphObservation,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSurface,
    ObservationProposal,
    graph_node_ref,
)
from pajin.graph.projection import (
    GraphProjector,
    GraphSnapshot,
    GraphSnapshotReason,
)

NOW = datetime(2026, 8, 21, 6, 0, tzinfo=UTC)
CAMPAIGN = "domain-admission"
SOURCE_PRODUCER_ID = "pajin.graph.test-ai-observation"
AUTHORITY_ID = "pajin.graph.admission-authority"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def _lineage(*, campaign_id: str = CAMPAIGN) -> GraphProposalLineage:
    return GraphProposalLineage(
        campaignId=campaign_id,
        runId="run:domain-admission:1",
        agentId="agent:ai-observer",
        taskId="task:ai-observation:1",
        requestId="tool_ai_observation_1",
        requestDigest=DIGEST_A,
        capabilityId="capability:ai-observe",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_B,
        actionPermitId="permit:ai-observe:1",
        actionPermitDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/ai-observation.json",
                sha256=DIGEST_E,
            )
        ],
        producedAt=NOW + timedelta(seconds=2),
    )


def _observation_proposal(
    *,
    campaign_id: str = CAMPAIGN,
    observation_type: str = "ai.behavior-observation",
) -> ObservationProposal:
    lineage = _lineage(campaign_id=campaign_id)
    action = GraphAction(
        campaignId=campaign_id,
        requestId=lineage.request_id,
        requestDigest=lineage.request_digest,
        authorityKind=GraphAuthorityKind.ACTION_PERMIT,
        authorityId=lineage.action_permit_id,
        authorityDigest=lineage.action_permit_digest,
        capabilityId=lineage.capability_id,
        capabilityVersion=lineage.capability_version,
        capabilityDigest=lineage.capability_digest,
        toolId="ai.observe",
        targetDigest=DIGEST_F,
        status=GraphActionStatus.SUCCEEDED,
        executedAt=NOW,
    )
    observation = GraphObservation(
        campaignId=campaign_id,
        observationType=observation_type,
        summary="An approved AI action observed an exact internal HTTP operation reference.",
        valueDigest=DIGEST_A,
        producerId=SOURCE_PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        origin=GraphContentOrigin.TARGET_DERIVED,
        confidence=1.0,
        observedAt=NOW + timedelta(seconds=1),
    )
    evidence = GraphEvidence(
        campaignId=campaign_id,
        reference=lineage.evidence[0].reference,
        sha256=lineage.evidence[0].sha256,
        sourceRootDigest=lineage.source_root_digest,
        dataClassification="internal",
    )
    edges = [
        GraphEdge(
            campaignId=campaign_id,
            relation=GraphRelation.PRODUCES,
            source=graph_node_ref(action),
            target=graph_node_ref(observation),
            authorityId=AUTHORITY_ID,
            authorityDigest=DIGEST_A,
        ),
        GraphEdge(
            campaignId=campaign_id,
            relation=GraphRelation.SUPPORTED_BY,
            source=graph_node_ref(observation),
            target=graph_node_ref(evidence),
            authorityId=AUTHORITY_ID,
            authorityDigest=DIGEST_A,
        ),
    ]
    return ObservationProposal(
        proposalId="proposal:ai-observation:1",
        producerId=SOURCE_PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        lineage=lineage,
        action=action,
        observation=observation,
        evidenceNodes=[evidence],
        edges=sorted(edges, key=lambda item: item.edge_id),
    )


def _snapshot(event_log: InMemoryGraphEventLog) -> GraphSnapshot:
    projection = GraphProjector.project(campaign_id=CAMPAIGN, events=event_log.events())
    return GraphSnapshot(
        campaignId=projection.campaign_id,
        revision=projection.revision,
        eventLogHeadDigest=projection.event_log_head_digest,
        projectionId=projection.projection_id,
        projectionDigest=projection.projection_digest,
        nodeProjectionDigest=projection.node_projection_digest,
        edgeProjectionDigest=projection.edge_projection_digest,
        reason=GraphSnapshotReason.REPLAN,
        createdAt=NOW + timedelta(seconds=4),
        creatorId="pajin.graph.snapshot-authority",
        creatorDigest=DIGEST_F,
        projection=projection,
    )


def _environment(
    *,
    observation_type: str = "ai.behavior-observation",
) -> tuple[
    CrossDomainGraphAdmissionGate,
    GraphAdmissionAuthority,
    InMemoryGraphEventLog,
    object,
]:
    source = _observation_proposal(observation_type=observation_type)
    trusted = TrustedGraphLineageRegistry([source.lineage])
    event_log = InMemoryGraphEventLog()
    authority = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id=AUTHORITY_ID,
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=SOURCE_PRODUCER_ID,
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_F,
                    allowedProposalKinds=(GraphProposalKind.OBSERVATION,),
                ),
                cross_domain_graph_producer_registration(),
            ]
        ),
        lineage_verifier=trusted,
        event_log=event_log,
        clock=lambda: NOW + timedelta(seconds=3),
    )
    source_event = authority.submit(source).event
    gate = CrossDomainGraphAdmissionGate(
        event_log=event_log,
        graph_admission=authority,
        trusted_lineages=trusted,
    )
    return gate, authority, event_log, source_event


def test_ai_observation_admits_web_surface_and_hypothesis_to_one_graph() -> None:
    gate, _, event_log, source_event = _environment()
    surface_candidate = gate.prepare_surface(
        source_event=source_event,
        snapshot=_snapshot(event_log),
        target_id="target:internal-api",
        locator_digest=DIGEST_B,
    )
    surface_admission = gate.admit(surface_candidate, snapshot=_snapshot(event_log))
    hypothesis_candidate = gate.prepare_hypothesis(
        source_event=source_event,
        snapshot=_snapshot(event_log),
        statement="The discovered Web operation may enforce authorization inconsistently.",
        expected_observable=(
            "Independent requests produce identity-dependent authorization results."
        ),
        confidence=0.6,
    )
    hypothesis_admission = gate.admit(
        hypothesis_candidate,
        snapshot=_snapshot(event_log),
    )
    projection = GraphProjector.project(campaign_id=CAMPAIGN, events=event_log.events())

    assert surface_admission.graph_event.decision is GraphAdmissionDecision.ADMITTED
    assert hypothesis_admission.graph_event.decision is GraphAdmissionDecision.ADMITTED
    assert isinstance(surface_candidate.proposal.surface, GraphSurface)
    assert isinstance(hypothesis_candidate.proposal.hypothesis, GraphHypothesis)
    assert {edge.relation for edge in projection.edges} >= {
        GraphRelation.DISCOVERS,
        GraphRelation.ENABLES,
    }
    assert {node.kind for node in projection.nodes} >= {
        GraphNodeKind.OBSERVATION,
        GraphNodeKind.SURFACE,
        GraphNodeKind.HYPOTHESIS,
    }
    assert projection.revision == 3


def test_admitted_knowledge_is_registered_not_authorized_and_permit_is_provenance_only() -> None:
    gate, _, event_log, source_event = _environment()
    candidate = gate.prepare_surface(
        source_event=source_event,
        snapshot=_snapshot(event_log),
        target_id="target:internal-api",
        locator_digest=DIGEST_B,
    )
    admission = gate.admit(candidate, snapshot=_snapshot(event_log))
    payload = admission.candidate.model_dump(mode="json", by_alias=True)

    assert candidate.target_knowledge_state == "registered-not-authorized"
    assert candidate.source_authority_provenance_bound is True
    assert all(
        payload[field] is False
        for field in (
            "campaignMutationAuthorized",
            "scopeExpansionAuthorized",
            "capabilityActivationAuthorized",
            "budgetChangeAuthorized",
            "egressChangeAuthorized",
            "credentialUseAuthorized",
            "workerSelectionAuthorized",
            "approvalSatisfied",
            "permitIssuanceAuthorized",
            "sourceAuthorityTransferAuthorized",
            "executionAuthorized",
        )
    )
    assert admission.graph_event.action_permit_id == source_event.action_permit_id
    assert admission.graph_event.action_permit_digest == source_event.action_permit_digest
    assert {
        "scope",
        "capability",
        "permit",
        "worker",
        "execution_authorized",
    }.isdisjoint(GraphSurface.model_fields)


def test_stale_snapshot_rejection_is_audited_and_exact_retry_is_idempotent() -> None:
    gate, _, event_log, source_event = _environment()
    snapshot = _snapshot(event_log)
    first = gate.prepare_surface(
        source_event=source_event,
        snapshot=snapshot,
        target_id="target:first-api",
        locator_digest=DIGEST_B,
    )
    stale = gate.prepare_surface(
        source_event=source_event,
        snapshot=snapshot,
        target_id="target:stale-api",
        locator_digest=DIGEST_C,
    )
    admitted = gate.admit(first, snapshot=snapshot)
    event_count = len(event_log.events())

    retry = gate.admit(first, snapshot=snapshot)
    with pytest.raises(CrossDomainGraphAdmissionError, match="stale-snapshot"):
        gate.admit(stale, snapshot=snapshot)

    assert retry.graph_event.event_id == admitted.graph_event.event_id
    assert len(event_log.events()) == event_count + 1
    assert event_log.events()[-1].reason is GraphAdmissionReason.STALE_SNAPSHOT
    assert event_log.admitted_node(stale.proposal.surface.node_id) is None


def test_candidate_rejects_producer_domain_and_authority_substitution() -> None:
    gate, _, event_log, source_event = _environment()
    candidate = gate.prepare_surface(
        source_event=source_event,
        snapshot=_snapshot(event_log),
        target_id="target:internal-api",
        locator_digest=DIGEST_B,
    )
    payload = candidate.model_dump(mode="json", by_alias=True)

    producer_substitution = dict(payload)
    producer_substitution["contract"] = dict(payload["contract"])
    producer_substitution["contract"]["producerDigest"] = "0" * 64
    with pytest.raises(ValidationError):
        CrossDomainGraphAdmissionCandidate.model_validate(producer_substitution)

    cloud = next(
        item
        for item in registered_multi_domain_graph_semantics().domain_type_sets
        if item.domain_classification.domain is SecurityDomain.CLOUD
    )
    domain_relabel = dict(payload)
    domain_relabel["contract"] = dict(payload["contract"])
    domain_relabel["contract"]["targetTypeSet"] = cloud.reference().model_dump(
        mode="json", by_alias=True
    )
    with pytest.raises(ValidationError):
        CrossDomainGraphAdmissionCandidate.model_validate(domain_relabel)

    authority_injection = dict(payload)
    authority_injection["sourceAuthorityTransferAuthorized"] = True
    with pytest.raises(ValidationError):
        CrossDomainGraphAdmissionCandidate.model_validate(authority_injection)


def test_gate_rejects_foreign_or_wrongly_classified_source_observation() -> None:
    gate, _, event_log, _ = _environment()
    foreign_source = _observation_proposal(campaign_id="foreign-campaign")
    foreign_log = InMemoryGraphEventLog()
    foreign_trusted = TrustedGraphLineageRegistry([foreign_source.lineage])
    foreign_authority = GraphAdmissionAuthority(
        campaign_id="foreign-campaign",
        authority_id=AUTHORITY_ID,
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=SOURCE_PRODUCER_ID,
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_F,
                    allowedProposalKinds=(GraphProposalKind.OBSERVATION,),
                )
            ]
        ),
        lineage_verifier=foreign_trusted,
        event_log=foreign_log,
        clock=lambda: NOW + timedelta(seconds=3),
    )
    foreign_event = foreign_authority.submit(foreign_source).event

    with pytest.raises(CrossDomainGraphAdmissionError, match="source"):
        gate.prepare_surface(
            source_event=foreign_event,
            snapshot=_snapshot(event_log),
            target_id="target:foreign-api",
            locator_digest=DIGEST_B,
        )

    wrong_gate, _, wrong_log, wrong_event = _environment(
        observation_type="web.protocol-observation"
    )
    with pytest.raises(CrossDomainGraphAdmissionError, match="source"):
        wrong_gate.prepare_surface(
            source_event=wrong_event,
            snapshot=_snapshot(wrong_log),
            target_id="target:wrong-domain-api",
            locator_digest=DIGEST_B,
        )


def test_contract_is_exact_ai_to_web_classification_without_execution_authority() -> None:
    contract = registered_cross_domain_graph_producer_contract()

    assert contract.source_type_set.domain_classification.domain is SecurityDomain.AI
    assert contract.target_type_set.domain_classification.domain is SecurityDomain.WEB
    assert contract.allowed_proposal_kinds == (
        GraphProposalKind.HYPOTHESIS,
        GraphProposalKind.SURFACE,
    )
    assert contract.knowledge_only is True
    assert contract.execution_authorized is False
    assert len(contract.contract_digest) == 64
