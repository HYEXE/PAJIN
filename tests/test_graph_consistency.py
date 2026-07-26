from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.graph import (
    GraphAction,
    GraphActionStatus,
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphAdmissionReason,
    GraphConsistencyAnalyzer,
    GraphConsistencyError,
    GraphContentOrigin,
    GraphDecision,
    GraphDecisionGuard,
    GraphDecisionKind,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphHypothesisState,
    GraphObservation,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjection,
    GraphProjectionReconciler,
    GraphProjectionReconciliationStatus,
    GraphProjectionStore,
    GraphProjector,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    GraphStaleDecisionError,
    GraphSurface,
    HypothesisProposal,
    InMemoryGraphEventLog,
    InMemoryGraphProjectionStore,
    InMemoryGraphSnapshotStore,
    ObservationProposal,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_node_ref,
    graph_snapshot_ref,
)

NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
CAMPAIGN = "graph-lab"
PRODUCER_ID = "pajin.graph.consistency-producer"
AUTHORITY_ID = "pajin.graph.admission-authority"
SNAPSHOT_CREATOR_ID = "pajin.graph.snapshot-authority"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def _digest_for(tag: str) -> str:
    values = {
        "surface": DIGEST_A,
        "duplicate": DIGEST_A,
        "alternate": DIGEST_B,
        "hypothesis": DIGEST_C,
        "support": DIGEST_D,
        "contradiction": DIGEST_E,
        "late": DIGEST_A,
    }
    return values[tag]


def _lineage(tag: str) -> GraphProposalLineage:
    digest = _digest_for(tag)
    return GraphProposalLineage(
        campaignId=CAMPAIGN,
        runId=f"run:graph:{tag}",
        agentId="agent:graph-specialist",
        taskId=f"task:graph:{tag}",
        requestId=f"tool_graph_{tag}",
        requestDigest=digest,
        capabilityGrantId=f"grant:graph:{tag}",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="capability:graph-observe",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_F,
        evidence=[
            GraphEvidenceBinding(
                reference=f"evidence/{tag}.json",
                sha256=digest,
            )
        ],
        producedAt=NOW + timedelta(seconds=4),
    )


def _surface_proposal(
    tag: str = "surface",
    *,
    proposal_id: str | None = None,
    locator_digest: str = DIGEST_A,
) -> SurfaceProposal:
    return SurfaceProposal(
        proposalId=proposal_id or f"proposal:surface:{tag}",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        lineage=_lineage(tag),
        surface=GraphSurface(
            campaignId=CAMPAIGN,
            targetId="target:hybrid",
            surfaceType="http-endpoint",
            locatorSchema="pajin.discovery.http-surface.v1",
            locatorDigest=locator_digest,
            origin=GraphContentOrigin.TRUSTED_CORE,
        ),
    )


def _hypothesis_proposal(surface: GraphSurface) -> HypothesisProposal:
    hypothesis = GraphHypothesis(
        campaignId=CAMPAIGN,
        hypothesisType="rag-indirect-prompt-injection",
        statement="Uploaded content may alter a RAG-backed agent decision.",
        expectedObservable="The agent requests a privileged Tool after retrieval.",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        origin=GraphContentOrigin.AGENT_DERIVED,
        confidence=0.7,
    )
    edge = GraphEdge(
        campaignId=CAMPAIGN,
        relation=GraphRelation.MOTIVATES,
        source=graph_node_ref(surface),
        target=graph_node_ref(hypothesis),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return HypothesisProposal(
        proposalId="proposal:hypothesis:1",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        lineage=_lineage("hypothesis"),
        hypothesis=hypothesis,
        edges=[edge],
    )


def _observation_proposal(
    tag: str,
    hypothesis: GraphHypothesis,
    relation: GraphRelation,
) -> ObservationProposal:
    lineage = _lineage(tag)
    action = GraphAction(
        campaignId=CAMPAIGN,
        requestId=lineage.request_id,
        requestDigest=lineage.request_digest,
        authorityKind="capability-grant",
        authorityId=lineage.capability_grant_id,
        authorityDigest=lineage.capability_grant_digest,
        capabilityId=lineage.capability_id,
        capabilityVersion=lineage.capability_version,
        capabilityDigest=lineage.capability_digest,
        toolId="graph.observe",
        targetDigest=DIGEST_A,
        status=GraphActionStatus.SUCCEEDED,
        executedAt=NOW + timedelta(seconds=1),
    )
    observation = GraphObservation(
        campaignId=CAMPAIGN,
        observationType=f"{tag}-signal",
        summary=f"The controlled observation produced a {tag} signal.",
        valueDigest=_digest_for(tag),
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        origin=GraphContentOrigin.TARGET_DERIVED,
        confidence=0.9,
        observedAt=NOW + timedelta(seconds=2),
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
            authorityId=AUTHORITY_ID,
            authorityDigest=DIGEST_A,
        ),
        GraphEdge(
            campaignId=CAMPAIGN,
            relation=GraphRelation.SUPPORTED_BY,
            source=graph_node_ref(observation),
            target=graph_node_ref(evidence),
            authorityId=AUTHORITY_ID,
            authorityDigest=DIGEST_A,
        ),
        GraphEdge(
            campaignId=CAMPAIGN,
            relation=relation,
            source=graph_node_ref(observation),
            target=graph_node_ref(hypothesis),
            authorityId=AUTHORITY_ID,
            authorityDigest=DIGEST_A,
        ),
    ]
    return ObservationProposal(
        proposalId=f"proposal:observation:{tag}",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        lineage=lineage,
        action=action,
        observation=observation,
        evidenceNodes=[evidence],
        edges=sorted(edges, key=lambda item: item.edge_id),
    )


GraphTestProposal = SurfaceProposal | HypothesisProposal | ObservationProposal


def _authority(
    proposals: list[GraphTestProposal],
) -> tuple[GraphAdmissionAuthority, InMemoryGraphEventLog]:
    event_log = InMemoryGraphEventLog()
    authority = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id=AUTHORITY_ID,
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=PRODUCER_ID,
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_F,
                    allowedProposalKinds=(
                        GraphProposalKind.HYPOTHESIS,
                        GraphProposalKind.OBSERVATION,
                        GraphProposalKind.SURFACE,
                    ),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry(
            proposal.lineage for proposal in proposals
        ),
        event_log=event_log,
        clock=lambda: NOW + timedelta(seconds=5),
    )
    return authority, event_log


def _contested_history() -> tuple[
    GraphAdmissionAuthority,
    InMemoryGraphEventLog,
    tuple[GraphTestProposal, ...],
]:
    surface = _surface_proposal()
    duplicate = _surface_proposal("duplicate")
    hypothesis = _hypothesis_proposal(surface.surface)
    supporting = _observation_proposal(
        "support",
        hypothesis.hypothesis,
        GraphRelation.SUPPORTS,
    )
    contradicting = _observation_proposal(
        "contradiction",
        hypothesis.hypothesis,
        GraphRelation.CONTRADICTS,
    )
    proposals: tuple[GraphTestProposal, ...] = (
        surface,
        duplicate,
        hypothesis,
        supporting,
        contradicting,
    )
    authority, event_log = _authority(list(proposals))
    for proposal in proposals:
        assert authority.submit(proposal).event.decision is GraphAdmissionDecision.ADMITTED
    return authority, event_log, proposals


def test_hypothesis_admission_requires_resolved_motivation() -> None:
    surface = _surface_proposal()
    hypothesis = _hypothesis_proposal(surface.surface)
    raw_proposal = hypothesis.model_dump(mode="json")
    raw_proposal["hypothesis"].update(
        {"node_id": "", "producer_digest": DIGEST_E}
    )
    with pytest.raises(ValidationError, match="payload producer differs"):
        HypothesisProposal.model_validate(raw_proposal)

    authority, event_log = _authority([surface, hypothesis])

    dangling = authority.submit(hypothesis)
    assert dangling.event.reason is GraphAdmissionReason.DANGLING_EDGE

    authority, event_log = _authority([surface, hypothesis])
    authority.submit(surface)
    admitted = authority.submit(hypothesis)
    assert admitted.event.decision is GraphAdmissionDecision.ADMITTED
    assert admitted.event.admitted_nodes == [hypothesis.hypothesis]
    assert admitted.event.admitted_edges == hypothesis.edges
    assert len(event_log.events()) == 2

    raw = admitted.event.model_dump(mode="json")
    raw.update({"event_id": "", "event_digest": "", "admitted_edges": []})
    with pytest.raises(ValidationError, match="invalid node material"):
        GraphAdmissionEvent.model_validate(raw)


def test_one_observation_cannot_support_and_contradict_same_hypothesis() -> None:
    surface = _surface_proposal()
    hypothesis = _hypothesis_proposal(surface.surface)
    proposal = _observation_proposal(
        "support",
        hypothesis.hypothesis,
        GraphRelation.SUPPORTS,
    )
    raw = proposal.model_dump(mode="json")
    contradictory = GraphEdge(
        campaignId=CAMPAIGN,
        relation=GraphRelation.CONTRADICTS,
        source=graph_node_ref(proposal.observation),
        target=graph_node_ref(hypothesis.hypothesis),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    raw["edges"] = sorted(
        [*raw["edges"], contradictory.model_dump(mode="json")],
        key=lambda item: item["edge_id"],
    )

    with pytest.raises(ValidationError, match="cannot support and contradict"):
        ObservationProposal.model_validate(raw)

    authority, _ = _authority([surface, hypothesis, proposal])
    authority.submit(surface)
    authority.submit(hypothesis)
    admitted = authority.submit(proposal).event
    event_raw = admitted.model_dump(mode="json")
    event_raw.update({"event_id": "", "event_digest": ""})
    event_raw["admitted_edges"] = sorted(
        [
            *event_raw["admitted_edges"],
            contradictory.model_dump(mode="json"),
        ],
        key=lambda item: item["edge_id"],
    )
    with pytest.raises(ValidationError, match="cannot support and contradict"):
        GraphAdmissionEvent.model_validate(event_raw)


def test_consistency_view_preserves_duplicate_provenance_and_contradictions() -> None:
    _, event_log, _ = _contested_history()
    events = event_log.events()

    hypothesis_only = GraphProjector.project(
        campaign_id=CAMPAIGN,
        events=events[:3],
    )
    open_view = GraphConsistencyAnalyzer.analyze(
        projection=hypothesis_only,
        events=events[:3],
    )
    assert open_view.duplicate_node_occurrence_count == 1
    assert open_view.hypotheses[0].state is GraphHypothesisState.OPEN

    supported_projection = GraphProjector.project(
        campaign_id=CAMPAIGN,
        events=events[:4],
    )
    supported_view = GraphConsistencyAnalyzer.analyze(
        projection=supported_projection,
        events=events[:4],
    )
    assert supported_view.hypotheses[0].state is GraphHypothesisState.SUPPORTED

    contested_projection = GraphProjector.project(
        campaign_id=CAMPAIGN,
        events=events,
    )
    contested_view = GraphConsistencyAnalyzer.analyze(
        projection=contested_projection,
        events=events,
    )
    assessment = contested_view.hypotheses[0]
    assert assessment.state is GraphHypothesisState.CONTESTED
    assert len(assessment.supporting_observation_ids) == 1
    assert len(assessment.contradicting_observation_ids) == 1
    assert contested_view.duplicate_node_occurrence_count == 1
    assert len(events) == 5

    with pytest.raises(GraphConsistencyError, match="differs from Event Log"):
        GraphConsistencyAnalyzer.analyze(
            projection=hypothesis_only,
            events=events,
        )


def test_concurrent_admission_serializes_equivocation_without_overwrite() -> None:
    proposal_id = "proposal:surface:concurrent"
    first = _surface_proposal("surface", proposal_id=proposal_id)
    second = _surface_proposal(
        "alternate",
        proposal_id=proposal_id,
        locator_digest=DIGEST_B,
    )
    authority, event_log = _authority([first, second])
    barrier = threading.Barrier(3)

    def submit(proposal: SurfaceProposal) -> object:
        barrier.wait()
        return authority.submit(proposal)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(submit, proposal) for proposal in (first, second)]
        barrier.wait()
        results = [future.result() for future in futures]

    events = event_log.events()
    assert len(events) == 2
    assert [event.sequence for event in events] == [1, 2]
    assert events[1].previous_event_digest == events[0].event_digest
    assert {result.event.decision for result in results} == {
        GraphAdmissionDecision.ADMITTED,
        GraphAdmissionDecision.REJECTED,
    }
    assert {result.event.reason for result in results} == {
        GraphAdmissionReason.ADMITTED,
        GraphAdmissionReason.PROPOSAL_EQUIVOCATION,
    }
    projected = GraphProjector.project(campaign_id=CAMPAIGN, events=events)
    assert len(projected.nodes) == 1


def test_concurrent_exact_retry_appends_one_event() -> None:
    proposal = _surface_proposal()
    authority, event_log = _authority([proposal])
    barrier = threading.Barrier(3)

    def submit() -> object:
        barrier.wait()
        return authority.submit(proposal)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(submit) for _ in range(2)]
        barrier.wait()
        results = [future.result() for future in futures]

    assert len(event_log.events()) == 1
    assert sorted(result.idempotent for result in results) == [False, True]
    assert len({result.event.event_id for result in results}) == 1


class _RacingProjectionStore(InMemoryGraphProjectionStore):
    def __init__(self, *, campaign_id: str) -> None:
        super().__init__(campaign_id=campaign_id)
        self._advance_barrier = threading.Barrier(2)

    def compare_and_advance(
        self,
        events: object,
        *,
        expected_revision: int,
        expected_head_digest: str | None,
    ) -> object:
        self._advance_barrier.wait()
        return super().compare_and_advance(
            events,
            expected_revision=expected_revision,
            expected_head_digest=expected_head_digest,
        )


def test_concurrent_reconciliation_retries_projection_cas() -> None:
    _, event_log, _ = _contested_history()
    store = _RacingProjectionStore(campaign_id=CAMPAIGN)
    reconcilers = [
        GraphProjectionReconciler(event_log=event_log, projection_store=store)
        for _ in range(2)
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda item: item.reconcile(), reconcilers))

    assert store.current().revision == len(event_log.events())
    assert {result.status for result in results} == {
        GraphProjectionReconciliationStatus.IN_SYNC,
        GraphProjectionReconciliationStatus.RECOVERED,
    }


def test_reconciler_recovers_event_projection_partial_write_and_is_idempotent() -> None:
    surface = _surface_proposal()
    duplicate = _surface_proposal("duplicate")
    authority, event_log = _authority([surface, duplicate])
    authority.submit(surface)
    store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    reconciler = GraphProjectionReconciler(
        event_log=event_log,
        projection_store=store,
    )

    first = reconciler.reconcile()
    assert first.status is GraphProjectionReconciliationStatus.RECOVERED
    assert first.recovered_event_count == 1

    authority.submit(duplicate)
    second = reconciler.reconcile()
    assert second.status is GraphProjectionReconciliationStatus.RECOVERED
    assert second.previous_revision == 1
    assert second.projection.revision == 2
    assert len(second.projection.nodes) == 1

    stable = reconciler.reconcile()
    assert stable.status is GraphProjectionReconciliationStatus.IN_SYNC
    assert stable.recovered_event_count == 0


class _DivergentProjectionStore:
    def __init__(self, projection: GraphProjection) -> None:
        self._projection = projection

    def current(self) -> GraphProjection:
        return self._projection

    def compare_and_advance(
        self,
        events: object,
        *,
        expected_revision: int,
        expected_head_digest: str | None,
    ) -> object:
        raise AssertionError("divergent projection must fail before publication")


def test_reconciler_rejects_divergent_projection_instead_of_replacing_it() -> None:
    surface = _surface_proposal()
    authority, event_log = _authority([surface])
    authority.submit(surface)

    alternate = _surface_proposal(
        "alternate",
        locator_digest=DIGEST_B,
    )
    alternate_authority, alternate_log = _authority([alternate])
    alternate_authority.submit(alternate)
    divergent = GraphProjector.project(
        campaign_id=CAMPAIGN,
        events=alternate_log.events(),
    )
    store: GraphProjectionStore = _DivergentProjectionStore(divergent)

    with pytest.raises(GraphConsistencyError, match="diverges"):
        GraphProjectionReconciler(
            event_log=event_log,
            projection_store=store,
        ).reconcile()


def _decision(snapshot: GraphSnapshot) -> GraphDecision:
    return GraphDecision(
        campaignId=CAMPAIGN,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=DIGEST_E,
        snapshot=graph_snapshot_ref(snapshot),
        actorId="pajin.graph.supervisor",
        actorDigest=DIGEST_D,
        createdAt=NOW + timedelta(seconds=11),
    )


def test_decision_guard_rejects_unprojected_and_projected_graph_change() -> None:
    surface = _surface_proposal()
    late = _surface_proposal("late")
    authority, event_log = _authority([surface, late])
    authority.submit(surface)
    projection_store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    reconciler = GraphProjectionReconciler(
        event_log=event_log,
        projection_store=projection_store,
    )
    reconciler.reconcile()
    snapshot_store = InMemoryGraphSnapshotStore()
    snapshot_authority = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_F,
        projection_store=projection_store,
        snapshot_store=snapshot_store,
        clock=lambda: NOW + timedelta(seconds=10),
    )
    snapshot = snapshot_authority.capture(GraphSnapshotReason.REPLAN)
    decision = _decision(snapshot)
    guard = GraphDecisionGuard(
        event_log=event_log,
        projection_store=projection_store,
        snapshot_store=snapshot_store,
        clock=lambda: NOW + timedelta(seconds=12),
    )

    preflight = guard.validate_for_dispatch(decision)
    assert preflight.decision_id == decision.decision_id
    assert preflight.revision == snapshot.revision
    assert preflight.projection_digest == snapshot.projection_digest

    authority.submit(late)
    with pytest.raises(GraphStaleDecisionError, match="recovery is required"):
        guard.validate_for_dispatch(decision)

    reconciler.reconcile()
    with pytest.raises(GraphStaleDecisionError, match="changed after"):
        guard.validate_for_dispatch(decision)

    current_snapshot = snapshot_authority.capture(GraphSnapshotReason.REPLAN)
    current_decision = _decision(current_snapshot)
    assert guard.validate_for_dispatch(current_decision).revision == 2


def test_decision_guard_revalidates_tampered_decision_identity() -> None:
    surface = _surface_proposal()
    authority, event_log = _authority([surface])
    authority.submit(surface)
    projection_store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    GraphProjectionReconciler(
        event_log=event_log,
        projection_store=projection_store,
    ).reconcile()
    snapshot_store = InMemoryGraphSnapshotStore()
    snapshot = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_F,
        projection_store=projection_store,
        snapshot_store=snapshot_store,
        clock=lambda: NOW + timedelta(seconds=10),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    decision = _decision(snapshot)
    tampered = decision.model_copy(
        update={"decision_payload_digest": DIGEST_A},
    )
    guard = GraphDecisionGuard(
        event_log=event_log,
        projection_store=projection_store,
        snapshot_store=snapshot_store,
    )

    with pytest.raises(GraphConsistencyError, match="not canonical"):
        guard.validate_for_dispatch(tampered)
