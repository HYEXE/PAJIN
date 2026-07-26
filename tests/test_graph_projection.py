from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.graph import (
    CampaignFactPayload,
    CampaignFactProposal,
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionReason,
    GraphAdmissionResult,
    GraphContentOrigin,
    GraphEdge,
    GraphHypothesis,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjection,
    GraphProjectionConflict,
    GraphProjectionCoordinator,
    GraphProjectionError,
    GraphProjector,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotError,
    GraphSnapshotReason,
    GraphSnapshotRef,
    GraphSurface,
    InMemoryGraphEventLog,
    InMemoryGraphProjectionStore,
    InMemoryGraphSnapshotStore,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_node_ref,
    graph_snapshot_ref,
)

NOW = datetime(2026, 7, 26, 9, 0, tzinfo=UTC)
CAMPAIGN = "graph-lab"
PRODUCER_ID = "pajin.graph.test-producer"
AUTHORITY_ID = "pajin.graph.admission-authority"
SNAPSHOT_CREATOR_ID = "pajin.graph.snapshot-authority"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def _lineage(*, campaign: str = CAMPAIGN) -> GraphProposalLineage:
    return GraphProposalLineage(
        campaignId=campaign,
        runId="run:graph:projection:1",
        agentId="agent:graph-specialist",
        taskId="task:graph:projection:1",
        requestId="tool_graph_projection_1",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:graph:1",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="capability:graph-observe",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_F,
        evidence=[
            {
                "reference": "evidence/graph-projection.json",
                "sha256": DIGEST_D,
            }
        ],
        producedAt=NOW + timedelta(seconds=2),
    )


def _surface_proposal(
    *,
    proposal_id: str = "proposal:surface:1",
    campaign: str = CAMPAIGN,
    locator_digest: str = DIGEST_A,
) -> SurfaceProposal:
    return SurfaceProposal(
        proposalId=proposal_id,
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_E,
        lineage=_lineage(campaign=campaign),
        surface=GraphSurface(
            campaignId=campaign,
            targetId="target:hybrid",
            surfaceType="http-endpoint",
            locatorSchema="pajin.discovery.http-surface.v1",
            locatorDigest=locator_digest,
            origin=GraphContentOrigin.TRUSTED_CORE,
        ),
    )


def _fact_proposal() -> CampaignFactProposal:
    return CampaignFactProposal(
        proposalId="proposal:fact:1",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_E,
        lineage=_lineage(),
        fact=CampaignFactPayload(
            factKey="target.graph-projection",
            statement="The target has a verified canonical graph projection.",
            valueDigest=DIGEST_B,
            producerId=PRODUCER_ID,
            producerVersion="1.0.0",
            producerDigest=DIGEST_E,
            origin=GraphContentOrigin.AGENT_DERIVED,
            recordedAt=NOW + timedelta(seconds=1),
        ),
    )


GraphTestProposal = SurfaceProposal | CampaignFactProposal


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
                    producerDigest=DIGEST_E,
                    allowedProposalKinds=(
                        GraphProposalKind.CAMPAIGN_FACT,
                        GraphProposalKind.SURFACE,
                    ),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry(
            proposal.lineage for proposal in proposals
        ),
        event_log=event_log,
        clock=lambda: NOW + timedelta(seconds=3),
    )
    return authority, event_log


def _history() -> tuple[InMemoryGraphEventLog, tuple[GraphAdmissionResult, ...]]:
    first = _surface_proposal()
    duplicate_material = _surface_proposal(proposal_id="proposal:surface:duplicate")
    equivocation = _surface_proposal(locator_digest=DIGEST_B)
    fact = _fact_proposal()
    authority, event_log = _authority([first, duplicate_material, fact])
    results = (
        authority.submit(first),
        authority.submit(duplicate_material),
        authority.submit(equivocation),
        authority.submit(fact),
    )
    return event_log, results


def test_projector_rebuilds_deterministic_exact_event_prefix() -> None:
    event_log, results = _history()
    store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    coordinator = GraphProjectionCoordinator(
        event_log=event_log,
        projection_store=store,
    )

    genesis = store.current()
    assert genesis.revision == 0
    assert genesis.event_log_head_digest is None
    assert genesis.nodes == ()
    assert genesis.edges == ()

    advanced = coordinator.refresh()
    replayed = GraphProjector.project(campaign_id=CAMPAIGN, events=event_log.events())

    assert advanced.projection == replayed
    assert advanced.previous_revision == 0
    assert advanced.applied_event_count == 4
    assert advanced.projection.revision == 4
    assert advanced.projection.event_log_head_digest == results[-1].event.event_digest
    assert len(advanced.projection.nodes) == 2
    assert advanced.projection.edges == ()
    assert coordinator.refresh().idempotent is True


def test_projection_revision_tracks_rejections_without_changing_material() -> None:
    event_log, results = _history()
    events = event_log.events()
    assert results[2].event.decision is GraphAdmissionDecision.REJECTED
    store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)

    first = store.compare_and_advance(
        events[:2],
        expected_revision=0,
        expected_head_digest=None,
    )
    rejected = store.compare_and_advance(
        events[:3],
        expected_revision=first.projection.revision,
        expected_head_digest=first.projection.event_log_head_digest,
    )

    assert rejected.applied_event_count == 1
    assert rejected.projection.revision == 3
    assert rejected.projection.nodes == first.projection.nodes
    assert rejected.projection.node_projection_digest == (
        first.projection.node_projection_digest
    )
    assert rejected.projection.projection_digest != first.projection.projection_digest


def test_projection_compare_and_set_rejects_stale_rollback_and_divergent_prefix() -> None:
    event_log, _ = _history()
    events = event_log.events()
    store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    current = store.compare_and_advance(
        events[:2],
        expected_revision=0,
        expected_head_digest=None,
    ).projection

    with pytest.raises(GraphProjectionConflict, match="compare-and-set"):
        store.compare_and_advance(
            events,
            expected_revision=0,
            expected_head_digest=None,
        )
    assert store.current() == current

    with pytest.raises(GraphProjectionConflict, match="rollback"):
        store.compare_and_advance(
            events[:1],
            expected_revision=current.revision,
            expected_head_digest=current.event_log_head_digest,
        )
    assert store.current() == current

    alternate_one = _surface_proposal(locator_digest=DIGEST_C)
    alternate_two = _surface_proposal(
        proposal_id="proposal:surface:alternate",
        locator_digest=DIGEST_D,
    )
    alternate_authority, alternate_log = _authority([alternate_one, alternate_two])
    alternate_authority.submit(alternate_one)
    alternate_authority.submit(alternate_two)
    with pytest.raises(GraphProjectionConflict, match="prefix differs"):
        store.compare_and_advance(
            alternate_log.events(),
            expected_revision=current.revision,
            expected_head_digest=current.event_log_head_digest,
        )
    assert store.current() == current


def test_projector_rejects_mutated_noncontiguous_and_foreign_events() -> None:
    event_log, _ = _history()
    events = event_log.events()

    mutated = events[0].model_copy(update={"sequence": 2})
    with pytest.raises(GraphProjectionError, match="not canonical"):
        GraphProjector.project(campaign_id=CAMPAIGN, events=(mutated,))

    with pytest.raises(GraphProjectionError, match="not contiguous"):
        GraphProjector.project(campaign_id=CAMPAIGN, events=events[1:])

    foreign = _surface_proposal(campaign="foreign-campaign")
    authority, foreign_log = _authority([foreign])
    rejected = authority.submit(foreign).event
    assert rejected.reason is GraphAdmissionReason.FOREIGN_CAMPAIGN
    assert rejected.campaign_id == CAMPAIGN
    assert rejected.proposal_campaign_id == "foreign-campaign"
    projected = GraphProjector.project(
        campaign_id=CAMPAIGN,
        events=foreign_log.events(),
    )
    assert projected.revision == 1
    assert projected.nodes == ()


def test_projection_model_rejects_identity_tamper_and_dangling_edges() -> None:
    event_log, _ = _history()
    projection = GraphProjector.project(
        campaign_id=CAMPAIGN,
        events=event_log.events(),
    )
    raw = projection.model_dump(mode="json")
    raw["revision"] += 1
    with pytest.raises(ValidationError, match="digest differs"):
        GraphProjection.model_validate(raw)

    surface = _surface_proposal().surface
    hypothesis = GraphHypothesis(
        campaignId=CAMPAIGN,
        hypothesisType="projection-integrity",
        statement="A Graph edge must resolve inside its exact projection.",
        expectedObservable="Projection validation rejects a dangling endpoint.",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_E,
        origin=GraphContentOrigin.AGENT_DERIVED,
        confidence=0.8,
    )
    dangling = GraphEdge(
        campaignId=CAMPAIGN,
        relation=GraphRelation.MOTIVATES,
        source=graph_node_ref(surface),
        target=graph_node_ref(hypothesis),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    with pytest.raises(ValidationError, match="dangling edge"):
        GraphProjection(
            campaignId=CAMPAIGN,
            revision=1,
            eventLogHeadDigest=DIGEST_A,
            nodes=(surface,),
            edges=(dangling,),
        )


def test_snapshot_captures_exact_projection_chain_and_resolves_reference() -> None:
    event_log, _ = _history()
    projection_store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    GraphProjectionCoordinator(
        event_log=event_log,
        projection_store=projection_store,
    ).refresh()
    snapshot_store = InMemoryGraphSnapshotStore()
    authority = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_F,
        projection_store=projection_store,
        snapshot_store=snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    )

    checkpoint = authority.capture(GraphSnapshotReason.CHECKPOINT)
    handoff = authority.capture(GraphSnapshotReason.HANDOFF)
    reference = graph_snapshot_ref(checkpoint)

    assert checkpoint.projection == projection_store.current()
    assert checkpoint.revision == checkpoint.projection.revision
    assert checkpoint.event_log_head_digest == (
        checkpoint.projection.event_log_head_digest
    )
    assert checkpoint.previous_snapshot_digest is None
    assert handoff.previous_snapshot_digest == checkpoint.snapshot_digest
    assert snapshot_store.resolve(reference) == checkpoint
    assert snapshot_store.head_digest() == handoff.snapshot_digest


def test_snapshot_store_rejects_writer_predecessor_and_reference_tamper() -> None:
    projection_store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    snapshot_store = InMemoryGraphSnapshotStore()
    authority = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_F,
        projection_store=projection_store,
        snapshot_store=snapshot_store,
        clock=lambda: NOW,
    )
    snapshot = authority.capture(GraphSnapshotReason.RECOVERY)

    with pytest.raises(GraphSnapshotError, match="already claimed"):
        snapshot_store.claim_writer("pajin.graph.second-snapshot-authority", DIGEST_E)
    with pytest.raises(GraphSnapshotError, match="write authority"):
        snapshot_store.append(snapshot, writer=object())

    reference_raw = graph_snapshot_ref(snapshot).model_dump(mode="json")
    reference_raw["projection_digest"] = DIGEST_A
    tampered_reference = GraphSnapshotRef.model_validate(reference_raw)
    with pytest.raises(GraphSnapshotError, match="differs from stored authority"):
        snapshot_store.resolve(tampered_reference)

    stale_store = InMemoryGraphSnapshotStore()
    stale_writer = stale_store.claim_writer(SNAPSHOT_CREATOR_ID, DIGEST_F)
    stale_raw = snapshot.model_dump(mode="json")
    stale_raw.update(
        {
            "snapshot_id": "",
            "snapshot_digest": "",
            "previous_snapshot_digest": DIGEST_B,
        }
    )
    stale = GraphSnapshot.model_validate(stale_raw)
    with pytest.raises(GraphSnapshotError, match="predecessor is stale"):
        stale_store.append(stale, writer=stale_writer)


def test_snapshot_store_defensively_copies_and_revalidates_snapshots() -> None:
    event_log, _ = _history()
    projection_store = InMemoryGraphProjectionStore(campaign_id=CAMPAIGN)
    GraphProjectionCoordinator(
        event_log=event_log,
        projection_store=projection_store,
    ).refresh()
    snapshot_store = InMemoryGraphSnapshotStore()
    authority = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_F,
        projection_store=projection_store,
        snapshot_store=snapshot_store,
        clock=lambda: NOW,
    )
    snapshot = authority.capture(GraphSnapshotReason.CHECKPOINT)
    reference = graph_snapshot_ref(snapshot)

    snapshot.projection.nodes[0].campaign_id = "foreign-campaign"
    resolved = snapshot_store.resolve(reference)
    assert resolved.projection.nodes[0].campaign_id == CAMPAIGN

    tampered = resolved.model_copy(deep=True)
    tampered.projection.nodes[0].campaign_id = "foreign-campaign"
    validation_store = InMemoryGraphSnapshotStore()
    validation_writer = validation_store.claim_writer(
        SNAPSHOT_CREATOR_ID,
        DIGEST_F,
    )
    with pytest.raises(GraphSnapshotError, match="not canonical"):
        validation_store.append(tampered, writer=validation_writer)
