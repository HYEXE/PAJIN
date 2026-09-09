"""Publish the urgent fixture through actual SQLite admission and projection writers."""

from pajin.graph import (
    CampaignFactPayload,
    CampaignFactProposal,
    GraphAction,
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphCampaignFact,
    GraphEvidence,
    GraphObservation,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSnapshot,
    ObservationProposal,
    TrustedGraphLineageRegistry,
)


def publish_urgent_projection(database, requested):
    from pajin.graph.sqlite_store import SQLiteGraphStore

    database = SQLiteGraphStore(database.path, campaign_id=database.campaign_id, initialize=False)
    current = database.projection_store.current()
    existing = {node.node_id for node in current.nodes}
    proposals = []
    for node in requested.projection.nodes:
        if node.node_id in existing or not isinstance(node, (GraphCampaignFact, GraphObservation)):
            continue
        lineage_args = dict(
            campaignId=node.campaign_id,
            runId="run:urgent-source",
            agentId="agent:sender:specialist",
            taskId="task_source_analysis",
            requestId="urgent_fact_1",
            requestDigest="a" * 64,
            capabilityGrantId="grant:urgent:1",
            capabilityGrantDigest="c" * 64,
            capabilityId="capability:observe-result",
            capabilityVersion="1.0.0",
            capabilityDigest="a" * 64,
            sourceRootDigest="d" * 64,
            evidence=[{"reference": "evidence/urgent-result.json", "sha256": "e" * 64}],
            producedAt=requested.created_at,
        )
        args = dict(
            proposalId=f"proposal:urgent:{node.node_id}",
            producerId=node.producer_id,
            producerVersion=node.producer_version,
            producerDigest=node.producer_digest,
        )
        if isinstance(node, GraphCampaignFact):
            proposal = CampaignFactProposal(
                **args,
                lineage=GraphProposalLineage(**lineage_args),
                fact=CampaignFactPayload.model_validate(
                    {name: getattr(node, name) for name in CampaignFactPayload.model_fields}
                ),
            )
        else:
            evidence = next(x for x in requested.projection.nodes if isinstance(x, GraphEvidence))
            action = next(x for x in requested.projection.nodes if isinstance(x, GraphAction))
            lineage_args.update(
                requestId=action.request_id,
                requestDigest=action.request_digest,
                capabilityGrantId=action.authority_id,
                capabilityGrantDigest=action.authority_digest,
                sourceRootDigest=evidence.source_root_digest,
                evidence=[{"reference": evidence.reference, "sha256": evidence.sha256}],
            )
            proposal = ObservationProposal(
                **args,
                lineage=GraphProposalLineage(**lineage_args),
                action=action,
                observation=node,
                evidenceNodes=[evidence],
                edges=list(requested.projection.edges),
            )
        proposals.append(proposal)
    authority = GraphAdmissionAuthority(
        campaign_id=database.campaign_id,
        authority_id="pajin.collaboration.urgent-snapshot-authority",
        authority_digest="a" * 64,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=proposal.producer_id,
                    producerVersion=proposal.producer_version,
                    producerDigest=proposal.producer_digest,
                    allowedProposalKinds=(
                        GraphProposalKind.CAMPAIGN_FACT,
                        GraphProposalKind.OBSERVATION,
                    ),
                )
                for proposal in proposals
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry(proposal.lineage for proposal in proposals),
        event_log=database.event_log,
        clock=lambda: requested.created_at,
    )
    for proposal in proposals:
        admitted = authority.submit(proposal)
        assert admitted.event.decision is GraphAdmissionDecision.ADMITTED, admitted
    projection = (
        GraphProjectionCoordinator(
            event_log=database.event_log,
            projection_store=database.projection_store,
        )
        .refresh()
        .projection
    )
    return GraphSnapshot(
        campaignId=database.campaign_id,
        previousSnapshotDigest=database.snapshot_store.head_digest(),
        graphSchemaVersion=projection.graph_schema_version,
        revision=projection.revision,
        eventLogHeadDigest=projection.event_log_head_digest,
        projectionId=projection.projection_id,
        projectionDigest=projection.projection_digest,
        nodeProjectionDigest=projection.node_projection_digest,
        edgeProjectionDigest=projection.edge_projection_digest,
        reason=requested.reason,
        createdAt=requested.created_at,
        creatorId=requested.creator_id,
        creatorDigest=requested.creator_digest,
        projection=projection,
    )
