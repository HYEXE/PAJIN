from __future__ import annotations

import sys
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from pajin.agentic.context_compaction import (
    CompactedAgentContext,
    ContextCompactionPolicy,
    compact_agent_context,
    verify_compacted_agent_context,
)
from pajin.agentic.durable import (
    AgenticCoordinationBinding,
    AgenticCoordinationError,
    AgenticCoordinationStore,
    VerifiedAgenticDurableHead,
)
from pajin.agentic.durable_graph import (
    AgenticGraphHeadError,
    CurrentGraphHeadResolver,
    VerifiedCurrentGraphHead,
)
from pajin.agentic.frontier import (
    FrontierCandidate,
    PathScoringPolicy,
    compile_frontier_candidate,
    default_path_scoring_policy,
)
from pajin.agentic.models import (
    AgentControlCommandKind,
    AgentEvent,
    AgentEventKind,
    ArtifactReference,
    ExploitGroupDefinition,
    HypothesisProposal,
    ModelPathEstimate,
    PentestSpecialization,
    TrustedPathFeatures,
)
from pajin.agentic.supervisor import (
    DynamicSupervisor,
    DynamicSupervisorPolicy,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.graph import (
    GraphAdmissionAuthority,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    GraphSurface,
    SQLiteGraphStore,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_node_ref,
    graph_snapshot_ref,
)
from pajin.graph import (
    HypothesisProposal as GraphHypothesisProposal,
)
from pajin.web_assessment.analysis_skill_projection import (
    registered_web_pentest_exploit_group,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="authoritative durable coordination requires Linux /proc descriptors",
)

CAMPAIGN = "agentic-compaction"
SUPERVISOR_ID = "agent:dynamic-supervisor"
TARGET_ID = "target:local-lab"
NOW = datetime(2026, 9, 18, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_F = "f" * 64

ROOT_SURFACE = GraphSurface(
    campaignId=CAMPAIGN,
    targetId=TARGET_ID,
    surfaceType="web.http-operation",
    locatorSchema="pajin.test.target-neutral-locator",
    locatorDigest=SHA_D,
    origin=GraphContentOrigin.TRUSTED_CORE,
)
ROOT_HYPOTHESIS = GraphHypothesis(
    campaignId=CAMPAIGN,
    hypothesisType="web.xss",
    statement="Canonical source Hypothesis for deterministic context compaction.",
    expectedObservable="A bounded independently verifiable XSS state transition.",
    producerId="pajin.agentic.context-compaction-tests",
    producerVersion="1.0.0",
    producerDigest=discovery_digest(
        "pajin.test.context-compaction-producer/v1",
        {"kind": "root-xss"},
    ),
    origin=GraphContentOrigin.TRUSTED_CORE,
    confidence=0.5,
)
ROOT_EDGE = GraphEdge(
    campaignId=CAMPAIGN,
    relation=GraphRelation.MOTIVATES,
    source=graph_node_ref(ROOT_SURFACE),
    target=graph_node_ref(ROOT_HYPOTHESIS),
    authorityId="agentic-context-compaction-test-authority",
    authorityDigest=SHA_A,
)


def _artifact(ordinal: int, *, artifact_id: str | None = None) -> ArtifactReference:
    return ArtifactReference(
        artifactId=artifact_id or f"artifact-{ordinal}",
        artifactSha256=f"{ordinal:x}" * 64,
        mediaType="application/json",
        sourceRunId=f"run-{ordinal}",
    )


def _policy(**updates: Any) -> ContextCompactionPolicy:
    values: dict[str, object] = {
        "maxSourceItems": 16,
        "maxRetainedItems": 2,
        "maxSourceReferenceBytes": 64 * 1024,
        "maxContextBytes": 32 * 1024,
        "maxContextNodes": 2048,
        "maxCompactionDepth": 3,
    }
    values.update(updates)
    return ContextCompactionPolicy.model_validate(values)


def _lineage(tag: str, *, producer_digest: str) -> GraphProposalLineage:
    digest = discovery_digest("pajin.test.context-compaction-lineage/v1", {"tag": tag})
    return GraphProposalLineage(
        campaignId=CAMPAIGN,
        runId=f"run:agentic-context-compaction:{tag}",
        agentId="agent:agentic-context-compaction-fixture",
        taskId=f"task:agentic-context-compaction:{tag}",
        requestId=f"agentic_context_compaction_{tag}",
        requestDigest=digest,
        capabilityGrantId=f"grant:agentic-context-compaction:{tag}",
        capabilityGrantDigest=producer_digest,
        capabilityId="capability:agentic-context-compaction-graph-fixture",
        capabilityVersion="1.0.0",
        capabilityDigest=SHA_C,
        sourceRootDigest=SHA_D,
        evidence=[
            GraphEvidenceBinding(
                reference=f"evidence/agentic-context-compaction-{tag}.json",
                sha256=digest,
            )
        ],
        producedAt=NOW,
    )


def _seed_current_graph(store: SQLiteGraphStore) -> None:
    surface_producer_id = "pajin.agentic.context-compaction-surface-fixture"
    surface_producer_digest = SHA_F
    surface = SurfaceProposal(
        proposalId="proposal:agentic-context-compaction:surface",
        producerId=surface_producer_id,
        producerVersion="1.0.0",
        producerDigest=surface_producer_digest,
        lineage=_lineage("surface", producer_digest=surface_producer_digest),
        surface=ROOT_SURFACE,
    )
    hypothesis = GraphHypothesisProposal(
        proposalId="proposal:agentic-context-compaction:hypothesis",
        producerId=ROOT_HYPOTHESIS.producer_id,
        producerVersion=ROOT_HYPOTHESIS.producer_version,
        producerDigest=ROOT_HYPOTHESIS.producer_digest,
        lineage=_lineage("hypothesis", producer_digest=ROOT_HYPOTHESIS.producer_digest),
        hypothesis=ROOT_HYPOTHESIS,
        edges=[ROOT_EDGE],
    )
    admission = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id="pajin.agentic.context-compaction-test-admission",
        authority_digest=SHA_A,
        producers=GraphProducerRegistry(
            (
                GraphProducerRegistration(
                    producerId=surface_producer_id,
                    producerVersion="1.0.0",
                    producerDigest=surface_producer_digest,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                GraphProducerRegistration(
                    producerId=ROOT_HYPOTHESIS.producer_id,
                    producerVersion=ROOT_HYPOTHESIS.producer_version,
                    producerDigest=ROOT_HYPOTHESIS.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.HYPOTHESIS,),
                ),
            )
        ),
        lineage_verifier=TrustedGraphLineageRegistry((surface.lineage, hypothesis.lineage)),
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    admission.submit(surface)
    admission.submit(hypothesis)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()


def _candidate(snapshot: GraphSnapshot) -> FrontierCandidate:
    proposal = HypothesisProposal(
        campaignId=CAMPAIGN,
        sourceSnapshotId=snapshot.snapshot_id,
        sourceSnapshotDigest=snapshot.snapshot_digest,
        parentHypothesisId=ROOT_HYPOTHESIS.node_id,
        ancestorHypothesisIds=(ROOT_HYPOTHESIS.node_id,),
        targetId=TARGET_ID,
        threatClass="xss",
        specialization=PentestSpecialization.XSS,
        depth=1,
        statement="Investigate a bounded successor XSS hypothesis.",
        expectedObservable="Observe an independently verifiable XSS state transition.",
        requiredEvidenceTypes=(
            "web.independent-replay",
            "web.negative-control",
        ),
        estimate=ModelPathEstimate(successLikelihoodBps=7_000),
    )
    features = TrustedPathFeatures(
        sourceSnapshotId=snapshot.snapshot_id,
        sourceSnapshotDigest=snapshot.snapshot_digest,
        sourceEvidenceIds=("evidence:agentic-context-compaction",),
        expectedImpactBps=7_000,
        privilegeGainBps=5_000,
        reachabilityGainBps=5_000,
        evidenceQualityBps=7_000,
        noveltyBps=7_000,
        executionCostBps=2_000,
        safetyRiskBps=1_000,
    )
    return compile_frontier_candidate(proposal, features)


@dataclass(frozen=True)
class _Harness:
    store: AgenticCoordinationStore
    head: VerifiedAgenticDurableHead
    resolver: CurrentGraphHeadResolver
    graph_head: VerifiedCurrentGraphHead
    snapshot: GraphSnapshot
    graph_authority: GraphSnapshotAuthority
    supervisor: DynamicSupervisor
    exploit_group: ExploitGroupDefinition
    supervisor_policy: DynamicSupervisorPolicy
    scoring_policy: PathScoringPolicy
    artifacts: tuple[ArtifactReference, ...]
    agent_id: str


@contextmanager
def _harness(
    tmp_path: Path,
    artifacts: tuple[ArtifactReference, ...],
    *,
    name: str = "primary",
) -> Iterator[_Harness]:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    graph_path = root / "graph.sqlite3"
    graph_store = SQLiteGraphStore(graph_path, campaign_id=CAMPAIGN)
    _seed_current_graph(graph_store)
    graph_authority = GraphSnapshotAuthority(
        creator_id="pajin.agentic.context-compaction-tests",
        creator_digest=SHA_A,
        projection_store=graph_store.projection_store,
        snapshot_store=graph_store.snapshot_store,
        clock=lambda: NOW,
    )
    snapshot = graph_authority.capture(GraphSnapshotReason.CHECKPOINT)
    resolver = CurrentGraphHeadResolver(graph_path, campaign_id=CAMPAIGN)
    graph_head = resolver.resolve(graph_snapshot_ref(snapshot))
    exploit_group = registered_web_pentest_exploit_group()
    supervisor_policy = DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0)
    scoring_policy = default_path_scoring_policy()
    supervisor = DynamicSupervisor(
        campaign_id=CAMPAIGN,
        supervisor_agent_id=SUPERVISOR_ID,
        source_snapshot=snapshot,
        allowed_target_ids=(TARGET_ID,),
        exploit_group=exploit_group,
        policy=supervisor_policy,
        scoring_policy=scoring_policy,
    )
    initial = supervisor.checkpoint()
    cycle = supervisor.plan_cycle((_candidate(snapshot),))
    binding = AgenticCoordinationBinding.from_checkpoint(
        initial,
        control_plane_run_id=f"agentic-control-plane:{name}",
        campaign_manifest_digest=SHA_B,
        deployment_digest=SHA_C,
        exploit_group=exploit_group,
        supervisor_policy=supervisor_policy,
        scoring_policy=scoring_policy,
    )
    store = AgenticCoordinationStore(
        root / "coordination.sqlite3",
        binding=binding,
        graph_resolver=resolver,
        graph_head=graph_head,
        store_id_factory=lambda: (
            "agentic-store:"
            + discovery_digest("pajin.test.context-compaction-store/v1", {"name": name})[:32]
        ),
    )
    initial_head = store.initialize_head(
        initial,
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    cycle_publication = store.publish_cycle(
        initial_head,
        cycle,
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    spawn_claim = store.claim_next_delivery(
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    assert spawn_claim is not None
    assert spawn_claim.command.command is AgentControlCommandKind.SPAWN
    spawn_admission = store.admit_delivery(
        spawn_claim,
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    store.acknowledge_delivery(
        spawn_claim,
        spawn_admission,
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    spawn_publication = store.publish_event(
        cycle_publication.head,
        AgentEvent(
            campaignId=CAMPAIGN,
            sequence=1,
            agentId=spawn_claim.command.target_agent_id,
            commandId=spawn_claim.command.command_id,
            event=AgentEventKind.ACKNOWLEDGED,
            summary="Spawn command durably admitted.",
        ),
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    assignment_claim = store.claim_next_delivery(
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    assert assignment_claim is not None
    assert assignment_claim.command.command is AgentControlCommandKind.ASSIGN
    assert assignment_claim.command.target_agent_id == spawn_claim.command.target_agent_id
    assignment_admission = store.admit_delivery(
        assignment_claim,
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    store.acknowledge_delivery(
        assignment_claim,
        assignment_admission,
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    terminal_publication = store.publish_event(
        spawn_publication.head,
        AgentEvent(
            campaignId=CAMPAIGN,
            sequence=1,
            agentId=assignment_claim.command.target_agent_id,
            commandId=assignment_claim.command.command_id,
            event=AgentEventKind.FINAL,
            taskId=assignment_claim.command.task_id,
            candidateId=assignment_claim.command.candidate_id,
            summary="Bounded context source task completed.",
            artifactRefs=artifacts,
        ),
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    head = terminal_publication.head
    restored = store.restore_supervisor(
        head,
        graph_resolver=resolver,
        graph_head=graph_head,
    )
    try:
        yield _Harness(
            store=store,
            head=head,
            resolver=resolver,
            graph_head=graph_head,
            snapshot=snapshot,
            graph_authority=graph_authority,
            supervisor=restored,
            exploit_group=exploit_group,
            supervisor_policy=supervisor_policy,
            scoring_policy=scoring_policy,
            artifacts=artifacts,
            agent_id=assignment_claim.command.target_agent_id,
        )
    finally:
        resolver.close()


def _advance(
    harness: _Harness,
    head: VerifiedAgenticDurableHead,
) -> VerifiedAgenticDurableHead:
    cycle = harness.supervisor.plan_cycle(())
    return harness.store.publish_cycle(
        head,
        cycle,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
    ).head


def _compact(
    harness: _Harness,
    head: VerifiedAgenticDurableHead,
    *,
    policy: ContextCompactionPolicy,
    source_artifacts: tuple[ArtifactReference, ...] | None = None,
    ancestor_contexts: tuple[CompactedAgentContext, ...] = (),
) -> CompactedAgentContext:
    return compact_agent_context(
        harness.store,
        head,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        agent_id=harness.agent_id,
        source_artifacts=(harness.artifacts if source_artifacts is None else source_artifacts),
        policy=policy,
        ancestor_contexts=ancestor_contexts,
    )


def test_compaction_is_deterministic_target_neutral_and_advisory_only(
    tmp_path: Path,
) -> None:
    artifacts = (_artifact(1), _artifact(2), _artifact(3))
    policy = _policy()
    with _harness(tmp_path, artifacts) as harness:
        first = _compact(harness, harness.head, policy=policy)
        second = _compact(harness, harness.head, policy=policy)
        verified = verify_compacted_agent_context(
            first,
            coordination_store=harness.store,
            durable_head=harness.head,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            agent_id=harness.agent_id,
            source_artifacts=artifacts,
            policy=policy,
        )

        assert first == second == verified
        assert first.source_checkpoint_id == harness.head.checkpoint.checkpoint_id
        assert first.source_checkpoint_digest == harness.head.checkpoint.checkpoint_digest
        assert first.source_snapshot_digest == harness.snapshot.snapshot_digest
        wire = first.model_dump(mode="json", by_alias=True)
        assert harness.snapshot.snapshot_id not in str(wire)

    assert first.source_artifact_count == 3
    assert first.input_artifact_count == 3
    assert first.unique_artifact_count == 3
    assert first.retained_artifact_count == 2
    assert first.omitted_artifact_count == 1
    assert first.compaction_depth == 1
    assert wire["contentIsUntrusted"] is True
    assert all(
        wire[field] is False
        for field in (
            "sourceContentEmbedded",
            "modelSummaryUsed",
            "targetIdentityIncluded",
            "targetLocatorIncluded",
            "authorityMaterialCompacted",
            "ledgerMaterialCompacted",
            "eventMaterialCompacted",
            "budgetMaterialCompacted",
            "graphMaterialCompacted",
            "summaryAuthority",
            "evidenceAuthority",
            "instructionAuthority",
            "scopeExpansionAuthorized",
            "capabilityGranted",
            "permitGranted",
            "executionAuthorized",
            "findingAuthority",
            "graphWriteAuthorized",
        )
    )
    serialized = str(wire)
    assert CAMPAIGN not in serialized
    assert SUPERVISOR_ID not in serialized
    assert harness.agent_id not in serialized
    assert TARGET_ID not in serialized
    assert all(artifact.artifact_id not in serialized for artifact in artifacts)
    assert all(artifact.artifact_sha256 not in serialized for artifact in artifacts)
    assert all(artifact.source_run_id not in serialized for artifact in artifacts)
    assert "application/json" not in serialized
    assert {"summary", "narrative", "prompt", "messages", "artifactContent"}.isdisjoint(wire)
    assert all(
        item["contentIsUntrusted"] is True
        and item["instructionAuthority"] is False
        and item["artifactIdentifierIncluded"] is False
        and item["sourceRunIdentifierIncluded"] is False
        for item in wire["retainedArtifactRefs"]
    )


def test_source_membership_and_order_must_exactly_match_verified_checkpoint(
    tmp_path: Path,
) -> None:
    artifacts = (_artifact(1), _artifact(2), _artifact(3))
    with _harness(tmp_path, artifacts) as harness:
        with pytest.raises(ValueError, match="membership or order"):
            _compact(
                harness,
                harness.head,
                source_artifacts=tuple(reversed(artifacts)),
                policy=_policy(),
            )

        substituted = ArtifactReference(
            artifactId=artifacts[0].artifact_id,
            artifactSha256="f" * 64,
            mediaType=artifacts[0].media_type,
            sourceRunId=artifacts[0].source_run_id,
        )
        with pytest.raises(ValueError, match="membership or order"):
            _compact(
                harness,
                harness.head,
                source_artifacts=(substituted, *artifacts[1:]),
                policy=_policy(),
            )


def test_item_reference_byte_output_byte_and_node_budgets_fail_closed(
    tmp_path: Path,
) -> None:
    artifacts = (_artifact(1), _artifact(2), _artifact(3))
    with _harness(tmp_path, artifacts) as harness:
        one = _compact(
            harness,
            harness.head,
            policy=_policy(maxRetainedItems=1),
        )
        assert one.retained_artifact_count == 1
        assert one.omitted_artifact_count == 2

        with pytest.raises(ValueError, match="source-item budget"):
            _compact(
                harness,
                harness.head,
                policy=_policy(maxSourceItems=2, maxRetainedItems=2),
            )
        with pytest.raises(ValueError, match="canonical byte limit"):
            _compact(
                harness,
                harness.head,
                policy=_policy(maxSourceReferenceBytes=128),
            )
        with pytest.raises(ValueError, match="canonical byte budget"):
            _compact(
                harness,
                harness.head,
                policy=_policy(maxContextBytes=1024),
            )
        with pytest.raises(ValueError, match="canonical node budget"):
            _compact(
                harness,
                harness.head,
                policy=_policy(maxContextNodes=64),
            )


def test_ancestor_chain_is_rebuilt_from_verified_history_and_bounded(
    tmp_path: Path,
) -> None:
    artifacts = (_artifact(1), _artifact(2))
    policy = _policy(maxRetainedItems=3, maxCompactionDepth=2)
    with _harness(tmp_path, artifacts) as harness:
        root = _compact(harness, harness.head, policy=policy)
        second_head = _advance(harness, harness.head)
        child = _compact(
            harness,
            second_head,
            policy=policy,
            ancestor_contexts=(root,),
        )
        with pytest.raises(ValueError, match="ancestors must be an exact tuple"):
            _compact(
                harness,
                second_head,
                policy=policy,
                ancestor_contexts=cast(Any, [root]),
            )

        assert child.compaction_depth == 2
        assert child.parent_context_digest == root.context_digest
        assert child.ancestor_context_digests == (root.context_digest,)
        assert child.input_artifact_count == 4
        assert child.unique_artifact_count == 2

        forged_wire = root.model_dump(mode="json", by_alias=True)
        forged_wire["retainedArtifactRefs"][0]["artifactReferenceDigest"] = "f" * 64
        forged_wire["retainedArtifactSequenceDigest"] = discovery_digest(
            "pajin.agentic.context-retained-artifact-sequence/v1",
            {
                "artifactReferenceDigests": [
                    item["artifactReferenceDigest"] for item in forged_wire["retainedArtifactRefs"]
                ]
            },
        )
        forged_wire["contextId"] = ""
        forged_wire["contextDigest"] = ""
        forged = CompactedAgentContext.model_validate(forged_wire)
        with pytest.raises(ValueError, match="verified checkpoint lineage"):
            _compact(
                harness,
                second_head,
                policy=policy,
                ancestor_contexts=(forged,),
            )

        third_head = _advance(harness, second_head)
        with pytest.raises(ValueError, match="exhaust the depth budget"):
            _compact(
                harness,
                third_head,
                policy=policy,
                ancestor_contexts=(root, child),
            )


def test_raw_stale_foreign_and_graph_stale_authorities_are_rejected(
    tmp_path: Path,
) -> None:
    artifacts = (_artifact(1),)
    with _harness(tmp_path, artifacts, name="first") as first:
        with pytest.raises(TypeError, match="verified durable head"):
            compact_agent_context(
                first.store,
                cast(Any, first.head.checkpoint),
                graph_resolver=first.resolver,
                graph_head=first.graph_head,
                agent_id=first.agent_id,
                source_artifacts=artifacts,
                policy=_policy(),
            )

        stale = first.head
        current = _advance(first, stale)
        with pytest.raises(AgenticCoordinationError, match="foreign or stale"):
            _compact(first, stale, policy=_policy())

        with (
            _harness(tmp_path, artifacts, name="second") as second,
            pytest.raises(AgenticCoordinationError, match="foreign or stale"),
        ):
            _compact(first, second.head, policy=_policy())

        first.graph_authority.capture(GraphSnapshotReason.HANDOFF)
        with pytest.raises((AgenticCoordinationError, AgenticGraphHeadError)):
            _compact(first, current, policy=_policy())


def test_tamper_model_copy_summary_and_non_wire_containers_are_rejected(
    tmp_path: Path,
) -> None:
    artifacts = (_artifact(1), _artifact(2))
    policy = _policy()
    with _harness(tmp_path, artifacts) as harness:
        context = _compact(harness, harness.head, policy=policy)

        tampered_wire = context.model_dump(mode="json", by_alias=True)
        tampered_wire["sourceArtifactSequenceDigest"] = "f" * 64
        tampered_wire["contextId"] = ""
        tampered_wire["contextDigest"] = ""
        self_consistent_tamper = CompactedAgentContext.model_validate(tampered_wire)
        with pytest.raises(ValueError, match="exact source projection"):
            verify_compacted_agent_context(
                self_consistent_tamper,
                coordination_store=harness.store,
                durable_head=harness.head,
                graph_resolver=harness.resolver,
                graph_head=harness.graph_head,
                agent_id=harness.agent_id,
                source_artifacts=artifacts,
                policy=policy,
            )

        smuggled_artifact = artifacts[0].model_copy(update={"content_included": True})
        with pytest.raises(ValidationError, match="content_included"):
            _compact(
                harness,
                harness.head,
                source_artifacts=(smuggled_artifact, artifacts[1]),
                policy=policy,
            )

        smuggled_policy = policy.model_copy(update={"model_summarization_allowed": True})
        with pytest.raises(ValidationError, match="model_summarization_allowed"):
            _compact(harness, harness.head, policy=smuggled_policy)

        smuggled_context = context.model_copy(update={"finding_authority": True})
        with pytest.raises(ValidationError, match="finding_authority"):
            CompactedAgentContext.model_validate(smuggled_context)

        smuggled_ref = context.retained_artifact_refs[0].model_copy(
            update={"instruction_authority": True}
        )
        nested_smuggle = context.model_copy(
            update={
                "retained_artifact_refs": (
                    smuggled_ref,
                    *context.retained_artifact_refs[1:],
                )
            }
        )
        with pytest.raises(ValidationError, match="instruction_authority"):
            CompactedAgentContext.model_validate(nested_smuggle)

        with_summary = context.model_dump(mode="json", by_alias=True)
        with_summary["summary"] = "caller-authored pseudo-summary"
        with pytest.raises(ValidationError, match="extra_forbidden"):
            CompactedAgentContext.model_validate(with_summary)

        with pytest.raises(ValueError, match="exact tuple"):
            _compact(
                harness,
                harness.head,
                source_artifacts=cast(Any, list(artifacts)),
                policy=policy,
            )
        with pytest.raises(ValueError, match="exact tuple"):
            _compact(
                harness,
                harness.head,
                source_artifacts=cast(Any, deque(artifacts)),
                policy=policy,
            )

        non_wire = context.model_dump(mode="json", by_alias=True)
        non_wire["ancestorContextDigests"] = deque()
        with pytest.raises(ValueError, match="unsupported value type"):
            CompactedAgentContext.model_validate(non_wire)


def test_cyclic_deep_oversized_and_non_string_key_inputs_fail_controlled(
    tmp_path: Path,
) -> None:
    with _harness(tmp_path, (_artifact(1),)) as harness:
        context = _compact(harness, harness.head, policy=_policy())

    cyclic = context.model_dump(mode="json", by_alias=True)
    cyclic["retainedArtifactRefs"] = cyclic
    with pytest.raises(ValueError, match="cycle"):
        CompactedAgentContext.model_validate(cyclic)

    deep = context.model_dump(mode="json", by_alias=True)
    cursor: dict[str, object] = {}
    deep["retainedArtifactRefs"] = cursor
    for _ in range(40):
        nested: dict[str, object] = {}
        cursor["next"] = nested
        cursor = nested
    with pytest.raises(ValueError, match="depth limit"):
        CompactedAgentContext.model_validate(deep)

    oversized = context.model_dump(mode="json", by_alias=True)
    oversized["retainedArtifactRefs"] = [{} for _ in range(9_000)]
    with pytest.raises(ValueError, match="node limit"):
        CompactedAgentContext.model_validate(oversized)

    invalid_key = context.model_dump(mode="json", by_alias=True)
    invalid_key[cast(Any, 1)] = "non-string key"
    with pytest.raises(ValueError, match="key must be a string"):
        CompactedAgentContext.model_validate(invalid_key)
