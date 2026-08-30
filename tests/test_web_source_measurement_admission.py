from __future__ import annotations

import json
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import pajin.workflow.web_source_measurement_admission as web_source_admission
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionReason,
    GraphProducerRegistration,
    GraphProducerRegistry,
    TrustedGraphLineageRegistry,
)
from pajin.graph.models import (
    GraphContentOrigin,
    GraphEdge,
    GraphEvidenceBinding,
    GraphNodeKind,
    GraphObservation,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSurface,
    ObservationProposal,
    SurfaceProposal,
    graph_node_ref,
)
from pajin.graph.projection import (
    GraphProjectionCoordinator,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow.web_source_measurement_admission import (
    WebZAPSourceGraphAdmissionBinding,
    WebZAPSourceKnowledgeAdmissionError,
    WebZAPSourceKnowledgeAdmissionGate,
    WebZAPSourceKnowledgeCandidate,
    WebZAPSourceObservationInputs,
    load_verified_web_zap_source_observation,
    web_zap_source_knowledge_producer_registration,
)
from tests.test_benchmark_zap_scanner import (
    _reseal_web_source_run,
    _run_web_source,
    _sarif,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
CAMPAIGN_ID = "web-002c-campaign"
AUTHORITY_ID = "graph-authority:web-002c"


def _inputs(context: SimpleNamespace) -> WebZAPSourceObservationInputs:
    return WebZAPSourceObservationInputs(
        outcome=context.outcome,
        measured_case=context.measured_case,
        capability_bundle=context.capability_bundle,
        lifecycle=context.lifecycle,
        release=context.measured_case.capability_release,
        target_adapter=context.target_adapter,
        private_ground_truth_profile=context.private_profile,
        scanner_plan=context.measured_case.scanner_plan,
        scanner_registration=context.measured_case.scanner_registration,
        journal_path=context.journal_path,
        catalog_provider=context.catalog_provider,
        measurement_trust_anchor=context.measurement_anchor,
        activation_store=context.activation_store,
        distribution_bundle=context.distribution_bundle,
        distribution_trust_anchor=context.distribution_anchor,
    )


def _graph_context(tmp_path: Path, context: SimpleNamespace) -> SimpleNamespace:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=CAMPAIGN_ID)
    surface_ref = context.measured_case.surface.reference()
    graph_surface = GraphSurface(
        campaignId=CAMPAIGN_ID,
        targetId=surface_ref.surface_id,
        surfaceType=surface_ref.surface_type,
        locatorSchema=surface_ref.locator_schema,
        locatorDigest=surface_ref.surface_digest,
        origin=GraphContentOrigin.TRUSTED_CORE,
    )
    now = datetime.now(UTC)
    seed_lineage = GraphProposalLineage(
        campaignId=CAMPAIGN_ID,
        runId="run:web-002c-surface-seed",
        agentId="agent:web-002c-surface-seed",
        taskId="task:web-002c-surface-seed",
        requestId="tool_web_002c_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:web-002c-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.web.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/web-002c-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=now,
    )
    seed = SurfaceProposal(
        proposalId="proposal:surface:web-002c",
        producerId="pajin.graph.web-002c-test-seed",
        producerVersion="1.0.0",
        producerDigest=DIGEST_D,
        lineage=seed_lineage,
        surface=graph_surface,
    )
    lineages = TrustedGraphLineageRegistry([seed_lineage])
    admission = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN_ID,
        authority_id=AUTHORITY_ID,
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId="pajin.graph.web-002c-test-seed",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                web_zap_source_knowledge_producer_registration(),
            ]
        ),
        lineage_verifier=lineages,
        event_log=store.event_log,
        clock=lambda: datetime.now(UTC) + timedelta(minutes=1),
    )
    assert admission.submit(seed).event.decision is GraphAdmissionDecision.ADMITTED
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshot_authority = GraphSnapshotAuthority(
        creator_id="pajin.graph.web-002c-test-snapshot",
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: datetime.now(UTC) + timedelta(minutes=2),
    )
    snapshot = snapshot_authority.capture(GraphSnapshotReason.CHECKPOINT)
    binding = WebZAPSourceGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
        graphSurface=graph_surface,
    )
    gate = WebZAPSourceKnowledgeAdmissionGate(
        graph_store=store,
        graph_admission=admission,
        trusted_lineages=lineages,
    )
    return SimpleNamespace(
        store=store,
        admission=admission,
        lineages=lineages,
        binding=binding,
        gate=gate,
        snapshot_authority=snapshot_authority,
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _all_keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _all_keys(item)}
    return set()


def _foreign_surface_sarif() -> bytes:
    value = json.loads(_sarif(rule_id="10036"))
    value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "http://foreign.invalid:8080/v1/users/lookup?id=1"
    return json.dumps(value, separators=(",", ":")).encode()


def test_web_002c_admits_neutral_observation_and_bounded_hypothesis_idempotently(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path / "source", sarif=_sarif(rule_id="10021"))
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)

    source = load_verified_web_zap_source_observation(inputs)
    candidate = graph.gate.prepare_candidate(inputs, graph.binding)
    admission = graph.gate.admit(inputs, candidate)
    retried = graph.gate.admit(inputs, candidate)

    assert {field.name for field in fields(source)} == {
        "measured_surface",
        "domain_graph_type_set",
        "source_authority",
        "source_run_id",
        "source_root_digest",
        "authority_reference",
        "authority_sha256",
        "observed_at",
        "source_count",
        "registered_surface_signal",
        "signal_digest",
    }
    assert not hasattr(source, "measured_case")
    assert not hasattr(source.source_authority, "lineages")
    assert source.registered_surface_signal is True
    assert candidate.registered_surface_signal is True
    assert candidate.hypothesis_proposal is not None
    assert admission == retried
    assert admission.bounded_hypothesis_admitted is True
    assert admission.observation_graph_event.source_authority_id == (
        source.source_authority.authority_id
    )
    assert admission.observation_graph_event.source_authority_digest == (
        source.source_authority.authority_digest
    )
    assert admission.observation_graph_event.capability_grant_id is None
    assert admission.observation_graph_event.capability_id is None
    assert admission.observation_graph_event.action_permit_id is None
    assert {node.kind for node in admission.observation_graph_event.admitted_nodes} == {
        GraphNodeKind.ACTION,
        GraphNodeKind.OBSERVATION,
        GraphNodeKind.EVIDENCE,
    }
    assert {edge.relation for edge in admission.observation_graph_event.admitted_edges} == {
        GraphRelation.PRODUCES,
        GraphRelation.SUPPORTED_BY,
    }
    assert admission.hypothesis_graph_event is not None
    assert admission.hypothesis_graph_event.admitted_edges[0].relation is (GraphRelation.ENABLES)
    assert len(graph.store.event_log.events()) == 3

    keys = _all_keys(admission.model_dump(mode="json", by_alias=True))
    assert keys.isdisjoint(
        {
            "rawSarifSha256",
            "rawSarifSizeBytes",
            "matchesKnownFinding",
            "knownFindingMatched",
            "groundTruthDigest",
            "groundTruthBindingDigest",
            "targetRunId",
            "targetImageId",
            "workerImageId",
            "scannerImageId",
            "providerEvidence",
        }
    )
    GraphProjectionCoordinator(
        event_log=graph.store.event_log,
        projection_store=graph.store.projection_store,
    ).refresh()
    post_admission_snapshot = graph.snapshot_authority.capture(GraphSnapshotReason.CHECKPOINT)
    public_json = json.dumps(
        {
            "candidate": candidate.model_dump(mode="json", by_alias=True),
            "admission": admission.model_dump(mode="json", by_alias=True),
            "events": [
                event.model_dump(mode="json", by_alias=True)
                for event in graph.store.event_log.events()
            ],
            "snapshot": post_admission_snapshot.model_dump(mode="json", by_alias=True),
        },
        sort_keys=True,
    )
    source_lineage = context.outcome.authority.lineages[0]
    forbidden_values = {
        "http://target:8080/v1/users/lookup?id=1",
        "bounded ZAP finding",
        "fixed-test",
        "10021",
        "benchmark:zap-scanner-baseline-v1",
        source_lineage.target_run_id,
        source_lineage.target_attempt_id,
        source_lineage.target_image_id,
        source_lineage.worker_image_id,
        source_lineage.scanner_image_id,
        source_lineage.execution_operation_id,
        source_lineage.cleanup_operation_id,
    }
    assert all(value not in public_json for value in forbidden_values)


def test_web_002c_emits_no_hypothesis_without_registered_surface_signal(
    tmp_path: Path,
) -> None:
    context = _run_web_source(
        tmp_path / "source",
        sarif=_foreign_surface_sarif(),
    )
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)

    source = load_verified_web_zap_source_observation(inputs)
    candidate = graph.gate.prepare_candidate(inputs, graph.binding)
    admission = graph.gate.admit(inputs, candidate)

    assert source.registered_surface_signal is False
    assert candidate.registered_surface_signal is False
    assert candidate.hypothesis_proposal is None
    assert admission.hypothesis_graph_event is None
    assert admission.bounded_hypothesis_admitted is False
    assert len(graph.store.event_log.events()) == 2
    public_json = json.dumps(
        {
            "candidate": candidate.model_dump(mode="json", by_alias=True),
            "admission": admission.model_dump(mode="json", by_alias=True),
        },
        sort_keys=True,
    )
    assert "foreign.invalid" not in public_json
    assert "10036" not in public_json
    assert "may warrant separately controlled validation" not in public_json


def test_web_002c_reopens_source_at_admission_and_rejects_resealed_tampering(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path / "source")
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)
    candidate = graph.gate.prepare_candidate(inputs, graph.binding)

    authority_path = context.outcome.run_path / context.outcome.authority_path
    authority_path.write_bytes(b"{}\n")
    _reseal_web_source_run(context)

    with pytest.raises(WebZAPSourceKnowledgeAdmissionError, match="failed closed"):
        graph.gate.admit(inputs, candidate)
    assert len(graph.store.event_log.events()) == 1


def test_web_002c_rejects_source_swapped_between_authority_and_snapshot_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _run_web_source(tmp_path / "source")
    inputs = _inputs(context)
    original_loader = web_source_admission.load_web_zap_source_measurement_authority

    def load_then_swap(*args: object, **kwargs: object):
        authority = original_loader(*args, **kwargs)
        authority_path = context.outcome.run_path / context.outcome.authority_path
        authority_path.write_bytes(b"{}\n")
        _reseal_web_source_run(context)
        return authority

    monkeypatch.setattr(
        web_source_admission,
        "load_web_zap_source_measurement_authority",
        load_then_swap,
    )

    with pytest.raises(WebZAPSourceKnowledgeAdmissionError, match="failed closed"):
        load_verified_web_zap_source_observation(inputs)


def test_web_002c_rejects_candidate_signal_or_identity_tampering(tmp_path: Path) -> None:
    context = _run_web_source(tmp_path / "source")
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)
    candidate = graph.gate.prepare_candidate(inputs, graph.binding)

    forged = candidate.model_copy(update={"registered_surface_signal": False})
    with pytest.raises(WebZAPSourceKnowledgeAdmissionError, match="failed closed"):
        graph.gate.admit(inputs, forged)

    serialized = candidate.model_dump(mode="json", by_alias=True)
    serialized["sourceMeasurement"]["authorityDigest"] = DIGEST_D
    with pytest.raises(ValidationError):
        WebZAPSourceKnowledgeCandidate.model_validate(serialized)

    hidden = candidate.model_copy(update={"unmodeled_authority": True})
    with pytest.raises(
        WebZAPSourceKnowledgeAdmissionError,
        match="unmodeled instance state",
    ):
        graph.gate.admit(inputs, hidden)
    hidden_graph = candidate.graph.model_copy(update={"unmodeled_authority": True})
    nested_hidden = candidate.model_copy(update={"graph": hidden_graph})
    with pytest.raises(
        WebZAPSourceKnowledgeAdmissionError,
        match="unmodeled instance state",
    ):
        graph.gate.admit(inputs, nested_hidden)
    assert len(graph.store.event_log.events()) == 1


def test_web_002c_rejects_hidden_state_inside_source_outcome_dataclass(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path / "source")
    hidden_authority = context.outcome.authority.model_copy(update={"unmodeled_authority": True})
    hidden_outcome = replace(context.outcome, authority=hidden_authority)
    inputs = replace(_inputs(context), outcome=hidden_outcome)

    with pytest.raises(WebZAPSourceKnowledgeAdmissionError, match="unmodeled instance state"):
        load_verified_web_zap_source_observation(inputs)


def test_web_002c_sealed_source_registration_binds_exact_proposal_and_head(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path / "source")
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)
    candidate = graph.gate.prepare_candidate(inputs, graph.binding)
    original = candidate.observation_proposal
    expected_head = candidate.graph.snapshot.event_log_head_digest
    assert expected_head is not None
    graph.lineages.register(
        original.lineage,
        proposal_digest=original.digest(),
        expected_event_log_head_digest=expected_head,
    )

    forged_observation = GraphObservation(
        campaignId=original.observation.campaign_id,
        observationType=original.observation.observation_type,
        summary="A forged semantic payload reuses otherwise valid sealed-source lineage.",
        valueDigest=DIGEST_D,
        producerId=original.producer_id,
        producerVersion=original.producer_version,
        producerDigest=original.producer_digest,
        origin=original.observation.origin,
        confidence=original.observation.confidence,
        observedAt=original.observation.observed_at,
    )
    forged_edges = sorted(
        [
            GraphEdge(
                campaignId=CAMPAIGN_ID,
                relation=GraphRelation.PRODUCES,
                source=graph_node_ref(original.action),
                target=graph_node_ref(forged_observation),
                authorityId=AUTHORITY_ID,
                authorityDigest=DIGEST_A,
            ),
            GraphEdge(
                campaignId=CAMPAIGN_ID,
                relation=GraphRelation.SUPPORTED_BY,
                source=graph_node_ref(forged_observation),
                target=graph_node_ref(original.evidence_nodes[0]),
                authorityId=AUTHORITY_ID,
                authorityDigest=DIGEST_A,
            ),
        ],
        key=lambda item: item.edge_id,
    )
    forged = ObservationProposal(
        proposalId="proposal:web-zap-observation:forged",
        producerId=original.producer_id,
        producerVersion=original.producer_version,
        producerDigest=original.producer_digest,
        lineage=original.lineage,
        action=original.action,
        observation=forged_observation,
        evidenceNodes=original.evidence_nodes,
        edges=forged_edges,
    )

    forged_result = graph.admission.submit_if_current(
        forged,
        expected_event_log_head_digest=expected_head,
    )
    direct_result = graph.admission.submit(original)

    assert forged_result.event.decision is GraphAdmissionDecision.REJECTED
    assert forged_result.event.reason is GraphAdmissionReason.LINEAGE_VERIFICATION_FAILED
    assert direct_result.event.decision is GraphAdmissionDecision.REJECTED
    assert direct_result.event.reason is GraphAdmissionReason.LINEAGE_VERIFICATION_FAILED


def test_web_002c_rejects_stale_snapshot_before_writing_knowledge(tmp_path: Path) -> None:
    context = _run_web_source(tmp_path / "source")
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)
    candidate = graph.gate.prepare_candidate(inputs, graph.binding)

    lineage = GraphProposalLineage(
        campaignId=CAMPAIGN_ID,
        runId="run:web-002c-head-advance",
        agentId="agent:web-002c-head-advance",
        taskId="task:web-002c-head-advance",
        requestId="tool_web_002c_head_advance",
        requestDigest=DIGEST_B,
        capabilityGrantId="grant:web-002c-head-advance",
        capabilityGrantDigest=DIGEST_C,
        capabilityId="pajin.web.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_D,
        sourceRootDigest=DIGEST_A,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/web-002c-head-advance.json",
                sha256=DIGEST_B,
            )
        ],
        producedAt=datetime.now(UTC),
    )
    graph.lineages.register(lineage)
    result = graph.admission.submit(
        SurfaceProposal(
            proposalId="proposal:surface:web-002c-head-advance",
            producerId="pajin.graph.web-002c-test-seed",
            producerVersion="1.0.0",
            producerDigest=DIGEST_D,
            lineage=lineage,
            surface=GraphSurface(
                campaignId=CAMPAIGN_ID,
                targetId="target:web-002c-head-advance",
                surfaceType="web.http-operation",
                locatorSchema="pajin.locator.web.http-operation.v1",
                locatorDigest=DIGEST_B,
                origin=GraphContentOrigin.TRUSTED_CORE,
            ),
        )
    )
    assert result.event.decision is GraphAdmissionDecision.ADMITTED

    with pytest.raises(WebZAPSourceKnowledgeAdmissionError, match="Graph Snapshot"):
        graph.gate.admit(inputs, candidate)
    assert len(graph.store.event_log.events()) == 2


def test_web_002c_rejects_graph_head_race_between_observation_and_hypothesis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _run_web_source(tmp_path / "source")
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)
    candidate = graph.gate.prepare_candidate(inputs, graph.binding)
    original_submit_if_current = graph.admission.submit_if_current
    advanced = False

    def submit_with_intervening_event(
        proposal: object,
        *,
        expected_event_log_head_digest: str,
    ):
        nonlocal advanced
        result = original_submit_if_current(
            proposal,
            expected_event_log_head_digest=expected_event_log_head_digest,
        )
        if not advanced and isinstance(proposal, ObservationProposal):
            advanced = True
            lineage = GraphProposalLineage(
                campaignId=CAMPAIGN_ID,
                runId="run:web-002c-inter-event-race",
                agentId="agent:web-002c-inter-event-race",
                taskId="task:web-002c-inter-event-race",
                requestId="tool_web_002c_inter_event_race",
                requestDigest=DIGEST_B,
                capabilityGrantId="grant:web-002c-inter-event-race",
                capabilityGrantDigest=DIGEST_C,
                capabilityId="pajin.web.surface-seed",
                capabilityVersion="1.0.0",
                capabilityDigest=DIGEST_D,
                sourceRootDigest=DIGEST_A,
                evidence=[
                    GraphEvidenceBinding(
                        reference="evidence/web-002c-inter-event-race.json",
                        sha256=DIGEST_B,
                    )
                ],
                producedAt=datetime.now(UTC),
            )
            graph.lineages.register(lineage)
            intervening = graph.admission.submit(
                SurfaceProposal(
                    proposalId="proposal:surface:web-002c-inter-event-race",
                    producerId="pajin.graph.web-002c-test-seed",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    lineage=lineage,
                    surface=GraphSurface(
                        campaignId=CAMPAIGN_ID,
                        targetId="target:web-002c-inter-event-race",
                        surfaceType="web.http-operation",
                        locatorSchema="pajin.locator.web.http-operation.v1",
                        locatorDigest=DIGEST_B,
                        origin=GraphContentOrigin.TRUSTED_CORE,
                    ),
                )
            )
            assert intervening.event.decision is GraphAdmissionDecision.ADMITTED
        return result

    monkeypatch.setattr(
        graph.admission,
        "submit_if_current",
        submit_with_intervening_event,
    )

    with pytest.raises(
        WebZAPSourceKnowledgeAdmissionError,
        match="Hypothesis source is no longer the current Graph head",
    ):
        graph.gate.admit(inputs, candidate)
    with pytest.raises(
        WebZAPSourceKnowledgeAdmissionError,
        match="Hypothesis source is no longer the current Graph head",
    ):
        graph.gate.admit(inputs, candidate)

    events = graph.store.event_log.events()
    assert [event.proposal_kind for event in events] == [
        GraphProposalKind.SURFACE,
        GraphProposalKind.OBSERVATION,
        GraphProposalKind.SURFACE,
    ]


def test_web_002c_source_authority_cannot_mix_with_capability_or_permit() -> None:
    lineage = GraphProposalLineage(
        campaignId=CAMPAIGN_ID,
        runId="run:web-002c-source-only",
        agentId="agent:web-002c-source-only",
        taskId="task:web-002c-source-only",
        requestId="tool_web_002c_source_only",
        requestDigest=DIGEST_A,
        sourceAuthorityId="source:web-002c",
        sourceAuthorityDigest=DIGEST_B,
        sourceRootDigest=DIGEST_C,
        evidence=[
            GraphEvidenceBinding(
                reference="web-zap-source-measurement-authority.json",
                sha256=DIGEST_D,
            )
        ],
        producedAt=datetime.now(UTC),
    )
    value = lineage.model_dump(mode="json", by_alias=True)
    value.update(
        {
            "capabilityGrantId": "grant:web-002c-forged",
            "capabilityGrantDigest": DIGEST_A,
            "capabilityId": "pajin.web.forged",
            "capabilityVersion": "1.0.0",
            "capabilityDigest": DIGEST_D,
        }
    )

    with pytest.raises(
        ValidationError,
        match="cannot claim Capability or Permit authority",
    ):
        GraphProposalLineage.model_validate(value)


def test_web_002c_graph_binding_requires_exact_projected_surface(tmp_path: Path) -> None:
    context = _run_web_source(tmp_path / "source")
    inputs = _inputs(context)
    graph = _graph_context(tmp_path / "graph", context)
    foreign = graph.binding.model_copy(
        update={
            "graph_surface": GraphSurface(
                campaignId=CAMPAIGN_ID,
                targetId="target:web-002c-foreign",
                surfaceType="web.http-operation",
                locatorSchema="pajin.locator.web.http-operation.v1",
                locatorDigest=DIGEST_C,
                origin=GraphContentOrigin.TRUSTED_CORE,
            )
        }
    )

    with pytest.raises(WebZAPSourceKnowledgeAdmissionError, match="Surface"):
        graph.gate.prepare_candidate(inputs, foreign)

    hidden = graph.binding.model_copy(update={"unmodeled_authority": True})
    with pytest.raises(
        WebZAPSourceKnowledgeAdmissionError,
        match="unmodeled instance state",
    ):
        graph.gate.prepare_candidate(inputs, hidden)
