from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import pajin.control_plane.decision_views as decision_views
import pajin.control_plane.graph_views as graph_views
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.graph_views import _build_hypothesis_attention_ranking
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.graph import (
    GraphAction,
    GraphActionStatus,
    GraphAdmissionAuthority,
    GraphAuthorityKind,
    GraphConsistencyView,
    GraphContentOrigin,
    GraphDecision,
    GraphDecisionKind,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphHypothesisAssessment,
    GraphHypothesisState,
    GraphObservation,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjection,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    ObservationProposal,
    SQLiteGraphDecisionAuditStore,
    SQLiteGraphStore,
    TrustedGraphLineageRegistry,
    graph_node_ref,
    graph_snapshot_ref,
)

CAMPAIGN = "graph-console"
NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
OPERATOR_TOKEN = "graph-view-operator-token-is-long-enough"
APPROVER_TOKEN = "graph-view-approver-token-is-long-enough"
AUDITOR_TOKEN = "graph-view-auditor-token-is-long-enough"
WORKER_TOKEN = "graph-view-worker-token-is-long-enough"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def _settings(
    database: Path,
    *,
    graph_database: Path | None,
    graph_decision_audit_database: Path | None = None,
) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{database.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="graph-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="graph-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            AUDITOR_TOKEN: Principal(
                subject="graph-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="graph-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"graph-view-test-signing-key-32-bytes"},
        graph_database=graph_database,
        graph_decision_audit_database=graph_decision_audit_database,
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _observation_proposal() -> ObservationProposal:
    lineage = GraphProposalLineage(
        campaignId=CAMPAIGN,
        runId="run:graph:console:1",
        agentId="agent:graph-console",
        taskId="task:graph-console:1",
        requestId="tool_graph_console_1",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:graph-console:1",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="capability:graph-observe",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_F,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/private-graph-console.json",
                sha256=DIGEST_D,
            )
        ],
        producedAt=NOW + timedelta(seconds=2),
    )
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
        summary="Private target-derived content must not enter the operator graph view.",
        valueDigest=DIGEST_A,
        producerId="pajin.graph.console-producer",
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
    edges = sorted(
        [
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
        ],
        key=lambda item: item.edge_id,
    )
    return ObservationProposal(
        proposalId="proposal:graph-console:observation",
        producerId="pajin.graph.console-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_E,
        lineage=lineage,
        action=action,
        observation=observation,
        evidenceNodes=[evidence],
        edges=edges,
    )


def _current_snapshot(path: Path) -> tuple[SQLiteGraphStore, GraphSnapshotAuthority, GraphSnapshot]:
    proposal = _observation_proposal()
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    authority = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id="pajin.graph.admission-authority",
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=proposal.producer_id,
                    producerVersion=proposal.producer_version,
                    producerDigest=proposal.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.OBSERVATION,),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry([proposal.lineage]),
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=3),
    )
    authority.submit(proposal)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshots = GraphSnapshotAuthority(
        creator_id="pajin.graph.console-snapshot-authority",
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    )
    snapshot = snapshots.capture(GraphSnapshotReason.CHECKPOINT)
    return store, snapshots, snapshot


def _endpoint(campaign: str, snapshot_id: str) -> str:
    return f"/v1/graphs/campaigns/{campaign}/snapshots/{snapshot_id}"


def _ranking_endpoint(campaign: str, snapshot_id: str) -> str:
    return f"/v1/hypotheses/campaigns/{campaign}/snapshots/{snapshot_id}/attention-ranking"


def _decision_audit_endpoint(campaign: str, snapshot_id: str) -> str:
    return f"/v1/decisions/campaigns/{campaign}/snapshots/{snapshot_id}/audit"


def _graph_decision(snapshot: GraphSnapshot, *, tag: str, seconds: int) -> GraphDecision:
    return GraphDecision(
        campaignId=CAMPAIGN,
        decisionKind=GraphDecisionKind.PLAN,
        decisionPayloadDigest=(tag * 64)[:64],
        snapshot=graph_snapshot_ref(snapshot),
        actorId=f"sensitive-decision-actor-{tag}",
        actorDigest=DIGEST_C,
        createdAt=snapshot.created_at + timedelta(seconds=seconds),
    )


def _decision_audit_store(
    path: Path,
    *,
    graph_database: Path,
) -> SQLiteGraphDecisionAuditStore:
    return SQLiteGraphDecisionAuditStore(
        path,
        graph_database=graph_database,
        campaign_id=CAMPAIGN,
        recorder_id="pajin.control-plane.decision-audit-recorder",
        recorder_digest=DIGEST_B,
        clock=lambda: NOW + timedelta(seconds=8),
    )


def _hypothesis(tag: str, confidence: float) -> GraphHypothesis:
    return GraphHypothesis(
        campaignId=CAMPAIGN,
        hypothesisType=f"attention-{tag}",
        statement=f"Sensitive hypothesis statement {tag}.",
        expectedObservable=f"Sensitive expected observable {tag}.",
        producerId="pajin.graph.ranking-producer",
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        origin=GraphContentOrigin.AGENT_DERIVED,
        confidence=confidence,
    )


def _ranking_fixture() -> tuple[GraphSnapshot, GraphConsistencyView]:
    state_hypotheses = [
        (GraphHypothesisState.CONTESTED, _hypothesis("contested", 0.9)),
        (GraphHypothesisState.SUPPORTED, _hypothesis("supported", 0.2)),
        (GraphHypothesisState.OPEN, _hypothesis("open", 0.99)),
        (GraphHypothesisState.CONTRADICTED, _hypothesis("contradicted", 1.0)),
    ]
    projection = GraphProjection(
        campaignId=CAMPAIGN,
        revision=0,
        eventLogHeadDigest=None,
        nodes=tuple(sorted((item[1] for item in state_hypotheses), key=lambda node: node.node_id)),
        edges=(),
    )
    snapshot = GraphSnapshot(
        campaignId=CAMPAIGN,
        revision=projection.revision,
        eventLogHeadDigest=projection.event_log_head_digest,
        projectionId=projection.projection_id,
        projectionDigest=projection.projection_digest,
        nodeProjectionDigest=projection.node_projection_digest,
        edgeProjectionDigest=projection.edge_projection_digest,
        reason=GraphSnapshotReason.CHECKPOINT,
        createdAt=NOW,
        creatorId="pajin.graph.ranking-snapshot-authority",
        creatorDigest=DIGEST_A,
        projection=projection,
    )
    support_id = "graph-node_" + "1" * 64
    contradiction_id = "graph-node_" + "2" * 64
    assessments = []
    for state, hypothesis in state_hypotheses:
        assessments.append(
            GraphHypothesisAssessment(
                hypothesis=graph_node_ref(hypothesis),
                supportingObservationIds=(
                    (support_id,)
                    if state in {GraphHypothesisState.CONTESTED, GraphHypothesisState.SUPPORTED}
                    else ()
                ),
                contradictingObservationIds=(
                    (contradiction_id,)
                    if state
                    in {
                        GraphHypothesisState.CONTESTED,
                        GraphHypothesisState.CONTRADICTED,
                    }
                    else ()
                ),
                state=state,
            )
        )
    consistency = GraphConsistencyView(
        campaignId=CAMPAIGN,
        revision=projection.revision,
        eventLogHeadDigest=projection.event_log_head_digest,
        projectionId=projection.projection_id,
        projectionDigest=projection.projection_digest,
        duplicateNodeOccurrenceCount=0,
        duplicateEdgeOccurrenceCount=0,
        hypotheses=tuple(sorted(assessments, key=lambda item: item.hypothesis.node_id)),
    )
    return snapshot, consistency


def test_verified_canonical_graph_view_is_operator_only_redacted_and_read_only(
    tmp_path: Path,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    before = (graph_database.read_bytes(), graph_database.stat().st_mtime_ns)
    app = create_app(_settings(tmp_path / "control-plane.db", graph_database=graph_database))
    path = _endpoint(CAMPAIGN, snapshot.snapshot_id)

    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth(APPROVER_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(AUDITOR_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(WORKER_TOKEN)).status_code == 403
        response = client.get(path, headers=_auth(OPERATOR_TOKEN))

    assert response.status_code == 200, response.text
    assert "no-store" in response.headers["cache-control"]
    body = response.json()
    assert body["kind"] == "VerifiedCanonicalGraphView"
    assert body["campaignId"] == CAMPAIGN
    assert body["snapshot"]["snapshotId"] == snapshot.snapshot_id
    assert body["projection"]["revision"] == 1
    assert body["nodeCount"] == 3
    assert body["edgeCount"] == 2
    assert {node["kind"] for node in body["nodes"]} == {
        "Action",
        "Evidence",
        "Observation",
    }
    assert {edge["relation"] for edge in body["edges"]} == {"produces", "supported-by"}
    assert body["authorityBoundary"] == {
        "canonicalGraphSnapshotVerified": True,
        "currentSnapshotVerified": True,
        "contentRedacted": True,
        "viewAuthorizesAdmission": False,
        "viewGrantsCapability": False,
        "viewGrantsPermit": False,
        "viewAuthorizesExecution": False,
    }
    serialized = json.dumps(body)
    assert "Private target-derived content" not in serialized
    assert "private-graph-console.json" not in serialized
    assert '"summary"' not in serialized
    assert '"reference"' not in serialized
    assert (graph_database.read_bytes(), graph_database.stat().st_mtime_ns) == before


def test_hypothesis_attention_ranking_is_operator_only_bounded_and_read_only(
    tmp_path: Path,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    before = (graph_database.read_bytes(), graph_database.stat().st_mtime_ns)
    app = create_app(_settings(tmp_path / "control-plane.db", graph_database=graph_database))
    path = _ranking_endpoint(CAMPAIGN, snapshot.snapshot_id)

    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth(APPROVER_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(AUDITOR_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(WORKER_TOKEN)).status_code == 403
        response = client.get(path, headers=_auth(OPERATOR_TOKEN))

    assert response.status_code == 200, response.text
    assert "no-store" in response.headers["cache-control"]
    body = response.json()
    assert body["kind"] == "VerifiedHypothesisAttentionRankingView"
    assert body["campaignId"] == CAMPAIGN
    assert body["snapshotId"] == snapshot.snapshot_id
    assert body["projectionId"] == snapshot.projection_id
    assert body["consistencyViewId"].startswith("graph-consistency-view_")
    assert body["rankingMethod"] == "canonical-state-confidence-review-attention/v1"
    assert body["hypothesisCount"] == 0
    assert body["hypotheses"] == []
    assert body["authorityBoundary"] == {
        "canonicalGraphSnapshotVerified": True,
        "currentSnapshotVerified": True,
        "consistencyViewVerified": True,
        "deterministicReviewOrder": True,
        "contentRedacted": True,
        "viewSelectsHypothesis": False,
        "viewRecordsDecision": False,
        "viewSchedulesWork": False,
        "viewAuthorizesExecution": False,
    }
    assert (graph_database.read_bytes(), graph_database.stat().st_mtime_ns) == before


def test_graph_decision_audit_view_is_operator_only_redacted_and_read_only(
    tmp_path: Path,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    audit = _decision_audit_store(audit_database, graph_database=graph_database)
    record = audit.append(_graph_decision(snapshot, tag="1", seconds=1))
    before = {
        graph_database: (graph_database.read_bytes(), graph_database.stat().st_mtime_ns),
        audit_database: (audit_database.read_bytes(), audit_database.stat().st_mtime_ns),
    }
    app = create_app(
        _settings(
            tmp_path / "control-plane.db",
            graph_database=graph_database,
            graph_decision_audit_database=audit_database,
        )
    )
    path = _decision_audit_endpoint(CAMPAIGN, snapshot.snapshot_id)

    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth(APPROVER_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(AUDITOR_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(WORKER_TOKEN)).status_code == 403
        response = client.get(path, headers=_auth(OPERATOR_TOKEN))

    assert response.status_code == 200, response.text
    assert "no-store" in response.headers["cache-control"]
    body = response.json()
    assert body["kind"] == "VerifiedGraphDecisionAuditView"
    assert body["campaignId"] == CAMPAIGN
    assert body["snapshotId"] == snapshot.snapshot_id
    assert body["projectionId"] == snapshot.projection_id
    assert body["auditSchemaVersion"] == 1
    assert body["recorderDigest"] == DIGEST_B
    assert body["totalRecordCount"] == 1
    assert body["currentSnapshotDecisionCount"] == 1
    assert body["auditHeadDigest"] == record.record_digest
    assert body["decisions"] == [
        {
            "sequence": 1,
            "recordId": record.record_id,
            "recordDigest": record.record_digest,
            "previousRecordDigest": None,
            "decisionId": record.decision.decision_id,
            "decisionDigest": record.decision.decision_digest,
            "decisionKind": "plan",
            "decisionPayloadDigest": record.decision.decision_payload_digest,
            "actorDigest": DIGEST_C,
            "recorderDigest": DIGEST_B,
            "decisionCreatedAt": record.decision.created_at.isoformat().replace("+00:00", "Z"),
            "recordedAt": record.recorded_at.isoformat().replace("+00:00", "Z"),
        }
    ]
    assert body["authorityBoundary"] == {
        "canonicalGraphSnapshotVerified": True,
        "currentSnapshotVerified": True,
        "completeAuditChainVerified": True,
        "historicalSnapshotBindingsVerified": True,
        "appendOnlyHistoricalRetention": True,
        "identifiersRedacted": True,
        "viewSelectsHypothesis": False,
        "viewRecordsDecision": False,
        "viewSchedulesWork": False,
        "viewApprovesAction": False,
        "viewGrantsCapability": False,
        "viewGrantsPermit": False,
        "viewAuthorizesExecution": False,
    }
    serialized = json.dumps(body)
    assert "sensitive-decision-actor" not in serialized
    assert "recorderId" not in serialized
    assert "actorId" not in serialized
    assert {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before
    } == before


def test_graph_decision_audit_view_filters_current_snapshot_but_verifies_history(
    tmp_path: Path,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, snapshots, first = _current_snapshot(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    audit = _decision_audit_store(audit_database, graph_database=graph_database)
    first_record = audit.append(_graph_decision(first, tag="2", seconds=1))
    second = snapshots.capture(GraphSnapshotReason.HANDOFF)
    second_record = audit.append(
        _graph_decision(second, tag="3", seconds=1),
        recorded_at=NOW + timedelta(seconds=10),
    )
    app = create_app(
        _settings(
            tmp_path / "control-plane.db",
            graph_database=graph_database,
            graph_decision_audit_database=audit_database,
        )
    )

    with TestClient(app) as client:
        stale = client.get(
            _decision_audit_endpoint(CAMPAIGN, first.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
        current = client.get(
            _decision_audit_endpoint(CAMPAIGN, second.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )

    assert stale.status_code == 409
    assert current.status_code == 200, current.text
    body = current.json()
    assert body["totalRecordCount"] == 2
    assert body["currentSnapshotDecisionCount"] == 1
    assert body["auditHeadDigest"] == second_record.record_digest
    assert body["decisions"][0]["recordId"] == second_record.record_id
    assert first_record.record_id not in json.dumps(body["decisions"])


def test_graph_decision_audit_view_fails_closed_for_configuration_and_aliases(
    tmp_path: Path,
) -> None:
    plausible_snapshot = "graph-snapshot_" + "0" * 64
    unavailable_app = create_app(
        _settings(
            tmp_path / "unavailable-control-plane.db",
            graph_database=None,
        )
    )
    with TestClient(unavailable_app) as client:
        unavailable = client.get(
            _decision_audit_endpoint(CAMPAIGN, plausible_snapshot),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert unavailable.status_code == 503

    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    _decision_audit_store(audit_database, graph_database=graph_database)
    configured_app = create_app(
        _settings(
            tmp_path / "configured-control-plane.db",
            graph_database=graph_database,
            graph_decision_audit_database=audit_database,
        )
    )
    alias_app = create_app(
        _settings(
            tmp_path / "alias-control-plane.db",
            graph_database=graph_database,
            graph_decision_audit_database=graph_database,
        )
    )
    with TestClient(configured_app) as client:
        absent = client.get(
            _decision_audit_endpoint(CAMPAIGN, plausible_snapshot),
            headers=_auth(OPERATOR_TOKEN),
        )
        empty = client.get(
            _decision_audit_endpoint(CAMPAIGN, snapshot.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    with TestClient(alias_app) as client:
        alias = client.get(
            _decision_audit_endpoint(CAMPAIGN, snapshot.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert absent.status_code == 404
    assert empty.status_code == 200, empty.text
    assert empty.json()["totalRecordCount"] == 0
    assert empty.json()["currentSnapshotDecisionCount"] == 0
    assert empty.json()["auditHeadDigest"] is None
    assert empty.json()["decisions"] == []
    assert alias.status_code == 409
    assert alias.json()["detail"] == "Graph Decision audit authority is not integrity-valid"


def test_graph_decision_audit_view_rejects_oversized_current_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    audit = _decision_audit_store(audit_database, graph_database=graph_database)
    record = audit.append(_graph_decision(snapshot, tag="4", seconds=1))
    app = create_app(
        _settings(
            tmp_path / "control-plane.db",
            graph_database=graph_database,
            graph_decision_audit_database=audit_database,
        )
    )
    monkeypatch.setattr(
        decision_views,
        "load_verified_graph_decision_audit",
        lambda *args, **kwargs: SimpleNamespace(
            records=(record,) * 501,
            current_snapshot=snapshot,
            schema_version=1,
            schema_digest=DIGEST_A,
            recorder_digest=DIGEST_B,
            head_digest=record.record_digest,
        ),
    )

    with TestClient(app) as client:
        response = client.get(
            _decision_audit_endpoint(CAMPAIGN, snapshot.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )

    assert response.status_code == 413
    assert response.json()["detail"] == (
        "Current Graph Snapshot Decision audit exceeds view limits"
    )


def test_hypothesis_attention_ranking_orders_canonical_states_without_deciding() -> None:
    snapshot, consistency = _ranking_fixture()

    view = _build_hypothesis_attention_ranking(snapshot, consistency)
    body = view.model_dump(mode="json", by_alias=True)

    assert [item["state"] for item in body["hypotheses"]] == [
        "contested",
        "supported",
        "open",
        "contradicted",
    ]
    assert [item["rank"] for item in body["hypotheses"]] == [1, 2, 3, 4]
    assert [item["attentionBand"] for item in body["hypotheses"]] == [
        "conflict-review",
        "evidence-supported",
        "evidence-needed",
        "contradicted-review",
    ]
    assert body["hypotheses"][0]["supportingObservationCount"] == 1
    assert body["hypotheses"][0]["contradictingObservationCount"] == 1
    serialized = json.dumps(body)
    assert "Sensitive hypothesis statement" not in serialized
    assert "Sensitive expected observable" not in serialized
    assert support_id_not_exposed(body)
    assert body["authorityBoundary"]["viewSelectsHypothesis"] is False
    assert body["authorityBoundary"]["viewRecordsDecision"] is False
    assert body["authorityBoundary"]["viewSchedulesWork"] is False
    assert body["authorityBoundary"]["viewAuthorizesExecution"] is False


def support_id_not_exposed(body: dict[str, object]) -> bool:
    serialized = json.dumps(body)
    return "graph-node_" + "1" * 64 not in serialized and "graph-node_" + "2" * 64 not in serialized


def test_hypothesis_attention_ranking_fails_closed_for_missing_stale_and_foreign(
    tmp_path: Path,
) -> None:
    plausible_snapshot = "graph-snapshot_" + "0" * 64
    missing_app = create_app(_settings(tmp_path / "missing-control-plane.db", graph_database=None))
    with TestClient(missing_app) as client:
        unavailable = client.get(
            _ranking_endpoint(CAMPAIGN, plausible_snapshot),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert unavailable.status_code == 503

    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, snapshots, first = _current_snapshot(graph_database)
    app = create_app(_settings(tmp_path / "control-plane.db", graph_database=graph_database))
    with TestClient(app) as client:
        absent = client.get(
            _ranking_endpoint(CAMPAIGN, plausible_snapshot),
            headers=_auth(OPERATOR_TOKEN),
        )
        foreign = client.get(
            _ranking_endpoint("foreign-campaign", first.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert absent.status_code == 404
    assert foreign.status_code == 409
    assert (
        foreign.json()["detail"] == "Hypothesis attention ranking authority is not integrity-valid"
    )

    second = snapshots.capture(GraphSnapshotReason.HANDOFF)
    with TestClient(app) as client:
        stale = client.get(
            _ranking_endpoint(CAMPAIGN, first.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
        current = client.get(
            _ranking_endpoint(CAMPAIGN, second.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert stale.status_code == 409
    assert current.status_code == 200


def test_hypothesis_attention_ranking_rejects_oversized_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    app = create_app(_settings(tmp_path / "control-plane.db", graph_database=graph_database))
    oversized = SimpleNamespace(
        projection=SimpleNamespace(nodes=[_hypothesis("oversized", 0.5)] * 501),
    )
    monkeypatch.setattr(
        graph_views,
        "load_verified_current_graph_snapshot_consistency",
        lambda *args, **kwargs: (oversized, SimpleNamespace()),
    )

    with TestClient(app) as client:
        response = client.get(
            _ranking_endpoint(CAMPAIGN, snapshot.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "Canonical Hypothesis ranking exceeds view limits"


def test_canonical_graph_view_fails_closed_for_missing_stale_and_foreign_authority(
    tmp_path: Path,
) -> None:
    missing_app = create_app(_settings(tmp_path / "missing-control-plane.db", graph_database=None))
    plausible_snapshot = "graph-snapshot_" + "0" * 64
    with TestClient(missing_app) as client:
        unavailable = client.get(
            _endpoint(CAMPAIGN, plausible_snapshot),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert unavailable.status_code == 503

    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, snapshots, first = _current_snapshot(graph_database)
    app = create_app(_settings(tmp_path / "control-plane.db", graph_database=graph_database))
    with TestClient(app) as client:
        absent = client.get(
            _endpoint(CAMPAIGN, plausible_snapshot),
            headers=_auth(OPERATOR_TOKEN),
        )
        foreign = client.get(
            _endpoint("foreign-campaign", first.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert absent.status_code == 404
    assert foreign.status_code == 409
    assert foreign.json()["detail"] == "Canonical Graph authority is not integrity-valid"

    second = snapshots.capture(GraphSnapshotReason.HANDOFF)
    with TestClient(app) as client:
        stale = client.get(
            _endpoint(CAMPAIGN, first.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
        current = client.get(
            _endpoint(CAMPAIGN, second.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert stale.status_code == 409
    assert current.status_code == 200


def test_canonical_graph_view_rejects_noncanonical_path_identifiers(tmp_path: Path) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    app = create_app(_settings(tmp_path / "control-plane.db", graph_database=graph_database))

    with TestClient(app) as client:
        bad_campaign = client.get(
            _endpoint("../escape", snapshot.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )
        bad_snapshot = client.get(
            _endpoint(CAMPAIGN, "graph-snapshot_bad"),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert bad_campaign.status_code in {404, 422}
    assert bad_snapshot.status_code == 422


def test_canonical_graph_view_rejects_oversized_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _current_snapshot(graph_database)
    app = create_app(_settings(tmp_path / "control-plane.db", graph_database=graph_database))
    oversized = SimpleNamespace(
        projection=SimpleNamespace(nodes=[None] * 501, edges=[]),
    )
    monkeypatch.setattr(
        graph_views,
        "load_verified_current_graph_snapshot",
        lambda *args, **kwargs: oversized,
    )

    with TestClient(app) as client:
        response = client.get(
            _endpoint(CAMPAIGN, snapshot.snapshot_id),
            headers=_auth(OPERATOR_TOKEN),
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "Canonical Graph Snapshot exceeds view limits"


def test_graph_database_loads_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", "graph-view-test-signing-key-32-bytes")
    database = tmp_path / "configured-graph.sqlite3"
    audit_database = tmp_path / "configured-decision-audit.sqlite3"
    monkeypatch.setenv("PAJIN_CP_GRAPH_DATABASE", str(database))
    monkeypatch.setenv(
        "PAJIN_CP_GRAPH_DECISION_AUDIT_DATABASE",
        str(audit_database),
    )

    settings = ControlPlaneSettings.from_env()

    assert settings.graph_database == database
    assert settings.graph_decision_audit_database == audit_database


@pytest.mark.parametrize("raw", ["", " ", "\t", "\r\n"])
def test_graph_database_environment_rejects_blank_values(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", "graph-view-test-signing-key-32-bytes")
    monkeypatch.setenv("PAJIN_CP_GRAPH_DATABASE", raw)

    with pytest.raises(RuntimeError, match="GRAPH_DATABASE must not be blank"):
        ControlPlaneSettings.from_env()


@pytest.mark.parametrize("raw", ["", " ", "\t", "\r\n"])
def test_graph_decision_audit_database_environment_rejects_blank_values(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", "graph-view-test-signing-key-32-bytes")
    monkeypatch.setenv("PAJIN_CP_GRAPH_DECISION_AUDIT_DATABASE", raw)

    with pytest.raises(RuntimeError, match="DECISION_AUDIT_DATABASE must not be blank"):
        ControlPlaneSettings.from_env()
