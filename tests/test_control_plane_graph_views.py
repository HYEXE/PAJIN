from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import pajin.control_plane.graph_views as graph_views
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.graph import (
    GraphAction,
    GraphActionStatus,
    GraphAdmissionAuthority,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphObservation,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    ObservationProposal,
    SQLiteGraphStore,
    TrustedGraphLineageRegistry,
    graph_node_ref,
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


def _settings(database: Path, *, graph_database: Path | None) -> ControlPlaneSettings:
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
    monkeypatch.setenv("PAJIN_CP_GRAPH_DATABASE", str(database))

    settings = ControlPlaneSettings.from_env()

    assert settings.graph_database == database


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
