from __future__ import annotations

import base64
import json
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient
from test_control_plane_graph_views import (
    APPROVER_TOKEN,
    CAMPAIGN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _current_snapshot,
    _endpoint,
    _settings,
)
from test_supervisor_checkpoint_scheduler import _graph

from pajin.control_plane.api import create_app
from pajin.control_plane.graph_pages import GraphPageCursorError, build_graph_page
from pajin.graph import GraphEdge, GraphProjection, GraphSnapshot, GraphSnapshotReason, GraphSurface


def test_large_snapshot_pages_cover_every_node_without_truncation(sample_campaign):
    _, _, original, _ = _graph(sample_campaign)
    projection = GraphProjection(
        campaignId=original.campaign_id,
        revision=1,
        eventLogHeadDigest=original.event_log_head_digest,
        nodes=tuple(
            sorted(
                (
                    GraphSurface(
                        campaignId=original.campaign_id,
                        targetId="large-fixture",
                        surfaceType="http-endpoint",
                        locatorSchema="pajin.discovery.http-surface.v1",
                        locatorDigest=sha256(str(index).encode()).hexdigest(),
                        origin="trusted-core",
                    )
                    for index in range(503)
                ),
                key=lambda item: item.node_id,
            )
        ),
        edges=(),
    )
    snapshot = GraphSnapshot.model_validate(
        {
            **original.model_dump(mode="python"),
            "snapshot_id": "",
            "snapshot_digest": "",
            "projection": projection,
            "projection_id": projection.projection_id,
            "projection_digest": projection.projection_digest,
            "node_projection_digest": projection.node_projection_digest,
            "edge_projection_digest": projection.edge_projection_digest,
        }
    )
    collected = []
    cursor = None
    offsets = []
    while True:
        page = build_graph_page(snapshot, limit=200, cursor=cursor)
        assert page.node_count == 503 and len(page.nodes) <= 200
        assert page.snapshot.snapshot_digest == snapshot.snapshot_digest
        collected.extend(item.node_id for item in page.nodes)
        offsets.append(page.page_offset)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert offsets == [0, 200, 400]
    assert collected == [item.node_id for item in snapshot.projection.nodes]


def test_real_sqlite_api_pages_preserve_auth_redaction_and_snapshot_consistency(tmp_path):
    path = tmp_path / "graph/graph.db"
    store, authority, snapshot = _current_snapshot(path)
    before = path.read_bytes()
    app = create_app(_settings(tmp_path / "cp.db", graph_database=path))
    route = _endpoint(CAMPAIGN, snapshot.snapshot_id) + "/pages"
    with TestClient(app) as client:
        assert client.get(route).status_code == 401
        for token in (APPROVER_TOKEN, WORKER_TOKEN):
            assert client.get(route, headers=_auth(token)).status_code == 403
        response = client.get(route, params={"limit": 1}, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 200, response.text
        first = response.json()
        assert len(first["nodes"]) == len(first["edges"]) == 1
        assert first["nodeCount"] == 3 and first["edgeCount"] == 2
        assert first["authorityBoundary"]["viewAuthorizesExecution"] is False
        # Endpoints in another page keep only their redacted identity and kind.
        assert set(first["edges"][0]["source"]) == {"nodeId", "kind"}
        second = client.get(
            route, params={"limit": 1, "cursor": first["nextCursor"]}, headers=_auth(OPERATOR_TOKEN)
        )
        assert second.status_code == 200, second.text
        third = client.get(
            route,
            params={"limit": 1, "cursor": second.json()["nextCursor"]},
            headers=_auth(OPERATOR_TOKEN),
        )
        assert third.status_code == 200 and third.json()["nextCursor"] is None
        nodes = first["nodes"] + second.json()["nodes"] + third.json()["nodes"]
        assert [item["nodeId"] for item in nodes] == [n.node_id for n in snapshot.projection.nodes]
        assert path.read_bytes() == before
        assert len(store.snapshot_store.snapshots()) == 1
        for params in (
            {"limit": 501},
            {"limit": 0},
            {"cursor": "invalid"},
            {"limit": 2, "cursor": first["nextCursor"]},
        ):
            assert (
                client.get(route, params=params, headers=_auth(OPERATOR_TOKEN)).status_code == 422
            )
        successor = authority.capture(GraphSnapshotReason.REPLAN)
        assert successor.snapshot_id != snapshot.snapshot_id
        stale = client.get(
            route, params={"limit": 1, "cursor": first["nextCursor"]}, headers=_auth(OPERATOR_TOKEN)
        )
        assert stale.status_code == 409
        mixed = client.get(
            _endpoint(CAMPAIGN, successor.snapshot_id) + "/pages",
            params={"limit": 1, "cursor": first["nextCursor"]},
            headers=_auth(OPERATOR_TOKEN),
        )
        assert mixed.status_code == 422


def test_pages_cover_more_than_one_thousand_edges_and_exhausted_node_pages(tmp_path):
    _, _, original = _current_snapshot(tmp_path / "graph/graph.db")
    edge = original.projection.edges[0]
    projection = GraphProjection(
        campaignId=original.campaign_id,
        revision=1,
        eventLogHeadDigest=original.event_log_head_digest,
        nodes=original.projection.nodes,
        edges=tuple(
            sorted(
                (
                    GraphEdge(
                        campaignId=original.campaign_id,
                        relation=edge.relation,
                        source=edge.source,
                        target=edge.target,
                        authorityId=f"page-authority:{index}",
                        authorityDigest="a" * 64,
                    )
                    for index in range(1001)
                ),
                key=lambda item: item.edge_id,
            )
        ),
    )
    snapshot = GraphSnapshot.model_validate(
        {
            **original.model_dump(mode="python"),
            "snapshot_id": "",
            "snapshot_digest": "",
            "projection": projection,
            "projection_id": projection.projection_id,
            "projection_digest": projection.projection_digest,
            "node_projection_digest": projection.node_projection_digest,
            "edge_projection_digest": projection.edge_projection_digest,
        }
    )
    pages = [build_graph_page(snapshot, limit=500)]
    while pages[-1].next_cursor:
        pages.append(build_graph_page(snapshot, limit=500, cursor=pages[-1].next_cursor))
    assert [len(page.edges) for page in pages] == [500, 500, 1]
    assert [len(page.nodes) for page in pages] == [3, 0, 0]
    assert [edge.edge_id for page in pages for edge in page.edges] == [
        edge.edge_id for edge in projection.edges
    ]


@pytest.mark.parametrize("change", ["campaign", "snapshot_digest", "projection_digest", "offset"])
def test_cursor_cannot_mix_identities_or_create_partial_pages(sample_campaign, change):
    _, _, snapshot, _ = _graph(sample_campaign, fact_count=4)
    first = build_graph_page(snapshot, limit=2)
    encoded = first.next_cursor
    raw = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    raw[change] = 3 if change == "offset" else "e" * 64 if "digest" in change else "other-campaign"
    cursor = (
        base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    with pytest.raises(GraphPageCursorError):
        build_graph_page(snapshot, limit=2, cursor=cursor)
