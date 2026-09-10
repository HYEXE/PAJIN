"""Historical replay remains exact even when stored rows are independently canonical."""

import sqlite3

import pytest
from test_graph_snapshot_cache import _fixture, _load, _tamper

from pajin.graph import GraphProjection, GraphProjector, GraphSnapshotReason, SQLiteGraphStoreError
from pajin.graph.sqlite_store import (
    _events_from_connection,
    _projection_bytes,
    _readonly_connection,
    _verified_projections,
)


def test_every_saved_prefix_matches_independent_full_replay(tmp_path):
    path, _store, authority, snapshot, _cache = _fixture(tmp_path)
    authority.capture(GraphSnapshotReason.REPLAN)
    with _readonly_connection(path) as db:
        events = _events_from_connection(db, campaign_id=snapshot.campaign_id)
        history = _verified_projections(db, campaign_id=snapshot.campaign_id, events=events)
    assert 0 in history and len(history) >= 2
    for revision, projection in history.items():
        expected = GraphProjector.project(
            campaign_id=snapshot.campaign_id, events=events[:revision]
        )
        assert _projection_bytes(projection) == _projection_bytes(expected)


@pytest.mark.parametrize("mutation", ["edge", "nodes", "event-head"])
def test_canonical_but_false_historical_projection_is_rejected(tmp_path, mutation):
    path, _store, authority, snapshot, cache = _fixture(tmp_path)
    successor = authority.capture(GraphSnapshotReason.REPLAN)
    assert _load(cache, successor) == successor
    old = snapshot.projection
    nodes, edges, head = old.nodes, old.edges, old.event_log_head_digest
    if mutation == "edge":
        assert edges
        edges = edges[:-1]
    elif mutation == "nodes":
        nodes, edges = (), ()
    else:
        head = "0" * 64
    # This replacement passes the full model, digest, canonical-byte and row-index gates.
    # Only comparison against the independently verified Event Log exposes the forgery.
    replacement = GraphProjection(
        campaignId=old.campaign_id,
        revision=old.revision,
        eventLogHeadDigest=head,
        nodes=nodes,
        edges=edges,
    )
    _tamper(
        path,
        "graph_projections",
        "UPDATE graph_projections SET projection_id=?, "
        "projection_digest=?, event_log_head_digest=?, projection_json=? WHERE revision=?",
        (
            replacement.projection_id,
            replacement.projection_digest,
            head,
            _projection_bytes(replacement),
            old.revision,
        ),
    )
    with pytest.raises(SQLiteGraphStoreError, match="differs from its Event Log prefix"):
        _load(cache, successor)
    assert cache._snapshot is None and cache._key is None


@pytest.mark.parametrize("kind", ["database", "snapshot"])
def test_inclusive_size_boundary_and_immediate_fallback(tmp_path, monkeypatch, kind):
    from test_graph_snapshot_cache import _count_full_verifications

    path, _store, _authority, snapshot, cache = _fixture(tmp_path)
    calls = _count_full_verifications(monkeypatch)
    if kind == "database":
        limit = path.stat().st_size
    else:
        with sqlite3.connect(path) as db:
            limit = db.execute(
                "SELECT length(snapshot_json) FROM graph_snapshots WHERE snapshot_id=?",
                (snapshot.snapshot_id,),
            ).fetchone()[0]
    attribute = "_database_limit" if kind == "database" else "_snapshot_limit"
    setattr(cache, attribute, limit)
    assert _load(cache, snapshot) == _load(cache, snapshot) == snapshot
    assert len(calls) == 1
    setattr(cache, attribute, limit - 1)
    assert _load(cache, snapshot) == _load(cache, snapshot) == snapshot
    assert len(calls) == 3 and cache._snapshot is None
