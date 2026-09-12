"""Historical replay remains exact even when stored rows are independently canonical."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_graph_snapshot_cache import _fixture, _load, _tamper

from pajin.graph import (
    GraphObservation,
    GraphProjection,
    GraphProjector,
    GraphSnapshot,
    GraphSnapshotError,
    GraphSnapshotReason,
    SQLiteGraphStoreError,
    load_verified_graph_snapshot_history,
)
from pajin.graph.sqlite_store import (
    _events_from_connection,
    _projection_bytes,
    _readonly_connection,
    _snapshot_bytes,
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


def test_current_reads_preserve_complete_independent_history_views(tmp_path):
    path, _store, authority, initial, cache = _fixture(tmp_path)
    successors = [authority.capture(GraphSnapshotReason.REPLAN) for _ in range(5)]
    current = successors[-1]
    assert _load(cache, current) == current
    history = load_verified_graph_snapshot_history(path, campaign_id=current.campaign_id)
    assert history[-6:] == (initial, *successors)
    # Historical results remain independent objects, and reading them cannot alter the cache.
    observation = next(
        node for node in history[-2].projection.nodes if isinstance(node, GraphObservation)
    )
    observation.summary = "caller changed one historical result"
    assert history[-1] == current
    assert _load(cache, current) == current
    with pytest.raises(GraphSnapshotError, match="current"):
        _load(cache, initial)


@pytest.mark.parametrize("requested", ["current", "missing"])
@pytest.mark.parametrize("row", ["first", "middle"])
def test_discarded_snapshot_corruption_is_checked_before_any_current_result(
    tmp_path, requested, row
):
    path, _store, authority, initial, cache = _fixture(tmp_path)
    snapshots = [initial, *(authority.capture(GraphSnapshotReason.REPLAN) for _ in range(5))]
    current = snapshots[-1]
    assert _load(cache, current) == current
    old = snapshots[0 if row == "first" else 2]
    _tamper(
        path,
        "graph_snapshots",
        "UPDATE graph_snapshots SET snapshot_json = ? WHERE snapshot_id = ?",
        (b"{}", old.snapshot_id),
    )
    selected = current.snapshot_id if requested == "current" else "graph-snapshot_" + "0" * 64
    with pytest.raises((GraphSnapshotError, SQLiteGraphStoreError)):
        cache.load(campaign_id=current.campaign_id, snapshot_id=selected)
    with pytest.raises((GraphSnapshotError, SQLiteGraphStoreError)):
        load_verified_graph_snapshot_history(path, campaign_id=current.campaign_id)


def test_concurrent_stale_and_current_requests_cannot_exchange_snapshot_results(tmp_path):
    _path, _store, authority, initial, cache = _fixture(tmp_path)
    current = authority.capture(GraphSnapshotReason.REPLAN)
    with ThreadPoolExecutor(max_workers=2) as pool:
        stale = pool.submit(_load, cache, initial)
        fresh = pool.submit(_load, cache, current)
        with pytest.raises(GraphSnapshotError, match="current"):
            stale.result(timeout=10)
        assert fresh.result(timeout=10) == current
    assert _load(cache, current) == current


@pytest.mark.parametrize("mutation", ["equal-float", "duplicate-projection", "extra-field"])
def test_equal_decoded_projection_still_requires_original_canonical_bytes(tmp_path, mutation):
    path, _store, authority, initial, cache = _fixture(tmp_path)
    current = authority.capture(GraphSnapshotReason.REPLAN)
    payload = initial.model_dump(mode="json", by_alias=True)
    if mutation == "equal-float":
        payload["projection"]["revision"] = float(initial.revision)
        assert payload["projection"] == initial.projection.model_dump(mode="json", by_alias=True)
    elif mutation == "extra-field":
        payload["projection"]["untrustedExtra"] = None
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if mutation == "duplicate-projection":
        raw = raw.replace(b'"projection":{', b'"projection":{},"projection":{', 1)
        assert json.loads(raw) == payload
    _tamper(
        path, "graph_snapshots",
        "UPDATE graph_snapshots SET snapshot_json=? WHERE snapshot_id=?",
        (raw, initial.snapshot_id),
    )
    with pytest.raises((GraphSnapshotError, SQLiteGraphStoreError)):
        _load(cache, current)
    assert cache._snapshot is None and cache._key is None


def test_valid_snapshot_cannot_substitute_another_canonical_projection(tmp_path):
    path, _store, authority, initial, cache = _fixture(tmp_path)
    current = authority.capture(GraphSnapshotReason.REPLAN)
    projection = GraphProjection(
        campaignId=initial.campaign_id, revision=initial.revision,
        eventLogHeadDigest=initial.event_log_head_digest, nodes=(), edges=(),
    )
    payload = initial.model_dump(mode="json", by_alias=True)
    payload.update({
        "projection": projection.model_dump(mode="json", by_alias=True),
        "projectionId": projection.projection_id,
        "projectionDigest": projection.projection_digest,
        "nodeProjectionDigest": projection.node_projection_digest,
        "edgeProjectionDigest": projection.edge_projection_digest,
        "snapshotId": "", "snapshotDigest": "",
    })
    forged = GraphSnapshot.model_validate(payload)
    assert GraphSnapshot.model_validate_json(_snapshot_bytes(forged)) == forged
    _tamper(
        path, "graph_snapshots",
        "UPDATE graph_snapshots SET snapshot_id=?, snapshot_digest=?, projection_digest=?, "
        "snapshot_json=? WHERE snapshot_id=?",
        (
            forged.snapshot_id, forged.snapshot_digest, forged.projection_digest,
            _snapshot_bytes(forged), initial.snapshot_id,
        ),
    )
    with pytest.raises(GraphSnapshotError, match="differs from its verified Projection"):
        _load(cache, current)
    assert cache._snapshot is None and cache._key is None
