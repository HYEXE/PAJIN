"""Historical cache hits retain byte integrity, cursor scope and caller isolation."""

import os
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_control_plane_graph_views import CAMPAIGN, _current_snapshot
from test_graph_snapshot_cache import _tamper

import pajin.graph.history_cache as cache_module
import pajin.graph.sqlite_store as store_module
from pajin.graph import GraphObservation, GraphSnapshotReason, SQLiteGraphStoreError
from pajin.graph.history import read_snapshot_history
from pajin.graph.history_cache import VerifiedSnapshotHistoryCache
from pajin.graph.sqlite_store import load_verified_graph_snapshot_history


def fixture(tmp_path, **limits):
    path = tmp_path / "history.db"
    _, authority, old = _current_snapshot(path)
    authority.capture(GraphSnapshotReason.REPLAN)
    return path, authority, old, VerifiedSnapshotHistoryCache(**limits)


def count_verifications(monkeypatch):
    calls = []
    original = cache_module._read_snapshot_history_from_connection

    def verify(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(cache_module, "_read_snapshot_history_from_connection", verify)
    return calls


def load(path, cache, old, **kwargs):
    return cache.load(path, campaign_id=CAMPAIGN, snapshot_id=old.snapshot_id, **kwargs)


def test_historical_hit_matches_full_reader_and_isolates_mutable_nodes(tmp_path, monkeypatch):
    path, _, old, cache = fixture(tmp_path)
    calls = count_verifications(monkeypatch)
    expected = read_snapshot_history(path, campaign_id=CAMPAIGN, snapshot_id=old.snapshot_id)
    first = load(path, cache, old)
    assert first == expected and first.snapshot == old
    node = next(n for n in first.snapshot.projection.nodes if isinstance(n, GraphObservation))
    node.summary = "caller changed only its copy"
    assert load(path, cache, old) == expected and len(calls) == 1
    history = load_verified_graph_snapshot_history(path, campaign_id=CAMPAIGN)
    historical_node = next(
        n for n in history[0].projection.nodes if isinstance(n, GraphObservation)
    )
    historical_node.summary = "older public snapshot mutation"
    assert history[1].projection.nodes != history[0].projection.nodes
    assert load(path, cache, old) == expected


@pytest.mark.parametrize(
    "table,column",
    [
        ("graph_events", "event_json"),
        ("graph_nodes", "node_json"),
        ("graph_projections", "projection_json"),
        ("graph_snapshots", "snapshot_json"),
    ],
)
def test_unselected_bytes_with_restored_mtime_invalidate_hit(tmp_path, table, column):
    path, _, old, cache = fixture(tmp_path)
    load(path, cache, old)
    info = path.stat()
    _tamper(
        path,
        table,
        f"UPDATE {table} SET {column}=? WHERE rowid=(SELECT max(rowid) FROM {table})",
        (b"{}",),
    )
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    with pytest.raises((ValueError, SQLiteGraphStoreError)):
        load(path, cache, old)
    assert cache._selection is None and cache._key is None


def test_expected_state_checked_on_hit_and_after_append(tmp_path, monkeypatch):
    path, authority, old, cache = fixture(tmp_path)
    calls = count_verifications(monkeypatch)
    state = load(path, cache, old).state_digest
    assert load(path, cache, old, expected_state=state).state_digest == state
    assert len(calls) == 1
    with pytest.raises(SQLiteGraphStoreError, match="changed"):
        load(path, cache, old, expected_state="0" * 64)
    assert cache._selection is None
    load(path, cache, old)
    authority.capture(GraphSnapshotReason.HANDOFF)
    with pytest.raises(SQLiteGraphStoreError, match="changed"):
        load(path, cache, old, expected_state=state)
    assert load(path, cache, old).state_digest != state


def test_history_head_is_checked_independently_of_cache_hash(tmp_path, monkeypatch):
    path, authority, old, cache = fixture(tmp_path)
    monkeypatch.setattr(cache_module, "_database_digest", lambda *a, **k: "a" * 64)
    load(path, cache, old)
    authority.capture(GraphSnapshotReason.HANDOFF)
    with pytest.raises(SQLiteGraphStoreError, match="head changed"):
        load(path, cache, old)


def test_one_entry_across_paths_and_page_scopes(tmp_path, monkeypatch):
    path, _, old, cache = fixture(tmp_path)
    other = tmp_path / "other.db"
    shutil.copyfile(path, other)
    calls = count_verifications(monkeypatch)
    first = load(path, cache, old, limit=1)
    load(other, cache, old, limit=1)
    load(path, cache, old, limit=1)
    second = load(path, cache, old, offset=1, limit=1)
    assert len(calls) == 4
    assert first.entries != second.entries
    with pytest.raises(ValueError, match="outside"):
        load(path, cache, old, offset=2)


@pytest.mark.parametrize("limit", ["max_database_bytes", "max_snapshot_bytes"])
def test_zero_limit_uses_full_verification(tmp_path, monkeypatch, limit):
    path, _, old, cache = fixture(tmp_path, **{limit: 0})
    calls = count_verifications(monkeypatch)
    assert load(path, cache, old) == load(path, cache, old)
    assert len(calls) == 2 and cache._selection is None


def test_same_bytes_new_inode_require_verification_and_symlink_is_refused(tmp_path, monkeypatch):
    path, _, old, cache = fixture(tmp_path)
    calls = count_verifications(monkeypatch)
    first = load(path, cache, old)
    other = path.with_suffix(".replacement")
    shutil.copyfile(path, other)
    other.replace(path)
    assert load(path, cache, old) == first and len(calls) == 2
    path.rename(other)
    path.symlink_to(other)
    with pytest.raises(SQLiteGraphStoreError, match="identity"):
        load(path, cache, old)
    assert cache._selection is None


def test_second_hash_refuses_out_of_band_write(tmp_path, monkeypatch):
    path, _, old, cache = fixture(tmp_path)
    load(path, cache, old)
    original = cache_module._database_digest
    changed = False

    def digest(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            with path.open("ab") as stream:
                stream.write(b"\0")
        return result

    monkeypatch.setattr(cache_module, "_database_digest", digest)
    with pytest.raises(SQLiteGraphStoreError, match="changed during cached"):
        load(path, cache, old)
    assert cache._selection is None


@pytest.mark.parametrize("change", ["schema", "wal"])
def test_schema_and_journal_contract_checked_on_every_hit(tmp_path, monkeypatch, change):
    path, _, old, cache = fixture(tmp_path)
    load(path, cache, old)
    if change == "schema":
        monkeypatch.setattr(store_module, "_SCHEMA_DIGEST", "0" * 64)
    else:
        with sqlite3.connect(path) as connection:
            assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    with pytest.raises(SQLiteGraphStoreError):
        load(path, cache, old)
    assert cache._selection is None


def test_concurrent_readers_receive_independent_public_copies(tmp_path, monkeypatch):
    path, _, old, cache = fixture(tmp_path)
    calls = count_verifications(monkeypatch)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: load(path, cache, old), range(8)))
    assert len(calls) == 1 and all(result == results[0] for result in results)
    assert len({id(result.snapshot.projection.nodes[0]) for result in results}) == 8
