from __future__ import annotations

import os
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from threading import Event

import pytest
from fastapi.testclient import TestClient
from test_control_plane_graph_views import (
    CAMPAIGN,
    OPERATOR_TOKEN,
    _auth,
    _current_snapshot,
    _endpoint,
    _settings,
)

import pajin.graph.snapshot_cache as cache_module
import pajin.graph.sqlite_store as store_module
from pajin.control_plane.api import create_app
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.graph import (
    GraphObservation,
    GraphSnapshotError,
    GraphSnapshotReason,
    SQLiteGraphStoreError,
)
from pajin.graph.snapshot_cache import VerifiedCurrentGraphSnapshotCache


def _fixture(tmp_path, **limits):
    path = tmp_path / "graph/graph.db"
    store, authority, snapshot = _current_snapshot(path)
    return path, store, authority, snapshot, VerifiedCurrentGraphSnapshotCache(path, **limits)


def _load(cache, snapshot):
    return cache.load(campaign_id=CAMPAIGN, snapshot_id=snapshot.snapshot_id)


def _count_full_verifications(monkeypatch):
    calls = []
    original = cache_module._verified_current_snapshot_from_connection

    def verify(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(cache_module, "_verified_current_snapshot_from_connection", verify)
    return calls


def test_byte_identical_hit_isolated_from_caller_mutation(tmp_path, monkeypatch):
    _path, _store, _authority, snapshot, cache = _fixture(tmp_path)
    calls = _count_full_verifications(monkeypatch)
    first = _load(cache, snapshot)
    assert first == snapshot
    node = next(node for node in first.projection.nodes if isinstance(node, GraphObservation))
    node.summary = "caller changed its own copy"
    second = _load(cache, snapshot)
    assert second == snapshot and second != first and len(calls) == 1


def _tamper(path, table, statement, parameters=()):
    with sqlite3.connect(path) as connection:
        triggers = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)
        ).fetchall()
        for name, _ in triggers:
            connection.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
        connection.execute(statement, parameters)
        for _, sql in triggers:
            connection.execute(sql)


@pytest.mark.parametrize(
    "table,column",
    [
        ("graph_events", "event_json"),
        ("graph_nodes", "node_json"),
        ("graph_projections", "projection_json"),
        ("graph_snapshots", "snapshot_json"),
    ],
)
def test_old_history_tamper_with_restored_mtime_cannot_hit_cache(tmp_path, table, column):
    path, _store, authority, _snapshot, cache = _fixture(tmp_path)
    snapshot = authority.capture(GraphSnapshotReason.REPLAN)
    assert _load(cache, snapshot) == snapshot
    times = path.stat()
    # Damage the oldest row; the current head IDs themselves are unchanged.
    _tamper(
        path,
        table,
        f"UPDATE {table} SET {column} = ? WHERE rowid = (SELECT min(rowid) FROM {table})",
        (b"{}",),
    )
    os.utime(path, ns=(times.st_atime_ns, times.st_mtime_ns))
    with pytest.raises((ValueError, SQLiteGraphStoreError)):
        _load(cache, snapshot)
    assert cache._snapshot is None and cache._key is None


def test_head_check_is_independent_of_byte_cache_key(tmp_path, monkeypatch):
    _path, _store, authority, snapshot, cache = _fixture(tmp_path)
    monkeypatch.setattr(cache_module, "_database_digest", lambda *args, **kwargs: "a" * 64)
    assert _load(cache, snapshot) == snapshot
    authority.capture(GraphSnapshotReason.REPLAN)
    with pytest.raises(SQLiteGraphStoreError, match="current canonical head"):
        _load(cache, snapshot)


def test_raw_file_change_between_hashes_cannot_publish_cached_result(tmp_path, monkeypatch):
    path, _store, _authority, snapshot, cache = _fixture(tmp_path)
    _load(cache, snapshot)
    original = cache_module._database_digest
    changed = False

    def digest(*args, **kwargs):
        nonlocal changed
        value = original(*args, **kwargs)
        if not changed:
            changed = True
            # Deliberately model an out-of-band writer that ignores SQLite locks.
            with path.open("ab") as stream:
                stream.write(b"\x00")
        return value

    monkeypatch.setattr(cache_module, "_database_digest", digest)
    with pytest.raises(SQLiteGraphStoreError, match="changed during cached verification"):
        _load(cache, snapshot)
    assert cache._snapshot is None


def test_runtime_limit_change_evicts_a_warm_entry(tmp_path, monkeypatch):
    _path, _store, _authority, snapshot, cache = _fixture(tmp_path)
    calls = _count_full_verifications(monkeypatch)
    _load(cache, snapshot)
    cache._snapshot_limit = 0
    assert _load(cache, snapshot) == snapshot
    assert len(calls) == 2 and cache._snapshot is None


def test_successor_evicts_previous_snapshot_and_stale_cursor_is_not_reused(tmp_path, monkeypatch):
    _path, _store, authority, snapshot, cache = _fixture(tmp_path)
    calls = _count_full_verifications(monkeypatch)
    _load(cache, snapshot)
    successor = authority.capture(GraphSnapshotReason.REPLAN)
    assert _load(cache, successor) == successor
    assert len(calls) == 2 and cache._snapshot == successor
    with pytest.raises(GraphSnapshotError, match="current canonical head"):
        _load(cache, snapshot)


@pytest.mark.parametrize("limit", ["max_database_bytes", "max_snapshot_bytes"])
def test_size_limit_falls_back_to_full_verification(tmp_path, monkeypatch, limit):
    _path, _store, _authority, snapshot, cache = _fixture(tmp_path, **{limit: 0})
    calls = _count_full_verifications(monkeypatch)
    assert _load(cache, snapshot) == _load(cache, snapshot) == snapshot
    assert len(calls) == 2 and cache._snapshot is None


def test_same_bytes_under_replaced_inode_require_full_verification(tmp_path, monkeypatch):
    path, _store, _authority, snapshot, cache = _fixture(tmp_path)
    calls = _count_full_verifications(monkeypatch)
    _load(cache, snapshot)
    replacement = path.with_suffix(".replacement")
    shutil.copyfile(path, replacement)
    replacement.replace(path)
    assert _load(cache, snapshot) == snapshot and len(calls) == 2
    real = path.with_suffix(".real")
    path.rename(real)
    path.symlink_to(real)
    with pytest.raises(SQLiteGraphStoreError, match="identity"):
        _load(cache, snapshot)


def test_changed_verifier_contract_is_checked_on_a_hit(tmp_path, monkeypatch):
    _path, _store, _authority, snapshot, cache = _fixture(tmp_path)
    _load(cache, snapshot)
    monkeypatch.setattr(store_module, "_SCHEMA_DIGEST", "0" * 64)
    with pytest.raises(SQLiteGraphStoreError, match="metadata"):
        _load(cache, snapshot)


def test_wal_switch_cannot_reuse_cached_main_file(tmp_path):
    path, _store, _authority, snapshot, cache = _fixture(tmp_path)
    _load(cache, snapshot)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    with pytest.raises(SQLiteGraphStoreError, match="connection policy"):
        _load(cache, snapshot)


def test_writer_commit_waits_for_checked_read_then_invalidates_snapshot(tmp_path, monkeypatch):
    _path, _store, authority, snapshot, cache = _fixture(tmp_path)
    _load(cache, snapshot)
    hashing, release, writer_reserved = Event(), Event(), Event()
    original_digest = cache_module._database_digest
    original_transaction = store_module._write_transaction

    def digest(*args, **kwargs):
        value = original_digest(*args, **kwargs)
        hashing.set()
        assert release.wait(timeout=5)
        return value

    @contextmanager
    def transaction(*args, **kwargs):
        with original_transaction(*args, **kwargs) as connection:
            writer_reserved.set()
            yield connection

    monkeypatch.setattr(cache_module, "_database_digest", digest)
    monkeypatch.setattr(store_module, "_write_transaction", transaction)
    with ThreadPoolExecutor(max_workers=2) as pool:
        read = pool.submit(_load, cache, snapshot)
        assert hashing.wait(timeout=5)
        write = pool.submit(authority.capture, GraphSnapshotReason.REPLAN)
        try:
            assert writer_reserved.wait(timeout=5)
            assert not write.done()
        finally:
            release.set()
        assert read.result(timeout=5) == snapshot
        successor = write.result(timeout=5)
    with pytest.raises(GraphSnapshotError, match="current canonical head"):
        _load(cache, snapshot)
    assert _load(cache, successor) == successor


def test_warmed_view_does_not_cache_replaced_authentication_configuration(tmp_path):
    path, _store, _authority, snapshot, _cache = _fixture(tmp_path)
    settings = _settings(tmp_path / "cp.db", graph_database=path)
    endpoint = _endpoint(CAMPAIGN, snapshot.snapshot_id) + "/pages"
    with TestClient(create_app(settings)) as client:
        for _ in range(2):
            assert client.get(endpoint, headers=_auth(OPERATOR_TOKEN)).status_code == 200
        assert client.get(endpoint).status_code == 401
    changed = replace(
        settings,
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="changed-operator", roles=frozenset({PrincipalRole.WORKER})
            )
        },
    )
    with TestClient(create_app(changed)) as client:
        assert client.get(endpoint, headers=_auth(OPERATOR_TOKEN)).status_code == 403
