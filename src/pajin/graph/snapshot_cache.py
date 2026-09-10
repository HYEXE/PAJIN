"""Bound one verified snapshot to freshly checked complete SQLite bytes, never to stat hints."""

from __future__ import annotations

import os
import sqlite3
import threading
from hashlib import sha256
from pathlib import Path
from re import fullmatch

from pajin.graph.projection import GraphSnapshot
from pajin.graph.sqlite_store import (
    SQLiteGraphStoreError,
    _absolute_path,
    _canonical_snapshot,
    _file_identity,
    _readonly_connection,
    _validate_schema,
    _verified_current_snapshot_from_connection,
)

_DATABASE_LIMIT = 128 * 1024 * 1024
_SNAPSHOT_LIMIT = 16 * 1024 * 1024


def _database_digest(path: Path, *, limit: int) -> str:
    identity = _file_identity(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino) != identity[1] or info.st_size > limit:
            raise SQLiteGraphStoreError("Graph cache file identity or size changed")
        digest = sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise SQLiteGraphStoreError("Graph cache database exceeds its bounded read")
            digest.update(chunk)
        if size != info.st_size or _file_identity(path) != identity:
            raise SQLiteGraphStoreError("Graph cache file changed during hashing")
    return digest.hexdigest()


def _require_current_head(connection: sqlite3.Connection, snapshot: GraphSnapshot) -> None:
    event = connection.execute(
        "SELECT sequence, event_digest FROM graph_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    projection = connection.execute(
        "SELECT revision, projection_digest FROM graph_projections ORDER BY revision DESC LIMIT 1"
    ).fetchone()
    head = connection.execute(
        "SELECT snapshot_digest FROM graph_snapshots ORDER BY ordinal DESC LIMIT 1"
    ).fetchone()
    event_head = (event["sequence"], event["event_digest"]) if event is not None else (0, None)
    if (
        event_head != (snapshot.revision, snapshot.event_log_head_digest)
        or projection is None
        or projection["revision"] != snapshot.revision
        or projection["projection_digest"] != snapshot.projection_digest
        or head is None
        or head["snapshot_digest"] != snapshot.snapshot_digest
    ):
        raise SQLiteGraphStoreError("Graph cache Snapshot is not the current canonical head")


class VerifiedCurrentGraphSnapshotCache:
    """One POSIX local SQLite read cache; copies leave the instance, no authority decisions enter.

    Every lookup holds a SQLite DELETE-journal read transaction and checks schema,
    database bytes twice, head and file identity. Any byte change requires complete
    legacy verification. The shared object never escapes to a caller. Oversize
    inputs and platforms without O_NOFOLLOW use complete verification without caching.
    """

    def __init__(
        self,
        path: Path,
        *,
        max_database_bytes: int = _DATABASE_LIMIT,
        max_snapshot_bytes: int = _SNAPSHOT_LIMIT,
    ) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (max_database_bytes, max_snapshot_bytes)
        ):
            raise ValueError("Graph cache limits must be non-negative integers")
        self._path = _absolute_path(path)
        self._database_limit = max_database_bytes
        self._snapshot_limit = max_snapshot_bytes
        self._snapshot: GraphSnapshot | None = None
        self._key: tuple[tuple[tuple[int, int], tuple[int, int]], str, str, str] | None = None
        self._lock = threading.RLock()

    def load(self, *, campaign_id: str, snapshot_id: str) -> GraphSnapshot | None:
        if fullmatch(r"[a-z0-9][a-z0-9-]{2,79}", campaign_id) is None:
            raise ValueError("SQLite Graph Store campaign ID is invalid")
        if fullmatch(r"graph-snapshot_[a-f0-9]{64}", snapshot_id) is None:
            raise ValueError("Graph Snapshot ID is invalid")
        with self._lock:
            try:
                return self._load(campaign_id=campaign_id, snapshot_id=snapshot_id)
            except sqlite3.Error as exc:
                self._snapshot = None
                self._key = None
                raise SQLiteGraphStoreError("Graph cache database is not integrity-valid") from exc
            except BaseException:
                self._snapshot = None
                self._key = None
                raise

    def _load(self, *, campaign_id: str, snapshot_id: str) -> GraphSnapshot | None:
        identity = _file_identity(self._path)
        with _readonly_connection(self._path) as connection:
            # This establishes the read lock and preserves every existing schema/integrity gate.
            _validate_schema(connection, campaign_id=campaign_id)
            size_row = connection.execute(
                "SELECT length(snapshot_json) FROM graph_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            cacheable = (
                hasattr(os, "O_NOFOLLOW")
                and 0 < self._path.stat().st_size <= self._database_limit
                and size_row is not None
                and 0 < size_row[0] <= self._snapshot_limit
            )
            before = _database_digest(self._path, limit=self._database_limit) if cacheable else None
            key = (identity, campaign_id, snapshot_id, before) if before is not None else None
            snapshot: GraphSnapshot | None
            if key is not None and key == self._key and self._snapshot is not None:
                snapshot = self._snapshot
            else:
                self._snapshot = None
                self._key = None
                snapshot, _events = _verified_current_snapshot_from_connection(
                    connection, campaign_id=campaign_id, snapshot_id=snapshot_id
                )
                snapshot = _canonical_snapshot(snapshot) if snapshot is not None else None
            if snapshot is not None:
                _require_current_head(connection, snapshot)
            # Copy while the checked input is still pinned. The caller may mutate nested models.
            result = snapshot.model_copy(deep=True) if snapshot is not None else None
            if (
                before is not None
                and _database_digest(self._path, limit=self._database_limit) != before
            ):
                raise SQLiteGraphStoreError("Graph database changed during cached verification")
            if _file_identity(self._path) != identity:
                raise SQLiteGraphStoreError("Graph cache path changed during verification")
            self._snapshot = snapshot if key is not None else None
            self._key = key
        if _file_identity(self._path) != identity:
            raise SQLiteGraphStoreError("Graph cache path changed after verification")
        return result
