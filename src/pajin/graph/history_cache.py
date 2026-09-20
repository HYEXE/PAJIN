"""One bounded historical selection pinned to freshly verified complete database bytes."""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import replace
from pathlib import Path

from pajin.graph.history import (
    SnapshotHistorySelection,
    _history_state,
    _read_snapshot_history_from_connection,
    _validate_history_request,
)
from pajin.graph.snapshot_cache import _DATABASE_LIMIT, _SNAPSHOT_LIMIT, _database_digest
from pajin.graph.sqlite_store import (
    SQLiteGraphStoreError,
    _absolute_path,
    _file_identity,
    _readonly_connection,
    _validate_schema,
)


def _require_history_head(
    connection: sqlite3.Connection,
    campaign_id: str,
    selection: SnapshotHistorySelection,
) -> None:
    event = connection.execute(
        "SELECT event_digest FROM graph_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    projection = connection.execute(
        "SELECT revision, projection_digest FROM graph_projections ORDER BY revision DESC LIMIT 1"
    ).fetchone()
    head = connection.execute(
        "SELECT snapshot_id, snapshot_digest, projection_digest, revision "
        "FROM graph_snapshots ORDER BY ordinal DESC LIMIT 1"
    ).fetchone()
    count = connection.execute("SELECT count(*) FROM graph_snapshots").fetchone()[0]
    if projection is None:
        raise SQLiteGraphStoreError("Graph history cache has no current Projection")
    current_id = (
        head["snapshot_id"]
        if head is not None
        and (head["revision"], head["projection_digest"])
        == (projection["revision"], projection["projection_digest"])
        else None
    )
    if (
        count != selection.total
        or current_id != selection.current_snapshot_id
        or _history_state(
            campaign_id,
            head["snapshot_digest"] if head else None,
            event["event_digest"] if event else None,
            projection["projection_digest"],
        )
        != selection.state_digest
    ):
        raise SQLiteGraphStoreError("Graph history cache head changed")


class VerifiedSnapshotHistoryCache:
    """One entry across all Campaigns, protected by the complete legacy verification.

    A hit needs schema/integrity checks, unchanged full database hashes before and
    after the copy, and the same path/inode identity. Stat hints never grant a hit.
    Limits bound serialized input; Python object overhead is additional.
    """

    def __init__(
        self,
        *,
        max_database_bytes: int = _DATABASE_LIMIT,
        max_snapshot_bytes: int = _SNAPSHOT_LIMIT,
    ) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (max_database_bytes, max_snapshot_bytes)
        ):
            raise ValueError("Graph cache limits must be non-negative integers")
        self._database_limit = max_database_bytes
        self._snapshot_limit = max_snapshot_bytes
        self._selection: SnapshotHistorySelection | None = None
        self._key: tuple[object, ...] | None = None
        self._lock = threading.RLock()

    def load(
        self,
        path: Path,
        *,
        campaign_id: str,
        snapshot_id: str | None = None,
        offset: int = 0,
        limit: int = 25,
        expected_state: str | None = None,
    ) -> SnapshotHistorySelection:
        _validate_history_request(campaign_id, snapshot_id, offset, limit)
        database = _absolute_path(path)
        with self._lock:
            try:
                return self._load(
                    database,
                    campaign_id=campaign_id,
                    snapshot_id=snapshot_id,
                    offset=offset,
                    limit=limit,
                    expected_state=expected_state,
                )
            except sqlite3.Error as exc:
                self._selection = None
                self._key = None
                raise SQLiteGraphStoreError("Graph history cache is not integrity-valid") from exc
            except BaseException:
                self._selection = None
                self._key = None
                raise

    def _load(
        self,
        database: Path,
        *,
        campaign_id: str,
        snapshot_id: str | None,
        offset: int,
        limit: int,
        expected_state: str | None,
    ) -> SnapshotHistorySelection:
        identity = _file_identity(database)
        with _readonly_connection(database) as connection:
            _validate_schema(connection, campaign_id=campaign_id)
            row = (
                None
                if snapshot_id is None
                else connection.execute(
                    "SELECT length(snapshot_json) FROM graph_snapshots WHERE snapshot_id = ?",
                    (snapshot_id,),
                ).fetchone()
            )
            cacheable = (
                hasattr(os, "O_NOFOLLOW")
                and 0 < database.stat().st_size <= self._database_limit
                and (
                    snapshot_id is None or (row is not None and 0 < row[0] <= self._snapshot_limit)
                )
            )
            before = _database_digest(database, limit=self._database_limit) if cacheable else None
            key = (
                (database, identity, campaign_id, snapshot_id, offset, limit, before)
                if before is not None
                else None
            )
            if key is not None and key == self._key and self._selection is not None:
                selection = self._selection
            else:
                self._selection = None
                self._key = None
                selection = _read_snapshot_history_from_connection(
                    connection,
                    campaign_id=campaign_id,
                    snapshot_id=snapshot_id,
                    offset=offset,
                    limit=limit,
                    expected_state=None,
                )
            if expected_state is not None and selection.state_digest != expected_state:
                raise SQLiteGraphStoreError("Graph history changed; reload its current catalog")
            _require_history_head(connection, campaign_id, selection)
            # Entries contain immutable scalars. No shared mutable model leaves this cache.
            result = replace(
                selection,
                snapshot=selection.snapshot.model_copy(deep=True)
                if selection.snapshot is not None
                else None,
            )
            if (
                before is not None
                and _database_digest(database, limit=self._database_limit) != before
            ):
                raise SQLiteGraphStoreError("Graph database changed during cached history read")
            if _file_identity(database) != identity:
                raise SQLiteGraphStoreError("Graph history cache path changed during verification")
            self._key = key
            self._selection = selection if key is not None else None
        if _file_identity(database) != identity:
            raise SQLiteGraphStoreError("Graph history cache path changed after verification")
        return result
