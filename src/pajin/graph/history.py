"""Bounded historical selection after complete SQLite Graph integrity verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from re import fullmatch

from pajin.graph.models import graph_digest
from pajin.graph.projection import GraphSnapshot, GraphSnapshotReason
from pajin.graph.sqlite_store import (
    SQLiteGraphStoreError,
    _absolute_path,
    _events_from_connection,
    _file_identity,
    _readonly_connection,
    _require_exact_node_index,
    _validate_schema,
    _verified_projections,
    _verified_snapshots,
)


@dataclass(frozen=True)
class SnapshotHistoryEntry:
    ordinal: int
    snapshot_id: str
    snapshot_digest: str
    revision: int
    created_at: datetime
    reason: GraphSnapshotReason
    node_count: int
    edge_count: int


@dataclass(frozen=True)
class SnapshotHistorySelection:
    entries: tuple[SnapshotHistoryEntry, ...]
    total: int
    state_digest: str
    current_snapshot_id: str | None
    snapshot: GraphSnapshot | None


def read_snapshot_history(
    path: Path,
    *,
    campaign_id: str,
    snapshot_id: str | None = None,
    offset: int = 0,
    limit: int = 25,
    expected_state: str | None = None,
) -> SnapshotHistorySelection:
    if fullmatch(r"[a-z0-9][a-z0-9-]{2,79}", campaign_id) is None:
        raise ValueError("invalid Campaign identity")
    if snapshot_id is not None and fullmatch(r"graph-snapshot_[a-f0-9]{64}", snapshot_id) is None:
        raise ValueError("invalid Snapshot identity")
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("invalid history page bounds")
    database = _absolute_path(path)
    identity = _file_identity(database)
    entries = []
    last: GraphSnapshot | None = None
    with _readonly_connection(database) as connection:
        _validate_schema(connection, campaign_id=campaign_id)
        events = _events_from_connection(connection, campaign_id=campaign_id)
        _require_exact_node_index(connection, campaign_id=campaign_id, events=events)
        projections = _verified_projections(connection, campaign_id=campaign_id, events=events)
        total = connection.execute("SELECT count(*) FROM graph_snapshots").fetchone()[0]
        if offset >= max(1, total):
            raise ValueError("history cursor is outside the verified chain")

        def observe(ordinal: int, snapshot: GraphSnapshot) -> None:
            nonlocal last
            last = snapshot
            if total - offset - limit < ordinal <= total - offset:
                entries.append(
                    SnapshotHistoryEntry(
                        ordinal,
                        snapshot.snapshot_id,
                        snapshot.snapshot_digest,
                        snapshot.revision,
                        snapshot.created_at,
                        snapshot.reason,
                        len(snapshot.projection.nodes),
                        len(snapshot.projection.edges),
                    )
                )

        selected, head = _verified_snapshots(
            connection,
            campaign_id=campaign_id,
            projections=projections,
            retain_snapshot_id=snapshot_id or "",
            observe=observe,
        )
        current = projections[max(projections)]
        event_head = events[-1].event_digest if events else None
        if current.revision != len(events) or current.event_log_head_digest != event_head:
            raise SQLiteGraphStoreError(
                "Graph projection recovery is required before history reads"
            )
        state = graph_digest(
            "pajin.graph.history-state/v1",
            {
                "campaign": campaign_id,
                "snapshotHead": head,
                "eventHead": event_head,
                "projection": current.projection_digest,
            },
            max_bytes=4096,
        )
        if expected_state is not None and expected_state != state:
            raise SQLiteGraphStoreError("Graph history changed; reload its current catalog")
        current_id = last.snapshot_id if last is not None and last.projection == current else None
        result = SnapshotHistorySelection(
            tuple(reversed(entries)),
            total,
            state,
            current_id,
            selected.get(snapshot_id or ""),
        )
    if _file_identity(database) != identity:
        raise SQLiteGraphStoreError("Graph store changed during historical verification")
    return result
