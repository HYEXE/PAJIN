from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.graph import (
    GraphDecision,
    GraphDecisionAuditError,
    GraphDecisionKind,
    GraphProjectionCoordinator,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    SQLiteGraphDecisionAuditStore,
    SQLiteGraphStore,
    graph_snapshot_ref,
    load_verified_graph_decision_audit,
)

CAMPAIGN = "decision-audit"
NOW = datetime(2026, 8, 11, 1, 0, tzinfo=UTC)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


def _graph(path: Path) -> tuple[SQLiteGraphStore, GraphSnapshotAuthority, GraphSnapshot]:
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshots = GraphSnapshotAuthority(
        creator_id="pajin.graph.decision-audit-snapshot-authority",
        creator_digest=DIGEST_A,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW,
    )
    return store, snapshots, snapshots.capture(GraphSnapshotReason.CHECKPOINT)


def _decision(snapshot: GraphSnapshot, *, tag: str, seconds: int = 1) -> GraphDecision:
    return GraphDecision(
        campaignId=CAMPAIGN,
        decisionKind=GraphDecisionKind.PLAN,
        decisionPayloadDigest=(tag * 64)[:64],
        snapshot=graph_snapshot_ref(snapshot),
        actorId=f"sensitive-operator-{tag}",
        actorDigest=DIGEST_C,
        createdAt=snapshot.created_at + timedelta(seconds=seconds),
    )


def _audit(
    path: Path,
    *,
    graph_database: Path,
    clock: datetime = NOW + timedelta(seconds=2),
) -> SQLiteGraphDecisionAuditStore:
    return SQLiteGraphDecisionAuditStore(
        path,
        graph_database=graph_database,
        campaign_id=CAMPAIGN,
        recorder_id="pajin.graph.decision-audit-recorder",
        recorder_digest=DIGEST_B,
        clock=lambda: clock,
    )


def test_decision_audit_appends_reopens_and_keeps_exact_retry_idempotent(
    tmp_path: Path,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, snapshots, first = _graph(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    audit = _audit(audit_database, graph_database=graph_database)
    first_decision = _decision(first, tag="1")

    first_record = audit.append(first_decision)
    reopened = _audit(audit_database, graph_database=graph_database)
    assert reopened.records() == (first_record,)

    second = snapshots.capture(GraphSnapshotReason.HANDOFF)
    assert reopened.append(first_decision) == first_record
    second_decision = _decision(second, tag="2")
    second_record = reopened.append(
        second_decision,
        recorded_at=NOW + timedelta(seconds=4),
    )

    assert second_record.sequence == 2
    assert second_record.previous_record_digest == first_record.record_digest
    verified = load_verified_graph_decision_audit(
        audit_database,
        graph_database=graph_database,
        campaign_id=CAMPAIGN,
        snapshot_id=second.snapshot_id,
    )
    assert verified is not None
    assert verified.current_snapshot == second
    assert verified.records == (first_record, second_record)
    assert verified.head_digest == second_record.record_digest
    assert verified.recorder_digest == DIGEST_B


def test_decision_audit_multi_instance_exact_retry_has_one_winner(tmp_path: Path) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _graph(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    first = _audit(audit_database, graph_database=graph_database)
    second = _audit(audit_database, graph_database=graph_database)
    decision = _decision(snapshot, tag="3")

    with ThreadPoolExecutor(max_workers=8) as executor:
        records = tuple(
            executor.map(
                lambda index: (first, second)[index % 2].append(decision),
                range(8),
            )
        )

    assert len({record.record_id for record in records}) == 1
    assert first.records() == (records[0],)


def test_decision_audit_rejects_stale_foreign_and_path_aliases(tmp_path: Path) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, snapshots, first = _graph(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    audit = _audit(audit_database, graph_database=graph_database)
    snapshots.capture(GraphSnapshotReason.HANDOFF)

    with pytest.raises(GraphDecisionAuditError, match="append failed"):
        audit.append(_decision(first, tag="4"))
    foreign = _decision(first, tag="5").model_copy(update={"campaign_id": "foreign-campaign"})
    with pytest.raises(GraphDecisionAuditError, match="not canonical"):
        audit.append(foreign)
    with pytest.raises(GraphDecisionAuditError, match="distinct SQLite path families"):
        _audit(graph_database, graph_database=graph_database)
    with pytest.raises(GraphDecisionAuditError, match="distinct SQLite path families"):
        _audit(Path(f"{graph_database}-wal"), graph_database=graph_database)


def test_decision_audit_fails_closed_after_schema_chain_or_record_tamper(
    tmp_path: Path,
) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _graph(graph_database)

    schema_database = tmp_path / "schema-audit" / "decisions.sqlite3"
    schema_audit = _audit(schema_database, graph_database=graph_database)
    schema_audit.append(_decision(snapshot, tag="6"))
    with sqlite3.connect(schema_database) as connection:
        connection.execute("DROP TRIGGER graph_decision_audit_records_no_update")
    with pytest.raises(GraphDecisionAuditError, match="schema fingerprint"):
        schema_audit.records()

    chain_database = tmp_path / "chain-audit" / "decisions.sqlite3"
    chain_audit = _audit(chain_database, graph_database=graph_database)
    chain_audit.append(_decision(snapshot, tag="7"))
    chain_audit.append(
        _decision(snapshot, tag="8", seconds=2),
        recorded_at=NOW + timedelta(seconds=4),
    )
    with sqlite3.connect(chain_database) as connection:
        connection.execute("DROP TRIGGER graph_decision_audit_records_no_delete")
        connection.execute("DELETE FROM graph_decision_audit_records WHERE sequence = 1")
        connection.execute(
            """
            CREATE TRIGGER graph_decision_audit_records_no_delete
            BEFORE DELETE ON graph_decision_audit_records
            BEGIN
                SELECT RAISE(ABORT, 'graph_decision_audit_records is append-only');
            END
            """
        )
    with pytest.raises(GraphDecisionAuditError, match="sequence is not contiguous"):
        chain_audit.records()

    record_database = tmp_path / "record-audit" / "decisions.sqlite3"
    record_audit = _audit(record_database, graph_database=graph_database)
    record_audit.append(_decision(snapshot, tag="9"))
    with sqlite3.connect(record_database) as connection:
        connection.execute("DROP TRIGGER graph_decision_audit_records_no_update")
        connection.execute(
            "UPDATE graph_decision_audit_records SET actor_digest = ? WHERE sequence = 1",
            (DIGEST_D,),
        )
        connection.execute(
            """
            CREATE TRIGGER graph_decision_audit_records_no_update
            BEFORE UPDATE ON graph_decision_audit_records
            BEGIN
                SELECT RAISE(ABORT, 'graph_decision_audit_records is append-only');
            END
            """
        )
    with pytest.raises(GraphDecisionAuditError, match="row differs"):
        record_audit.records()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode semantics are required")
def test_verified_decision_audit_read_accepts_read_only_files(tmp_path: Path) -> None:
    graph_database = tmp_path / "graph" / "canonical.sqlite3"
    _store, _snapshots, snapshot = _graph(graph_database)
    audit_database = tmp_path / "audit" / "decisions.sqlite3"
    audit = _audit(audit_database, graph_database=graph_database)
    audit.append(_decision(snapshot, tag="a"))
    graph_mode = stat_mode = 0o600
    try:
        graph_mode = graph_database.stat().st_mode & 0o777
        stat_mode = audit_database.stat().st_mode & 0o777
        graph_database.chmod(0o400)
        audit_database.chmod(0o400)
        verified = load_verified_graph_decision_audit(
            audit_database,
            graph_database=graph_database,
            campaign_id=CAMPAIGN,
            snapshot_id=snapshot.snapshot_id,
        )
        assert verified is not None
        assert len(verified.records) == 1
    finally:
        graph_database.chmod(graph_mode)
        audit_database.chmod(stat_mode)
