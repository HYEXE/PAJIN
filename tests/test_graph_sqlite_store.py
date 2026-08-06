from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.graph import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphDecision,
    GraphDecisionGuard,
    GraphDecisionKind,
    GraphEventLog,
    GraphEventLogError,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionConflict,
    GraphProjectionCoordinator,
    GraphProjectionReconciler,
    GraphProjectionReconciliationStatus,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotError,
    GraphSnapshotReason,
    GraphStaleDecisionError,
    GraphSurface,
    InMemoryGraphEventLog,
    SQLiteGraphBackupSigner,
    SQLiteGraphBackupVerificationKey,
    SQLiteGraphStore,
    SQLiteGraphStoreError,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_snapshot_ref,
    sqlite_graph_backup_manifest_path,
    sqlite_graph_backup_public_key,
    sqlite_graph_retained_backup_manifest_path,
)
from pajin.graph.models import GraphContentOrigin

NOW = datetime(2026, 7, 26, 15, 0, tzinfo=UTC)
CAMPAIGN = "graph-lab"
PRODUCER_ID = "pajin.graph.sqlite-test-producer"
AUTHORITY_ID = "pajin.graph.admission-authority"
SNAPSHOT_CREATOR_ID = "pajin.graph.snapshot-authority"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64
BACKUP_SIGNING_KEY = bytes(range(32))
BACKUP_ENCRYPTION_KEY = bytes(reversed(range(32)))
BACKUP_SIGNING_KEY_ID = "graph-backup-signing-2026"
BACKUP_ENCRYPTION_KEY_ID = "graph-backup-encryption-2026"


def _lineage(tag: str) -> GraphProposalLineage:
    digests = {
        "first": DIGEST_A,
        "second": DIGEST_B,
        "third": DIGEST_C,
        "alternate": DIGEST_D,
    }
    digest = digests[tag]
    return GraphProposalLineage(
        campaignId=CAMPAIGN,
        runId=f"run:graph:sqlite:{tag}",
        agentId="agent:graph-specialist",
        taskId=f"task:graph:sqlite:{tag}",
        requestId=f"tool_graph_sqlite_{tag}",
        requestDigest=digest,
        capabilityGrantId=f"grant:graph:sqlite:{tag}",
        capabilityGrantDigest=DIGEST_E,
        capabilityId="capability:graph-observe",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_F,
        sourceRootDigest=DIGEST_D,
        evidence=[
            {
                "reference": f"evidence/graph-sqlite-{tag}.json",
                "sha256": digest,
            }
        ],
        producedAt=NOW + timedelta(seconds=2),
    )


def _surface_proposal(tag: str) -> SurfaceProposal:
    digests = {
        "first": DIGEST_A,
        "second": DIGEST_B,
        "third": DIGEST_C,
        "alternate": DIGEST_D,
    }
    return SurfaceProposal(
        proposalId=f"proposal:surface:sqlite:{tag}",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        lineage=_lineage(tag),
        surface=GraphSurface(
            campaignId=CAMPAIGN,
            targetId="target:hybrid",
            surfaceType="http-endpoint",
            locatorSchema="pajin.discovery.http-surface.v1",
            locatorDigest=digests[tag],
            origin=GraphContentOrigin.TRUSTED_CORE,
        ),
    )


def _authority(
    event_log: GraphEventLog,
    proposals: list[SurfaceProposal],
) -> GraphAdmissionAuthority:
    return GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id=AUTHORITY_ID,
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=PRODUCER_ID,
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_F,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry(
            proposal.lineage for proposal in proposals
        ),
        event_log=event_log,
        clock=lambda: NOW + timedelta(seconds=3),
    )


def _admit(
    store: SQLiteGraphStore,
    proposals: list[SurfaceProposal],
) -> tuple[GraphAdmissionEvent, ...]:
    authority = _authority(store.event_log, proposals)
    return tuple(authority.submit(proposal).event for proposal in proposals)


def _seeded_store(
    path: Path,
) -> tuple[SQLiteGraphStore, tuple[SurfaceProposal, ...]]:
    proposals = (_surface_proposal("first"), _surface_proposal("second"))
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    events = _admit(store, list(proposals))
    assert all(event.decision is GraphAdmissionDecision.ADMITTED for event in events)
    return store, proposals


def _run_hard_exit(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    project_root = Path(__file__).parents[1]
    environment = os.environ.copy()
    source_root = str(project_root / "src")
    inherited_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root
        if not inherited_pythonpath
        else f"{source_root}{os.pathsep}{inherited_pythonpath}"
    )
    return subprocess.run(
        [sys.executable, "-c", script, *arguments],
        cwd=project_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _backup_verification_key() -> SQLiteGraphBackupVerificationKey:
    return SQLiteGraphBackupVerificationKey(
        keyId=BACKUP_SIGNING_KEY_ID,
        publicKeyBase64url=sqlite_graph_backup_public_key(BACKUP_SIGNING_KEY),
    )


def _backup_signer() -> SQLiteGraphBackupSigner:
    return SQLiteGraphBackupSigner.from_private_key_bytes(
        key=_backup_verification_key(),
        private_key=BACKUP_SIGNING_KEY,
    )


def test_sqlite_store_reopens_event_projection_and_snapshot_state(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, proposals = _seeded_store(path)
    projection = GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh().projection
    snapshot = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    ).capture(GraphSnapshotReason.CHECKPOINT)

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)

    assert reopened.event_log.events() == store.event_log.events()
    assert reopened.projection_store.current() == projection
    assert reopened.snapshot_store.snapshots() == (snapshot,)
    assert reopened.snapshot_store.resolve(graph_snapshot_ref(snapshot)) == snapshot

    retry_authority = _authority(reopened.event_log, list(proposals))
    retry = retry_authority.submit(proposals[0])
    assert retry.idempotent is True
    assert retry.event == store.event_log.events()[0]
    assert len(reopened.event_log.events()) == 2


def test_event_commit_survives_projection_lag_and_reconciles_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(path)
    assert store.projection_store.current().revision == 0

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    result = GraphProjectionReconciler(
        event_log=reopened.event_log,
        projection_store=reopened.projection_store,
    ).reconcile()

    assert result.status is GraphProjectionReconciliationStatus.RECOVERED
    assert result.previous_revision == 0
    assert result.projection.revision == 2
    assert result.recovered_event_count == 2
    assert GraphProjectionReconciler(
        event_log=reopened.event_log,
        projection_store=reopened.projection_store,
    ).reconcile().status is GraphProjectionReconciliationStatus.IN_SYNC


def test_verified_backup_restore_round_trips_exact_graph_state(tmp_path: Path) -> None:
    source = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(source)
    projection = GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh().projection
    snapshot = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    ).capture(GraphSnapshotReason.RECOVERY)
    backup = tmp_path / "backups" / "graph-lab.sqlite3"

    manifest = store.create_backup(
        backup,
        created_at=NOW + timedelta(seconds=5),
    )

    assert backup.is_file()
    assert sqlite_graph_backup_manifest_path(backup).is_file()
    assert manifest.event_count == 2
    assert manifest.event_log_head_digest == store.event_log.events()[-1].event_digest
    assert manifest.projection_revision == projection.revision
    assert manifest.projection_digest == projection.projection_digest
    assert manifest.snapshot_count == 1
    assert manifest.snapshot_head_digest == snapshot.snapshot_digest
    assert manifest.action_permit_count == 0
    restored = SQLiteGraphStore.restore_backup(
        backup,
        destination=tmp_path / "restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
    )
    assert restored.event_log.events() == store.event_log.events()
    assert restored.projection_store.current() == projection
    assert restored.snapshot_store.snapshots() == (snapshot,)
    assert restored.permit_store.permits() == ()


def test_backup_and_restore_fail_closed_on_existing_or_tampered_material(
    tmp_path: Path,
) -> None:
    source = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(source)
    backup = tmp_path / "backups" / "graph-lab.sqlite3"
    store.create_backup(backup, created_at=NOW + timedelta(seconds=5))

    with pytest.raises(SQLiteGraphStoreError, match="already exists"):
        store.create_backup(backup, created_at=NOW + timedelta(seconds=6))

    destination = tmp_path / "restored" / "canonical-graph.sqlite3"
    SQLiteGraphStore.restore_backup(
        backup,
        destination=destination,
        campaign_id=CAMPAIGN,
    )
    with pytest.raises(SQLiteGraphStoreError, match="already exists"):
        SQLiteGraphStore.restore_backup(
            backup,
            destination=destination,
            campaign_id=CAMPAIGN,
        )

    manifest_path = sqlite_graph_backup_manifest_path(backup)
    manifest_document = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_document["eventCount"] = 3
    manifest_path.write_text(
        json.dumps(manifest_document, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(SQLiteGraphStoreError, match="manifest is invalid"):
        SQLiteGraphStore.restore_backup(
            backup,
            destination=tmp_path / "tampered-manifest" / "canonical-graph.sqlite3",
            campaign_id=CAMPAIGN,
        )

    second_backup = tmp_path / "backups" / "graph-lab-second.sqlite3"
    store.create_backup(
        second_backup,
        created_at=NOW + timedelta(seconds=7),
    )
    database = bytearray(second_backup.read_bytes())
    database[-1] ^= 1
    second_backup.write_bytes(database)
    with pytest.raises(SQLiteGraphStoreError, match="database digest differs"):
        SQLiteGraphStore.restore_backup(
            second_backup,
            destination=tmp_path / "tampered" / "canonical-graph.sqlite3",
            campaign_id=CAMPAIGN,
        )


def test_signed_encrypted_retained_backup_restores_from_detached_process(
    tmp_path: Path,
) -> None:
    source = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(source)
    projection = GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh().projection
    snapshot = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    ).capture(GraphSnapshotReason.RECOVERY)
    retained = tmp_path / "retention-source" / "graph-lab.sqlite3.enc"

    manifest = store.create_retained_backup(
        retained,
        encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
        encryption_key=BACKUP_ENCRYPTION_KEY,
        signer=_backup_signer(),
        created_at=NOW + timedelta(seconds=5),
    )

    assert manifest.api_version == (
        "pajin.dev/sqlite-graph-retained-backup-manifest/v1alpha3"
    )
    assert manifest.statement.api_version == (
        "pajin.dev/sqlite-graph-retained-backup/v1alpha3"
    )
    assert manifest.statement.backup_manifest.api_version == (
        "pajin.dev/sqlite-graph-backup-manifest/v1alpha3"
    )
    assert manifest.statement.backup_manifest.schema_version == 4
    ciphertext = retained.read_bytes()
    assert retained.is_file()
    assert sqlite_graph_retained_backup_manifest_path(retained).is_file()
    assert not ciphertext.startswith(b"SQLite format 3")
    assert b"SQLite format 3" not in ciphertext
    retained_manifest_bytes = sqlite_graph_retained_backup_manifest_path(retained).read_bytes()
    assert BACKUP_ENCRYPTION_KEY.hex().encode() not in retained_manifest_bytes
    assert BACKUP_SIGNING_KEY.hex().encode() not in retained_manifest_bytes
    assert {item.name for item in retained.parent.iterdir()} == {
        retained.name,
        sqlite_graph_retained_backup_manifest_path(retained).name,
    }
    assert manifest.statement.backup_manifest.projection_digest == (projection.projection_digest)
    assert manifest.statement.backup_manifest.snapshot_head_digest == (snapshot.snapshot_digest)

    detached = tmp_path / "detached-retention" / retained.name
    detached.parent.mkdir()
    detached.write_bytes(ciphertext)
    sqlite_graph_retained_backup_manifest_path(detached).write_bytes(
        sqlite_graph_retained_backup_manifest_path(retained).read_bytes()
    )
    restored_path = tmp_path / "independent-restore" / "canonical-graph.sqlite3"
    child = _run_hard_exit(
        """
import os
import sys
from pathlib import Path
from pajin.graph import SQLiteGraphBackupVerificationKey, SQLiteGraphStore

trusted_key = SQLiteGraphBackupVerificationKey(
    keyId=sys.argv[5],
    publicKeyBase64url=sys.argv[6],
)
restored = SQLiteGraphStore.restore_retained_backup(
    Path(sys.argv[1]),
    destination=Path(sys.argv[2]),
    campaign_id=sys.argv[3],
    encryption_key_id=sys.argv[4],
    encryption_key=bytes.fromhex(sys.argv[7]),
    trusted_signing_keys=(trusted_key,),
)
if (
    len(restored.event_log.events()) != 2
    or restored.projection_store.current().revision != 2
    or len(restored.snapshot_store.snapshots()) != 1
):
    os._exit(70)
os._exit(94)
""",
        str(detached),
        str(restored_path),
        CAMPAIGN,
        BACKUP_ENCRYPTION_KEY_ID,
        BACKUP_SIGNING_KEY_ID,
        _backup_verification_key().public_key_base64url,
        BACKUP_ENCRYPTION_KEY.hex(),
    )

    assert child.returncode == 94, child.stderr
    restored = SQLiteGraphStore(restored_path, campaign_id=CAMPAIGN)
    assert restored.event_log.events() == store.event_log.events()
    assert restored.projection_store.current() == projection
    assert restored.snapshot_store.snapshots() == (snapshot,)


def test_retained_backup_rejects_untrusted_or_wrong_keys_without_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(source)
    retained = tmp_path / "retention" / "graph-lab.sqlite3.enc"
    store.create_retained_backup(
        retained,
        encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
        encryption_key=BACKUP_ENCRYPTION_KEY,
        signer=_backup_signer(),
        created_at=NOW + timedelta(seconds=5),
    )

    with pytest.raises(SQLiteGraphStoreError, match="already exists"):
        store.create_retained_backup(
            retained,
            encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
            encryption_key=BACKUP_ENCRYPTION_KEY,
            signer=_backup_signer(),
            created_at=NOW + timedelta(seconds=6),
        )

    untrusted_destination = tmp_path / "untrusted-restore" / "canonical-graph.sqlite3"
    with pytest.raises(SQLiteGraphStoreError, match="signing key is not trusted"):
        SQLiteGraphStore.restore_retained_backup(
            retained,
            destination=untrusted_destination,
            campaign_id=CAMPAIGN,
            encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
            encryption_key=BACKUP_ENCRYPTION_KEY,
            trusted_signing_keys=(),
        )
    assert not untrusted_destination.exists()

    wrong_key_destination = tmp_path / "wrong-key-restore" / "canonical-graph.sqlite3"
    with pytest.raises(SQLiteGraphStoreError, match="authentication failed"):
        SQLiteGraphStore.restore_retained_backup(
            retained,
            destination=wrong_key_destination,
            campaign_id=CAMPAIGN,
            encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
            encryption_key=b"x" * 32,
            trusted_signing_keys=(_backup_verification_key(),),
        )
    assert not wrong_key_destination.exists()

    existing_destination = tmp_path / "existing" / "canonical-graph.sqlite3"
    existing_destination.parent.mkdir()
    existing_destination.write_bytes(b"do-not-replace")
    with pytest.raises(SQLiteGraphStoreError, match="already exists"):
        SQLiteGraphStore.restore_retained_backup(
            retained,
            destination=existing_destination,
            campaign_id=CAMPAIGN,
            encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
            encryption_key=BACKUP_ENCRYPTION_KEY,
            trusted_signing_keys=(_backup_verification_key(),),
        )
    assert existing_destination.read_bytes() == b"do-not-replace"


def test_retained_backup_rejects_signature_and_ciphertext_tampering(
    tmp_path: Path,
) -> None:
    source = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(source)
    signed = tmp_path / "retention" / "signed.sqlite3.enc"
    store.create_retained_backup(
        signed,
        encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
        encryption_key=BACKUP_ENCRYPTION_KEY,
        signer=_backup_signer(),
        created_at=NOW + timedelta(seconds=5),
    )
    signed_manifest_path = sqlite_graph_retained_backup_manifest_path(signed)
    signed_manifest = bytearray(signed_manifest_path.read_bytes())
    signature_offset = signed_manifest.index(b'"signatureBase64url":"') + len(
        b'"signatureBase64url":"'
    )
    signed_manifest[signature_offset] = (
        ord("A") if signed_manifest[signature_offset] != ord("A") else ord("B")
    )
    signed_manifest_path.write_bytes(signed_manifest)
    signature_destination = tmp_path / "signature-tamper" / "canonical-graph.sqlite3"
    with pytest.raises(SQLiteGraphStoreError, match="signature verification failed"):
        SQLiteGraphStore.restore_retained_backup(
            signed,
            destination=signature_destination,
            campaign_id=CAMPAIGN,
            encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
            encryption_key=BACKUP_ENCRYPTION_KEY,
            trusted_signing_keys=(_backup_verification_key(),),
        )
    assert not signature_destination.exists()

    tampered = tmp_path / "retention" / "tampered.sqlite3.enc"
    store.create_retained_backup(
        tampered,
        encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
        encryption_key=BACKUP_ENCRYPTION_KEY,
        signer=_backup_signer(),
        created_at=NOW + timedelta(seconds=6),
    )
    ciphertext = bytearray(tampered.read_bytes())
    ciphertext[-1] ^= 1
    tampered.write_bytes(ciphertext)
    ciphertext_destination = tmp_path / "ciphertext-tamper" / "canonical-graph.sqlite3"
    with pytest.raises(SQLiteGraphStoreError, match="ciphertext digest differs"):
        SQLiteGraphStore.restore_retained_backup(
            tampered,
            destination=ciphertext_destination,
            campaign_id=CAMPAIGN,
            encryption_key_id=BACKUP_ENCRYPTION_KEY_ID,
            encryption_key=BACKUP_ENCRYPTION_KEY,
            trusted_signing_keys=(_backup_verification_key(),),
        )
    assert not ciphertext_destination.exists()


def test_process_hard_exit_after_projection_commit_preserves_committed_revision(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(path)
    assert store.projection_store.current().revision == 0
    child = _run_hard_exit(
        """
import os
import sys
from pathlib import Path
from pajin.graph import GraphProjectionReconciler, SQLiteGraphStore

store = SQLiteGraphStore(Path(sys.argv[1]), campaign_id=sys.argv[2])
result = GraphProjectionReconciler(
    event_log=store.event_log,
    projection_store=store.projection_store,
).reconcile()
if result.projection.revision != 2:
    os._exit(70)
os._exit(91)
""",
        str(path),
        CAMPAIGN,
    )

    assert child.returncode == 91, child.stderr
    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    assert reopened.projection_store.current().revision == 2
    assert len(reopened.event_log.events()) == 2


def test_process_hard_exit_before_transaction_commit_rolls_back_partial_writer(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    child = _run_hard_exit(
        """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute("PRAGMA synchronous = FULL")
connection.execute("BEGIN IMMEDIATE")
connection.execute(
    "INSERT INTO graph_store_writers (writer_kind, writer_id, writer_digest) "
    "VALUES ('snapshot', 'pajin.graph.interrupted-writer', ?)",
    ("f" * 64,),
)
os._exit(92)
""",
        str(path),
    )

    assert child.returncode == 92, child.stderr
    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    reopened.snapshot_store.claim_writer(SNAPSHOT_CREATOR_ID, DIGEST_B)
    assert reopened.snapshot_store.head_digest() is None


def test_process_hard_exit_after_backup_publish_restores_verified_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(path)
    projection = GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh().projection
    backup = tmp_path / "backups" / "graph-lab.sqlite3"
    child = _run_hard_exit(
        """
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from pajin.graph import SQLiteGraphStore

store = SQLiteGraphStore(Path(sys.argv[1]), campaign_id=sys.argv[3])
store.create_backup(
    Path(sys.argv[2]),
    created_at=datetime(2026, 7, 26, 15, 0, 5, tzinfo=UTC),
)
os._exit(93)
""",
        str(path),
        str(backup),
        CAMPAIGN,
    )

    assert child.returncode == 93, child.stderr
    restored = SQLiteGraphStore.restore_backup(
        backup,
        destination=tmp_path / "restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
    )
    assert restored.event_log.events() == store.event_log.events()
    assert restored.projection_store.current() == projection


def test_cross_instance_event_append_and_projection_cas_have_one_winner(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    first_store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    second_store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    first_proposal = _surface_proposal("first")
    second_proposal = _surface_proposal("second")

    first_reference_log = InMemoryGraphEventLog()
    second_reference_log = InMemoryGraphEventLog()
    first_event = _authority(first_reference_log, [first_proposal]).submit(
        first_proposal
    ).event
    second_event = _authority(second_reference_log, [second_proposal]).submit(
        second_proposal
    ).event
    first_writer = first_store.event_log.claim_writer(AUTHORITY_ID, DIGEST_A)
    second_writer = second_store.event_log.claim_writer(AUTHORITY_ID, DIGEST_A)

    def append_first() -> GraphAdmissionEvent:
        return first_store.event_log.append(first_event, writer=first_writer)

    def append_second() -> GraphAdmissionEvent:
        return second_store.event_log.append(second_event, writer=second_writer)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            pool.submit(append_first),
            pool.submit(append_second),
        ]
    successes = [future.result() for future in outcomes if future.exception() is None]
    failures = [future.exception() for future in outcomes if future.exception() is not None]

    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], GraphEventLogError)
    events = first_store.event_log.events()
    assert events == tuple(successes)

    third_proposal = _surface_proposal("third")
    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    third = _authority(reopened.event_log, [third_proposal]).submit(third_proposal)
    assert third.event.sequence == 2
    all_events = reopened.event_log.events()

    left = SQLiteGraphStore(path, campaign_id=CAMPAIGN).projection_store
    right = SQLiteGraphStore(path, campaign_id=CAMPAIGN).projection_store

    def advance_left() -> int:
        return left.compare_and_advance(
            all_events,
            expected_revision=0,
            expected_head_digest=None,
        ).projection.revision

    def advance_right() -> int:
        return right.compare_and_advance(
            all_events,
            expected_revision=0,
            expected_head_digest=None,
        ).projection.revision

    with ThreadPoolExecutor(max_workers=2) as pool:
        advances = [pool.submit(advance_left), pool.submit(advance_right)]
    projection_successes = [
        future.result() for future in advances if future.exception() is None
    ]
    projection_failures = [
        future.exception() for future in advances if future.exception() is not None
    ]

    assert projection_successes == [2]
    assert len(projection_failures) == 1
    assert isinstance(projection_failures[0], GraphProjectionConflict)
    assert left.current().revision == 2


def test_store_pins_campaign_and_writer_identities(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    store.event_log.claim_writer(AUTHORITY_ID, DIGEST_A)
    store.snapshot_store.claim_writer(SNAPSHOT_CREATOR_ID, DIGEST_B)

    with pytest.raises(SQLiteGraphStoreError, match="Campaign identity differs"):
        SQLiteGraphStore(path, campaign_id="other-campaign")

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    with pytest.raises(SQLiteGraphStoreError, match="writer identity is already pinned"):
        reopened.event_log.claim_writer("pajin.graph.other-authority", DIGEST_A)
    with pytest.raises(SQLiteGraphStoreError, match="writer identity is already pinned"):
        reopened.snapshot_store.claim_writer("pajin.graph.other-snapshot-authority", DIGEST_B)


def test_projection_rejects_events_outside_its_durable_log(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(path)
    alternate = _surface_proposal("alternate")
    reference_log = InMemoryGraphEventLog()
    alternate_event = _authority(reference_log, [alternate]).submit(alternate).event

    with pytest.raises(GraphProjectionConflict, match="durable Event Log prefix"):
        store.projection_store.compare_and_advance(
            (alternate_event,),
            expected_revision=0,
            expected_head_digest=None,
        )

    assert store.projection_store.current().revision == 0


def test_snapshot_requires_durably_published_projection_and_exact_predecessor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(path)
    projection = GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh().projection
    authority = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    )
    first = authority.capture(GraphSnapshotReason.CHECKPOINT)

    raw = first.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "snapshotId": "",
            "snapshotDigest": "",
            "previousSnapshotDigest": None,
            "reason": GraphSnapshotReason.RECOVERY.value,
            "createdAt": NOW + timedelta(seconds=5),
        }
    )
    stale = GraphSnapshot.model_validate(raw)
    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    writer = reopened.snapshot_store.claim_writer(SNAPSHOT_CREATOR_ID, DIGEST_B)
    with pytest.raises(GraphSnapshotError, match="predecessor is stale"):
        reopened.snapshot_store.append(stale, writer=writer)

    assert store.projection_store.current() == projection
    assert store.snapshot_store.snapshots() == (first,)


def test_append_only_schema_and_schema_fingerprint_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _ = _seeded_store(path)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM graph_events")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE graph_projections SET projection_digest = ? WHERE revision = 0",
                (DIGEST_E,),
            )
        connection.execute("DROP TRIGGER graph_events_no_delete")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SQLiteGraphStoreError, match="schema fingerprint"):
        SQLiteGraphStore(path, campaign_id=CAMPAIGN)


@pytest.mark.skipif(os.name != "posix", reason="POSIX link semantics are not portable")
def test_store_rejects_symlink_and_hard_link_leaf(tmp_path: Path) -> None:
    state = tmp_path / "private-state"
    state.mkdir(mode=0o700)
    external = tmp_path / "external.sqlite3"
    external.write_bytes(b"do-not-touch")
    external.chmod(0o600)

    symlink = state / "symlink.sqlite3"
    symlink.symlink_to(external)
    with pytest.raises(SQLiteGraphStoreError, match="regular file"):
        SQLiteGraphStore(symlink, campaign_id=CAMPAIGN)

    hard_link = state / "hard-link.sqlite3"
    os.link(external, hard_link)
    with pytest.raises(SQLiteGraphStoreError, match="private regular file"):
        SQLiteGraphStore(hard_link, campaign_id=CAMPAIGN)

    assert external.read_bytes() == b"do-not-touch"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics are not portable")
def test_store_rejects_symlink_parent_component(tmp_path: Path) -> None:
    external_state = tmp_path / "external-state"
    external_state.mkdir(mode=0o700)
    linked_state = tmp_path / "linked-state"
    linked_state.symlink_to(external_state, target_is_directory=True)

    with pytest.raises(SQLiteGraphStoreError, match="non-directory component"):
        SQLiteGraphStore(
            linked_state / "nested" / "canonical-graph.sqlite3",
            campaign_id=CAMPAIGN,
        )

    assert list(external_state.iterdir()) == []


def test_stale_decision_guard_detects_durable_event_log_ahead(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    first = _surface_proposal("first")
    second = _surface_proposal("second")
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    authority = _authority(store.event_log, [first, second])
    authority.submit(first)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshot = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    decision = GraphDecision(
        campaignId=CAMPAIGN,
        decisionKind=GraphDecisionKind.REPLAN,
        snapshot=graph_snapshot_ref(snapshot),
        actorId="pajin.graph.test-planner",
        actorDigest=DIGEST_C,
        decisionPayloadDigest=DIGEST_D,
        createdAt=NOW + timedelta(seconds=5),
    )
    authority.submit(second)

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    with pytest.raises(GraphStaleDecisionError, match="recovery is required"):
        GraphDecisionGuard(
            event_log=reopened.event_log,
            projection_store=reopened.projection_store,
            snapshot_store=reopened.snapshot_store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).validate_for_dispatch(decision)
