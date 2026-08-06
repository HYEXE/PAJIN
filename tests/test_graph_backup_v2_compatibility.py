from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pajin.graph.backup_retention as backup_retention_module
import pajin.graph.sqlite_store as sqlite_store_module
from pajin.graph import SQLiteGraphStore
from tests import test_graph_action_permit as permit_tests


def test_historical_graph_schema_digests_are_frozen_literals() -> None:
    assert sqlite_store_module._LEGACY_SCHEMA_DIGEST == (
        "0e6b63061032ee8361da0f8dd2ad8e414bd74773b190d67c4c0d9d7c820efd6d"
    )
    assert sqlite_store_module._ACTION_PERMIT_SCHEMA_DIGEST == (
        "9865a8770d10c7776e268481577b2095a2fc6a094c059d876f962487caf7909c"
    )
    assert sqlite_store_module._CLEANUP_SCHEMA_DIGEST == (
        "a88ae9384c2fceb5a76a37d6c6f5f54e1690663f1b0aea25559c95c84c61137a"
    )


def _copy_current_store_as_v3(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700)
    connection = sqlite3.connect(destination)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        for statement in sqlite_store_module._CLEANUP_SCHEMA_OBJECT_SQL.values():
            connection.execute(statement)
        connection.executemany(
            "INSERT INTO graph_store_metadata (key, value) VALUES (?, ?)",
            (
                ("schema_version", "3"),
                ("schema_digest", sqlite_store_module._CLEANUP_SCHEMA_DIGEST),
                ("campaign_id", permit_tests.CAMPAIGN),
            ),
        )
        connection.execute("ATTACH DATABASE ? AS current_store", (str(source),))
        for table in (
            "graph_store_writers",
            "graph_events",
            "graph_nodes",
            "graph_projections",
            "graph_snapshots",
            "graph_action_permit_writers",
            "graph_action_permits",
            "graph_action_cleanup_reservations",
            "graph_cleanup_permits",
        ):
            columns = tuple(
                row[1]
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            column_sql = ", ".join(columns)
            connection.execute(
                f"INSERT INTO {table} ({column_sql}) "
                f"SELECT {column_sql} FROM current_store.{table}"
            )
        connection.execute("PRAGMA user_version = 3")
        connection.execute(f"PRAGMA application_id = {sqlite_store_module._APPLICATION_ID}")
        connection.commit()
        connection.execute("DETACH DATABASE current_store")
    finally:
        connection.close()


def _seed_populated_v3_backup(tmp_path: Path):
    assert sqlite_store_module._CLEANUP_SCHEMA_DIGEST == (
        "a88ae9384c2fceb5a76a37d6c6f5f54e1690663f1b0aea25559c95c84c61137a"
    )
    current_path = tmp_path / "current-v4" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = permit_tests._seed(current_path)
    cleanup = permit_tests._cleanup_capability()
    envelope = permit_tests._reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = permit_tests._action_proposal(envelope, action, decision)
    reversible = permit_tests._reversible_authority(
        store,
        action,
        cleanup,
    ).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        permit_tests._cleanup_reservation_request(envelope, proposal, cleanup),
    )
    cleanup_decision, request = permit_tests._cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    cleanup_authorization = permit_tests._cleanup_authority(
        store,
        action,
        cleanup,
    ).authorize_for_dispatch(envelope, request, cleanup_decision)
    backup = tmp_path / "legacy-v3" / "graph-lab.sqlite3"
    _copy_current_store_as_v3(current_path, backup)
    database = backup.read_bytes()
    state = sqlite_store_module._verified_v3_graph_store_state(
        backup,
        campaign_id=permit_tests.CAMPAIGN,
    )
    manifest = sqlite_store_module._SQLiteGraphBackupManifestV2(
        campaignId=permit_tests.CAMPAIGN,
        createdAt=permit_tests.NOW + timedelta(seconds=11),
        databaseSha256=sqlite_store_module.sha256(database).hexdigest(),
        databaseBytes=len(database),
        eventCount=state.event_count,
        eventLogHeadDigest=state.event_log_head_digest,
        projectionRevision=state.projection_revision,
        projectionDigest=state.projection_digest,
        snapshotCount=state.snapshot_count,
        snapshotHeadDigest=state.snapshot_head_digest,
        actionPermitCount=state.action_permit_count,
        actionPermitHeadDigest=state.action_permit_head_digest,
        cleanupReservationCount=state.cleanup_reservation_count,
        cleanupReservationHeadDigest=state.cleanup_reservation_head_digest,
        cleanupPermitCount=state.cleanup_permit_count,
        cleanupPermitHeadDigest=state.cleanup_permit_head_digest,
    )
    sqlite_store_module.sqlite_graph_backup_manifest_path(backup).write_bytes(
        sqlite_store_module._backup_manifest_bytes(manifest)
    )
    return (
        backup,
        manifest,
        reversible.cleanup_reservation,
        cleanup_authorization.permit,
    )


def test_v1alpha2_cleanup_backup_is_verified_then_migrated_to_v4(
    tmp_path: Path,
) -> None:
    backup, manifest, reservation, cleanup_permit = _seed_populated_v3_backup(tmp_path)

    assert manifest.api_version == "pajin.dev/sqlite-graph-backup-manifest/v1alpha2"
    assert manifest.schema_version == 3
    assert manifest.cleanup_reservation_count == 1
    assert manifest.cleanup_reservation_head_digest == reservation.cleanup_reservation_digest
    assert manifest.cleanup_permit_count == 1
    assert manifest.cleanup_permit_head_digest == cleanup_permit.cleanup_permit_digest

    restored = SQLiteGraphStore.restore_backup(
        backup,
        destination=tmp_path / "restored-v1alpha2" / "canonical-graph.sqlite3",
        campaign_id=permit_tests.CAMPAIGN,
    )

    assert restored.permit_store.cleanup_reservations() == (reservation,)
    assert restored.permit_store.cleanup_permits() == (cleanup_permit,)
    assert restored.permit_store.action_approvals() == ()
    assert restored.permit_store.approval_consumptions() == ()
    with sqlite3.connect(restored.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)


def test_retained_v1alpha2_uses_frozen_domains_and_restores(tmp_path: Path) -> None:
    plaintext, low_level_manifest, reservation, cleanup_permit = (
        _seed_populated_v3_backup(tmp_path)
    )
    database = plaintext.read_bytes()
    encryption_key = bytes(reversed(range(32)))
    signing_seed = bytes(range(32))
    encryption_key_id = "legacy-v2-retained-encryption"
    nonce = bytes(range(12))
    nonce_base64url = backup_retention_module._base64url_encode(nonce)
    aad = backup_retention_module._retained_backup_aad(
        low_level_manifest,
        encryption_key_id=encryption_key_id,
        nonce_base64url=nonce_base64url,
    )
    assert backup_retention_module._ENCRYPTION_AAD_DOMAIN_V2 == (
        b"pajin.graph.sqlite-retained-backup-aad/v2\0"
    )
    assert aad.startswith(backup_retention_module._ENCRYPTION_AAD_DOMAIN_V2)
    ciphertext = backup_retention_module.AESGCM(encryption_key).encrypt(
        nonce,
        database,
        aad,
    )
    statement = backup_retention_module._SQLiteGraphRetainedBackupStatementV2(
        backupManifest=low_level_manifest,
        encryptionKeyId=encryption_key_id,
        nonceBase64url=nonce_base64url,
        ciphertextSha256=sqlite_store_module.sha256(ciphertext).hexdigest(),
        ciphertextBytes=len(ciphertext),
    )
    verification_key = backup_retention_module.SQLiteGraphBackupVerificationKey(
        keyId="legacy-v2-retained-signing",
        publicKeyBase64url=backup_retention_module.sqlite_graph_backup_public_key(
            signing_seed
        ),
    )
    signer = backup_retention_module.SQLiteGraphBackupSigner.from_private_key_bytes(
        key=verification_key,
        private_key=signing_seed,
    )
    statement_bytes = backup_retention_module._retained_backup_statement_bytes(statement)
    assert backup_retention_module._SIGNATURE_DOMAIN_V2 == (
        b"pajin.graph.sqlite-retained-backup-signature/v2\0"
    )
    manifest = backup_retention_module._SQLiteGraphRetainedBackupManifestV2(
        statement=statement,
        signingKeyId=verification_key.key_id,
        signatureBase64url=backup_retention_module._base64url_encode(
            signer.private_key.sign(
                backup_retention_module._SIGNATURE_DOMAIN_V2 + statement_bytes
            )
        ),
    )
    retained = tmp_path / "retained-v1alpha2" / "graph-lab.sqlite3.enc"
    retained.parent.mkdir(mode=0o700)
    retained.write_bytes(ciphertext)
    backup_retention_module.sqlite_graph_retained_backup_manifest_path(
        retained
    ).write_bytes(backup_retention_module._retained_backup_manifest_bytes(manifest))

    verified = backup_retention_module.verify_retained_sqlite_graph_backup(
        retained,
        trusted_signing_keys=(verification_key,),
    )
    restored = SQLiteGraphStore.restore_retained_backup(
        retained,
        destination=(
            tmp_path / "retained-v1alpha2-restored" / "canonical-graph.sqlite3"
        ),
        campaign_id=permit_tests.CAMPAIGN,
        encryption_key_id=encryption_key_id,
        encryption_key=encryption_key,
        trusted_signing_keys=(verification_key,),
    )

    assert verified.manifest.api_version.endswith("/v1alpha2")
    assert verified.manifest.statement.api_version.endswith("/v1alpha2")
    assert verified.manifest.statement.backup_manifest == low_level_manifest
    assert restored.permit_store.cleanup_reservations() == (reservation,)
    assert restored.permit_store.cleanup_permits() == (cleanup_permit,)
    assert restored.permit_store.action_approvals() == ()
    assert restored.permit_store.approval_consumptions() == ()
