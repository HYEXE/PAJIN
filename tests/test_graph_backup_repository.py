from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.graph import (
    SQLiteGraphBackupInventoryManifest,
    SQLiteGraphBackupInventorySigner,
    SQLiteGraphBackupInventoryStatement,
    SQLiteGraphBackupObjectLockMode,
    SQLiteGraphBackupRepositoryError,
    SQLiteGraphBackupRetentionObjectKind,
    SQLiteGraphBackupRetentionObjectReceipt,
    SQLiteGraphBackupRetentionPutRequest,
    SQLiteGraphBackupSigner,
    SQLiteGraphBackupVerificationKey,
    SQLiteGraphStore,
    append_sqlite_graph_backup_inventory,
    publish_retained_sqlite_graph_backup,
    restore_published_sqlite_graph_backup,
    sqlite_graph_backup_inventory_anchor,
    sqlite_graph_backup_public_key,
    verify_sqlite_graph_backup_inventory_chain,
)

NOW = datetime(2026, 7, 28, 3, 0, tzinfo=UTC)
CAMPAIGN = "graph-retention-lab"
BACKUP_PRIVATE_KEY = bytes(range(32))
INVENTORY_PRIVATE_KEY = bytes(reversed(range(32)))
ENCRYPTION_KEY = sha256(b"graph-retention-encryption-key").digest()
BACKUP_KEY_ID = "graph-backup-signing-2026"
INVENTORY_KEY_ID = "graph-backup-inventory-2026"
ENCRYPTION_KEY_ID = "graph-backup-encryption-2026"


def _verification_key(
    key_id: str,
    private_key: bytes,
) -> SQLiteGraphBackupVerificationKey:
    return SQLiteGraphBackupVerificationKey(
        keyId=key_id,
        publicKeyBase64url=sqlite_graph_backup_public_key(private_key),
    )


def _backup_key() -> SQLiteGraphBackupVerificationKey:
    return _verification_key(BACKUP_KEY_ID, BACKUP_PRIVATE_KEY)


def _inventory_key() -> SQLiteGraphBackupVerificationKey:
    return _verification_key(INVENTORY_KEY_ID, INVENTORY_PRIVATE_KEY)


def _backup_signer() -> SQLiteGraphBackupSigner:
    return SQLiteGraphBackupSigner.from_private_key_bytes(
        key=_backup_key(),
        private_key=BACKUP_PRIVATE_KEY,
    )


def _inventory_signer() -> SQLiteGraphBackupInventorySigner:
    return SQLiteGraphBackupInventorySigner.from_private_key_bytes(
        key=_inventory_key(),
        private_key=INVENTORY_PRIVATE_KEY,
    )


@dataclass
class _LockedMemoryBackend:
    repository_id: str = "retention-repository-test"
    fail_kind: SQLiteGraphBackupRetentionObjectKind | None = None
    shorten_retention: bool = False
    objects: dict[
        str,
        tuple[bytes, SQLiteGraphBackupRetentionObjectReceipt],
    ] = field(default_factory=dict)
    put_calls: int = 0

    def put_if_absent(
        self,
        request: SQLiteGraphBackupRetentionPutRequest,
        content: bytes,
    ) -> SQLiteGraphBackupRetentionObjectReceipt:
        self.put_calls += 1
        if self.fail_kind is request.object_kind:
            raise OSError("injected immutable backend failure")
        if (
            len(content) != request.content_bytes
            or sha256(content).hexdigest() != request.content_sha256
        ):
            raise ValueError("backend received content outside its request")
        existing = self.objects.get(request.object_key)
        if existing is not None:
            if existing[0] != content:
                raise ValueError("immutable backend object replacement was attempted")
            return existing[1]
        retained_until = request.retention_until
        if self.shorten_retention:
            retained_until = request.requested_at + timedelta(days=1)
        stored_at = request.requested_at + timedelta(seconds=1)
        receipt = SQLiteGraphBackupRetentionObjectReceipt(
            repositoryId=self.repository_id,
            campaignId=request.campaign_id,
            retainedBackupId=request.retained_backup_id,
            objectKind=request.object_kind,
            objectKey=request.object_key,
            contentSha256=request.content_sha256,
            contentBytes=request.content_bytes,
            objectVersion=f"version-{request.content_sha256[:16]}",
            objectLockMode=request.object_lock_mode,
            retentionUntil=retained_until,
            storedAt=stored_at,
            backendEvidenceSha256=sha256(
                (
                    f"{self.repository_id}\0{request.object_key}\0"
                    f"{request.content_sha256}\0{retained_until.isoformat()}"
                ).encode()
            ).hexdigest(),
        )
        self.objects[request.object_key] = (content, receipt)
        return receipt

    def read_exact(
        self,
        receipt: SQLiteGraphBackupRetentionObjectReceipt,
    ) -> bytes:
        stored = self.objects.get(receipt.object_key)
        if stored is None or stored[1].object_version != receipt.object_version:
            raise OSError("immutable backend object version is absent")
        return stored[0]

    def delete(self, object_key: str, *, at: datetime) -> None:
        stored = self.objects[object_key]
        if at < stored[1].retention_until:
            raise PermissionError("object lock is still active")
        del self.objects[object_key]


def _retained_backup(
    tmp_path: Path,
    *,
    name: str,
    created_at: datetime,
) -> Path:
    store = SQLiteGraphStore(
        tmp_path / "source" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
    )
    destination = tmp_path / "retained" / f"{name}.sqlite3.enc"
    store.create_retained_backup(
        destination,
        encryption_key_id=ENCRYPTION_KEY_ID,
        encryption_key=ENCRYPTION_KEY,
        signer=_backup_signer(),
        created_at=created_at,
    )
    return destination


def _publish(
    retained: Path,
    backend: _LockedMemoryBackend,
    *,
    requested_at: datetime,
):
    return publish_retained_sqlite_graph_backup(
        retained,
        backend=backend,
        retention_until=requested_at + timedelta(days=30),
        object_lock_mode=SQLiteGraphBackupObjectLockMode.COMPLIANCE,
        trusted_signing_keys=(_backup_key(),),
        requested_at=requested_at,
    )


def test_immutable_publication_inventory_and_pinned_backend_restore(
    tmp_path: Path,
) -> None:
    backend = _LockedMemoryBackend()
    first_retained = _retained_backup(
        tmp_path,
        name="first",
        created_at=NOW,
    )
    first_publication = _publish(first_retained, backend, requested_at=NOW)
    repeated = _publish(first_retained, backend, requested_at=NOW)

    assert repeated == first_publication
    assert backend.put_calls == 4
    assert len(backend.objects) == 2
    assert all(
        receipt.object_lock_mode is SQLiteGraphBackupObjectLockMode.COMPLIANCE
        for _, receipt in backend.objects.values()
    )
    with pytest.raises(PermissionError, match="object lock"):
        backend.delete(
            first_publication.ciphertext_receipt.object_key,
            at=NOW + timedelta(days=1),
        )

    first_inventory = append_sqlite_graph_backup_inventory(
        (),
        first_publication,
        signer=_inventory_signer(),
        trusted_signing_keys=(_inventory_key(),),
        issued_at=NOW + timedelta(minutes=1),
    )
    second_retained = _retained_backup(
        tmp_path,
        name="second",
        created_at=NOW + timedelta(hours=1),
    )
    second_publication = _publish(
        second_retained,
        backend,
        requested_at=NOW + timedelta(hours=1),
    )
    second_inventory = append_sqlite_graph_backup_inventory(
        (first_inventory,),
        second_publication,
        signer=_inventory_signer(),
        trusted_signing_keys=(_inventory_key(),),
        issued_at=NOW + timedelta(hours=1, minutes=1),
    )
    chain = (first_inventory, second_inventory)
    verified = verify_sqlite_graph_backup_inventory_chain(
        chain,
        trusted_signing_keys=(_inventory_key(),),
    )

    assert verified.publications == (first_publication, second_publication)
    assert verified.anchor == sqlite_graph_backup_inventory_anchor(second_inventory)
    unanchored_destination = tmp_path / "unanchored" / "canonical-graph.sqlite3"
    with pytest.raises(SQLiteGraphBackupRepositoryError, match="requires an external"):
        restore_published_sqlite_graph_backup(
            chain,
            required_anchor=None,  # type: ignore[arg-type]
            retained_backup_id=first_publication.retained_backup_id,
            backend=backend,
            destination=unanchored_destination,
            campaign_id=CAMPAIGN,
            encryption_key_id=ENCRYPTION_KEY_ID,
            encryption_key=ENCRYPTION_KEY,
            trusted_signing_keys=(_backup_key(),),
            trusted_inventory_keys=(_inventory_key(),),
        )
    assert not unanchored_destination.exists()
    restored = restore_published_sqlite_graph_backup(
        chain,
        required_anchor=verified.anchor,
        retained_backup_id=first_publication.retained_backup_id,
        backend=backend,
        destination=tmp_path / "restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
        encryption_key_id=ENCRYPTION_KEY_ID,
        encryption_key=ENCRYPTION_KEY,
        trusted_signing_keys=(_backup_key(),),
        trusted_inventory_keys=(_inventory_key(),),
    )
    assert restored.event_log.events() == ()
    assert restored.projection_store.current().revision == 0


def test_external_anchor_rejects_inventory_rollback_fork_and_reordering(
    tmp_path: Path,
) -> None:
    backend = _LockedMemoryBackend()
    first = _publish(
        _retained_backup(tmp_path, name="first", created_at=NOW),
        backend,
        requested_at=NOW,
    )
    second = _publish(
        _retained_backup(
            tmp_path,
            name="second",
            created_at=NOW + timedelta(hours=1),
        ),
        backend,
        requested_at=NOW + timedelta(hours=1),
    )
    third = _publish(
        _retained_backup(
            tmp_path,
            name="third",
            created_at=NOW + timedelta(hours=2),
        ),
        backend,
        requested_at=NOW + timedelta(hours=2),
    )
    inventory_one = append_sqlite_graph_backup_inventory(
        (),
        first,
        signer=_inventory_signer(),
        trusted_signing_keys=(_inventory_key(),),
        issued_at=NOW + timedelta(minutes=1),
    )
    inventory_two = append_sqlite_graph_backup_inventory(
        (inventory_one,),
        second,
        signer=_inventory_signer(),
        trusted_signing_keys=(_inventory_key(),),
        issued_at=NOW + timedelta(hours=1, minutes=1),
    )
    anchor_two = sqlite_graph_backup_inventory_anchor(inventory_two)

    with pytest.raises(SQLiteGraphBackupRepositoryError, match="older than"):
        verify_sqlite_graph_backup_inventory_chain(
            (inventory_one,),
            trusted_signing_keys=(_inventory_key(),),
            required_anchor=anchor_two,
        )

    fork_two = append_sqlite_graph_backup_inventory(
        (inventory_one,),
        third,
        signer=_inventory_signer(),
        trusted_signing_keys=(_inventory_key(),),
        issued_at=NOW + timedelta(hours=2, minutes=1),
    )
    with pytest.raises(SQLiteGraphBackupRepositoryError, match="fork differs"):
        verify_sqlite_graph_backup_inventory_chain(
            (inventory_one, fork_two),
            trusted_signing_keys=(_inventory_key(),),
            required_anchor=anchor_two,
        )

    reordered_statement = SQLiteGraphBackupInventoryStatement(
        campaignId=CAMPAIGN,
        sequence=2,
        previousInventorySha256=inventory_two.statement.previous_inventory_sha256,
        publications=(second, first),
        issuedAt=NOW + timedelta(hours=1, minutes=2),
    )
    reordered = _inventory_signer().sign(reordered_statement)
    with pytest.raises(SQLiteGraphBackupRepositoryError, match="append-only extension"):
        verify_sqlite_graph_backup_inventory_chain(
            (inventory_one, reordered),
            trusted_signing_keys=(_inventory_key(),),
        )


def test_backend_receipt_and_partial_publication_fail_closed(
    tmp_path: Path,
) -> None:
    retained = _retained_backup(tmp_path, name="first", created_at=NOW)
    short_backend = _LockedMemoryBackend(shorten_retention=True)
    with pytest.raises(SQLiteGraphBackupRepositoryError, match="receipt differs"):
        _publish(retained, short_backend, requested_at=NOW)

    partial_backend = _LockedMemoryBackend(fail_kind=SQLiteGraphBackupRetentionObjectKind.MANIFEST)
    with pytest.raises(SQLiteGraphBackupRepositoryError, match="publication failed"):
        _publish(retained, partial_backend, requested_at=NOW)
    assert len(partial_backend.objects) == 1
    assert next(iter(partial_backend.objects.values()))[1].object_kind is (
        SQLiteGraphBackupRetentionObjectKind.CIPHERTEXT
    )


def test_repository_read_tampering_never_creates_restore_destination(
    tmp_path: Path,
) -> None:
    backend = _LockedMemoryBackend()
    retained = _retained_backup(tmp_path, name="first", created_at=NOW)
    publication = _publish(retained, backend, requested_at=NOW)
    inventory = append_sqlite_graph_backup_inventory(
        (),
        publication,
        signer=_inventory_signer(),
        trusted_signing_keys=(_inventory_key(),),
        issued_at=NOW + timedelta(minutes=1),
    )
    anchor = sqlite_graph_backup_inventory_anchor(inventory)
    object_key = publication.ciphertext_receipt.object_key
    original, receipt = backend.objects[object_key]
    tampered = bytearray(original)
    tampered[-1] ^= 1
    backend.objects[object_key] = (bytes(tampered), receipt)
    destination = tmp_path / "tampered-restore" / "canonical-graph.sqlite3"

    with pytest.raises(SQLiteGraphBackupRepositoryError, match="differs from its receipt"):
        restore_published_sqlite_graph_backup(
            (inventory,),
            required_anchor=anchor,
            retained_backup_id=publication.retained_backup_id,
            backend=backend,
            destination=destination,
            campaign_id=CAMPAIGN,
            encryption_key_id=ENCRYPTION_KEY_ID,
            encryption_key=ENCRYPTION_KEY,
            trusted_signing_keys=(_backup_key(),),
            trusted_inventory_keys=(_inventory_key(),),
        )
    assert not destination.exists()


def test_inventory_signature_tampering_is_rejected(tmp_path: Path) -> None:
    backend = _LockedMemoryBackend()
    publication = _publish(
        _retained_backup(tmp_path, name="first", created_at=NOW),
        backend,
        requested_at=NOW,
    )
    inventory = append_sqlite_graph_backup_inventory(
        (),
        publication,
        signer=_inventory_signer(),
        trusted_signing_keys=(_inventory_key(),),
        issued_at=NOW + timedelta(minutes=1),
    )
    raw = inventory.model_dump(mode="json", by_alias=True)
    signature = raw["signatureBase64url"]
    raw["signatureBase64url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = SQLiteGraphBackupInventoryManifest.model_validate(raw)

    with pytest.raises(SQLiteGraphBackupRepositoryError, match="signature verification failed"):
        verify_sqlite_graph_backup_inventory_chain(
            (tampered,),
            trusted_signing_keys=(_inventory_key(),),
        )
