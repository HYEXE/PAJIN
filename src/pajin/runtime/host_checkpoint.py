"""Encrypted, independently pinned checkpoints for a declared local recovery set."""

from __future__ import annotations

import base64
import os
import sqlite3
import stat
import tempfile
import time
from collections.abc import Iterable
from contextlib import ExitStack
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pajin.control_plane.security import CheckpointSigner
from pajin.graph.backup_retention import (
    SQLiteGraphBackupSigner,
    SQLiteGraphBackupVerificationKey,
    create_retained_sqlite_graph_backup,
    restore_retained_sqlite_graph_backup,
    sqlite_graph_retained_backup_manifest_path,
)
from pajin.graph.sqlite_store import (
    SQLiteGraphStore,
    _fsync_graph_directory,
    _prepare_private_parent,
    _publish_exclusive,
    _require_absent_leaf,
    _write_private_temporary,
)
from pajin.runtime.host_checkpoint_models import (
    MAX_CHECKPOINT_BYTES,
    MAX_CHECKPOINT_FILES,
    MAX_MANIFEST_BYTES,
    HostCheckpointError,
    HostCheckpointManifest,
    HostCheckpointObject,
    HostCheckpointPlan,
    HostCheckpointStatement,
    canonical,
)
from pajin.runtime.host_checkpoint_stores import readonly_database, verify_recovery_stores
from pajin.runtime.host_gate import HostActivityLease
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

_MAGIC = b"PAJIN-HOST-CHECKPOINT-V1\n"
_SIGNATURE_DOMAIN = b"pajin.host-checkpoint.signature/v1\0"
_AAD_DOMAIN = b"pajin.host-checkpoint.encryption/v1\0"


def _read(path: Path, limit: int = MAX_CHECKPOINT_BYTES) -> bytes:
    return read_bounded_regular_bytes(
        path, max_bytes=limit, label="host checkpoint member", require_single_link=True,
    )


def _safe_directory(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise HostCheckpointError("checkpoint directories must be absolute and unambiguous")
    for parent in (path, *path.parents):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise HostCheckpointError("checkpoint directories must not contain links")
    return path


def _canonical_plan(plan: HostCheckpointPlan, expected_sha256: str) -> HostCheckpointPlan:
    owned = HostCheckpointPlan.model_validate_json(canonical(plan))
    if owned.digest != expected_sha256:
        raise HostCheckpointError("recovery plan differs from its external pin")
    return owned


def _require_partition(state: Path, plan: HostCheckpointPlan) -> None:
    _safe_directory(state)
    if not state.is_dir():
        raise HostCheckpointError("required host state directory is missing")
    required = {member.path for member in plan.members}
    sidecars = {
        member.path + suffix for member in plan.members if member.kind != "artifact"
        for suffix in ("-wal", "-shm")
    }
    present: set[str] = set()
    size = 0
    for directory, directories, filenames in os.walk(state, followlinks=False):
        for name in directories:
            if (Path(directory) / name).is_symlink():
                raise HostCheckpointError("state directory contains a symbolic link")
        for name in filenames:
            path = Path(directory) / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise HostCheckpointError("state contains a linked or nonregular member")
            relative = path.relative_to(state).as_posix()
            if relative not in required | sidecars:
                raise HostCheckpointError("state contains an undeclared member or hot journal")
            present.add(relative)
            size += metadata.st_size
            if size > MAX_CHECKPOINT_BYTES or len(present) > MAX_CHECKPOINT_FILES * 3:
                raise HostCheckpointError("host state exceeds the recovery set bounds")
    if not required <= present:
        raise HostCheckpointError("state is missing a required member")


def _write_new(path: Path, content: bytes) -> None:
    _prepare_private_parent(path.parent)
    temporary = _write_private_temporary(path, content)
    try:
        _publish_exclusive(temporary, path, label="host checkpoint object")
    finally:
        temporary.unlink(missing_ok=True)


def _copy_database(source: sqlite3.Connection, destination: Path) -> None:
    _write_new(destination, b"")
    deadline = time.monotonic() + 30

    def progress(status: int, remaining: int, total: int) -> None:
        if time.monotonic() > deadline or destination.stat().st_size > MAX_CHECKPOINT_BYTES:
            raise HostCheckpointError("SQLite checkpoint exceeded its time or size bound")

    target = sqlite3.connect(f"{destination.as_uri()}?mode=rw", uri=True)
    try:
        source.backup(target, pages=256, progress=progress, sleep=0.01)
        target.execute("PRAGMA journal_mode = DELETE")
    finally:
        target.close()
    with destination.open("rb") as handle:
        os.fsync(handle.fileno())


def _object_names(plan: HostCheckpointPlan) -> list[str]:
    names: list[str] = []
    for index, member in enumerate(plan.members):
        name = f"members/{index:04d}"
        names.append(name)
        if member.kind == "graph-sqlite":
            names.append(name + ".manifest.json")
    return sorted(names)


def _collect(
    lease: HostActivityLease, plan: HostCheckpointPlan, workspace: Path, *,
    encryption_key_id: str, encryption_key: bytes, signer: SQLiteGraphBackupSigner,
    checkpoint_signer: CheckpointSigner, created_at: datetime,
) -> tuple[tuple[HostCheckpointObject, ...], bytes]:
    state = lease.root / "state"
    _require_partition(state, plan)
    objects: dict[str, bytes] = {}
    with ExitStack() as stack:
        databases: dict[str, tuple[sqlite3.Connection, int]] = {}
        identities: dict[str, tuple[int, int]] = {}
        for member in plan.members:
            path = state / member.path
            info = path.stat()
            identities[member.path] = (info.st_dev, info.st_ino)
            if member.kind != "artifact":
                connection = stack.enter_context(readonly_database(path))
                databases[member.path] = (
                    connection, int(connection.execute("PRAGMA data_version").fetchone()[0]),
                )
        # Validate the copied CP/journal, not a migrated or repaired source.
        snapshot_state = workspace / "state"
        for index, member in enumerate(plan.members):
            lease.require_active(exclusive=True)
            path = state / member.path
            name = f"members/{index:04d}"
            destination = snapshot_state / member.path
            if member.kind == "graph-sqlite":
                retained = workspace / name
                assert member.campaign_id is not None
                create_retained_sqlite_graph_backup(
                    SQLiteGraphStore(path, campaign_id=member.campaign_id, initialize=False),
                    retained, encryption_key_id=encryption_key_id, encryption_key=encryption_key,
                    signer=signer, created_at=created_at,
                )
                objects[name] = _read(retained)
                objects[name + ".manifest.json"] = _read(
                    sqlite_graph_retained_backup_manifest_path(retained), MAX_MANIFEST_BYTES,
                )
                restore_retained_sqlite_graph_backup(
                    retained, destination=destination, campaign_id=member.campaign_id,
                    encryption_key_id=encryption_key_id, encryption_key=encryption_key,
                    trusted_signing_keys=(signer.key,),
                )
            elif member.kind == "artifact":
                content = _read(path)
                if sha256(content).hexdigest() != member.artifact_sha256 or content.startswith(
                    b"SQLite format 3\0",
                ):
                    raise HostCheckpointError("artifact differs from its pin or hides a database")
                objects[name] = content
                _write_new(destination, content)
            else:
                _copy_database(databases[member.path][0], destination)
                objects[name] = _read(destination)
            if sum(len(value) for value in objects.values()) > MAX_CHECKPOINT_BYTES:
                raise HostCheckpointError("checkpoint contents exceed the byte bound")
        verify_recovery_stores(snapshot_state, plan, checkpoint_signer=checkpoint_signer)
        _require_partition(state, plan)
        for member in plan.members:
            path = state / member.path
            info = path.stat()
            if identities[member.path] != (info.st_dev, info.st_ino):
                raise HostCheckpointError("checkpoint source identity changed while copying")
            if member.kind == "artifact":
                if sha256(_read(path)).hexdigest() != member.artifact_sha256:
                    raise HostCheckpointError("checkpoint artifact changed while copying")
            else:
                connection, version = databases[member.path]
                if connection.execute("PRAGMA data_version").fetchone()[0] != version:
                    raise HostCheckpointError("checkpoint database changed while copying")
        lease.require_active(exclusive=True)
    descriptions = tuple(HostCheckpointObject(
        path=name, sha256=sha256(objects[name]).hexdigest(), size=len(objects[name]),
    ) for name in sorted(objects))
    return descriptions, b"".join(objects[item.path] for item in descriptions)


def create_host_checkpoint(
    lease: HostActivityLease, *, plan: HostCheckpointPlan, expected_plan_sha256: str,
    destination: Path, encryption_key_id: str, encryption_key: bytes,
    signer: SQLiteGraphBackupSigner, checkpoint_signer: CheckpointSigner,
    created_at: datetime | None = None,
) -> HostCheckpointManifest:
    """Retain exclusion through verification and single-file exclusive publication."""
    lease.require_active(exclusive=True)
    plan = _canonical_plan(plan, expected_plan_sha256)
    if plan.gate != lease.identity:
        raise HostCheckpointError("recovery plan belongs to a different enrolled host")
    if lease.recovery_required and plan.enrollment is None:
        raise HostCheckpointError("v3 host recovery requires its complete first-use enrollment")
    if plan.enrollment is not None:
        from pajin.runtime.host_recovery import inspect_recovery_inventory

        if inspect_recovery_inventory(lease, require_complete=True) != plan.enrollment:
            raise HostCheckpointError("checkpoint first-use enrollment changed before collection")
    _safe_directory(destination.parent)
    if destination.is_relative_to(lease.root):
        raise HostCheckpointError("checkpoint destination must be outside the source host root")
    _require_absent_leaf(destination, label="host checkpoint")
    # Validate all caller-owned cryptographic metadata before reading sensitive state.
    if type(encryption_key) is not bytes or len(encryption_key) != 32:
        raise HostCheckpointError("checkpoint encryption requires an AES-256 key")
    from pydantic import TypeAdapter

    from pajin.runtime.host_checkpoint_models import Identifier

    TypeAdapter(Identifier).validate_python(encryption_key_id)
    created_at = created_at or datetime.now(UTC)
    nonce = os.urandom(12)
    _prepare_private_parent(destination.parent)
    with tempfile.TemporaryDirectory(prefix=".host-checkpoint-", dir=destination.parent) as folder:
        objects, plaintext = _collect(
            lease, plan, Path(folder), encryption_key_id=encryption_key_id,
            encryption_key=encryption_key, signer=signer, checkpoint_signer=checkpoint_signer,
            created_at=created_at,
        )
        ciphertext = AESGCM(encryption_key).encrypt(
            nonce, plaintext, _AAD_DOMAIN + plan.digest.encode() + encryption_key_id.encode(),
        )
        statement = HostCheckpointStatement(
            plan=plan, createdAt=created_at, encryptionKeyId=encryption_key_id,
            nonceHex=nonce.hex(), objects=objects, ciphertextSha256=sha256(ciphertext).hexdigest(),
            ciphertextBytes=len(ciphertext),
        )
        manifest = HostCheckpointManifest(
            statement=statement, signingKeyId=signer.key.key_id,
            signatureHex=signer.private_key.sign(_SIGNATURE_DOMAIN + canonical(statement)).hex(),
        )
        metadata = canonical(manifest)
        if len(metadata) > MAX_MANIFEST_BYTES:
            raise HostCheckpointError("checkpoint manifest exceeds its byte bound")
        lease.require_active(exclusive=True)
        _write_new(destination, _MAGIC + len(metadata).to_bytes(8) + metadata + ciphertext)
        return manifest


def _authenticate(
    source: Path, *, expected_checkpoint_sha256: str, expected_plan_sha256: str,
    encryption_key_id: str, encryption_key: bytes,
    trusted_signing_keys: tuple[SQLiteGraphBackupVerificationKey, ...],
) -> tuple[HostCheckpointManifest, dict[str, bytes]]:
    raw = _read(source, MAX_CHECKPOINT_BYTES + MAX_MANIFEST_BYTES + len(_MAGIC) + 24)
    if not raw.startswith(_MAGIC) or len(raw) < len(_MAGIC) + 8:
        raise HostCheckpointError("checkpoint envelope version is not supported")
    size = int.from_bytes(raw[len(_MAGIC):len(_MAGIC) + 8])
    if not 0 < size <= MAX_MANIFEST_BYTES:
        raise HostCheckpointError("checkpoint manifest length is invalid")
    metadata = raw[len(_MAGIC) + 8:len(_MAGIC) + 8 + size]
    manifest = HostCheckpointManifest.model_validate(parse_strict_json_bytes(
        metadata, label="host checkpoint manifest", max_bytes=MAX_MANIFEST_BYTES,
    ))
    statement = manifest.statement
    if (
        metadata != canonical(manifest) or manifest.digest != expected_checkpoint_sha256
        or statement.plan.digest != expected_plan_sha256
        or statement.encryption_key_id != encryption_key_id
        or [item.path for item in statement.objects] != _object_names(statement.plan)
    ):
        raise HostCheckpointError("checkpoint differs from its independently expected identity")
    keys = {item.key_id: item for item in trusted_signing_keys}
    if len(keys) != len(trusted_signing_keys) or manifest.signing_key_id not in keys:
        raise HostCheckpointError("checkpoint signing key is not uniquely trusted")
    key = SQLiteGraphBackupVerificationKey.model_validate_json(
        keys[manifest.signing_key_id].model_dump_json(),
    )
    Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(
        key.public_key_base64url + "=",
    )).verify(bytes.fromhex(manifest.signature_hex), _SIGNATURE_DOMAIN + canonical(statement))
    ciphertext = raw[len(_MAGIC) + 8 + size:]
    if len(ciphertext) != statement.ciphertext_bytes or sha256(ciphertext).hexdigest() != (
        statement.ciphertext_sha256
    ):
        raise HostCheckpointError("checkpoint ciphertext is incomplete or changed")
    if type(encryption_key) is not bytes or len(encryption_key) != 32:
        raise HostCheckpointError("checkpoint encryption requires an AES-256 key")
    plaintext = AESGCM(encryption_key).decrypt(
        bytes.fromhex(statement.nonce_hex), ciphertext,
        _AAD_DOMAIN + statement.plan.digest.encode() + encryption_key_id.encode(),
    )
    objects: dict[str, bytes] = {}
    offset = 0
    for item in statement.objects:
        value = plaintext[offset:offset + item.size]
        if len(value) != item.size or sha256(value).hexdigest() != item.sha256:
            raise HostCheckpointError("checkpoint object contents differ from the signed inventory")
        objects[item.path] = value
        offset += item.size
    if offset != len(plaintext):
        raise HostCheckpointError("checkpoint contains unlisted trailing data")
    return manifest, objects


def restore_host_checkpoint(
    source: Path, *, destination: Path, expected_checkpoint_sha256: str,
    expected_plan_sha256: str, encryption_key_id: str, encryption_key: bytes,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
    checkpoint_signer: CheckpointSigner,
) -> HostCheckpointManifest:
    """Verify privately, restore only a new root, and publish a completion marker last.

    The result has no runtime gate. It requires separately reviewed deployment
    configuration and enrollment; this function never resumes an execution.
    """
    _safe_directory(destination.parent)
    _require_absent_leaf(destination, label="host restore destination")
    keys = tuple(trusted_signing_keys)
    manifest, objects = _authenticate(
        source, expected_checkpoint_sha256=expected_checkpoint_sha256,
        expected_plan_sha256=expected_plan_sha256, encryption_key_id=encryption_key_id,
        encryption_key=encryption_key, trusted_signing_keys=keys,
    )
    _prepare_private_parent(destination.parent)
    with tempfile.TemporaryDirectory(prefix=".host-restore-", dir=destination.parent) as folder:
        workspace = Path(folder)
        state = workspace / "state"
        for index, member in enumerate(manifest.statement.plan.members):
            name = f"members/{index:04d}"
            if member.kind == "graph-sqlite":
                retained = workspace / name
                _write_new(retained, objects[name])
                _write_new(
                    sqlite_graph_retained_backup_manifest_path(retained),
                    objects[name + ".manifest.json"],
                )
                assert member.campaign_id is not None
                restore_retained_sqlite_graph_backup(
                    retained, destination=state / member.path, campaign_id=member.campaign_id,
                    encryption_key_id=encryption_key_id, encryption_key=encryption_key,
                    trusted_signing_keys=keys,
                )
            else:
                _write_new(state / member.path, objects[name])
        verify_recovery_stores(state, manifest.statement.plan, checkpoint_signer=checkpoint_signer)
        # mkdir is the exclusive reservation: rename alone could replace an empty directory.
        destination.mkdir(mode=0o700)
        os.rename(state, destination / "state")
        _fsync_graph_directory(destination)
        _write_new(destination / "restored-checkpoint.json", canonical(manifest))
        _fsync_graph_directory(destination.parent)
    return manifest
