from __future__ import annotations

import base64
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.control_plane.object_storage_activation import (
    ObjectStorageAuthorityHeadCheckpoint,
    ObjectStorageAuthorityHeadStore,
    ObjectStorageAuthorityHeadStoreError,
    object_storage_authority_backup_manifest_path,
    object_storage_authority_store_identity_path,
)
from pajin.control_plane.object_storage_authority import ObjectStorageDeploymentAuthority

NOW = datetime(2026, 8, 18, 3, 0, tzinfo=UTC)


def _authority(
    *,
    revision: int = 1,
    previous: str | None = None,
    issued_at: datetime = NOW,
    endpoint: str = "https://objects.example.test",
    prefix: str = "pajin-artifacts/tenant-a",
) -> ObjectStorageDeploymentAuthority:
    return ObjectStorageDeploymentAuthority(
        deploymentId="object-storage:prod-a",
        revision=revision,
        previousAuthorityDigest=previous,
        issuedAt=issued_at,
        tenantId="tenant:a",
        endpointOrigin=endpoint,
        objectKeyPrefix=prefix,
        uploadTtlSeconds=300,
    )


def _second(first: ObjectStorageDeploymentAuthority) -> ObjectStorageDeploymentAuthority:
    return _authority(
        revision=2,
        previous=first.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
        endpoint="https://objects-2.example.test",
    )


def _checkpoint_argument(checkpoint: ObjectStorageAuthorityHeadCheckpoint) -> str:
    raw = checkpoint.model_dump_json(by_alias=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _run_hard_exit(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    source_root = Path(__file__).resolve().parents[1] / "src"
    current = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(source_root) if not current else os.pathsep.join((str(source_root), current))
    )
    return subprocess.run(
        [sys.executable, "-c", script, *arguments],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_bootstrap_commits_revision_one_and_restart_requires_existing_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    first = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        first,
        activated_at=NOW + timedelta(seconds=1),
    )
    checkpoint = store.checkpoint()

    assert path.is_file()
    assert object_storage_authority_store_identity_path(path).is_file()
    assert store.latest().authority == first
    assert checkpoint.revision == 1
    assert checkpoint.authority_digest == first.authority_digest
    assert checkpoint.provider_integration_eligible is False
    reopened = ObjectStorageAuthorityHeadStore.open(
        path,
        expected_checkpoint=checkpoint,
    )
    assert reopened.latest() == store.latest()

    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="already exists"):
        ObjectStorageAuthorityHeadStore.bootstrap(
            path,
            first,
            activated_at=NOW + timedelta(seconds=2),
        )


def test_open_never_creates_or_bootstraps_missing_state(tmp_path: Path) -> None:
    path = tmp_path / "missing" / "head.sqlite3"

    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="restore is required"):
        ObjectStorageAuthorityHeadStore.open(path)

    assert not path.exists()
    assert not object_storage_authority_store_identity_path(path).exists()


def test_activation_is_write_before_use_and_exact_retry_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    first = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        first,
        activated_at=NOW + timedelta(seconds=1),
    )
    first_checkpoint = store.checkpoint()
    second = _second(first)

    activated = store.activate(
        second,
        expected_checkpoint=first_checkpoint,
        activated_at=NOW + timedelta(minutes=2),
    )
    second_checkpoint = store.checkpoint()
    retried = store.activate(
        second,
        expected_checkpoint=first_checkpoint,
        activated_at=NOW + timedelta(hours=1),
    )

    assert activated.authority == second
    assert retried == activated
    assert retried.activated_at == NOW + timedelta(minutes=2)
    assert (
        ObjectStorageAuthorityHeadStore.open(
            path,
            expected_checkpoint=first_checkpoint,
        ).latest()
        == activated
    )
    assert (
        store.require_current(
            second,
            expected_checkpoint=second_checkpoint,
        )
        == activated
    )
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="durable current head"):
        store.require_current(first, expected_checkpoint=first_checkpoint)
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="durable current head"):
        store.require_current(second, expected_checkpoint=first_checkpoint)


def test_activation_rejects_rollback_gap_equivocation_and_cross_store_checkpoint(
    tmp_path: Path,
) -> None:
    first = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        tmp_path / "first" / "head.sqlite3",
        first,
        activated_at=NOW + timedelta(seconds=1),
    )
    first_checkpoint = store.checkpoint()
    second = _second(first)
    store.activate(
        second,
        expected_checkpoint=first_checkpoint,
        activated_at=NOW + timedelta(minutes=2),
    )
    second_checkpoint = store.checkpoint()

    for candidate in (
        first,
        _authority(
            revision=4,
            previous=second.authority_digest,
            issued_at=NOW + timedelta(minutes=3),
        ),
        _authority(
            revision=2,
            previous=first.authority_digest,
            issued_at=NOW + timedelta(minutes=1),
            prefix="pajin-artifacts/equivocation",
        ),
    ):
        with pytest.raises(ObjectStorageAuthorityHeadStoreError):
            store.activate(
                candidate,
                expected_checkpoint=second_checkpoint,
                activated_at=NOW + timedelta(minutes=4),
            )

    other = ObjectStorageAuthorityHeadStore.bootstrap(
        tmp_path / "second" / "head.sqlite3",
        first,
        activated_at=NOW + timedelta(seconds=2),
    )
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="another store"):
        store.activate(
            second,
            expected_checkpoint=other.checkpoint(),
            activated_at=NOW + timedelta(minutes=4),
        )


def test_database_loss_is_not_reinterpreted_as_bootstrap_and_verified_restore_recovers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    first = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        first,
        activated_at=NOW + timedelta(seconds=1),
    )
    first_checkpoint = store.checkpoint()
    second = _second(first)
    store.activate(
        second,
        expected_checkpoint=first_checkpoint,
        activated_at=NOW + timedelta(minutes=2),
    )
    second_checkpoint = store.checkpoint()
    backup = tmp_path / "backup" / "head.sqlite3"
    manifest = store.create_backup(
        backup,
        expected_checkpoint=second_checkpoint,
        created_at=NOW + timedelta(minutes=3),
    )
    identity_bytes = object_storage_authority_store_identity_path(path).read_bytes()

    path.unlink()
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="restore is required"):
        ObjectStorageAuthorityHeadStore.open(path, expected_checkpoint=second_checkpoint)
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="identity already exists"):
        ObjectStorageAuthorityHeadStore.bootstrap(
            path,
            first,
            activated_at=NOW + timedelta(minutes=4),
        )

    restored = ObjectStorageAuthorityHeadStore.restore_backup(
        backup,
        destination=path,
        expected_checkpoint=second_checkpoint,
    )
    assert restored.latest().authority == second
    assert restored.checkpoint() == manifest.head_checkpoint
    assert object_storage_authority_store_identity_path(path).read_bytes() == identity_bytes


def test_restore_rejects_stale_backup_behind_external_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    first = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        first,
        activated_at=NOW + timedelta(seconds=1),
    )
    first_checkpoint = store.checkpoint()
    stale_backup = tmp_path / "backup" / "revision-one.sqlite3"
    store.create_backup(
        stale_backup,
        expected_checkpoint=first_checkpoint,
        created_at=NOW + timedelta(minutes=1),
    )
    store.activate(
        _second(first),
        expected_checkpoint=first_checkpoint,
        activated_at=NOW + timedelta(minutes=2),
    )
    current_checkpoint = store.checkpoint()
    path.unlink()

    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="behind the expected"):
        ObjectStorageAuthorityHeadStore.restore_backup(
            stale_backup,
            destination=path,
            expected_checkpoint=current_checkpoint,
        )
    assert not path.exists()


def test_restore_rejects_backup_and_manifest_tampering_without_destination(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        _authority(),
        activated_at=NOW + timedelta(seconds=1),
    )
    checkpoint = store.checkpoint()
    backup = tmp_path / "backup" / "head.sqlite3"
    store.create_backup(
        backup,
        expected_checkpoint=checkpoint,
        created_at=NOW + timedelta(minutes=1),
    )
    destination = tmp_path / "restore" / "head.sqlite3"

    database = bytearray(backup.read_bytes())
    database[-1] ^= 1
    backup.write_bytes(database)
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="database digest differs"):
        ObjectStorageAuthorityHeadStore.restore_backup(
            backup,
            destination=destination,
            expected_checkpoint=checkpoint,
        )
    assert not destination.exists()

    clean_backup = tmp_path / "backup" / "clean.sqlite3"
    store.create_backup(
        clean_backup,
        expected_checkpoint=checkpoint,
        created_at=NOW + timedelta(minutes=2),
    )
    manifest_path = object_storage_authority_backup_manifest_path(clean_backup)
    manifest = manifest_path.read_bytes()
    manifest_path.write_bytes(manifest[:-2] + b',"unexpected":true}\n')
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="manifest is invalid"):
        ObjectStorageAuthorityHeadStore.restore_backup(
            clean_backup,
            destination=destination,
            expected_checkpoint=checkpoint,
        )
    assert not destination.exists()


def test_activation_wires_reject_scalar_coercion_and_backup_before_head(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        _authority(),
        activated_at=NOW + timedelta(seconds=1),
    )
    checkpoint = store.checkpoint()
    activation_raw = store.latest().model_dump(mode="json", by_alias=True)
    checkpoint_raw = checkpoint.model_dump(mode="json", by_alias=True)

    with pytest.raises(ValidationError):
        type(store.latest()).model_validate(
            {**activation_raw, "authorityHeadActive": 1, "activationDigest": ""}
        )
    with pytest.raises(ValidationError):
        ObjectStorageAuthorityHeadCheckpoint.model_validate(
            {**checkpoint_raw, "providerIntegrationEligible": 0, "checkpointDigest": ""}
        )
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="predates"):
        store.create_backup(
            tmp_path / "backup" / "head.sqlite3",
            expected_checkpoint=checkpoint,
            created_at=NOW,
        )


def test_open_rejects_identity_or_schema_guard_tampering(tmp_path: Path) -> None:
    identity_path = tmp_path / "identity" / "head.sqlite3"
    ObjectStorageAuthorityHeadStore.bootstrap(
        identity_path,
        _authority(),
        activated_at=NOW + timedelta(seconds=1),
    )
    marker = object_storage_authority_store_identity_path(identity_path)
    raw = marker.read_bytes()
    marker.write_bytes(raw.replace(b'"tenant:a"', b'"tenant:b"'))
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="identity is invalid"):
        ObjectStorageAuthorityHeadStore.open(identity_path)

    schema_path = tmp_path / "schema" / "head.sqlite3"
    schema_store = ObjectStorageAuthorityHeadStore.bootstrap(
        schema_path,
        _authority(),
        activated_at=NOW + timedelta(seconds=1),
    )
    assert schema_store.latest().authority.revision == 1
    connection = sqlite3.connect(schema_path)
    connection.execute("DROP TRIGGER activations_no_delete")
    connection.commit()
    connection.close()
    with pytest.raises(ObjectStorageAuthorityHeadStoreError, match="schema inventory differs"):
        ObjectStorageAuthorityHeadStore.open(schema_path)


def test_hard_exit_before_commit_rolls_back_uncommitted_successor(tmp_path: Path) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    first = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        first,
        activated_at=NOW + timedelta(seconds=1),
    )
    checkpoint = store.checkpoint()
    second = _second(first)
    child = _run_hard_exit(
        """
import base64
import os
import sqlite3
import sys
from datetime import UTC, datetime
from pajin.control_plane.object_storage_activation import ObjectStorageAuthorityHeadActivation
from pajin.control_plane.object_storage_authority import ObjectStorageDeploymentAuthority

authority = ObjectStorageDeploymentAuthority.model_validate_json(
    base64.urlsafe_b64decode(sys.argv[2]).decode("utf-8")
)
activation = ObjectStorageAuthorityHeadActivation(
    storeIdentityDigest=sys.argv[3],
    authority=authority,
    activatedAt=datetime(2026, 8, 18, 3, 2, tzinfo=UTC),
)
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute("PRAGMA synchronous = FULL")
connection.execute("BEGIN IMMEDIATE")
connection.execute(
    "INSERT INTO activations(revision, authority_digest, activation_digest, activation_json) "
    "VALUES (?, ?, ?, ?)",
    (
        activation.authority.revision,
        activation.authority.authority_digest,
        activation.activation_digest,
        activation.model_dump_json(by_alias=True),
    ),
)
os._exit(92)
""",
        str(path),
        base64.urlsafe_b64encode(second.model_dump_json(by_alias=True).encode()).decode(),
        checkpoint.store_identity_digest,
    )

    assert child.returncode == 92, child.stderr
    reopened = ObjectStorageAuthorityHeadStore.open(
        path,
        expected_checkpoint=checkpoint,
    )
    assert reopened.latest().authority == first


def test_hard_exit_after_activation_return_preserves_committed_successor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority" / "head.sqlite3"
    first = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        path,
        first,
        activated_at=NOW + timedelta(seconds=1),
    )
    first_checkpoint = store.checkpoint()
    second = _second(first)
    child = _run_hard_exit(
        """
import base64
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from pajin.control_plane.object_storage_activation import (
    ObjectStorageAuthorityHeadCheckpoint,
    ObjectStorageAuthorityHeadStore,
)
from pajin.control_plane.object_storage_authority import ObjectStorageDeploymentAuthority

checkpoint = ObjectStorageAuthorityHeadCheckpoint.model_validate_json(
    base64.urlsafe_b64decode(sys.argv[2]).decode("utf-8")
)
authority = ObjectStorageDeploymentAuthority.model_validate_json(
    base64.urlsafe_b64decode(sys.argv[3]).decode("utf-8")
)
store = ObjectStorageAuthorityHeadStore.open(
    Path(sys.argv[1]),
    expected_checkpoint=checkpoint,
)
activation = store.activate(
    authority,
    expected_checkpoint=checkpoint,
    activated_at=datetime(2026, 8, 18, 3, 2, tzinfo=UTC),
)
if activation.authority.revision != 2:
    os._exit(70)
os._exit(93)
""",
        str(path),
        _checkpoint_argument(first_checkpoint),
        base64.urlsafe_b64encode(second.model_dump_json(by_alias=True).encode()).decode(),
    )

    assert child.returncode == 93, child.stderr
    reopened = ObjectStorageAuthorityHeadStore.open(
        path,
        expected_checkpoint=first_checkpoint,
    )
    assert reopened.latest().authority == second
    current = reopened.checkpoint()
    assert reopened.require_current(second, expected_checkpoint=current).authority == second
