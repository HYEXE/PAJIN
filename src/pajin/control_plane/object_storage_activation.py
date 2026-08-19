"""Durable, non-provider activation for Object Storage deployment authority heads."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.control_plane.object_storage_authority import (
    ObjectStorageDeploymentAuthority,
    ObjectStorageDeploymentAuthorityError,
    select_object_storage_deployment_authority,
)
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

OBJECT_STORAGE_AUTHORITY_STORE_IDENTITY_API_VERSION = (
    "pajin.control-plane.object-storage-authority-store-identity/v1"
)
OBJECT_STORAGE_AUTHORITY_HEAD_ACTIVATION_API_VERSION = (
    "pajin.control-plane.object-storage-authority-head-activation/v1"
)
OBJECT_STORAGE_AUTHORITY_HEAD_CHECKPOINT_API_VERSION = (
    "pajin.control-plane.object-storage-authority-head-checkpoint/v1"
)
OBJECT_STORAGE_AUTHORITY_HEAD_BACKUP_API_VERSION = (
    "pajin.control-plane.object-storage-authority-head-backup/v1"
)

_SCHEMA_VERSION = 1
_BUSY_TIMEOUT_MS = 5_000
_MAX_ACTIVATIONS = 100_000
_MAX_ACTIVATION_JSON_BYTES = 16_384
_MAX_IDENTITY_BYTES = 8_192
_MAX_BACKUP_BYTES = 64 * 1024 * 1024
_MAX_BACKUP_MANIFEST_BYTES = 16_384
_SHA256_PATTERN = r"^[a-f0-9]{64}$"

_SCHEMA_SQL = """
CREATE TABLE store_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    schema_digest TEXT NOT NULL,
    identity_digest TEXT NOT NULL
);
CREATE TABLE activations (
    revision INTEGER PRIMARY KEY CHECK(revision >= 1),
    authority_digest TEXT NOT NULL UNIQUE,
    activation_digest TEXT NOT NULL UNIQUE,
    activation_json TEXT NOT NULL
);
CREATE TRIGGER store_metadata_no_update
BEFORE UPDATE ON store_metadata
BEGIN SELECT RAISE(ABORT, 'store metadata is immutable'); END;
CREATE TRIGGER store_metadata_no_delete
BEFORE DELETE ON store_metadata
BEGIN SELECT RAISE(ABORT, 'store metadata is immutable'); END;
CREATE TRIGGER store_metadata_no_insert
BEFORE INSERT ON store_metadata
WHEN EXISTS (SELECT 1 FROM store_metadata)
BEGIN SELECT RAISE(ABORT, 'store metadata is immutable'); END;
CREATE TRIGGER activations_no_update
BEFORE UPDATE ON activations
BEGIN SELECT RAISE(ABORT, 'authority activations are append-only'); END;
CREATE TRIGGER activations_no_delete
BEFORE DELETE ON activations
BEGIN SELECT RAISE(ABORT, 'authority activations are append-only'); END;
CREATE TRIGGER activations_no_replace
BEFORE INSERT ON activations
WHEN EXISTS (
    SELECT 1 FROM activations
    WHERE revision = NEW.revision
       OR authority_digest = NEW.authority_digest
       OR activation_digest = NEW.activation_digest
)
BEGIN SELECT RAISE(ABORT, 'authority activations are append-only'); END;
"""
_SCHEMA_DIGEST = sha256(
    b"pajin.control-plane.object-storage-authority-store-schema/v1\x00"
    + _SCHEMA_SQL.encode("utf-8")
).hexdigest()


class ObjectStorageAuthorityHeadStoreError(RuntimeError):
    """Raised when durable Object Storage authority state is absent or inconsistent."""


def _canonical_json(value: object) -> bytes:
    import json

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _domain_digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\x00" + _canonical_json(value)).hexdigest()


def _normalize_timestamp(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset")
    return value.astimezone(UTC)


class ObjectStorageAuthorityStoreIdentity(StrictModel):
    """Immutable provisioning marker kept independently from the mutable SQLite head."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-authority-store-identity/v1"] = Field(
        default="pajin.control-plane.object-storage-authority-store-identity/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageAuthorityStoreIdentity"] = "ObjectStorageAuthorityStoreIdentity"
    identity_digest: str = Field(default="", alias="identityDigest", max_length=64)
    deployment_id: str = Field(alias="deploymentId", min_length=1, max_length=200)
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=200)
    genesis_authority_digest: str = Field(
        alias="genesisAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    provisioned_at: datetime = Field(alias="provisionedAt")
    provider_integration_eligible: Literal[False] = Field(
        default=False,
        alias="providerIntegrationEligible",
    )

    @field_validator("provisioned_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage store provisioning time")

    @field_validator("provider_integration_eligible", mode="before")
    @classmethod
    def require_boolean_flag(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage store identity flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"identity_digest"})
        digest = _domain_digest(OBJECT_STORAGE_AUTHORITY_STORE_IDENTITY_API_VERSION, material)
        if self.identity_digest and self.identity_digest != digest:
            raise ValueError("Object Storage authority store identity digest differs")
        object.__setattr__(self, "identity_digest", digest)
        return self


class ObjectStorageAuthorityHeadActivation(StrictModel):
    """One authority revision durably committed before it can be selected for use."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-authority-head-activation/v1"] = Field(
        default="pajin.control-plane.object-storage-authority-head-activation/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageAuthorityHeadActivation"] = "ObjectStorageAuthorityHeadActivation"
    activation_digest: str = Field(default="", alias="activationDigest", max_length=64)
    store_identity_digest: str = Field(
        alias="storeIdentityDigest",
        pattern=_SHA256_PATTERN,
    )
    authority: ObjectStorageDeploymentAuthority
    activated_at: datetime = Field(alias="activatedAt")
    authority_head_active: Literal[True] = Field(default=True, alias="authorityHeadActive")
    provider_integration_eligible: Literal[False] = Field(
        default=False,
        alias="providerIntegrationEligible",
    )
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("activated_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage authority activation time")

    @field_validator(
        "authority_head_active",
        "provider_integration_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_boolean_flags(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage activation flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_activation(self) -> Self:
        if self.activated_at < self.authority.issued_at:
            raise ValueError("Object Storage authority cannot activate before it was issued")
        material = self.model_dump(mode="json", by_alias=True, exclude={"activation_digest"})
        digest = _domain_digest(OBJECT_STORAGE_AUTHORITY_HEAD_ACTIVATION_API_VERSION, material)
        if self.activation_digest and self.activation_digest != digest:
            raise ValueError("Object Storage authority activation digest differs")
        object.__setattr__(self, "activation_digest", digest)
        return self


class ObjectStorageAuthorityHeadCheckpoint(StrictModel):
    """Secret-free external checkpoint for detecting stale restore or lost head state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-authority-head-checkpoint/v1"] = Field(
        default="pajin.control-plane.object-storage-authority-head-checkpoint/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageAuthorityHeadCheckpoint"] = "ObjectStorageAuthorityHeadCheckpoint"
    checkpoint_digest: str = Field(default="", alias="checkpointDigest", max_length=64)
    store_identity_digest: str = Field(
        alias="storeIdentityDigest",
        pattern=_SHA256_PATTERN,
    )
    deployment_id: str = Field(alias="deploymentId", min_length=1, max_length=200)
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=200)
    revision: int = Field(strict=True, ge=1, le=2**31 - 1)
    authority_digest: str = Field(alias="authorityDigest", pattern=_SHA256_PATTERN)
    activation_digest: str = Field(alias="activationDigest", pattern=_SHA256_PATTERN)
    provider_integration_eligible: Literal[False] = Field(
        default=False,
        alias="providerIntegrationEligible",
    )

    @field_validator("provider_integration_eligible", mode="before")
    @classmethod
    def require_boolean_flag(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage checkpoint flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_checkpoint(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"checkpoint_digest"})
        digest = _domain_digest(OBJECT_STORAGE_AUTHORITY_HEAD_CHECKPOINT_API_VERSION, material)
        if self.checkpoint_digest and self.checkpoint_digest != digest:
            raise ValueError("Object Storage authority head checkpoint digest differs")
        object.__setattr__(self, "checkpoint_digest", digest)
        return self


class ObjectStorageAuthorityHeadBackupManifest(StrictModel):
    """Content-addressed local backup manifest bound to exact logical head state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-authority-head-backup/v1"] = Field(
        default="pajin.control-plane.object-storage-authority-head-backup/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageAuthorityHeadBackupManifest"] = (
        "ObjectStorageAuthorityHeadBackupManifest"
    )
    backup_id: str = Field(default="", alias="backupId", max_length=112)
    schema_version: Literal[1] = Field(default=1, alias="schemaVersion")
    schema_digest: str = Field(
        default=_SCHEMA_DIGEST,
        alias="schemaDigest",
        pattern=_SHA256_PATTERN,
    )
    created_at: datetime = Field(alias="createdAt")
    database_sha256: str = Field(alias="databaseSha256", pattern=_SHA256_PATTERN)
    database_bytes: int = Field(alias="databaseBytes", strict=True, ge=1, le=_MAX_BACKUP_BYTES)
    store_identity: ObjectStorageAuthorityStoreIdentity = Field(alias="storeIdentity")
    head_checkpoint: ObjectStorageAuthorityHeadCheckpoint = Field(alias="headCheckpoint")

    @field_validator("created_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage authority backup time")

    @field_validator("schema_version", "database_bytes", mode="before")
    @classmethod
    def require_integer_fields(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Object Storage backup numeric fields must be JSON integers")
        return value

    @model_validator(mode="after")
    def bind_backup(self) -> Self:
        if self.schema_digest != _SCHEMA_DIGEST:
            raise ValueError("Object Storage authority backup schema digest differs")
        if self.head_checkpoint.store_identity_digest != self.store_identity.identity_digest:
            raise ValueError("Object Storage authority backup identity differs from its head")
        material = self.model_dump(mode="json", by_alias=True, exclude={"backup_id"})
        digest = _domain_digest(OBJECT_STORAGE_AUTHORITY_HEAD_BACKUP_API_VERSION, material)
        backup_id = f"object-storage-authority-head-backup_{digest}"
        if self.backup_id and self.backup_id != backup_id:
            raise ValueError("Object Storage authority backup ID differs")
        object.__setattr__(self, "backup_id", backup_id)
        return self


def object_storage_authority_store_identity_path(database: Path) -> Path:
    """Return the immutable provisioning marker for one authority-head database."""

    path = Path(os.path.abspath(database))
    return Path(f"{path}.identity.json")


def object_storage_authority_backup_manifest_path(backup: Path) -> Path:
    """Return the canonical manifest sidecar for one authority-head backup."""

    path = Path(os.path.abspath(backup))
    return Path(f"{path}.manifest.json")


class ObjectStorageAuthorityHeadStore:
    """One deployment-owned append-only SQLite authority-head chain.

    `bootstrap` is an explicit provisioning action and never runs from `open`. A restart
    requires both the database and its immutable identity marker. Provider code is not
    present in this slice; a future adapter must call `require_current` immediately before
    issuing a URL or performing a remote operation.
    """

    def __init__(self, path: Path, identity: ObjectStorageAuthorityStoreIdentity) -> None:
        self.path = Path(os.path.abspath(path))
        self.identity = identity.model_copy(deep=True)

    @classmethod
    def bootstrap(
        cls,
        path: Path,
        authority: ObjectStorageDeploymentAuthority,
        *,
        activated_at: datetime,
    ) -> ObjectStorageAuthorityHeadStore:
        """Provision a previously absent store and commit revision one before return."""

        database = Path(os.path.abspath(path))
        identity_path = object_storage_authority_store_identity_path(database)
        _prepare_private_parent(database.parent)
        _require_absent(database, label="Object Storage authority database")
        _require_absent(identity_path, label="Object Storage authority store identity")
        try:
            genesis = select_object_storage_deployment_authority(None, authority)
            activation_time = _normalize_timestamp(
                activated_at,
                label="Object Storage authority activation time",
            )
            identity = ObjectStorageAuthorityStoreIdentity(
                deploymentId=genesis.deployment_id,
                tenantId=genesis.tenant_id,
                genesisAuthorityDigest=genesis.authority_digest,
                provisionedAt=activation_time,
            )
        except (ObjectStorageDeploymentAuthorityError, ValidationError, ValueError) as exc:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority bootstrap input is invalid"
            ) from exc

        temporary_database = _private_temporary_path(database)
        temporary_identity: Path | None = None
        try:
            temporary_identity = _write_private_temporary(
                identity_path,
                _identity_bytes(identity),
            )
            _publish_exclusive(
                temporary_identity,
                identity_path,
                label="Object Storage authority store identity",
            )
            temporary_identity = None
            _initialize_database(temporary_database, identity)
            store = cls(temporary_database, identity)
            store._activate_bootstrap(genesis, activated_at=activation_time)
            _publish_exclusive(
                temporary_database,
                database,
                label="Object Storage authority database",
            )
            return cls.open(database)
        except BaseException:
            # The published identity is deliberately retained after a partial provisioning
            # failure so a restart cannot silently reinterpret the path as first bootstrap.
            raise
        finally:
            with suppress(FileNotFoundError):
                temporary_database.unlink()
            if temporary_identity is not None:
                with suppress(FileNotFoundError):
                    temporary_identity.unlink()

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint | None = None,
    ) -> ObjectStorageAuthorityHeadStore:
        """Open existing state without creating or bootstrapping anything."""

        database = Path(os.path.abspath(path))
        identity_path = object_storage_authority_store_identity_path(database)
        if not database.exists() or not identity_path.exists():
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority state is incomplete; restore is required"
            )
        identity = _read_identity(identity_path)
        store = cls(database, identity)
        activations = store._read_all()
        if expected_checkpoint is not None:
            _require_checkpoint_in_history(activations, identity, expected_checkpoint)
        return store

    def latest(self) -> ObjectStorageAuthorityHeadActivation:
        """Return the fully revalidated durable head."""

        return self._read_all()[-1].model_copy(deep=True)

    def checkpoint(self) -> ObjectStorageAuthorityHeadCheckpoint:
        """Return the exact current head checkpoint for independent retention."""

        return _checkpoint(self.identity, self.latest())

    def activate(
        self,
        authority: ObjectStorageDeploymentAuthority,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        activated_at: datetime,
    ) -> ObjectStorageAuthorityHeadActivation:
        """Commit one exact retry or contiguous successor before returning it."""

        activation_time = _normalize_timestamp(
            activated_at,
            label="Object Storage authority activation time",
        )
        try:
            with _write_transaction(self.path) as connection:
                activations = _read_all_from_connection(connection, self.identity)
                _require_checkpoint_in_history(
                    activations,
                    self.identity,
                    expected_checkpoint,
                )
                current = activations[-1]
                selected = select_object_storage_deployment_authority(
                    current.authority,
                    authority,
                )
                if selected == current.authority:
                    return current.model_copy(deep=True)
                if activation_time < current.activated_at:
                    raise ObjectStorageAuthorityHeadStoreError(
                        "Object Storage authority activation time moved backwards"
                    )
                activation = ObjectStorageAuthorityHeadActivation(
                    storeIdentityDigest=self.identity.identity_digest,
                    authority=selected,
                    activatedAt=activation_time,
                )
                _insert_activation(connection, activation)
        except ObjectStorageDeploymentAuthorityError as exc:
            raise ObjectStorageAuthorityHeadStoreError(str(exc)) from exc
        except sqlite3.Error as exc:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority activation write failed"
            ) from exc
        committed = self.latest()
        if committed != activation:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority activation commit differs from requested head"
            )
        return committed

    def require_current(
        self,
        authority: ObjectStorageDeploymentAuthority,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
    ) -> ObjectStorageAuthorityHeadActivation:
        """Fail closed unless both caller authority and checkpoint equal the durable head."""

        latest = self.latest()
        checkpoint = _checkpoint(self.identity, latest)
        try:
            candidate_checkpoint = ObjectStorageAuthorityHeadCheckpoint.model_validate(
                expected_checkpoint.model_dump(mode="json", by_alias=True)
            )
            candidate_authority = ObjectStorageDeploymentAuthority.model_validate(
                authority.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority use input is invalid"
            ) from exc
        if candidate_checkpoint != checkpoint or candidate_authority != latest.authority:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage remote operation authority is not the durable current head"
            )
        return latest.model_copy(deep=True)

    def create_backup(
        self,
        destination: Path,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        created_at: datetime,
    ) -> ObjectStorageAuthorityHeadBackupManifest:
        """Publish one exclusive local backup after full logical verification."""

        created = _normalize_timestamp(created_at, label="Object Storage authority backup time")
        activations = self._read_all()
        _require_checkpoint_in_history(activations, self.identity, expected_checkpoint)
        if created < activations[-1].activated_at:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority backup predates the durable head"
            )
        backup = Path(os.path.abspath(destination))
        manifest_path = object_storage_authority_backup_manifest_path(backup)
        if self.path in {backup, manifest_path}:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority backup overlaps the live store"
            )
        _prepare_private_parent(backup.parent)
        _require_absent(backup, label="Object Storage authority backup")
        _require_absent(manifest_path, label="Object Storage authority backup manifest")
        temporary_backup = _private_temporary_path(backup)
        temporary_manifest: Path | None = None
        backup_published = False
        try:
            _copy_database(self.path, temporary_backup)
            copied = ObjectStorageAuthorityHeadStore(temporary_backup, self.identity)
            copied_activations = copied._read_all()
            if copied_activations != activations:
                raise ObjectStorageAuthorityHeadStoreError(
                    "Object Storage authority backup logical state differs"
                )
            database_bytes = read_bounded_regular_bytes(
                temporary_backup,
                max_bytes=_MAX_BACKUP_BYTES,
                label="Object Storage authority backup database",
                require_single_link=True,
            )
            manifest = ObjectStorageAuthorityHeadBackupManifest(
                createdAt=created,
                databaseSha256=sha256(database_bytes).hexdigest(),
                databaseBytes=len(database_bytes),
                storeIdentity=self.identity,
                headCheckpoint=_checkpoint(self.identity, copied_activations[-1]),
            )
            temporary_manifest = _write_private_temporary(
                manifest_path,
                _backup_manifest_bytes(manifest),
            )
            _publish_exclusive(
                temporary_backup,
                backup,
                label="Object Storage authority backup",
            )
            backup_published = True
            _publish_exclusive(
                temporary_manifest,
                manifest_path,
                label="Object Storage authority backup manifest",
            )
            temporary_manifest = None
            return manifest
        except (OSError, sqlite3.Error, ValidationError, ValueError) as exc:
            if backup_published:
                with suppress(OSError):
                    backup.unlink()
                    _fsync_directory(backup.parent)
            if isinstance(exc, ObjectStorageAuthorityHeadStoreError):
                raise
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority backup creation failed"
            ) from exc
        finally:
            with suppress(FileNotFoundError):
                temporary_backup.unlink()
            if temporary_manifest is not None:
                with suppress(FileNotFoundError):
                    temporary_manifest.unlink()

    @classmethod
    def restore_backup(
        cls,
        backup: Path,
        *,
        destination: Path,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
    ) -> ObjectStorageAuthorityHeadStore:
        """Restore verified state to an absent DB, reusing or creating its identity marker."""

        backup_path = Path(os.path.abspath(backup))
        manifest_path = object_storage_authority_backup_manifest_path(backup_path)
        destination_path = Path(os.path.abspath(destination))
        identity_path = object_storage_authority_store_identity_path(destination_path)
        if destination_path in {backup_path, manifest_path}:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority restore overlaps its backup"
            )
        _prepare_private_parent(destination_path.parent)
        _require_absent(destination_path, label="Object Storage authority restore destination")
        manifest = _read_backup_manifest(manifest_path)
        database_bytes = read_bounded_regular_bytes(
            backup_path,
            max_bytes=_MAX_BACKUP_BYTES,
            label="Object Storage authority backup database",
            require_single_link=True,
        )
        if (
            len(database_bytes) != manifest.database_bytes
            or sha256(database_bytes).hexdigest() != manifest.database_sha256
        ):
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority backup database digest differs"
            )
        if identity_path.exists():
            if _read_identity(identity_path) != manifest.store_identity:
                raise ObjectStorageAuthorityHeadStoreError(
                    "Object Storage authority restore identity differs"
                )
        else:
            _require_absent(identity_path, label="Object Storage authority store identity")

        temporary = _private_temporary_path(destination_path)
        identity_temporary: Path | None = None
        destination_published = False
        try:
            _write_existing_private_file(temporary, database_bytes)
            candidate = cls(temporary, manifest.store_identity)
            activations = candidate._read_all()
            if _checkpoint(manifest.store_identity, activations[-1]) != manifest.head_checkpoint:
                raise ObjectStorageAuthorityHeadStoreError(
                    "Object Storage authority backup head differs from its manifest"
                )
            _require_checkpoint_in_history(
                activations,
                manifest.store_identity,
                expected_checkpoint,
            )
            if not identity_path.exists():
                identity_temporary = _write_private_temporary(
                    identity_path,
                    _identity_bytes(manifest.store_identity),
                )
                _publish_exclusive(
                    identity_temporary,
                    identity_path,
                    label="Object Storage authority store identity",
                )
                identity_temporary = None
            _publish_exclusive(
                temporary,
                destination_path,
                label="Object Storage authority restore destination",
            )
            destination_published = True
            return cls.open(
                destination_path,
                expected_checkpoint=expected_checkpoint,
            )
        except (OSError, sqlite3.Error, ValidationError, ValueError) as exc:
            if destination_published:
                with suppress(OSError):
                    destination_path.unlink()
                    _fsync_directory(destination_path.parent)
            if isinstance(exc, ObjectStorageAuthorityHeadStoreError):
                raise
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority backup restore failed"
            ) from exc
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()
            if identity_temporary is not None:
                with suppress(FileNotFoundError):
                    identity_temporary.unlink()

    def _activate_bootstrap(
        self,
        authority: ObjectStorageDeploymentAuthority,
        *,
        activated_at: datetime,
    ) -> ObjectStorageAuthorityHeadActivation:
        activation = ObjectStorageAuthorityHeadActivation(
            storeIdentityDigest=self.identity.identity_digest,
            authority=authority,
            activatedAt=activated_at,
        )
        try:
            with _write_transaction(self.path) as connection:
                if _activation_row_count(connection) != 0:
                    raise ObjectStorageAuthorityHeadStoreError(
                        "Object Storage authority bootstrap store is not empty"
                    )
                _insert_activation(connection, activation)
        except sqlite3.Error as exc:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority bootstrap write failed"
            ) from exc
        return activation

    def _read_all(self) -> tuple[ObjectStorageAuthorityHeadActivation, ...]:
        try:
            with _read_transaction(self.path) as connection:
                return _read_all_from_connection(connection, self.identity)
        except sqlite3.Error as exc:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority state read failed"
            ) from exc


def _checkpoint(
    identity: ObjectStorageAuthorityStoreIdentity,
    activation: ObjectStorageAuthorityHeadActivation,
) -> ObjectStorageAuthorityHeadCheckpoint:
    authority = activation.authority
    return ObjectStorageAuthorityHeadCheckpoint(
        storeIdentityDigest=identity.identity_digest,
        deploymentId=authority.deployment_id,
        tenantId=authority.tenant_id,
        revision=authority.revision,
        authorityDigest=authority.authority_digest,
        activationDigest=activation.activation_digest,
    )


def _require_checkpoint_in_history(
    activations: tuple[ObjectStorageAuthorityHeadActivation, ...],
    identity: ObjectStorageAuthorityStoreIdentity,
    checkpoint: ObjectStorageAuthorityHeadCheckpoint,
) -> None:
    try:
        expected = ObjectStorageAuthorityHeadCheckpoint.model_validate(
            checkpoint.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority expected checkpoint is invalid"
        ) from exc
    if expected.store_identity_digest != identity.identity_digest:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority expected checkpoint belongs to another store"
        )
    if expected.revision > len(activations):
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority durable head is behind the expected checkpoint"
        )
    if _checkpoint(identity, activations[expected.revision - 1]) != expected:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority expected checkpoint is absent from durable history"
        )


def _activation_row_count(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COUNT(*) FROM activations").fetchone()
    if row is None:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority activation count is missing"
        )
    count = int(row[0])
    if count > _MAX_ACTIVATIONS:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority activation history exceeds its bound"
        )
    return count


def _insert_activation(
    connection: sqlite3.Connection,
    activation: ObjectStorageAuthorityHeadActivation,
) -> None:
    connection.execute(
        """
        INSERT INTO activations(
            revision, authority_digest, activation_digest, activation_json
        ) VALUES (?, ?, ?, ?)
        """,
        (
            activation.authority.revision,
            activation.authority.authority_digest,
            activation.activation_digest,
            activation.model_dump_json(by_alias=True),
        ),
    )


def _read_all_from_connection(
    connection: sqlite3.Connection,
    identity: ObjectStorageAuthorityStoreIdentity,
) -> tuple[ObjectStorageAuthorityHeadActivation, ...]:
    _validate_database(connection, identity)
    count = _activation_row_count(connection)
    if count == 0:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority store has no durable head"
        )
    rows = connection.execute(
        "SELECT revision, authority_digest, activation_digest, activation_json "
        "FROM activations ORDER BY revision"
    ).fetchall()
    if len(rows) != count:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority activation inventory changed during read"
        )
    activations: list[ObjectStorageAuthorityHeadActivation] = []
    previous: ObjectStorageAuthorityHeadActivation | None = None
    for ordinal, row in enumerate(rows, start=1):
        raw = str(row["activation_json"])
        if len(raw.encode("utf-8")) > _MAX_ACTIVATION_JSON_BYTES:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority activation exceeds its byte bound"
            )
        try:
            activation = ObjectStorageAuthorityHeadActivation.model_validate_json(raw)
        except (ValidationError, ValueError) as exc:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority activation content is invalid"
            ) from exc
        if (
            int(row["revision"]) != ordinal
            or activation.authority.revision != ordinal
            or str(row["authority_digest"]) != activation.authority.authority_digest
            or str(row["activation_digest"]) != activation.activation_digest
            or activation.store_identity_digest != identity.identity_digest
            or activation.authority.deployment_id != identity.deployment_id
            or activation.authority.tenant_id != identity.tenant_id
        ):
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority activation row differs from its content"
            )
        try:
            if previous is None:
                if activation.authority.authority_digest != identity.genesis_authority_digest:
                    raise ObjectStorageAuthorityHeadStoreError(
                        "Object Storage authority genesis differs from store identity"
                    )
                selected = select_object_storage_deployment_authority(None, activation.authority)
            else:
                selected = select_object_storage_deployment_authority(
                    previous.authority,
                    activation.authority,
                )
                if activation.activated_at < previous.activated_at:
                    raise ObjectStorageAuthorityHeadStoreError(
                        "Object Storage authority activation time moved backwards"
                    )
        except ObjectStorageDeploymentAuthorityError as exc:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority durable chain is inconsistent"
            ) from exc
        if selected != activation.authority:
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority durable chain is inconsistent"
            )
        activations.append(activation)
        previous = activation
    return tuple(activations)


def _initialize_database(
    path: Path,
    identity: ObjectStorageAuthorityStoreIdentity,
) -> None:
    connection: sqlite3.Connection | None = None
    try:
        connection = _open_write_connection(path)
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority journal mode differs"
            )
        connection.executescript(_SCHEMA_SQL)
        connection.execute(
            "INSERT INTO store_metadata(singleton, schema_version, schema_digest, identity_digest) "
            "VALUES (1, ?, ?, ?)",
            (_SCHEMA_VERSION, _SCHEMA_DIGEST, identity.identity_digest),
        )
        connection.commit()
        if os.name == "posix":
            path.chmod(0o600)
        _validate_database(connection, identity)
    except sqlite3.Error as exc:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority database could not initialize"
        ) from exc
    finally:
        if connection is not None:
            connection.close()


def _validate_database(
    connection: sqlite3.Connection,
    identity: ObjectStorageAuthorityStoreIdentity,
) -> None:
    quick_check = connection.execute("PRAGMA quick_check").fetchone()
    if quick_check is None or str(quick_check[0]) != "ok":
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority database integrity check failed"
        )
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    triggers = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
    }
    if tables != {"store_metadata", "activations"} or triggers != {
        "store_metadata_no_update",
        "store_metadata_no_delete",
        "store_metadata_no_insert",
        "activations_no_update",
        "activations_no_delete",
        "activations_no_replace",
    }:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority database schema inventory differs"
        )
    row = connection.execute(
        "SELECT schema_version, schema_digest, identity_digest "
        "FROM store_metadata WHERE singleton = 1"
    ).fetchone()
    if row is None or connection.execute("SELECT COUNT(*) FROM store_metadata").fetchone()[0] != 1:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority database metadata is incomplete"
        )
    if (
        int(row["schema_version"]) != _SCHEMA_VERSION
        or str(row["schema_digest"]) != _SCHEMA_DIGEST
        or str(row["identity_digest"]) != identity.identity_digest
    ):
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority database metadata differs"
        )


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    connection = _open_write_connection(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
        _require_safe_path(path)
        _require_safe_sidecars(path)


@contextmanager
def _read_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA query_only = ON")
    connection.execute("BEGIN")
    try:
        yield connection
    finally:
        connection.rollback()
        connection.close()
        _require_safe_path(path)
        _require_safe_sidecars(path)


def _open_write_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


def _copy_database(source: Path, destination: Path) -> None:
    destination_connection: sqlite3.Connection | None = None
    try:
        with _read_transaction(source) as source_connection:
            destination_connection = _open_write_connection(destination)
            source_connection.backup(destination_connection)
        if destination_connection is not None:
            destination_connection.close()
            destination_connection = None
        if os.name == "posix":
            destination.chmod(0o600)
        _require_safe_path(destination)
        _require_safe_sidecars(destination)
    finally:
        if destination_connection is not None:
            destination_connection.close()


def _read_identity(path: Path) -> ObjectStorageAuthorityStoreIdentity:
    raw = read_bounded_regular_bytes(
        path,
        max_bytes=_MAX_IDENTITY_BYTES,
        label="Object Storage authority store identity",
        require_single_link=True,
    )
    try:
        parsed = parse_strict_json_bytes(
            raw,
            label="Object Storage authority store identity",
            max_bytes=_MAX_IDENTITY_BYTES,
            max_depth=8,
            max_nodes=64,
        )
        identity = ObjectStorageAuthorityStoreIdentity.model_validate(parsed)
    except (TypeError, ValidationError, ValueError) as exc:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority store identity is invalid"
        ) from exc
    if raw != _identity_bytes(identity):
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority store identity is not canonical bytes"
        )
    return identity


def _identity_bytes(identity: ObjectStorageAuthorityStoreIdentity) -> bytes:
    return _canonical_json(identity.model_dump(mode="json", by_alias=True)) + b"\n"


def _read_backup_manifest(path: Path) -> ObjectStorageAuthorityHeadBackupManifest:
    raw = read_bounded_regular_bytes(
        path,
        max_bytes=_MAX_BACKUP_MANIFEST_BYTES,
        label="Object Storage authority backup manifest",
        require_single_link=True,
    )
    try:
        parsed = parse_strict_json_bytes(
            raw,
            label="Object Storage authority backup manifest",
            max_bytes=_MAX_BACKUP_MANIFEST_BYTES,
            max_depth=16,
            max_nodes=256,
        )
        manifest = ObjectStorageAuthorityHeadBackupManifest.model_validate(parsed)
    except (TypeError, ValidationError, ValueError) as exc:
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority backup manifest is invalid"
        ) from exc
    if raw != _backup_manifest_bytes(manifest):
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority backup manifest is not canonical bytes"
        )
    return manifest


def _backup_manifest_bytes(manifest: ObjectStorageAuthorityHeadBackupManifest) -> bytes:
    return _canonical_json(manifest.model_dump(mode="json", by_alias=True)) + b"\n"


def _prepare_private_parent(parent: Path) -> None:
    probe = parent / ".object-storage-authority-path-probe"
    _require_safe_path(probe)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        parent.chmod(0o700)
    _require_safe_path(probe)


def _require_absent(path: Path, *, label: str) -> None:
    _require_safe_path(path)
    if path.exists() or path.is_symlink() or path.is_junction():
        raise ObjectStorageAuthorityHeadStoreError(f"{label} already exists")


def _private_temporary_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.close(descriptor)
    path = Path(name)
    if os.name == "posix":
        path.chmod(0o600)
    return path


def _write_private_temporary(destination: Path, content: bytes) -> Path:
    temporary = _private_temporary_path(destination)
    try:
        _write_existing_private_file(temporary, content)
        return temporary
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _write_existing_private_file(path: Path, content: bytes) -> None:
    _require_safe_path(path)
    with path.open("wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name == "posix":
        path.chmod(0o600)


def _publish_exclusive(source: Path, destination: Path, *, label: str) -> None:
    _require_absent(destination, label=label)
    try:
        os.link(source, destination)
    except FileExistsError as exc:
        raise ObjectStorageAuthorityHeadStoreError(f"{label} already exists") from exc
    except OSError as exc:
        raise ObjectStorageAuthorityHeadStoreError(f"{label} publication failed") from exc
    try:
        source.unlink()
    except OSError as exc:
        with suppress(OSError):
            destination.unlink()
        raise ObjectStorageAuthorityHeadStoreError(
            f"{label} publication finalization failed"
        ) from exc
    _fsync_directory(destination.parent)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_safe_path(path: Path) -> None:
    parent = path.parent
    if any(
        ancestor.exists() and (ancestor.is_symlink() or ancestor.is_junction())
        for ancestor in (parent, *parent.parents)
    ):
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority state ancestor is unsafe"
        )
    if parent.exists() and not parent.is_dir():
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority state parent is unsafe"
        )
    if (path.exists() or path.is_symlink() or path.is_junction()) and (
        not path.is_file() or path.is_symlink() or path.is_junction() or path.stat().st_nlink != 1
    ):
        raise ObjectStorageAuthorityHeadStoreError(
            "Object Storage authority state is not a single-link regular file"
        )


def _require_safe_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not (sidecar.exists() or sidecar.is_symlink() or sidecar.is_junction()):
            continue
        if (
            not sidecar.is_file()
            or sidecar.is_symlink()
            or sidecar.is_junction()
            or sidecar.stat().st_nlink != 1
        ):
            raise ObjectStorageAuthorityHeadStoreError(
                "Object Storage authority database sidecar is unsafe"
            )
