"""Signed, encrypted retention bundles for durable SQLite Graph backups."""

from __future__ import annotations

import base64
import binascii
import os
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from re import fullmatch
from typing import Annotated, Literal, Self

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.models import canonical_graph_json
from pajin.graph.sqlite_store import (
    _MAX_GRAPH_BACKUP_BYTES,
    SQLiteGraphBackupManifest,
    SQLiteGraphStore,
    SQLiteGraphStoreError,
    _absolute_path,
    _backup_manifest_bytes,
    _fsync_graph_directory,
    _prepare_private_parent,
    _publish_exclusive,
    _require_absent_leaf,
    _SQLiteGraphBackupManifestV1,
    _write_private_temporary,
    sqlite_graph_backup_manifest_path,
)
from pajin.runtime.safe_files import (
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)

GRAPH_STORE_RETAINED_BACKUP_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-retained-backup/v1alpha2"
] = "pajin.dev/sqlite-graph-retained-backup/v1alpha2"
GRAPH_STORE_RETAINED_BACKUP_MANIFEST_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-retained-backup-manifest/v1alpha2"
] = "pajin.dev/sqlite-graph-retained-backup-manifest/v1alpha2"

_LEGACY_RETAINED_BACKUP_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-retained-backup/v1alpha1"
] = (
    "pajin.dev/sqlite-graph-retained-backup/v1alpha1"
)
_LEGACY_RETAINED_BACKUP_MANIFEST_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-retained-backup-manifest/v1alpha1"
] = (
    "pajin.dev/sqlite-graph-retained-backup-manifest/v1alpha1"
)
_SIGNATURE_DOMAIN_V1 = b"pajin.graph.sqlite-retained-backup-signature/v1\0"
_SIGNATURE_DOMAIN_V2 = b"pajin.graph.sqlite-retained-backup-signature/v2\0"
_ENCRYPTION_AAD_DOMAIN_V1 = b"pajin.graph.sqlite-retained-backup-aad/v1\0"
_ENCRYPTION_AAD_DOMAIN_V2 = b"pajin.graph.sqlite-retained-backup-aad/v2\0"
_MAX_RETAINED_BACKUP_BYTES = _MAX_GRAPH_BACKUP_BYTES + 16
_MAX_RETAINED_BACKUP_MANIFEST_BYTES = 256 * 1024
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


class SQLiteGraphBackupVerificationKey(StrictModel):
    """One externally managed Ed25519 public key trusted for backup restoration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    key_id: _Identifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )

    @model_validator(mode="after")
    def require_canonical_public_key(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="SQLite Graph backup public key",
        )
        return self


class _SQLiteGraphRetainedBackupStatementV1(StrictModel):
    """Exact historical v1alpha1 retained statement over a schema-v2 backup."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/sqlite-graph-retained-backup/v1alpha1"
    ] = Field(
        default=_LEGACY_RETAINED_BACKUP_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphRetainedBackup"] = "SQLiteGraphRetainedBackup"
    retained_backup_id: str = Field(default="", alias="retainedBackupId", max_length=105)
    backup_manifest: _SQLiteGraphBackupManifestV1 = Field(alias="backupManifest")
    encryption_algorithm: Literal["AES-256-GCM"] = Field(
        default="AES-256-GCM",
        alias="encryptionAlgorithm",
    )
    encryption_key_id: _Identifier = Field(alias="encryptionKeyId")
    nonce_base64url: str = Field(
        alias="nonceBase64url",
        pattern=r"^[A-Za-z0-9_-]{16}$",
    )
    ciphertext_sha256: _Sha256 = Field(alias="ciphertextSha256")
    ciphertext_bytes: int = Field(
        alias="ciphertextBytes",
        ge=17,
        le=_MAX_RETAINED_BACKUP_BYTES,
    )

    @field_validator("nonce_base64url")
    @classmethod
    def require_canonical_nonce(cls, value: str) -> str:
        _base64url_decode(
            value,
            expected_length=12,
            label="SQLite Graph backup encryption nonce",
        )
        return value

    @model_validator(mode="after")
    def bind_retained_backup_identity(self) -> Self:
        _bind_retained_backup_identity(self)
        return self


class SQLiteGraphRetainedBackupStatement(StrictModel):
    """Signed v1alpha2 identity of one encrypted schema-v3 Graph backup."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-retained-backup/v1alpha2"] = Field(
        default=GRAPH_STORE_RETAINED_BACKUP_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphRetainedBackup"] = "SQLiteGraphRetainedBackup"
    retained_backup_id: str = Field(default="", alias="retainedBackupId", max_length=105)
    backup_manifest: SQLiteGraphBackupManifest = Field(alias="backupManifest")
    encryption_algorithm: Literal["AES-256-GCM"] = Field(
        default="AES-256-GCM",
        alias="encryptionAlgorithm",
    )
    encryption_key_id: _Identifier = Field(alias="encryptionKeyId")
    nonce_base64url: str = Field(
        alias="nonceBase64url",
        pattern=r"^[A-Za-z0-9_-]{16}$",
    )
    ciphertext_sha256: _Sha256 = Field(alias="ciphertextSha256")
    ciphertext_bytes: int = Field(
        alias="ciphertextBytes",
        ge=17,
        le=_MAX_RETAINED_BACKUP_BYTES,
    )

    @field_validator("nonce_base64url")
    @classmethod
    def require_canonical_nonce(cls, value: str) -> str:
        _base64url_decode(
            value,
            expected_length=12,
            label="SQLite Graph backup encryption nonce",
        )
        return value

    @model_validator(mode="after")
    def bind_retained_backup_identity(self) -> Self:
        _bind_retained_backup_identity(self)
        return self


def _bind_retained_backup_identity[
    RetainedStatementT: (
        _SQLiteGraphRetainedBackupStatementV1,
        SQLiteGraphRetainedBackupStatement,
    )
](statement: RetainedStatementT) -> RetainedStatementT:
    if statement.ciphertext_bytes != statement.backup_manifest.database_bytes + 16:
        raise ValueError("SQLite Graph retained backup ciphertext length is inconsistent")
    material = statement.model_dump(
        mode="json",
        by_alias=True,
        exclude={"retained_backup_id"},
    )
    digest = sha256(
        canonical_graph_json(
            material,
            label="SQLiteGraphRetainedBackupStatement",
            max_bytes=_MAX_RETAINED_BACKUP_MANIFEST_BYTES,
        )
    ).hexdigest()
    retained_backup_id = f"graph-store-retained-backup_{digest}"
    if statement.retained_backup_id and statement.retained_backup_id != retained_backup_id:
        raise ValueError("SQLite Graph retained backup ID differs from canonical material")
    object.__setattr__(statement, "retained_backup_id", retained_backup_id)
    return statement


class _SQLiteGraphRetainedBackupManifestV1(StrictModel):
    """Exact historical v1alpha1 detached signature bundle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/sqlite-graph-retained-backup-manifest/v1alpha1"
    ] = Field(
        default=_LEGACY_RETAINED_BACKUP_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphRetainedBackupManifest"] = (
        "SQLiteGraphRetainedBackupManifest"
    )
    statement: _SQLiteGraphRetainedBackupStatementV1
    signing_key_id: _Identifier = Field(alias="signingKeyId")
    signing_algorithm: Literal["Ed25519"] = Field(
        default="Ed25519",
        alias="signingAlgorithm",
    )
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_signature(self) -> Self:
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="SQLite Graph backup signature",
        )
        return self


class SQLiteGraphRetainedBackupManifest(StrictModel):
    """Canonical v1alpha2 detached signature bundle for one encrypted backup."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-retained-backup-manifest/v1alpha2"] = Field(
        default=GRAPH_STORE_RETAINED_BACKUP_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphRetainedBackupManifest"] = "SQLiteGraphRetainedBackupManifest"
    statement: SQLiteGraphRetainedBackupStatement
    signing_key_id: _Identifier = Field(alias="signingKeyId")
    signing_algorithm: Literal["Ed25519"] = Field(
        default="Ed25519",
        alias="signingAlgorithm",
    )
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_signature(self) -> Self:
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="SQLite Graph backup signature",
        )
        return self


@dataclass(frozen=True, slots=True)
class SQLiteGraphBackupSigner:
    """Sign retained-backup statements without serializing the private key."""

    key: SQLiteGraphBackupVerificationKey
    private_key: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        key: SQLiteGraphBackupVerificationKey,
        private_key: bytes,
    ) -> SQLiteGraphBackupSigner:
        if len(private_key) != 32:
            raise ValueError("Ed25519 SQLite Graph backup private key must contain 32 bytes")
        return cls(
            key=key,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
        )

    def __post_init__(self) -> None:
        try:
            canonical_key = SQLiteGraphBackupVerificationKey.model_validate(
                self.key.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise ValueError("SQLite Graph backup signing key is not canonical") from exc
        object.__setattr__(self, "key", canonical_key)
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            self.key.public_key_base64url,
            expected_length=32,
            label="SQLite Graph backup signing public key",
        )
        if public_bytes != expected:
            raise ValueError("SQLite Graph backup private key does not match its verification key")

    def sign(
        self,
        statement: SQLiteGraphRetainedBackupStatement,
    ) -> SQLiteGraphRetainedBackupManifest:
        canonical = _retained_backup_statement_bytes(statement)
        return SQLiteGraphRetainedBackupManifest(
            statement=statement,
            signingKeyId=self.key.key_id,
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN_V2 + canonical)
            ),
        )


@dataclass(frozen=True, slots=True)
class SQLiteGraphVerifiedRetainedBackup:
    """A signature-verified encrypted object and its exact canonical manifest bytes."""

    manifest: SQLiteGraphRetainedBackupManifest | _SQLiteGraphRetainedBackupManifestV1
    ciphertext: bytes = field(repr=False)
    manifest_bytes: bytes = field(repr=False)


def sqlite_graph_backup_public_key(private_key: bytes) -> str:
    """Derive the canonical public verification key from a raw Ed25519 seed."""

    if len(private_key) != 32:
        raise ValueError("Ed25519 SQLite Graph backup private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def sqlite_graph_retained_backup_manifest_path(retained_backup: Path) -> Path:
    """Return the fixed signed-manifest sidecar for one encrypted backup object."""

    normalized = _absolute_path(retained_backup)
    return Path(f"{normalized}.manifest.json")


def sqlite_graph_retained_backup_manifest_bytes(
    manifest: SQLiteGraphRetainedBackupManifest,
) -> bytes:
    """Serialize the exact canonical retained-backup manifest wire bytes."""

    return _retained_backup_manifest_bytes(manifest)


def verify_retained_sqlite_graph_backup(
    retained_backup: Path,
    *,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
) -> SQLiteGraphVerifiedRetainedBackup:
    """Verify canonical signature and ciphertext identity without decrypting."""

    retained_path = _absolute_path(retained_backup)
    manifest_path = sqlite_graph_retained_backup_manifest_path(retained_path)
    try:
        manifest_raw = read_bounded_regular_bytes(
            manifest_path,
            max_bytes=_MAX_RETAINED_BACKUP_MANIFEST_BYTES,
            label="SQLite Graph retained backup manifest",
            require_single_link=True,
        )
        try:
            parsed = parse_strict_json_bytes(
                manifest_raw,
                label="SQLite Graph retained backup manifest",
                max_bytes=_MAX_RETAINED_BACKUP_MANIFEST_BYTES,
                max_depth=24,
                max_nodes=128,
            )
            if not isinstance(parsed, dict):
                raise ValueError("retained backup manifest must be an object")
            api_version = parsed.get("apiVersion")
            manifest: (
                SQLiteGraphRetainedBackupManifest
                | _SQLiteGraphRetainedBackupManifestV1
            )
            if api_version == GRAPH_STORE_RETAINED_BACKUP_MANIFEST_API_VERSION:
                manifest = SQLiteGraphRetainedBackupManifest.model_validate(parsed)
            elif api_version == _LEGACY_RETAINED_BACKUP_MANIFEST_API_VERSION:
                manifest = _SQLiteGraphRetainedBackupManifestV1.model_validate(parsed)
            else:
                raise ValueError("retained backup manifest apiVersion is unsupported")
        except (ValidationError, ValueError) as exc:
            raise SQLiteGraphStoreError("SQLite Graph retained backup manifest is invalid") from exc
        if manifest_raw != _retained_backup_manifest_bytes(manifest):
            raise SQLiteGraphStoreError(
                "SQLite Graph retained backup manifest is not canonical bytes"
            )
        _verify_retained_backup_signature(manifest, trusted_signing_keys)
        ciphertext = read_bounded_regular_bytes(
            retained_path,
            max_bytes=_MAX_RETAINED_BACKUP_BYTES,
            label="SQLite Graph retained backup ciphertext",
            require_single_link=True,
        )
        statement = manifest.statement
        if (
            len(ciphertext) != statement.ciphertext_bytes
            or sha256(ciphertext).hexdigest() != statement.ciphertext_sha256
        ):
            raise SQLiteGraphStoreError("SQLite Graph retained backup ciphertext digest differs")
        return SQLiteGraphVerifiedRetainedBackup(
            manifest=manifest,
            ciphertext=ciphertext,
            manifest_bytes=manifest_raw,
        )
    except (
        OSError,
        ValidationError,
        ValueError,
        SQLiteGraphStoreError,
    ) as exc:
        if isinstance(exc, SQLiteGraphStoreError):
            raise
        raise SQLiteGraphStoreError("SQLite Graph retained backup verification failed") from exc


def create_retained_sqlite_graph_backup(
    store: SQLiteGraphStore,
    destination: Path,
    *,
    encryption_key_id: str,
    encryption_key: bytes,
    signer: SQLiteGraphBackupSigner,
    created_at: datetime | None = None,
) -> SQLiteGraphRetainedBackupManifest:
    """Create an encrypted and signed object suitable for off-host retention."""

    if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
        raise ValueError("AES-256-GCM SQLite Graph backup key must contain 32 bytes")
    if fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$", encryption_key_id) is None:
        raise ValueError("SQLite Graph backup encryption key ID is invalid")
    retained_path = _absolute_path(destination)
    manifest_path = sqlite_graph_retained_backup_manifest_path(retained_path)
    if store.path in {retained_path, manifest_path}:
        raise SQLiteGraphStoreError("SQLite Graph retained backup must not replace the live store")
    _prepare_private_parent(retained_path.parent)
    _require_absent_leaf(retained_path, label="SQLite Graph retained backup")
    _require_absent_leaf(
        manifest_path,
        label="SQLite Graph retained backup manifest",
    )

    workspace = _private_workspace(retained_path.parent)
    plaintext_backup = workspace / "canonical-graph.sqlite3"
    temporary_ciphertext: Path | None = None
    temporary_manifest: Path | None = None
    ciphertext_published = False
    try:
        backup_manifest = store.create_backup(
            plaintext_backup,
            created_at=created_at,
        )
        plaintext = read_bounded_regular_bytes(
            plaintext_backup,
            max_bytes=_MAX_GRAPH_BACKUP_BYTES,
            label="SQLite Graph retained backup plaintext",
            require_single_link=True,
        )
        nonce = os.urandom(12)
        nonce_base64url = _base64url_encode(nonce)
        aad = _retained_backup_aad(
            backup_manifest,
            encryption_key_id=encryption_key_id,
            nonce_base64url=nonce_base64url,
        )
        ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, aad)
        statement = SQLiteGraphRetainedBackupStatement(
            backupManifest=backup_manifest,
            encryptionKeyId=encryption_key_id,
            nonceBase64url=nonce_base64url,
            ciphertextSha256=sha256(ciphertext).hexdigest(),
            ciphertextBytes=len(ciphertext),
        )
        manifest = signer.sign(statement)
        temporary_ciphertext = _write_private_temporary(
            retained_path,
            ciphertext,
        )
        temporary_manifest = _write_private_temporary(
            manifest_path,
            _retained_backup_manifest_bytes(manifest),
        )
        _publish_exclusive(
            temporary_ciphertext,
            retained_path,
            label="SQLite Graph retained backup",
        )
        temporary_ciphertext = None
        ciphertext_published = True
        _publish_exclusive(
            temporary_manifest,
            manifest_path,
            label="SQLite Graph retained backup manifest",
        )
        temporary_manifest = None
        return manifest
    except (
        OSError,
        ValidationError,
        ValueError,
        SQLiteGraphStoreError,
    ) as exc:
        if ciphertext_published:
            with suppress(OSError):
                retained_path.unlink()
                _fsync_graph_directory(retained_path.parent)
        if isinstance(exc, SQLiteGraphStoreError):
            raise
        raise SQLiteGraphStoreError("SQLite Graph retained backup creation failed") from exc
    finally:
        if temporary_ciphertext is not None:
            with suppress(FileNotFoundError):
                temporary_ciphertext.unlink()
        if temporary_manifest is not None:
            with suppress(FileNotFoundError):
                temporary_manifest.unlink()
        _remove_private_workspace(workspace)


def restore_retained_sqlite_graph_backup(
    retained_backup: Path,
    *,
    destination: Path,
    campaign_id: str,
    encryption_key_id: str,
    encryption_key: bytes,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
) -> SQLiteGraphStore:
    """Verify, decrypt, and independently restore one retained backup object."""

    if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
        raise ValueError("AES-256-GCM SQLite Graph backup key must contain 32 bytes")
    retained_path = _absolute_path(retained_backup)
    manifest_path = sqlite_graph_retained_backup_manifest_path(retained_path)
    destination_path = _absolute_path(destination)
    if destination_path in {retained_path, manifest_path}:
        raise SQLiteGraphStoreError(
            "SQLite Graph retained backup restore destination overlaps its bundle"
        )
    _prepare_private_parent(destination_path.parent)
    _require_absent_leaf(
        destination_path,
        label="SQLite Graph retained backup restore destination",
    )
    workspace: Path | None = None
    plaintext_backup: Path | None = None
    try:
        verified = verify_retained_sqlite_graph_backup(
            retained_path,
            trusted_signing_keys=trusted_signing_keys,
        )
        manifest = verified.manifest
        statement = manifest.statement
        if statement.backup_manifest.campaign_id != campaign_id:
            raise SQLiteGraphStoreError("SQLite Graph retained backup belongs to another Campaign")
        if statement.encryption_key_id != encryption_key_id:
            raise SQLiteGraphStoreError(
                "SQLite Graph retained backup encryption key is not trusted"
            )
        ciphertext = verified.ciphertext
        nonce = _base64url_decode(
            statement.nonce_base64url,
            expected_length=12,
            label="SQLite Graph backup encryption nonce",
        )
        aad = _retained_backup_aad(
            statement.backup_manifest,
            encryption_key_id=statement.encryption_key_id,
            nonce_base64url=statement.nonce_base64url,
        )
        try:
            plaintext = AESGCM(encryption_key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise SQLiteGraphStoreError(
                "SQLite Graph retained backup decryption authentication failed"
            ) from exc
        if (
            len(plaintext) != statement.backup_manifest.database_bytes
            or sha256(plaintext).hexdigest() != statement.backup_manifest.database_sha256
        ):
            raise SQLiteGraphStoreError("SQLite Graph retained backup plaintext digest differs")

        workspace = _private_workspace(destination_path.parent)
        plaintext_backup = workspace / "canonical-graph.sqlite3"
        temporary_plaintext = _write_private_temporary(
            plaintext_backup,
            plaintext,
        )
        _publish_exclusive(
            temporary_plaintext,
            plaintext_backup,
            label="SQLite Graph retained backup plaintext",
        )
        plaintext_manifest_path = sqlite_graph_backup_manifest_path(plaintext_backup)
        temporary_plaintext_manifest = _write_private_temporary(
            plaintext_manifest_path,
            _backup_manifest_bytes(statement.backup_manifest),
        )
        _publish_exclusive(
            temporary_plaintext_manifest,
            plaintext_manifest_path,
            label="SQLite Graph retained backup plaintext manifest",
        )
        return SQLiteGraphStore.restore_backup(
            plaintext_backup,
            destination=destination_path,
            campaign_id=campaign_id,
        )
    except (
        OSError,
        ValidationError,
        ValueError,
        SQLiteGraphStoreError,
    ) as exc:
        if isinstance(exc, SQLiteGraphStoreError):
            raise
        raise SQLiteGraphStoreError("SQLite Graph retained backup restore failed") from exc
    finally:
        if workspace is not None and plaintext_backup is not None:
            _remove_private_workspace(workspace)


def _verify_retained_backup_signature(
    manifest: SQLiteGraphRetainedBackupManifest | _SQLiteGraphRetainedBackupManifestV1,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
) -> None:
    try:
        keys = tuple(
            SQLiteGraphBackupVerificationKey.model_validate(
                key.model_dump(mode="json", by_alias=True)
            )
            for key in trusted_signing_keys
        )
    except (AttributeError, ValidationError) as exc:
        raise SQLiteGraphStoreError("SQLite Graph backup verification key is invalid") from exc
    if len({key.key_id for key in keys}) != len(keys):
        raise SQLiteGraphStoreError("SQLite Graph backup verification key IDs are not unique")
    key = next(
        (item for item in keys if item.key_id == manifest.signing_key_id),
        None,
    )
    if key is None:
        raise SQLiteGraphStoreError("SQLite Graph retained backup signing key is not trusted")
    try:
        signature_domain = (
            _SIGNATURE_DOMAIN_V2
            if isinstance(manifest, SQLiteGraphRetainedBackupManifest)
            else _SIGNATURE_DOMAIN_V1
        )
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="SQLite Graph backup public key",
            )
        ).verify(
            _base64url_decode(
                manifest.signature_base64url,
                expected_length=64,
                label="SQLite Graph backup signature",
            ),
            signature_domain + _retained_backup_statement_bytes(manifest.statement),
        )
    except InvalidSignature as exc:
        raise SQLiteGraphStoreError(
            "SQLite Graph retained backup signature verification failed"
        ) from exc


def _retained_backup_aad(
    backup_manifest: SQLiteGraphBackupManifest | _SQLiteGraphBackupManifestV1,
    *,
    encryption_key_id: str,
    nonce_base64url: str,
) -> bytes:
    if isinstance(backup_manifest, SQLiteGraphBackupManifest):
        aad_domain = _ENCRYPTION_AAD_DOMAIN_V2
        retained_api_version: str = GRAPH_STORE_RETAINED_BACKUP_API_VERSION
    else:
        aad_domain = _ENCRYPTION_AAD_DOMAIN_V1
        retained_api_version = _LEGACY_RETAINED_BACKUP_API_VERSION
    return aad_domain + canonical_graph_json(
        {
            "apiVersion": retained_api_version,
            "backupId": backup_manifest.backup_id,
            "campaignId": backup_manifest.campaign_id,
            "encryptionAlgorithm": "AES-256-GCM",
            "encryptionKeyId": encryption_key_id,
            "nonceBase64url": nonce_base64url,
        },
        label="SQLiteGraphRetainedBackupAAD",
        max_bytes=4 * 1024,
    )


def _retained_backup_statement_bytes(
    statement: SQLiteGraphRetainedBackupStatement
    | _SQLiteGraphRetainedBackupStatementV1,
) -> bytes:
    return canonical_graph_json(
        statement.model_dump(mode="json", by_alias=True),
        label="SQLiteGraphRetainedBackupStatement",
        max_bytes=_MAX_RETAINED_BACKUP_MANIFEST_BYTES,
    )


def _retained_backup_manifest_bytes(
    manifest: SQLiteGraphRetainedBackupManifest | _SQLiteGraphRetainedBackupManifestV1,
) -> bytes:
    return (
        canonical_graph_json(
            manifest.model_dump(mode="json", by_alias=True),
            label="SQLiteGraphRetainedBackupManifest",
            max_bytes=_MAX_RETAINED_BACKUP_MANIFEST_BYTES,
        )
        + b"\n"
    )


def _private_workspace(parent: Path) -> Path:
    workspace = Path(
        tempfile.mkdtemp(
            prefix=".graph-retained-backup.",
            dir=parent,
        )
    )
    if os.name == "posix":
        workspace.chmod(0o700)
    return workspace


def _remove_private_workspace(workspace: Path) -> None:
    with suppress(FileNotFoundError):
        for child in workspace.iterdir():
            child.unlink()
        workspace.rmdir()
