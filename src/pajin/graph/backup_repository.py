"""Immutable backend publication and signed anti-rollback inventory for Graph backups."""

from __future__ import annotations

import base64
import binascii
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.backup_retention import (
    SQLiteGraphBackupVerificationKey,
    restore_retained_sqlite_graph_backup,
    sqlite_graph_retained_backup_manifest_path,
    verify_retained_sqlite_graph_backup,
)
from pajin.graph.models import canonical_graph_json
from pajin.graph.sqlite_store import (
    SQLiteGraphStore,
    SQLiteGraphStoreError,
    _absolute_path,
    _prepare_private_parent,
    _publish_exclusive,
    _require_absent_leaf,
    _write_private_temporary,
)

GRAPH_BACKUP_RETENTION_PUT_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-retention-put/v1alpha1"
] = "pajin.dev/sqlite-graph-backup-retention-put/v1alpha1"
GRAPH_BACKUP_RETENTION_RECEIPT_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-retention-receipt/v1alpha1"
] = "pajin.dev/sqlite-graph-backup-retention-receipt/v1alpha1"
GRAPH_BACKUP_RETENTION_PUBLICATION_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-retention-publication/v1alpha1"
] = "pajin.dev/sqlite-graph-backup-retention-publication/v1alpha1"
GRAPH_BACKUP_INVENTORY_API_VERSION: Literal["pajin.dev/sqlite-graph-backup-inventory/v1alpha1"] = (
    "pajin.dev/sqlite-graph-backup-inventory/v1alpha1"
)
GRAPH_BACKUP_INVENTORY_MANIFEST_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-inventory-manifest/v1alpha1"
] = "pajin.dev/sqlite-graph-backup-inventory-manifest/v1alpha1"
GRAPH_BACKUP_INVENTORY_ANCHOR_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-inventory-anchor/v1alpha1"
] = "pajin.dev/sqlite-graph-backup-inventory-anchor/v1alpha1"

_INVENTORY_SIGNATURE_DOMAIN = b"pajin.graph.sqlite-backup-inventory-signature/v1\0"
_MAX_OBJECT_KEY_BYTES = 1_024
_MAX_OBJECT_VERSION_BYTES = 256
_MAX_INVENTORY_PUBLICATIONS = 1_024
_MAX_INVENTORY_BYTES = 8 * 1024 * 1024
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RetainedBackupId = Annotated[
    str,
    Field(pattern=r"^graph-store-retained-backup_[a-f0-9]{64}$"),
]


class SQLiteGraphBackupRepositoryError(SQLiteGraphStoreError):
    """Raised when immutable retention or inventory verification fails closed."""


class SQLiteGraphBackupRetentionObjectKind(StrEnum):
    """The two immutable objects that form one retained backup publication."""

    CIPHERTEXT = "ciphertext"
    MANIFEST = "manifest"


class SQLiteGraphBackupObjectLockMode(StrEnum):
    """Backend-reported object-lock policy required for a publication."""

    GOVERNANCE = "governance"
    COMPLIANCE = "compliance"


def _require_aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


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


def _canonical_object_key(value: str) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("SQLite Graph backup object key must be valid UTF-8") from exc
    path = PurePosixPath(value)
    if (
        not encoded
        or len(encoded) > _MAX_OBJECT_KEY_BYTES
        or path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
    ):
        raise ValueError("SQLite Graph backup object key must be a canonical relative path")
    return value


class SQLiteGraphBackupRetentionPutRequest(StrictModel):
    """Exact immutable-object expectation sent to one retention backend."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-retention-put/v1alpha1"] = Field(
        default=GRAPH_BACKUP_RETENTION_PUT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupRetentionPut"] = "SQLiteGraphBackupRetentionPut"
    repository_id: _Identifier = Field(alias="repositoryId")
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    retained_backup_id: _RetainedBackupId = Field(alias="retainedBackupId")
    object_kind: SQLiteGraphBackupRetentionObjectKind = Field(alias="objectKind")
    object_key: str = Field(alias="objectKey", min_length=1, max_length=_MAX_OBJECT_KEY_BYTES)
    content_sha256: _Sha256 = Field(alias="contentSha256")
    content_bytes: int = Field(alias="contentBytes", strict=True, ge=1, le=512 * 1024 * 1024)
    object_lock_mode: SQLiteGraphBackupObjectLockMode = Field(alias="objectLockMode")
    retention_until: datetime = Field(alias="retentionUntil")
    requested_at: datetime = Field(alias="requestedAt")

    @field_validator("object_key")
    @classmethod
    def require_canonical_object_key(cls, value: str) -> str:
        return _canonical_object_key(value)

    @model_validator(mode="after")
    def require_future_retention(self) -> Self:
        requested = _require_aware_utc(self.requested_at, label="retention request time")
        retained = _require_aware_utc(self.retention_until, label="retention end time")
        if retained <= requested:
            raise ValueError("SQLite Graph backup retention window must end after its request")
        return self


class SQLiteGraphBackupRetentionObjectReceipt(StrictModel):
    """Backend observation that one exact object is immutable through a deadline."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-retention-receipt/v1alpha1"] = Field(
        default=GRAPH_BACKUP_RETENTION_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupRetentionObjectReceipt"] = (
        "SQLiteGraphBackupRetentionObjectReceipt"
    )
    repository_id: _Identifier = Field(alias="repositoryId")
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    retained_backup_id: _RetainedBackupId = Field(alias="retainedBackupId")
    object_kind: SQLiteGraphBackupRetentionObjectKind = Field(alias="objectKind")
    object_key: str = Field(alias="objectKey", min_length=1, max_length=_MAX_OBJECT_KEY_BYTES)
    content_sha256: _Sha256 = Field(alias="contentSha256")
    content_bytes: int = Field(alias="contentBytes", strict=True, ge=1, le=512 * 1024 * 1024)
    object_version: str = Field(
        alias="objectVersion",
        min_length=1,
        max_length=_MAX_OBJECT_VERSION_BYTES,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/=-]*$",
    )
    object_lock_mode: SQLiteGraphBackupObjectLockMode = Field(alias="objectLockMode")
    retention_until: datetime = Field(alias="retentionUntil")
    stored_at: datetime = Field(alias="storedAt")
    backend_evidence_sha256: _Sha256 = Field(alias="backendEvidenceSha256")

    @field_validator("object_key")
    @classmethod
    def require_canonical_object_key(cls, value: str) -> str:
        return _canonical_object_key(value)

    @model_validator(mode="after")
    def require_nonempty_retention(self) -> Self:
        stored = _require_aware_utc(self.stored_at, label="object store time")
        retained = _require_aware_utc(self.retention_until, label="object retention end time")
        if retained <= stored:
            raise ValueError("SQLite Graph backup object retention window is empty")
        return self


class SQLiteGraphBackupRetentionBackend(Protocol):
    """Externally implemented immutable object repository boundary."""

    @property
    def repository_id(self) -> str:
        """Return the configured repository identity."""

    def put_if_absent(
        self,
        request: SQLiteGraphBackupRetentionPutRequest,
        content: bytes,
    ) -> SQLiteGraphBackupRetentionObjectReceipt:
        """Create or observe the same immutable object without replacement."""

    def read_exact(
        self,
        receipt: SQLiteGraphBackupRetentionObjectReceipt,
    ) -> bytes:
        """Read the exact object version named by one verified receipt."""


class SQLiteGraphBackupRetentionPublication(StrictModel):
    """Content-addressed pair of backend receipts for one retained backup."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-retention-publication/v1alpha1"] = Field(
        default=GRAPH_BACKUP_RETENTION_PUBLICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupRetentionPublication"] = "SQLiteGraphBackupRetentionPublication"
    publication_id: str = Field(default="", alias="publicationId", max_length=108)
    retained_backup_id: _RetainedBackupId = Field(alias="retainedBackupId")
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    retained_manifest_sha256: _Sha256 = Field(alias="retainedManifestSha256")
    ciphertext_receipt: SQLiteGraphBackupRetentionObjectReceipt = Field(alias="ciphertextReceipt")
    manifest_receipt: SQLiteGraphBackupRetentionObjectReceipt = Field(alias="manifestReceipt")

    @model_validator(mode="after")
    def bind_publication_identity(self) -> Self:
        ciphertext = self.ciphertext_receipt
        manifest = self.manifest_receipt
        expected_prefix = f"{self.campaign_id}/{self.retained_backup_id}"
        if (
            ciphertext.repository_id != manifest.repository_id
            or ciphertext.campaign_id != self.campaign_id
            or manifest.campaign_id != self.campaign_id
            or ciphertext.retained_backup_id != self.retained_backup_id
            or manifest.retained_backup_id != self.retained_backup_id
            or ciphertext.object_kind is not SQLiteGraphBackupRetentionObjectKind.CIPHERTEXT
            or manifest.object_kind is not SQLiteGraphBackupRetentionObjectKind.MANIFEST
            or ciphertext.object_key != f"{expected_prefix}/ciphertext.bin"
            or manifest.object_key != f"{expected_prefix}/manifest.json"
            or manifest.content_sha256 != self.retained_manifest_sha256
        ):
            raise ValueError("SQLite Graph backup publication receipts are inconsistent")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"publication_id"},
        )
        digest = sha256(
            canonical_graph_json(
                material,
                label="SQLiteGraphBackupRetentionPublication",
                max_bytes=256 * 1024,
            )
        ).hexdigest()
        publication_id = f"graph-backup-publication_{digest}"
        if self.publication_id and self.publication_id != publication_id:
            raise ValueError("SQLite Graph backup publication ID differs from canonical material")
        object.__setattr__(self, "publication_id", publication_id)
        return self


class SQLiteGraphBackupInventoryStatement(StrictModel):
    """One cumulative append-only inventory revision for retained publications."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-inventory/v1alpha1"] = Field(
        default=GRAPH_BACKUP_INVENTORY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupInventory"] = "SQLiteGraphBackupInventory"
    inventory_id: str = Field(default="", alias="inventoryId", max_length=106)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    sequence: int = Field(strict=True, ge=1, le=_MAX_INVENTORY_PUBLICATIONS)
    previous_inventory_sha256: _Sha256 | None = Field(alias="previousInventorySha256")
    publications: tuple[SQLiteGraphBackupRetentionPublication, ...] = Field(
        min_length=1,
        max_length=_MAX_INVENTORY_PUBLICATIONS,
    )
    issued_at: datetime = Field(alias="issuedAt")

    @model_validator(mode="after")
    def bind_inventory_identity(self) -> Self:
        _require_aware_utc(self.issued_at, label="backup inventory issue time")
        if self.sequence != len(self.publications):
            raise ValueError("SQLite Graph backup inventory sequence differs from its entries")
        if (self.sequence == 1) is not (self.previous_inventory_sha256 is None):
            raise ValueError("SQLite Graph backup inventory predecessor is inconsistent")
        if any(item.campaign_id != self.campaign_id for item in self.publications):
            raise ValueError("SQLite Graph backup inventory contains another Campaign")
        retained_ids = [item.retained_backup_id for item in self.publications]
        publication_ids = [item.publication_id for item in self.publications]
        if len(retained_ids) != len(set(retained_ids)) or len(publication_ids) != len(
            set(publication_ids)
        ):
            raise ValueError("SQLite Graph backup inventory contains duplicate publications")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"inventory_id"},
        )
        digest = sha256(
            canonical_graph_json(
                material,
                label="SQLiteGraphBackupInventoryStatement",
                max_bytes=_MAX_INVENTORY_BYTES,
            )
        ).hexdigest()
        inventory_id = f"graph-backup-inventory_{digest}"
        if self.inventory_id and self.inventory_id != inventory_id:
            raise ValueError("SQLite Graph backup inventory ID differs from canonical material")
        object.__setattr__(self, "inventory_id", inventory_id)
        return self


class SQLiteGraphBackupInventoryManifest(StrictModel):
    """Externally signed canonical wire bundle for one inventory revision."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-inventory-manifest/v1alpha1"] = Field(
        default=GRAPH_BACKUP_INVENTORY_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupInventoryManifest"] = "SQLiteGraphBackupInventoryManifest"
    statement: SQLiteGraphBackupInventoryStatement
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
            label="SQLite Graph backup inventory signature",
        )
        return self


class SQLiteGraphBackupInventoryAnchor(StrictModel):
    """Externally pinned minimum inventory revision used to reject rollback."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-inventory-anchor/v1alpha1"] = Field(
        default=GRAPH_BACKUP_INVENTORY_ANCHOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupInventoryAnchor"] = "SQLiteGraphBackupInventoryAnchor"
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    sequence: int = Field(strict=True, ge=1, le=_MAX_INVENTORY_PUBLICATIONS)
    inventory_id: str = Field(
        alias="inventoryId",
        pattern=r"^graph-backup-inventory_[a-f0-9]{64}$",
    )
    inventory_manifest_sha256: _Sha256 = Field(alias="inventoryManifestSha256")


@dataclass(frozen=True, slots=True)
class SQLiteGraphBackupInventorySigner:
    """Sign inventory revisions with an externally managed Ed25519 key."""

    key: SQLiteGraphBackupVerificationKey
    private_key: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        key: SQLiteGraphBackupVerificationKey,
        private_key: bytes,
    ) -> SQLiteGraphBackupInventorySigner:
        if len(private_key) != 32:
            raise ValueError(
                "Ed25519 SQLite Graph backup inventory private key must contain 32 bytes"
            )
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
            raise ValueError("SQLite Graph backup inventory signing key is invalid") from exc
        object.__setattr__(self, "key", canonical_key)
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            self.key.public_key_base64url,
            expected_length=32,
            label="SQLite Graph backup inventory public key",
        )
        if public_bytes != expected:
            raise ValueError(
                "SQLite Graph backup inventory private key does not match its public key"
            )

    def sign(
        self,
        statement: SQLiteGraphBackupInventoryStatement,
    ) -> SQLiteGraphBackupInventoryManifest:
        return SQLiteGraphBackupInventoryManifest(
            statement=statement,
            signingKeyId=self.key.key_id,
            signatureBase64url=_base64url_encode(
                self.private_key.sign(
                    _INVENTORY_SIGNATURE_DOMAIN + _inventory_statement_bytes(statement)
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class SQLiteGraphVerifiedBackupInventory:
    """A fully verified chain, its latest anchor, and cumulative publications."""

    anchor: SQLiteGraphBackupInventoryAnchor
    publications: tuple[SQLiteGraphBackupRetentionPublication, ...]


def publish_retained_sqlite_graph_backup(
    retained_backup: Path,
    *,
    backend: SQLiteGraphBackupRetentionBackend,
    retention_until: datetime,
    object_lock_mode: SQLiteGraphBackupObjectLockMode,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
    requested_at: datetime | None = None,
) -> SQLiteGraphBackupRetentionPublication:
    """Publish verified ciphertext and manifest through a put-if-absent backend."""

    requested = _require_aware_utc(
        requested_at or datetime.now(UTC),
        label="retention request time",
    )
    retained = _require_aware_utc(retention_until, label="retention end time")
    if retained <= requested:
        raise ValueError("SQLite Graph backup retention window must end after its request")
    verified = verify_retained_sqlite_graph_backup(
        retained_backup,
        trusted_signing_keys=trusted_signing_keys,
    )
    statement = verified.manifest.statement
    repository_id = backend.repository_id
    prefix = f"{statement.backup_manifest.campaign_id}/{statement.retained_backup_id}"
    ciphertext_request = SQLiteGraphBackupRetentionPutRequest(
        repositoryId=repository_id,
        campaignId=statement.backup_manifest.campaign_id,
        retainedBackupId=statement.retained_backup_id,
        objectKind=SQLiteGraphBackupRetentionObjectKind.CIPHERTEXT,
        objectKey=f"{prefix}/ciphertext.bin",
        contentSha256=statement.ciphertext_sha256,
        contentBytes=statement.ciphertext_bytes,
        objectLockMode=object_lock_mode,
        retentionUntil=retained,
        requestedAt=requested,
    )
    manifest_sha256 = sha256(verified.manifest_bytes).hexdigest()
    manifest_request = SQLiteGraphBackupRetentionPutRequest(
        repositoryId=repository_id,
        campaignId=statement.backup_manifest.campaign_id,
        retainedBackupId=statement.retained_backup_id,
        objectKind=SQLiteGraphBackupRetentionObjectKind.MANIFEST,
        objectKey=f"{prefix}/manifest.json",
        contentSha256=manifest_sha256,
        contentBytes=len(verified.manifest_bytes),
        objectLockMode=object_lock_mode,
        retentionUntil=retained,
        requestedAt=requested,
    )
    try:
        ciphertext_receipt = backend.put_if_absent(
            ciphertext_request,
            verified.ciphertext,
        )
        _require_exact_backend_receipt(ciphertext_request, ciphertext_receipt)
        manifest_receipt = backend.put_if_absent(
            manifest_request,
            verified.manifest_bytes,
        )
        _require_exact_backend_receipt(manifest_request, manifest_receipt)
        return SQLiteGraphBackupRetentionPublication(
            retainedBackupId=statement.retained_backup_id,
            campaignId=statement.backup_manifest.campaign_id,
            retainedManifestSha256=manifest_sha256,
            ciphertextReceipt=ciphertext_receipt,
            manifestReceipt=manifest_receipt,
        )
    except (
        OSError,
        ValidationError,
        ValueError,
        SQLiteGraphBackupRepositoryError,
        SQLiteGraphStoreError,
    ) as exc:
        if isinstance(exc, SQLiteGraphBackupRepositoryError):
            raise
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph retained backup publication failed"
        ) from exc


def append_sqlite_graph_backup_inventory(
    chain: Iterable[SQLiteGraphBackupInventoryManifest],
    publication: SQLiteGraphBackupRetentionPublication,
    *,
    signer: SQLiteGraphBackupInventorySigner,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
    issued_at: datetime | None = None,
) -> SQLiteGraphBackupInventoryManifest:
    """Append exactly one publication to a verified cumulative inventory chain."""

    existing = tuple(chain)
    timestamp = _require_aware_utc(
        issued_at or datetime.now(UTC),
        label="backup inventory issue time",
    )
    publications: tuple[SQLiteGraphBackupRetentionPublication, ...]
    previous_sha256: str | None
    if existing:
        verified = verify_sqlite_graph_backup_inventory_chain(
            existing,
            trusted_signing_keys=trusted_signing_keys,
        )
        latest = existing[-1]
        if publication.campaign_id != verified.anchor.campaign_id:
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup publication belongs to another Campaign"
            )
        if timestamp <= _require_aware_utc(
            latest.statement.issued_at,
            label="previous backup inventory issue time",
        ):
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup inventory issue time did not advance"
            )
        publications = (*verified.publications, publication)
        previous_sha256 = sha256(sqlite_graph_backup_inventory_manifest_bytes(latest)).hexdigest()
    else:
        publications = (publication,)
        previous_sha256 = None
    try:
        statement = SQLiteGraphBackupInventoryStatement(
            campaignId=publication.campaign_id,
            sequence=len(publications),
            previousInventorySha256=previous_sha256,
            publications=publications,
            issuedAt=timestamp,
        )
        return signer.sign(statement)
    except (ValidationError, ValueError) as exc:
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup inventory append failed"
        ) from exc


def verify_sqlite_graph_backup_inventory_chain(
    chain: Iterable[SQLiteGraphBackupInventoryManifest],
    *,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
    required_anchor: SQLiteGraphBackupInventoryAnchor | None = None,
) -> SQLiteGraphVerifiedBackupInventory:
    """Verify signatures, prefix extension, and an optional external anti-rollback pin."""

    manifests = tuple(chain)
    if not manifests:
        raise SQLiteGraphBackupRepositoryError("SQLite Graph backup inventory chain is empty")
    keys = _canonical_verification_keys(trusted_signing_keys)
    previous: SQLiteGraphBackupInventoryManifest | None = None
    canonical_manifests: list[SQLiteGraphBackupInventoryManifest] = []
    for expected_sequence, candidate in enumerate(manifests, start=1):
        try:
            manifest = SQLiteGraphBackupInventoryManifest.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup inventory manifest is invalid"
            ) from exc
        _verify_inventory_signature(manifest, keys)
        statement = manifest.statement
        if statement.sequence != expected_sequence:
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup inventory sequence is not contiguous"
            )
        if previous is None:
            if statement.previous_inventory_sha256 is not None:
                raise SQLiteGraphBackupRepositoryError(
                    "SQLite Graph backup inventory genesis has a predecessor"
                )
        else:
            previous_statement = previous.statement
            expected_previous = sha256(
                sqlite_graph_backup_inventory_manifest_bytes(previous)
            ).hexdigest()
            if (
                statement.campaign_id != previous_statement.campaign_id
                or statement.previous_inventory_sha256 != expected_previous
                or statement.publications[:-1] != previous_statement.publications
                or statement.issued_at <= previous_statement.issued_at
            ):
                raise SQLiteGraphBackupRepositoryError(
                    "SQLite Graph backup inventory is not an exact append-only extension"
                )
        canonical_manifests.append(manifest)
        previous = manifest
    latest = canonical_manifests[-1]
    anchor = sqlite_graph_backup_inventory_anchor(latest)
    if required_anchor is not None:
        try:
            required = SQLiteGraphBackupInventoryAnchor.model_validate(
                required_anchor.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup inventory anchor is invalid"
            ) from exc
        if required.campaign_id != anchor.campaign_id:
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup inventory anchor belongs to another Campaign"
            )
        if anchor.sequence < required.sequence:
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup inventory is older than the external anchor"
            )
        pinned = canonical_manifests[required.sequence - 1]
        pinned_anchor = sqlite_graph_backup_inventory_anchor(pinned)
        if pinned_anchor != required:
            raise SQLiteGraphBackupRepositoryError(
                "SQLite Graph backup inventory fork differs from the external anchor"
            )
    return SQLiteGraphVerifiedBackupInventory(
        anchor=anchor,
        publications=latest.statement.publications,
    )


def restore_published_sqlite_graph_backup(
    chain: Iterable[SQLiteGraphBackupInventoryManifest],
    *,
    required_anchor: SQLiteGraphBackupInventoryAnchor,
    retained_backup_id: str,
    backend: SQLiteGraphBackupRetentionBackend,
    destination: Path,
    campaign_id: str,
    encryption_key_id: str,
    encryption_key: bytes,
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
    trusted_inventory_keys: Iterable[SQLiteGraphBackupVerificationKey],
) -> SQLiteGraphStore:
    """Restore one backend object only after verifying the externally pinned inventory."""

    if required_anchor is None:
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph published backup restore requires an external inventory anchor"
        )
    verified_inventory = verify_sqlite_graph_backup_inventory_chain(
        chain,
        trusted_signing_keys=trusted_inventory_keys,
        required_anchor=required_anchor,
    )
    publication = next(
        (
            item
            for item in verified_inventory.publications
            if item.retained_backup_id == retained_backup_id
        ),
        None,
    )
    if publication is None:
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph retained backup is absent from the verified inventory"
        )
    if (
        publication.campaign_id != campaign_id
        or publication.ciphertext_receipt.repository_id != backend.repository_id
    ):
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph retained backup publication authority differs"
        )
    destination_path = _absolute_path(destination)
    _prepare_private_parent(destination_path.parent)
    _require_absent_leaf(
        destination_path,
        label="SQLite Graph published backup restore destination",
    )
    workspace = Path(
        tempfile.mkdtemp(
            prefix=".graph-backup-repository-restore.",
            dir=destination_path.parent,
        )
    )
    retained_path = workspace / "retained-backup.enc"
    try:
        ciphertext = backend.read_exact(publication.ciphertext_receipt)
        manifest_bytes = backend.read_exact(publication.manifest_receipt)
        _require_receipt_content(publication.ciphertext_receipt, ciphertext)
        _require_receipt_content(publication.manifest_receipt, manifest_bytes)
        temporary_ciphertext = _write_private_temporary(retained_path, ciphertext)
        _publish_exclusive(
            temporary_ciphertext,
            retained_path,
            label="SQLite Graph repository restore ciphertext",
        )
        retained_manifest_path = sqlite_graph_retained_backup_manifest_path(retained_path)
        temporary_manifest = _write_private_temporary(
            retained_manifest_path,
            manifest_bytes,
        )
        _publish_exclusive(
            temporary_manifest,
            retained_manifest_path,
            label="SQLite Graph repository restore manifest",
        )
        return restore_retained_sqlite_graph_backup(
            retained_path,
            destination=destination_path,
            campaign_id=campaign_id,
            encryption_key_id=encryption_key_id,
            encryption_key=encryption_key,
            trusted_signing_keys=trusted_signing_keys,
        )
    except (
        OSError,
        ValidationError,
        ValueError,
        SQLiteGraphBackupRepositoryError,
        SQLiteGraphStoreError,
    ) as exc:
        if isinstance(exc, SQLiteGraphBackupRepositoryError):
            raise
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph published backup restore failed"
        ) from exc
    finally:
        with suppress(FileNotFoundError):
            for child in workspace.iterdir():
                child.unlink()
            workspace.rmdir()


def sqlite_graph_backup_inventory_manifest_bytes(
    manifest: SQLiteGraphBackupInventoryManifest,
) -> bytes:
    """Serialize exact canonical signed inventory bytes."""

    return (
        canonical_graph_json(
            manifest.model_dump(mode="json", by_alias=True),
            label="SQLiteGraphBackupInventoryManifest",
            max_bytes=_MAX_INVENTORY_BYTES,
        )
        + b"\n"
    )


def sqlite_graph_backup_inventory_anchor(
    manifest: SQLiteGraphBackupInventoryManifest,
) -> SQLiteGraphBackupInventoryAnchor:
    """Derive the externally persisted anti-rollback pin for one revision."""

    canonical = sqlite_graph_backup_inventory_manifest_bytes(manifest)
    return SQLiteGraphBackupInventoryAnchor(
        campaignId=manifest.statement.campaign_id,
        sequence=manifest.statement.sequence,
        inventoryId=manifest.statement.inventory_id,
        inventoryManifestSha256=sha256(canonical).hexdigest(),
    )


def _inventory_statement_bytes(statement: SQLiteGraphBackupInventoryStatement) -> bytes:
    return canonical_graph_json(
        statement.model_dump(mode="json", by_alias=True),
        label="SQLiteGraphBackupInventoryStatement",
        max_bytes=_MAX_INVENTORY_BYTES,
    )


def _canonical_verification_keys(
    trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
) -> dict[str, SQLiteGraphBackupVerificationKey]:
    try:
        keys = tuple(
            SQLiteGraphBackupVerificationKey.model_validate(
                key.model_dump(mode="json", by_alias=True)
            )
            for key in trusted_signing_keys
        )
    except (AttributeError, ValidationError) as exc:
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup inventory verification key is invalid"
        ) from exc
    if len({key.key_id for key in keys}) != len(keys):
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup inventory verification key IDs are not unique"
        )
    return {key.key_id: key for key in keys}


def _verify_inventory_signature(
    manifest: SQLiteGraphBackupInventoryManifest,
    keys: dict[str, SQLiteGraphBackupVerificationKey],
) -> None:
    key = keys.get(manifest.signing_key_id)
    if key is None:
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup inventory signing key is not trusted"
        )
    try:
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="SQLite Graph backup inventory public key",
            )
        ).verify(
            _base64url_decode(
                manifest.signature_base64url,
                expected_length=64,
                label="SQLite Graph backup inventory signature",
            ),
            _INVENTORY_SIGNATURE_DOMAIN + _inventory_statement_bytes(manifest.statement),
        )
    except InvalidSignature as exc:
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup inventory signature verification failed"
        ) from exc


def _require_exact_backend_receipt(
    request: SQLiteGraphBackupRetentionPutRequest,
    receipt: SQLiteGraphBackupRetentionObjectReceipt,
) -> None:
    try:
        canonical = SQLiteGraphBackupRetentionObjectReceipt.model_validate(
            receipt.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup backend receipt is invalid"
        ) from exc
    if (
        canonical.repository_id != request.repository_id
        or canonical.campaign_id != request.campaign_id
        or canonical.retained_backup_id != request.retained_backup_id
        or canonical.object_kind is not request.object_kind
        or canonical.object_key != request.object_key
        or canonical.content_sha256 != request.content_sha256
        or canonical.content_bytes != request.content_bytes
        or canonical.object_lock_mode is not request.object_lock_mode
        or canonical.retention_until < request.retention_until
        or canonical.stored_at < request.requested_at
    ):
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup backend receipt differs from its put request"
        )


def _require_receipt_content(
    receipt: SQLiteGraphBackupRetentionObjectReceipt,
    content: bytes,
) -> None:
    if (
        not isinstance(content, bytes)
        or len(content) != receipt.content_bytes
        or sha256(content).hexdigest() != receipt.content_sha256
    ):
        raise SQLiteGraphBackupRepositoryError(
            "SQLite Graph backup repository object differs from its receipt"
        )
