"""Durable provider activation and attempt recovery for Object Storage transport."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from abc import abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from functools import cache
from hashlib import sha256
from pathlib import Path
from typing import Literal, Protocol, Self, TypeVar, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.control_plane.artifact_transfer import PortableArtifactMultipartTransportReceipt
from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.object_storage_activation import (
    ObjectStorageAuthorityHeadActivation,
    ObjectStorageAuthorityHeadCheckpoint,
    ObjectStorageAuthorityHeadStore,
    ObjectStorageAuthorityHeadStoreError,
)
from pajin.control_plane.object_storage_authority import (
    ObjectStorageDeploymentAuthority,
    ObjectStorageTransportBinding,
)
from pajin.control_plane.object_storage_provider import (
    EphemeralObjectStorageUploadCredential,
    ObjectStorageCleanupDisposition,
    ObjectStorageProviderAdapter,
    ObjectStorageProviderAdapterDefinition,
    ObjectStorageProviderCallRejected,
    ObjectStorageProviderRuntime,
)
from pajin.domain.models import StrictModel

OBJECT_STORAGE_PROVIDER_DEPLOYMENT_PROFILE_API_VERSION = (
    "pajin.control-plane.object-storage-provider-deployment-profile/v1"
)
OBJECT_STORAGE_CONCRETE_PROVIDER_ACTIVATION_API_VERSION = (
    "pajin.control-plane.object-storage-concrete-provider-activation/v1"
)
OBJECT_STORAGE_PROVIDER_ATTEMPT_API_VERSION = (
    "pajin.control-plane.object-storage-provider-attempt/v1"
)
OBJECT_STORAGE_PROVIDER_ATTEMPT_OPERATION_API_VERSION = (
    "pajin.control-plane.object-storage-provider-attempt-operation/v1"
)
OBJECT_STORAGE_PROVIDER_ATTEMPT_RECORD_API_VERSION = (
    "pajin.control-plane.object-storage-provider-attempt-record/v1"
)
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_OPERATION_ID_PATTERN = re.compile(
    r"^object-storage-attempt-operation_f([0-9]{20})_([a-f0-9]{64})$"
)
_BUSY_TIMEOUT_MS = 5_000
_MAX_JSON_BYTES = 8 * 1024 * 1024
_SCHEMA_VERSION = "1"
_SCHEMA_SQL = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE activations (
    sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
    activation_digest TEXT NOT NULL UNIQUE,
    activation_json TEXT NOT NULL
);
CREATE TABLE fences (
    scope_digest TEXT PRIMARY KEY,
    value INTEGER NOT NULL CHECK(value >= 1)
);
CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    scope_digest TEXT NOT NULL,
    fence INTEGER NOT NULL CHECK(fence >= 1),
    attempt_json TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open', 'completed', 'reconciled')),
    active_recovery_fence INTEGER,
    resolution TEXT,
    UNIQUE(scope_digest, fence)
);
CREATE UNIQUE INDEX one_open_object_storage_attempt
ON attempts(state) WHERE state = 'open';
CREATE TABLE records (
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    sequence INTEGER NOT NULL CHECK(sequence >= 1),
    operation_id TEXT NOT NULL,
    record_type TEXT NOT NULL CHECK(
        record_type IN ('intent', 'succeeded', 'rejected', 'unknown')
    ),
    record_json TEXT NOT NULL,
    PRIMARY KEY(attempt_id, sequence),
    UNIQUE(attempt_id, operation_id, record_type)
);
CREATE TRIGGER activations_no_update
BEFORE UPDATE ON activations BEGIN SELECT RAISE(ABORT, 'activations are append-only'); END;
CREATE TRIGGER activations_no_delete
BEFORE DELETE ON activations BEGIN SELECT RAISE(ABORT, 'activations are append-only'); END;
CREATE TRIGGER records_no_update
BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT, 'records are append-only'); END;
CREATE TRIGGER records_no_delete
BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT, 'records are append-only'); END;
"""
_SCHEMA_DIGEST = sha256(_SCHEMA_SQL.encode("utf-8")).hexdigest()
_T = TypeVar("_T")


class ObjectStorageProviderRecoveryError(RuntimeError):
    """Raised when durable provider activation or recovery cannot be proven."""


def _canonical_json(value: object) -> bytes:
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


class ObjectStorageProviderDeploymentProfile(StrictModel):
    """Secret-free guarantees required from one deployment-supplied provider."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-deployment-profile/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-provider-deployment-profile/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageProviderDeploymentProfile"] = (
        "ObjectStorageProviderDeploymentProfile"
    )
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    provider_family: str = Field(alias="providerFamily", pattern=_IDENTIFIER_PATTERN)
    credential_custody: Literal["deployment-runtime-only"] = Field(
        default="deployment-runtime-only",
        alias="credentialCustody",
    )
    multipart_idempotency: Literal["operation-id-with-monotonic-fence"] = Field(
        default="operation-id-with-monotonic-fence",
        alias="multipartIdempotency",
    )
    signature_coverage: Literal["put-exact-key-expiry"] = Field(
        default="put-exact-key-expiry",
        alias="signatureCoverage",
    )
    redirect_policy: Literal["reject-all"] = Field(
        default="reject-all",
        alias="redirectPolicy",
    )
    server_side_encryption_policy_id: str = Field(
        alias="serverSideEncryptionPolicyId",
        pattern=_IDENTIFIER_PATTERN,
    )
    read_after_write_consistency: Literal["strong"] = Field(
        default="strong",
        alias="readAfterWriteConsistency",
    )
    prefix_cleanup_semantics: Literal["idempotent-observed"] = Field(
        default="idempotent-observed",
        alias="prefixCleanupSemantics",
    )
    local_conformance_profile_id: str = Field(
        alias="localConformanceProfileId",
        pattern=_IDENTIFIER_PATTERN,
    )
    transport_only: Literal[True] = Field(default=True, alias="transportOnly")
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator(
        "transport_only",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage provider profile flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_profile(self) -> Self:
        if self.profile_digest and not re.fullmatch(_SHA256_PATTERN, self.profile_digest):
            raise ValueError("Object Storage provider profile digest must be lowercase SHA-256")
        material = self.model_dump(mode="json", by_alias=True, exclude={"profile_digest"})
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_DEPLOYMENT_PROFILE_API_VERSION, material)
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("Object Storage provider profile digest differs")
        object.__setattr__(self, "profile_digest", digest)
        return self


class ObjectStorageConcreteProviderActivation(StrictModel):
    """Append-only activation of one exact provider against one exact authority head."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-concrete-provider-activation/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-concrete-provider-activation/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageConcreteProviderActivation"] = (
        "ObjectStorageConcreteProviderActivation"
    )
    activation_digest: str = Field(default="", alias="activationDigest", max_length=64)
    sequence: int = Field(strict=True, ge=1, le=2**31 - 1)
    previous_activation_digest: str | None = Field(
        default=None,
        alias="previousActivationDigest",
        pattern=_SHA256_PATTERN,
    )
    authority_checkpoint: ObjectStorageAuthorityHeadCheckpoint = Field(alias="authorityCheckpoint")
    adapter: ObjectStorageProviderAdapterDefinition
    deployment_profile: ObjectStorageProviderDeploymentProfile = Field(alias="deploymentProfile")
    activated_at: datetime = Field(alias="activatedAt")
    transport_active: Literal[True] = Field(default=True, alias="transportActive")
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
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage provider activation time")

    @field_validator(
        "transport_active",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage provider activation flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_activation(self) -> Self:
        if (self.sequence == 1) != (self.previous_activation_digest is None):
            raise ValueError("Object Storage provider activation chain is not contiguous")
        if self.adapter.endpoint_origin == "":
            raise ValueError("Object Storage provider activation adapter is empty")
        if self.activation_digest and not re.fullmatch(_SHA256_PATTERN, self.activation_digest):
            raise ValueError("Object Storage provider activation digest must be lowercase SHA-256")
        material = self.model_dump(mode="json", by_alias=True, exclude={"activation_digest"})
        digest = _domain_digest(
            OBJECT_STORAGE_CONCRETE_PROVIDER_ACTIVATION_API_VERSION,
            material,
        )
        if self.activation_digest and self.activation_digest != digest:
            raise ValueError("Object Storage provider activation digest differs")
        object.__setattr__(self, "activation_digest", digest)
        return self


class ObjectStorageProviderAttempt(StrictModel):
    """One durable attempt bound to provider activation, authority head, and binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-attempt/v1"] = Field(
        default="pajin.control-plane.object-storage-provider-attempt/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageProviderAttempt"] = "ObjectStorageProviderAttempt"
    attempt_id: str = Field(default="", alias="attemptId", max_length=96)
    attempt_digest: str = Field(default="", alias="attemptDigest", max_length=64)
    activation_digest: str = Field(alias="activationDigest", pattern=_SHA256_PATTERN)
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    authority_checkpoint: ObjectStorageAuthorityHeadCheckpoint = Field(alias="authorityCheckpoint")
    binding_digest: str = Field(alias="bindingDigest", pattern=_SHA256_PATTERN)
    fence: int = Field(strict=True, ge=1, le=2**63 - 1)
    started_at: datetime = Field(alias="startedAt")
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("started_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage provider attempt start")

    @field_validator(
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage provider attempt flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_attempt(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attempt_id", "attempt_digest"},
        )
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_ATTEMPT_API_VERSION, material)
        attempt_id = f"object-storage-attempt_{digest}"
        if self.attempt_digest and self.attempt_digest != digest:
            raise ValueError("Object Storage provider attempt digest differs")
        if self.attempt_id and self.attempt_id != attempt_id:
            raise ValueError("Object Storage provider attempt ID differs")
        object.__setattr__(self, "attempt_digest", digest)
        object.__setattr__(self, "attempt_id", attempt_id)
        return self


_Action = Literal[
    "issue-upload-part",
    "complete-upload",
    "read-object",
    "cleanup-upload",
    "reconcile-upload",
]


class ObjectStorageProviderAttemptOperation(StrictModel):
    """One provider operation whose ID visibly carries its monotonic fence."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-attempt-operation/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-provider-attempt-operation/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageProviderAttemptOperation"] = "ObjectStorageProviderAttemptOperation"
    operation_id: str = Field(default="", alias="operationId", max_length=140)
    operation_digest: str = Field(default="", alias="operationDigest", max_length=64)
    attempt_id: str = Field(alias="attemptId", min_length=87, max_length=96)
    attempt_digest: str = Field(alias="attemptDigest", pattern=_SHA256_PATTERN)
    activation_digest: str = Field(alias="activationDigest", pattern=_SHA256_PATTERN)
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    authority_checkpoint_digest: str = Field(
        alias="authorityCheckpointDigest",
        pattern=_SHA256_PATTERN,
    )
    binding_digest: str = Field(alias="bindingDigest", pattern=_SHA256_PATTERN)
    fence: int = Field(strict=True, ge=1, le=2**63 - 1)
    action: _Action
    object_key_digest: str | None = Field(
        default=None,
        alias="objectKeyDigest",
        pattern=_SHA256_PATTERN,
    )

    @model_validator(mode="after")
    def bind_operation(self) -> Self:
        if (self.action in {"issue-upload-part", "read-object"}) != (
            self.object_key_digest is not None
        ):
            raise ValueError("Object Storage provider operation object-key binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"operation_id", "operation_digest"},
        )
        digest = _domain_digest(
            OBJECT_STORAGE_PROVIDER_ATTEMPT_OPERATION_API_VERSION,
            material,
        )
        operation_id = f"object-storage-attempt-operation_f{self.fence:020d}_{digest}"
        if self.operation_digest and self.operation_digest != digest:
            raise ValueError("Object Storage provider operation digest differs")
        if self.operation_id and self.operation_id != operation_id:
            raise ValueError("Object Storage provider operation ID differs")
        object.__setattr__(self, "operation_digest", digest)
        object.__setattr__(self, "operation_id", operation_id)
        return self


class ObjectStorageProviderAttemptRecord(StrictModel):
    """One append-only journal record without credentials, URLs, or remote bytes."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-attempt-record/v1"] = Field(
        default="pajin.control-plane.object-storage-provider-attempt-record/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageProviderAttemptRecord"] = "ObjectStorageProviderAttemptRecord"
    record_digest: str = Field(default="", alias="recordDigest", max_length=64)
    sequence: int = Field(strict=True, ge=1, le=2**31 - 1)
    record_type: Literal["intent", "succeeded", "rejected", "unknown"] = Field(alias="recordType")
    operation: ObjectStorageProviderAttemptOperation
    result_code: str | None = Field(
        default=None,
        alias="resultCode",
        pattern=_IDENTIFIER_PATTERN,
    )
    result_digest: str | None = Field(
        default=None,
        alias="resultDigest",
        pattern=_SHA256_PATTERN,
    )
    occurred_at: datetime = Field(alias="occurredAt")
    previous_record_digest: str | None = Field(
        default=None,
        alias="previousRecordDigest",
        pattern=_SHA256_PATTERN,
    )

    @field_validator("occurred_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage provider record time")

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        if self.record_type == "intent":
            if self.result_code is not None or self.result_digest is not None:
                raise ValueError("Object Storage provider intent cannot contain a result")
        elif self.result_code is None:
            raise ValueError("Object Storage provider outcome must contain a result code")
        material = self.model_dump(mode="json", by_alias=True, exclude={"record_digest"})
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_ATTEMPT_RECORD_API_VERSION, material)
        if self.record_digest and self.record_digest != digest:
            raise ValueError("Object Storage provider record digest differs")
        object.__setattr__(self, "record_digest", digest)
        return self


class ObjectStorageProviderReconciliationDisposition(StrEnum):
    """Provider-owned observation of an abandoned binding."""

    COMPLETED = "completed"
    UPLOAD_OPEN = "upload-open"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class RecoverableObjectStorageProviderAdapter(ObjectStorageProviderAdapter, Protocol):
    """A concrete provider that enforces operation-ID fences and can reconcile."""

    @property
    @abstractmethod
    def deployment_profile(self) -> ObjectStorageProviderDeploymentProfile:
        """Return the exact non-secret deployment guarantees."""

    @abstractmethod
    def reconcile_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageProviderReconciliationDisposition:
        """Observe abandoned provider state without granting Artifact authority."""


def object_storage_provider_operation_fence(operation_id: str) -> int:
    """Extract the mandatory monotonic fence that a concrete provider must enforce."""

    match = _OPERATION_ID_PATTERN.fullmatch(operation_id)
    if match is None:
        raise ValueError("Object Storage provider operation ID is invalid")
    return int(match.group(1))


def _operation(
    attempt: ObjectStorageProviderAttempt,
    *,
    fence: int,
    action: _Action,
    object_key: str | None = None,
) -> ObjectStorageProviderAttemptOperation:
    return ObjectStorageProviderAttemptOperation(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        activationDigest=attempt.activation_digest,
        adapterDigest=attempt.adapter_digest,
        authorityCheckpointDigest=attempt.authority_checkpoint.checkpoint_digest,
        bindingDigest=attempt.binding_digest,
        fence=fence,
        action=action,
        objectKeyDigest=(
            _domain_digest("pajin.control-plane.object-storage-object-key/v1", object_key)
            if object_key is not None
            else None
        ),
    )


class ObjectStorageProviderAttemptJournal:
    """Explicitly provisioned SQLite activation and intent-before-call journal."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))

    @classmethod
    def bootstrap(
        cls,
        path: Path,
        *,
        authority_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        adapter: ObjectStorageProviderAdapterDefinition,
        deployment_profile: ObjectStorageProviderDeploymentProfile,
        activated_at: datetime,
    ) -> ObjectStorageProviderAttemptJournal:
        database = Path(os.path.abspath(path))
        _require_safe_path(database)
        if database.exists():
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider attempt journal already exists"
            )
        database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _require_safe_path(database)
        try:
            activation = ObjectStorageConcreteProviderActivation(
                sequence=1,
                authorityCheckpoint=authority_checkpoint,
                adapter=adapter,
                deploymentProfile=deployment_profile,
                activatedAt=activated_at,
            )
            connection = _open_connection(database, readonly=False)
            try:
                mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
                if mode is None or str(mode[0]).lower() != "delete":
                    raise ObjectStorageProviderRecoveryError(
                        "Object Storage provider journal mode differs"
                    )
                connection.executescript(_SCHEMA_SQL)
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    (("schema_version", _SCHEMA_VERSION), ("schema_digest", _SCHEMA_DIGEST)),
                )
                _insert_activation(connection, activation)
                connection.commit()
            finally:
                connection.close()
            database.chmod(0o600)
            return cls.open(database)
        except (sqlite3.Error, ValidationError, ValueError) as exc:
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider attempt journal could not bootstrap"
            ) from exc

    @classmethod
    def open(cls, path: Path) -> ObjectStorageProviderAttemptJournal:
        database = Path(os.path.abspath(path))
        if not database.exists():
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider attempt journal is absent; "
                "explicit bootstrap or restore is required"
            )
        journal = cls(database)
        with _read_transaction(database) as connection:
            _validate_database(connection)
            _read_activations(connection)
            rows = connection.execute("SELECT * FROM attempts ORDER BY rowid").fetchall()
            for row in rows:
                journal._snapshot(connection, row)
        return journal

    def latest_activation(self) -> ObjectStorageConcreteProviderActivation:
        with _read_transaction(self.path) as connection:
            return _read_activations(connection)[-1].model_copy(deep=True)

    def require_active(
        self,
        *,
        authority_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        adapter: ObjectStorageProviderAdapterDefinition,
        deployment_profile: ObjectStorageProviderDeploymentProfile,
    ) -> ObjectStorageConcreteProviderActivation:
        latest = self.latest_activation()
        if (
            latest.authority_checkpoint != authority_checkpoint
            or latest.adapter != adapter
            or latest.deployment_profile != deployment_profile
        ):
            raise ObjectStorageProviderRecoveryError(
                "Object Storage concrete provider is not active for the durable current head"
            )
        return latest

    def activate(
        self,
        *,
        authority_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        adapter: ObjectStorageProviderAdapterDefinition,
        deployment_profile: ObjectStorageProviderDeploymentProfile,
        activated_at: datetime,
    ) -> ObjectStorageConcreteProviderActivation:
        with _write_transaction(self.path) as connection:
            _require_no_open_attempt(connection)
            activations = _read_activations(connection)
            current = activations[-1]
            candidate_material = (
                authority_checkpoint,
                adapter,
                deployment_profile,
            )
            if candidate_material == (
                current.authority_checkpoint,
                current.adapter,
                current.deployment_profile,
            ):
                return current.model_copy(deep=True)
            if (
                authority_checkpoint.store_identity_digest
                != current.authority_checkpoint.store_identity_digest
                or authority_checkpoint.deployment_id != current.authority_checkpoint.deployment_id
                or authority_checkpoint.tenant_id != current.authority_checkpoint.tenant_id
                or authority_checkpoint.revision < current.authority_checkpoint.revision
            ):
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider activation authority transition is invalid"
                )
            activation = ObjectStorageConcreteProviderActivation(
                sequence=current.sequence + 1,
                previousActivationDigest=current.activation_digest,
                authorityCheckpoint=authority_checkpoint,
                adapter=adapter,
                deploymentProfile=deployment_profile,
                activatedAt=activated_at,
            )
            if activation.activated_at < current.activated_at:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider activation time moved backwards"
                )
            _insert_activation(connection, activation)
        committed = self.latest_activation()
        if committed != activation:
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider activation commit differs"
            )
        return committed

    def begin_attempt(
        self,
        *,
        activation: ObjectStorageConcreteProviderActivation,
        binding: ObjectStorageTransportBinding,
        started_at: datetime,
    ) -> ObjectStorageProviderAttempt:
        scope = _scope_digest(activation, binding)
        with _write_transaction(self.path) as connection:
            _require_no_open_attempt(connection)
            current = _read_activations(connection)[-1]
            if current != activation:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider attempt activation is stale"
                )
            if (
                binding.deployment.authority_digest
                != activation.authority_checkpoint.authority_digest
                or binding.deployment.deployment_id != activation.authority_checkpoint.deployment_id
                or binding.deployment.tenant_id != activation.authority_checkpoint.tenant_id
                or binding.deployment.endpoint_origin != activation.adapter.endpoint_origin
                or binding.deployment.transport_profile != activation.adapter.transport_profile
            ):
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider attempt binding differs from activation"
                )
            fence = _next_fence(connection, scope)
            attempt = ObjectStorageProviderAttempt(
                activationDigest=activation.activation_digest,
                adapterDigest=activation.adapter.adapter_digest,
                authorityCheckpoint=activation.authority_checkpoint,
                bindingDigest=binding.binding_digest,
                fence=fence,
                startedAt=started_at,
            )
            if (
                attempt.started_at < activation.activated_at
                or attempt.started_at < binding.issued_at
                or attempt.started_at >= binding.expires_at
            ):
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider attempt is outside its active binding window"
                )
            attempt_json = attempt.model_dump_json(by_alias=True)
            binding_json = binding.model_dump_json(by_alias=True)
            if (
                len(attempt_json.encode()) > _MAX_JSON_BYTES
                or len(binding_json.encode()) > _MAX_JSON_BYTES
            ):
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider attempt exceeds its durable byte bound"
                )
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, scope_digest, fence, attempt_json, binding_json,
                    state, active_recovery_fence, resolution
                ) VALUES (?, ?, ?, ?, ?, 'open', NULL, NULL)
                """,
                (attempt.attempt_id, scope, fence, attempt_json, binding_json),
            )
        return attempt

    def pending(
        self,
    ) -> tuple[
        tuple[
            ObjectStorageConcreteProviderActivation,
            ObjectStorageTransportBinding,
            ObjectStorageProviderAttempt,
            tuple[ObjectStorageProviderAttemptRecord, ...],
        ],
        ...,
    ]:
        with _read_transaction(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE state = 'open' ORDER BY rowid"
            ).fetchall()
            return tuple(self._snapshot(connection, row) for row in rows)

    def claim_recovery(self, attempt: ObjectStorageProviderAttempt) -> int:
        with _write_transaction(self.path) as connection:
            row = _required_open_attempt(connection, attempt.attempt_id)
            durable = ObjectStorageProviderAttempt.model_validate_json(str(row["attempt_json"]))
            if durable != attempt:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider recovery attempt differs"
                )
            fence = _next_fence(connection, str(row["scope_digest"]))
            connection.execute(
                "UPDATE attempts SET active_recovery_fence = ? WHERE attempt_id = ?",
                (fence, attempt.attempt_id),
            )
        return fence

    def append_intent(self, operation: ObjectStorageProviderAttemptOperation) -> None:
        self._append_record(operation, record_type="intent")

    def append_succeeded(
        self,
        operation: ObjectStorageProviderAttemptOperation,
        *,
        result_code: str,
        result_digest: str | None = None,
    ) -> None:
        self._append_record(
            operation,
            record_type="succeeded",
            result_code=result_code,
            result_digest=result_digest,
        )

    def append_rejected(self, operation: ObjectStorageProviderAttemptOperation) -> None:
        self._append_record(
            operation,
            record_type="rejected",
            result_code="provider-rejected",
        )

    def append_unknown(self, operation: ObjectStorageProviderAttemptOperation) -> None:
        self._append_record(
            operation,
            record_type="unknown",
            result_code="provider-outcome-unknown",
        )

    def mark_completed(self, attempt_id: str, *, fence: int) -> None:
        self._mark_terminal(attempt_id, fence=fence, state="completed", resolution="staged")

    def mark_reconciled(
        self,
        attempt_id: str,
        *,
        fence: int,
        resolution: Literal["absent", "cleaned"],
    ) -> None:
        self._mark_terminal(
            attempt_id,
            fence=fence,
            state="reconciled",
            resolution=resolution,
        )

    def require_no_pending(self) -> None:
        with _read_transaction(self.path) as connection:
            _require_no_open_attempt(connection)

    def _mark_terminal(
        self,
        attempt_id: str,
        *,
        fence: int,
        state: Literal["completed", "reconciled"],
        resolution: Literal["staged", "absent", "cleaned"],
    ) -> None:
        with _write_transaction(self.path) as connection:
            row = _required_open_attempt(connection, attempt_id)
            if fence != _active_fence(row):
                raise ObjectStorageProviderRecoveryError(
                    "Stale Object Storage provider fence cannot close attempt"
                )
            connection.execute(
                "UPDATE attempts SET state = ?, resolution = ? WHERE attempt_id = ?",
                (state, resolution, attempt_id),
            )

    def _append_record(
        self,
        operation: ObjectStorageProviderAttemptOperation,
        *,
        record_type: Literal["intent", "succeeded", "rejected", "unknown"],
        result_code: str | None = None,
        result_digest: str | None = None,
    ) -> None:
        with _write_transaction(self.path) as connection:
            row = _required_open_attempt(connection, operation.attempt_id)
            attempt = ObjectStorageProviderAttempt.model_validate_json(str(row["attempt_json"]))
            if (
                operation.fence != _active_fence(row)
                or operation.attempt_digest != attempt.attempt_digest
                or operation.activation_digest != attempt.activation_digest
                or operation.adapter_digest != attempt.adapter_digest
                or operation.authority_checkpoint_digest
                != attempt.authority_checkpoint.checkpoint_digest
                or operation.binding_digest != attempt.binding_digest
            ):
                raise ObjectStorageProviderRecoveryError(
                    "Stale or foreign Object Storage provider operation cannot mutate journal"
                )
            existing = connection.execute(
                "SELECT record_type FROM records WHERE attempt_id = ? AND operation_id = ?",
                (attempt.attempt_id, operation.operation_id),
            ).fetchall()
            existing_types = {str(item[0]) for item in existing}
            if record_type == "intent":
                if existing_types:
                    raise ObjectStorageProviderRecoveryError(
                        "Object Storage provider operation intent already exists"
                    )
            elif existing_types != {"intent"}:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider outcome lacks one exact durable intent"
                )
            prior = connection.execute(
                """
                SELECT record_json FROM records
                WHERE attempt_id = ? ORDER BY sequence DESC LIMIT 1
                """,
                (attempt.attempt_id,),
            ).fetchone()
            previous = (
                ObjectStorageProviderAttemptRecord.model_validate_json(str(prior[0])).record_digest
                if prior is not None
                else None
            )
            sequence = int(
                connection.execute(
                    """
                    SELECT COALESCE(MAX(sequence), 0) + 1
                    FROM records WHERE attempt_id = ?
                    """,
                    (attempt.attempt_id,),
                ).fetchone()[0]
            )
            record = ObjectStorageProviderAttemptRecord(
                sequence=sequence,
                recordType=record_type,
                operation=operation,
                resultCode=result_code,
                resultDigest=result_digest,
                occurredAt=datetime.now(UTC),
                previousRecordDigest=previous,
            )
            record_json = record.model_dump_json(by_alias=True)
            if len(record_json.encode()) > _MAX_JSON_BYTES:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider journal record exceeds its byte bound"
                )
            connection.execute(
                """
                INSERT INTO records(
                    attempt_id, sequence, operation_id, record_type, record_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    attempt.attempt_id,
                    sequence,
                    operation.operation_id,
                    record_type,
                    record_json,
                ),
            )

    @staticmethod
    def _snapshot(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> tuple[
        ObjectStorageConcreteProviderActivation,
        ObjectStorageTransportBinding,
        ObjectStorageProviderAttempt,
        tuple[ObjectStorageProviderAttemptRecord, ...],
    ]:
        attempt = ObjectStorageProviderAttempt.model_validate_json(str(row["attempt_json"]))
        binding = ObjectStorageTransportBinding.model_validate_json(str(row["binding_json"]))
        activation_row = connection.execute(
            "SELECT activation_json FROM activations WHERE activation_digest = ?",
            (attempt.activation_digest,),
        ).fetchone()
        if activation_row is None:
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider attempt activation is absent"
            )
        activation = ObjectStorageConcreteProviderActivation.model_validate_json(
            str(activation_row[0])
        )
        if (
            attempt.attempt_id != str(row["attempt_id"])
            or attempt.fence != int(row["fence"])
            or attempt.binding_digest != binding.binding_digest
            or attempt.adapter_digest != activation.adapter.adapter_digest
            or attempt.authority_checkpoint != activation.authority_checkpoint
        ):
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider attempt durable identity differs"
            )
        records = tuple(
            ObjectStorageProviderAttemptRecord.model_validate_json(str(item[0]))
            for item in connection.execute(
                "SELECT record_json FROM records WHERE attempt_id = ? ORDER BY sequence",
                (attempt.attempt_id,),
            ).fetchall()
        )
        previous: str | None = None
        for sequence, record in enumerate(records, start=1):
            if (
                record.sequence != sequence
                or record.previous_record_digest != previous
                or record.operation.attempt_id != attempt.attempt_id
            ):
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider journal record chain differs"
                )
            previous = record.record_digest
        return activation, binding, attempt, records


class _JournaledProvider:
    def __init__(
        self,
        provider: RecoverableObjectStorageProviderAdapter,
        journal: ObjectStorageProviderAttemptJournal,
        attempt: ObjectStorageProviderAttempt,
        *,
        fence: int,
    ) -> None:
        self._provider = provider
        self._journal = journal
        self._attempt = attempt
        self._fence = fence

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._provider.definition

    def issue_upload_part(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        expires_at: datetime,
        operation_id: str,
    ) -> EphemeralObjectStorageUploadCredential:
        del operation_id
        operation = _operation(
            self._attempt,
            fence=self._fence,
            action="issue-upload-part",
            object_key=object_key,
        )
        return self._call(
            operation,
            lambda: self._provider.issue_upload_part(
                binding=binding,
                object_key=object_key,
                expires_at=expires_at,
                operation_id=operation.operation_id,
            ),
            result=lambda value: (
                "credential-issued",
                _credential_result_digest(value),
            ),
        )

    def complete_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> None:
        del operation_id
        operation = _operation(
            self._attempt,
            fence=self._fence,
            action="complete-upload",
        )
        return self._call(
            operation,
            lambda: self._provider.complete_upload(
                binding=binding,
                operation_id=operation.operation_id,
            ),
            result=lambda value: (
                "completed" if value is None else "unsupported-result",
                None,
            ),
        )

    def read_object(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        max_bytes: int,
        operation_id: str,
    ) -> bytes:
        del operation_id
        operation = _operation(
            self._attempt,
            fence=self._fence,
            action="read-object",
            object_key=object_key,
        )
        return self._call(
            operation,
            lambda: self._provider.read_object(
                binding=binding,
                object_key=object_key,
                max_bytes=max_bytes,
                operation_id=operation.operation_id,
            ),
            result=lambda value: (
                "bytes-read" if type(value) is bytes else "unsupported-result",
                (
                    _domain_digest(
                        "pajin.control-plane.object-storage-read-result/v1",
                        {"bytes": len(value), "sha256": sha256(value).hexdigest()},
                    )
                    if type(value) is bytes
                    else None
                ),
            ),
        )

    def cleanup_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageCleanupDisposition:
        del operation_id
        operation = _operation(
            self._attempt,
            fence=self._fence,
            action="cleanup-upload",
        )
        return self._call(
            operation,
            lambda: self._provider.cleanup_upload(
                binding=binding,
                operation_id=operation.operation_id,
            ),
            result=lambda value: (
                (
                    f"cleanup-{value.value}"
                    if type(value) is ObjectStorageCleanupDisposition
                    else "unsupported-result"
                ),
                None,
            ),
        )

    def reconcile_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
    ) -> ObjectStorageProviderReconciliationDisposition:
        operation = _operation(
            self._attempt,
            fence=self._fence,
            action="reconcile-upload",
        )
        value = self._call(
            operation,
            lambda: self._provider.reconcile_upload(
                binding=binding,
                operation_id=operation.operation_id,
            ),
            result=lambda item: (
                (
                    f"reconcile-{item.value}"
                    if type(item) is ObjectStorageProviderReconciliationDisposition
                    else "unsupported-result"
                ),
                None,
            ),
        )
        if type(value) is not ObjectStorageProviderReconciliationDisposition:
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider returned an invalid reconciliation disposition"
            )
        return value

    def _call(
        self,
        operation: ObjectStorageProviderAttemptOperation,
        call: Callable[[], _T],
        *,
        result: Callable[[_T], tuple[str, str | None]],
    ) -> _T:
        self._journal.append_intent(operation)
        try:
            value = call()
            result_code, result_digest = result(value)
            self._journal.append_succeeded(
                operation,
                result_code=result_code,
                result_digest=result_digest,
            )
            return value
        except ObjectStorageProviderCallRejected:
            self._journal.append_rejected(operation)
            raise
        except BaseException:
            self._journal.append_unknown(operation)
            raise


class ObjectStorageProviderAttemptSession:
    """One fenced provider session whose terminal state is durable."""

    def __init__(
        self,
        *,
        runtime: ObjectStorageProviderRuntime,
        journal: ObjectStorageProviderAttemptJournal,
        attempt: ObjectStorageProviderAttempt,
    ) -> None:
        self._runtime = runtime
        self._journal = journal
        self.attempt = attempt.model_copy(deep=True)

    def issue_upload_part(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        file_index: int,
        part_number: int,
        now: datetime,
    ) -> EphemeralObjectStorageUploadCredential:
        return self._runtime.issue_upload_part(
            binding,
            expected_checkpoint=self.attempt.authority_checkpoint,
            file_index=file_index,
            part_number=part_number,
            now=now,
        )

    def complete_and_stage(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        now: datetime,
    ) -> PortableArtifactMultipartTransportReceipt:
        receipt = self._runtime.complete_and_stage(
            binding,
            expected_checkpoint=self.attempt.authority_checkpoint,
            now=now,
        )
        self._journal.mark_completed(
            self.attempt.attempt_id,
            fence=self.attempt.fence,
        )
        return receipt

    def cleanup_upload(
        self,
        binding: ObjectStorageTransportBinding,
    ) -> ObjectStorageCleanupDisposition:
        disposition = self._runtime.cleanup_upload(
            binding,
            expected_checkpoint=self.attempt.authority_checkpoint,
        )
        self._journal.mark_reconciled(
            self.attempt.attempt_id,
            fence=self.attempt.fence,
            resolution="cleaned",
        )
        return disposition


class RecoverableObjectStorageProviderRuntime:
    """Concrete provider runtime that reconciles pending attempts before new work."""

    def __init__(
        self,
        *,
        authority_store: ObjectStorageAuthorityHeadStore,
        repository: ManagedArtifactRepository,
        provider: RecoverableObjectStorageProviderAdapter,
        journal: ObjectStorageProviderAttemptJournal,
    ) -> None:
        try:
            definition = ObjectStorageProviderAdapterDefinition.model_validate(
                provider.definition.model_dump(mode="json", by_alias=True)
            )
            profile = ObjectStorageProviderDeploymentProfile.model_validate(
                provider.deployment_profile.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise ObjectStorageProviderRecoveryError(
                "Object Storage recoverable provider identity is invalid"
            ) from exc
        journal.require_active(
            authority_checkpoint=authority_store.checkpoint(),
            adapter=definition,
            deployment_profile=profile,
        )
        self._authority_store = authority_store
        self._repository = repository
        self._provider = provider
        self._journal = journal
        self._definition = definition
        self._profile = profile

    def begin_attempt(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        now: datetime,
    ) -> ObjectStorageProviderAttemptSession:
        self._journal.require_no_pending()
        try:
            self._authority_store.require_current(
                binding.deployment,
                expected_checkpoint=expected_checkpoint,
            )
        except ObjectStorageAuthorityHeadStoreError as exc:
            raise ObjectStorageProviderRecoveryError(
                "Object Storage attempt lacks the durable current authority head"
            ) from exc
        activation = self._journal.require_active(
            authority_checkpoint=expected_checkpoint,
            adapter=self._definition,
            deployment_profile=self._profile,
        )
        attempt = self._journal.begin_attempt(
            activation=activation,
            binding=binding,
            started_at=now,
        )
        journaled = _JournaledProvider(
            self._provider,
            self._journal,
            attempt,
            fence=attempt.fence,
        )
        runtime = ObjectStorageProviderRuntime(
            authority_store=self._authority_store,
            repository=self._repository,
            provider=cast(ObjectStorageProviderAdapter, journaled),
        )
        return ObjectStorageProviderAttemptSession(
            runtime=runtime,
            journal=self._journal,
            attempt=attempt,
        )

    def reconcile_pending(self) -> tuple[str, ...]:
        reconciled: list[str] = []
        for activation, binding, attempt, _records in self._journal.pending():
            if (
                activation.adapter != self._definition
                or activation.deployment_profile != self._profile
            ):
                raise ObjectStorageProviderRecoveryError(
                    "Pending Object Storage attempt belongs to another concrete provider"
                )
            try:
                self._authority_store.require_current(
                    binding.deployment,
                    expected_checkpoint=attempt.authority_checkpoint,
                )
            except ObjectStorageAuthorityHeadStoreError as exc:
                raise ObjectStorageProviderRecoveryError(
                    "Pending Object Storage attempt no longer has its authority head"
                ) from exc
            fence = self._journal.claim_recovery(attempt)
            provider = _JournaledProvider(
                self._provider,
                self._journal,
                attempt,
                fence=fence,
            )
            try:
                disposition = provider.reconcile_upload(binding=binding)
            except Exception:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider reconciliation failed; new work is fenced"
                ) from None
            if disposition is ObjectStorageProviderReconciliationDisposition.UNKNOWN:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider reconciliation remains unknown; new work is fenced"
                )
            if disposition is ObjectStorageProviderReconciliationDisposition.ABSENT:
                self._journal.mark_reconciled(
                    attempt.attempt_id,
                    fence=fence,
                    resolution="absent",
                )
                reconciled.append(attempt.attempt_id)
                continue
            try:
                self._authority_store.require_current(
                    binding.deployment,
                    expected_checkpoint=attempt.authority_checkpoint,
                )
            except ObjectStorageAuthorityHeadStoreError as exc:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage cleanup lost its durable current authority head"
                ) from exc
            try:
                cleanup = provider.cleanup_upload(
                    binding=binding,
                    operation_id="journal-owned",
                )
            except Exception:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage provider cleanup failed; new work is fenced"
                ) from None
            if cleanup not in {
                ObjectStorageCleanupDisposition.CLEANED,
                ObjectStorageCleanupDisposition.ALREADY_ABSENT,
            }:
                raise ObjectStorageProviderRecoveryError(
                    "Object Storage cleanup remains unknown; new work is fenced"
                )
            self._journal.mark_reconciled(
                attempt.attempt_id,
                fence=fence,
                resolution="cleaned",
            )
            reconciled.append(attempt.attempt_id)
        return tuple(reconciled)

    def activate_successor(
        self,
        authority: ObjectStorageDeploymentAuthority,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        activated_at: datetime,
    ) -> tuple[
        ObjectStorageAuthorityHeadActivation,
        ObjectStorageConcreteProviderActivation,
    ]:
        """Rotate head then provider activation, while pending attempts block the first write."""

        self._journal.require_no_pending()
        head = self._authority_store.activate(
            authority,
            expected_checkpoint=expected_checkpoint,
            activated_at=activated_at,
        )
        activation = self._journal.activate(
            authority_checkpoint=self._authority_store.checkpoint(),
            adapter=self._definition,
            deployment_profile=self._profile,
            activated_at=activated_at,
        )
        return head, activation


def _credential_result_digest(value: object) -> str | None:
    if not isinstance(value, EphemeralObjectStorageUploadCredential):
        return None
    return _domain_digest(
        "pajin.control-plane.object-storage-credential-result/v1",
        {
            "method": value.method,
            "objectKeyDigest": _domain_digest(
                "pajin.control-plane.object-storage-object-key/v1",
                value.object_key,
            ),
            "expiresAt": value.expires_at.isoformat(),
        },
    )


def _scope_digest(
    activation: ObjectStorageConcreteProviderActivation,
    binding: ObjectStorageTransportBinding,
) -> str:
    return _domain_digest(
        "pajin.control-plane.object-storage-provider-attempt-scope/v1",
        {
            "activationDigest": activation.activation_digest,
            "bindingDigest": binding.binding_digest,
        },
    )


def _insert_activation(
    connection: sqlite3.Connection,
    activation: ObjectStorageConcreteProviderActivation,
) -> None:
    raw = activation.model_dump_json(by_alias=True)
    if len(raw.encode()) > _MAX_JSON_BYTES:
        raise ObjectStorageProviderRecoveryError(
            "Object Storage provider activation exceeds its durable byte bound"
        )
    connection.execute(
        """
        INSERT INTO activations(sequence, activation_digest, activation_json)
        VALUES (?, ?, ?)
        """,
        (activation.sequence, activation.activation_digest, raw),
    )


def _read_activations(
    connection: sqlite3.Connection,
) -> tuple[ObjectStorageConcreteProviderActivation, ...]:
    rows = connection.execute(
        "SELECT sequence, activation_digest, activation_json FROM activations ORDER BY sequence"
    ).fetchall()
    if not rows:
        raise ObjectStorageProviderRecoveryError(
            "Object Storage provider journal has no concrete activation"
        )
    activations: list[ObjectStorageConcreteProviderActivation] = []
    previous: str | None = None
    for expected_sequence, row in enumerate(rows, start=1):
        activation = ObjectStorageConcreteProviderActivation.model_validate_json(str(row[2]))
        if (
            activation.sequence != expected_sequence
            or activation.sequence != int(row[0])
            or activation.activation_digest != str(row[1])
            or activation.previous_activation_digest != previous
        ):
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider activation chain differs"
            )
        activations.append(activation)
        previous = activation.activation_digest
    return tuple(activations)


def _require_no_open_attempt(connection: sqlite3.Connection) -> None:
    if (
        connection.execute("SELECT 1 FROM attempts WHERE state = 'open' LIMIT 1").fetchone()
        is not None
    ):
        raise ObjectStorageProviderRecoveryError(
            "Unresolved Object Storage provider attempt must be reconciled first"
        )


def _required_open_attempt(connection: sqlite3.Connection, attempt_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM attempts WHERE attempt_id = ? AND state = 'open'",
        (attempt_id,),
    ).fetchone()
    if row is None:
        raise ObjectStorageProviderRecoveryError("Object Storage provider attempt is not open")
    return cast(sqlite3.Row, row)


def _active_fence(row: sqlite3.Row) -> int:
    active = row["active_recovery_fence"]
    return int(active) if active is not None else int(row["fence"])


def _next_fence(connection: sqlite3.Connection, scope: str) -> int:
    row = connection.execute(
        "SELECT value FROM fences WHERE scope_digest = ?",
        (scope,),
    ).fetchone()
    value = 1 if row is None else int(row[0]) + 1
    connection.execute(
        """
        INSERT INTO fences(scope_digest, value) VALUES (?, ?)
        ON CONFLICT(scope_digest) DO UPDATE SET value = excluded.value
        """,
        (scope, value),
    )
    return value


def _validate_database(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchall()
    if [str(row[0]) for row in integrity] != ["ok"]:
        raise ObjectStorageProviderRecoveryError(
            "Object Storage provider journal integrity check failed"
        )
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise ObjectStorageProviderRecoveryError(
            "Object Storage provider journal foreign keys differ"
        )
    if _schema_inventory(connection) != _expected_schema_inventory():
        raise ObjectStorageProviderRecoveryError(
            "Object Storage provider journal schema inventory differs"
        )
    metadata = dict(connection.execute("SELECT key, value FROM metadata").fetchall())
    if metadata != {
        "schema_version": _SCHEMA_VERSION,
        "schema_digest": _SCHEMA_DIGEST,
    }:
        raise ObjectStorageProviderRecoveryError("Object Storage provider journal metadata differs")


def _schema_inventory(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (str(row[0]), str(row[1]), str(row[2]), str(row[3]))
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
    )


@cache
def _expected_schema_inventory() -> tuple[tuple[str, str, str, str], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA_SQL)
        return _schema_inventory(connection)
    finally:
        connection.close()


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    connection = _open_connection(path, readonly=False)
    try:
        _validate_database(connection)
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
        _require_safe_path(path)


@contextmanager
def _read_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    connection = _open_connection(path, readonly=True)
    connection.execute("BEGIN")
    try:
        _validate_database(connection)
        yield connection
    finally:
        connection.rollback()
        connection.close()
        _require_safe_path(path)


def _open_connection(path: Path, *, readonly: bool) -> sqlite3.Connection:
    target: str | Path = f"file:{path.as_posix()}?mode=ro" if readonly else path
    connection = sqlite3.connect(
        target,
        uri=readonly,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    if readonly:
        connection.execute("PRAGMA query_only = ON")
    else:
        connection.execute("PRAGMA synchronous = FULL")
    return connection


def _require_safe_path(path: Path) -> None:
    parent = path.parent
    if any(
        ancestor.exists() and (ancestor.is_symlink() or ancestor.is_junction())
        for ancestor in (parent, *parent.parents)
    ):
        raise ObjectStorageProviderRecoveryError(
            "Object Storage provider journal ancestor is unsafe"
        )
    if parent.exists() and not parent.is_dir():
        raise ObjectStorageProviderRecoveryError("Object Storage provider journal parent is unsafe")
    if (path.exists() or path.is_symlink() or path.is_junction()) and (
        not path.is_file() or path.is_symlink() or path.is_junction() or path.stat().st_nlink != 1
    ):
        raise ObjectStorageProviderRecoveryError(
            "Object Storage provider journal is not a single-link regular file"
        )
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
            raise ObjectStorageProviderRecoveryError(
                "Object Storage provider journal sidecar is unsafe"
            )
