"""Fresh, revocable deployment admission for one selected Object Storage provider."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import cache
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.object_storage_activation import (
    ObjectStorageAuthorityHeadCheckpoint,
    ObjectStorageAuthorityHeadStore,
    ObjectStorageAuthorityHeadStoreError,
)
from pajin.control_plane.object_storage_authority import ObjectStorageTransportBinding
from pajin.control_plane.object_storage_conformance import ObjectStorageProviderConformanceReport
from pajin.control_plane.object_storage_minio import MinioS3ProviderInventory
from pajin.control_plane.object_storage_provider import (
    EphemeralObjectStorageUploadCredential,
    ObjectStorageCleanupDisposition,
    ObjectStorageProviderAdapterDefinition,
    ObjectStorageProviderCallRejected,
)
from pajin.control_plane.object_storage_recovery import (
    ObjectStorageConcreteProviderActivation,
    ObjectStorageProviderAttemptJournal,
    ObjectStorageProviderAttemptSession,
    ObjectStorageProviderDeploymentProfile,
    ObjectStorageProviderReconciliationDisposition,
    ObjectStorageProviderRecoveryError,
    RecoverableObjectStorageProviderAdapter,
    RecoverableObjectStorageProviderRuntime,
)
from pajin.domain.models import StrictModel

OBJECT_STORAGE_SELECTED_PROVIDER_EVIDENCE_API_VERSION = (
    "pajin.control-plane.object-storage-selected-provider-evidence/v1"
)
OBJECT_STORAGE_PROVIDER_ADMISSION_POLICY_API_VERSION = (
    "pajin.control-plane.object-storage-provider-admission-policy/v1"
)
OBJECT_STORAGE_PROVIDER_DEPLOYMENT_ADMISSION_API_VERSION = (
    "pajin.control-plane.object-storage-provider-deployment-admission/v1"
)
OBJECT_STORAGE_PROVIDER_ADMISSION_STORE_IDENTITY_API_VERSION = (
    "pajin.control-plane.object-storage-provider-admission-store-identity/v1"
)
OBJECT_STORAGE_PROVIDER_ADMISSION_CHECKPOINT_API_VERSION = (
    "pajin.control-plane.object-storage-provider-admission-checkpoint/v1"
)
OBJECT_STORAGE_SELECTED_REPORT_MAX_AGE_SECONDS = 3_600

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_MAX_JSON_BYTES = 512 * 1024
_BUSY_TIMEOUT_MS = 5_000
_SCHEMA_VERSION = "1"
_SCHEMA_SQL = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    identity_json TEXT NOT NULL
);
CREATE TABLE policies (
    sequence INTEGER PRIMARY KEY,
    policy_digest TEXT NOT NULL UNIQUE,
    policy_json TEXT NOT NULL
);
CREATE TABLE admissions (
    sequence INTEGER PRIMARY KEY,
    admission_digest TEXT NOT NULL UNIQUE,
    admission_json TEXT NOT NULL
);
"""
_SCHEMA_DIGEST = sha256(_SCHEMA_SQL.encode("utf-8")).hexdigest()


class ObjectStorageProviderAdmissionError(RuntimeError):
    """Raised when selected-provider deployment admission is absent or stale."""


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


def _require_digest_tuple(value: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if value != tuple(sorted(set(value))) or any(
        re.fullmatch(_SHA256_PATTERN, item) is None for item in value
    ):
        raise ValueError(f"{label} must be uniquely sorted lowercase SHA-256 values")
    return value


class ObjectStorageSelectedProviderEvidence(StrictModel):
    """Secret-free binding of one exact inventory, activation, and passing report."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-selected-provider-evidence/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-selected-provider-evidence/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageSelectedProviderEvidence"] = "ObjectStorageSelectedProviderEvidence"
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    inventory: MinioS3ProviderInventory
    inventory_digest: str = Field(alias="inventoryDigest", pattern=_SHA256_PATTERN)
    activation: ObjectStorageConcreteProviderActivation
    activation_digest: str = Field(alias="activationDigest", pattern=_SHA256_PATTERN)
    report: ObjectStorageProviderConformanceReport
    report_digest: str = Field(alias="reportDigest", pattern=_SHA256_PATTERN)
    public_network_eligible: Literal[False] = Field(
        default=False,
        alias="publicNetworkEligible",
    )
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator(
        "public_network_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage selected-provider evidence flags must be booleans")
        return value

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        activation = self.activation
        report = self.report
        inventory = self.inventory
        if (
            self.inventory_digest != inventory.inventory_digest
            or self.activation_digest != activation.activation_digest
            or self.report_digest != report.report_digest
            or report.activation_digest != activation.activation_digest
            or report.authority_checkpoint_digest
            != activation.authority_checkpoint.checkpoint_digest
            or report.adapter_digest != activation.adapter.adapter_digest
            or report.deployment_profile_digest != activation.deployment_profile.profile_digest
            or report.local_conformance_profile_id
            != activation.deployment_profile.local_conformance_profile_id
            or activation.adapter.endpoint_origin != inventory.endpoint_origin
            or activation.deployment_profile.provider_family != inventory.provider_family
            or activation.deployment_profile.server_side_encryption_policy_id
            != inventory.encryption_policy_id
            or activation.deployment_profile.local_conformance_profile_id
            != report.local_conformance_profile_id
            or report.started_at < activation.activated_at
        ):
            raise ValueError("Object Storage selected-provider evidence binding differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"evidence_digest"})
        digest = _domain_digest(OBJECT_STORAGE_SELECTED_PROVIDER_EVIDENCE_API_VERSION, material)
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("Object Storage selected-provider evidence digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self


class ObjectStorageProviderAdmissionPolicy(StrictModel):
    """Append-only deployment policy selecting or revoking one exact evidence chain."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-admission-policy/v1"] = Field(
        default="pajin.control-plane.object-storage-provider-admission-policy/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageProviderAdmissionPolicy"] = "ObjectStorageProviderAdmissionPolicy"
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    sequence: int = Field(strict=True, ge=1, le=2**31 - 1)
    previous_policy_digest: str | None = Field(
        default=None,
        alias="previousPolicyDigest",
        pattern=_SHA256_PATTERN,
    )
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime = Field(alias="issuedAt")
    admission_enabled: bool = Field(alias="admissionEnabled")
    max_report_age_seconds: Literal[3600] = Field(
        default=3600,
        alias="maxReportAgeSeconds",
    )
    selected_evidence_digest: str | None = Field(
        default=None,
        alias="selectedEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    selected_inventory_digest: str | None = Field(
        default=None,
        alias="selectedInventoryDigest",
        pattern=_SHA256_PATTERN,
    )
    selected_report_digest: str | None = Field(
        default=None,
        alias="selectedReportDigest",
        pattern=_SHA256_PATTERN,
    )
    selected_activation_digest: str | None = Field(
        default=None,
        alias="selectedActivationDigest",
        pattern=_SHA256_PATTERN,
    )
    selected_authority_checkpoint_digest: str | None = Field(
        default=None,
        alias="selectedAuthorityCheckpointDigest",
        pattern=_SHA256_PATTERN,
    )
    selected_adapter_digest: str | None = Field(
        default=None,
        alias="selectedAdapterDigest",
        pattern=_SHA256_PATTERN,
    )
    selected_deployment_profile_digest: str | None = Field(
        default=None,
        alias="selectedDeploymentProfileDigest",
        pattern=_SHA256_PATTERN,
    )
    revoked_inventory_digests: tuple[str, ...] = Field(
        default=(),
        alias="revokedInventoryDigests",
    )
    revoked_report_digests: tuple[str, ...] = Field(
        default=(),
        alias="revokedReportDigests",
    )
    transport_admission_eligible: bool = Field(alias="transportAdmissionEligible")
    public_network_eligible: Literal[False] = Field(
        default=False,
        alias="publicNetworkEligible",
    )
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("issued_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage admission policy issue time")

    @field_validator("sequence", "max_report_age_seconds", mode="before")
    @classmethod
    def require_integer_fields(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Object Storage admission policy numeric fields must be integers")
        return value

    @field_validator(
        "admission_enabled",
        "transport_admission_eligible",
        "public_network_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage admission policy flags must be booleans")
        return value

    @field_validator("revoked_inventory_digests")
    @classmethod
    def require_inventory_revocations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_digest_tuple(value, label="Object Storage inventory revocations")

    @field_validator("revoked_report_digests")
    @classmethod
    def require_report_revocations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_digest_tuple(value, label="Object Storage report revocations")

    @model_validator(mode="after")
    def bind_policy(self) -> Self:
        if (self.sequence == 1) != (self.previous_policy_digest is None):
            raise ValueError("Object Storage admission policy chain is not contiguous")
        selected = (
            self.selected_evidence_digest,
            self.selected_inventory_digest,
            self.selected_report_digest,
            self.selected_activation_digest,
            self.selected_authority_checkpoint_digest,
            self.selected_adapter_digest,
            self.selected_deployment_profile_digest,
        )
        if self.admission_enabled:
            if any(item is None for item in selected) or not self.transport_admission_eligible:
                raise ValueError("Enabled Object Storage admission policy selection is incomplete")
            if (
                self.selected_inventory_digest in self.revoked_inventory_digests
                or self.selected_report_digest in self.revoked_report_digests
            ):
                raise ValueError("Enabled Object Storage admission policy selects revoked evidence")
        elif any(item is not None for item in selected) or self.transport_admission_eligible:
            raise ValueError("Disabled Object Storage admission policy retains a selection")
        material = self.model_dump(mode="json", by_alias=True, exclude={"policy_digest"})
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_ADMISSION_POLICY_API_VERSION, material)
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Object Storage admission policy digest differs")
        object.__setattr__(self, "policy_digest", digest)
        return self


class ObjectStorageProviderAdmissionStoreIdentity(StrictModel):
    """Immutable identity of one explicitly provisioned admission store."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.control-plane.object-storage-provider-admission-store-identity/v1"
    ] = Field(
        default="pajin.control-plane.object-storage-provider-admission-store-identity/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageProviderAdmissionStoreIdentity"] = (
        "ObjectStorageProviderAdmissionStoreIdentity"
    )
    identity_digest: str = Field(default="", alias="identityDigest", max_length=64)
    store_id: str = Field(alias="storeId", pattern=_IDENTIFIER_PATTERN)
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    provisioned_at: datetime = Field(alias="provisionedAt")

    @field_validator("provisioned_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage admission store provision time")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"identity_digest"})
        digest = _domain_digest(
            OBJECT_STORAGE_PROVIDER_ADMISSION_STORE_IDENTITY_API_VERSION,
            material,
        )
        if self.identity_digest and self.identity_digest != digest:
            raise ValueError("Object Storage admission store identity digest differs")
        object.__setattr__(self, "identity_digest", digest)
        return self


class ObjectStorageProviderDeploymentAdmission(StrictModel):
    """Current, time-bounded authority for starting the exact selected provider."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-deployment-admission/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-provider-deployment-admission/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageProviderDeploymentAdmission"] = (
        "ObjectStorageProviderDeploymentAdmission"
    )
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    sequence: int = Field(strict=True, ge=1, le=2**31 - 1)
    previous_admission_digest: str | None = Field(
        default=None,
        alias="previousAdmissionDigest",
        pattern=_SHA256_PATTERN,
    )
    store_identity_digest: str = Field(alias="storeIdentityDigest", pattern=_SHA256_PATTERN)
    policy_digest: str = Field(alias="policyDigest", pattern=_SHA256_PATTERN)
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    evidence_digest: str = Field(alias="evidenceDigest", pattern=_SHA256_PATTERN)
    inventory_digest: str = Field(alias="inventoryDigest", pattern=_SHA256_PATTERN)
    report_digest: str = Field(alias="reportDigest", pattern=_SHA256_PATTERN)
    activation_digest: str = Field(alias="activationDigest", pattern=_SHA256_PATTERN)
    authority_checkpoint_digest: str = Field(
        alias="authorityCheckpointDigest",
        pattern=_SHA256_PATTERN,
    )
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    deployment_profile_digest: str = Field(
        alias="deploymentProfileDigest",
        pattern=_SHA256_PATTERN,
    )
    report_finished_at: datetime = Field(alias="reportFinishedAt")
    evaluated_at: datetime = Field(alias="evaluatedAt")
    valid_until: datetime = Field(alias="validUntil")
    max_report_age_seconds: Literal[3600] = Field(
        default=3600,
        alias="maxReportAgeSeconds",
    )
    transport_admission_eligible: Literal[True] = Field(
        default=True,
        alias="transportAdmissionEligible",
    )
    public_network_eligible: Literal[False] = Field(
        default=False,
        alias="publicNetworkEligible",
    )
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("report_finished_at", "evaluated_at", "valid_until")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage deployment admission time")

    @field_validator("sequence", "max_report_age_seconds", mode="before")
    @classmethod
    def require_integer_fields(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Object Storage deployment admission numeric fields must be integers")
        return value

    @field_validator(
        "transport_admission_eligible",
        "public_network_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage deployment admission flags must be booleans")
        return value

    @model_validator(mode="after")
    def bind_admission(self) -> Self:
        if (self.sequence == 1) != (self.previous_admission_digest is None):
            raise ValueError("Object Storage deployment admission chain is not contiguous")
        expected_until = self.report_finished_at + timedelta(seconds=self.max_report_age_seconds)
        if (
            self.valid_until != expected_until
            or self.evaluated_at < self.report_finished_at
            or self.evaluated_at >= self.valid_until
        ):
            raise ValueError("Object Storage deployment admission freshness differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"admission_digest"})
        digest = _domain_digest(
            OBJECT_STORAGE_PROVIDER_DEPLOYMENT_ADMISSION_API_VERSION,
            material,
        )
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Object Storage deployment admission digest differs")
        object.__setattr__(self, "admission_digest", digest)
        return self


class ObjectStorageProviderAdmissionCheckpoint(StrictModel):
    """External checkpoint for the current policy and admission heads."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-admission-checkpoint/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-provider-admission-checkpoint/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageProviderAdmissionCheckpoint"] = (
        "ObjectStorageProviderAdmissionCheckpoint"
    )
    checkpoint_digest: str = Field(default="", alias="checkpointDigest", max_length=64)
    store_identity_digest: str = Field(alias="storeIdentityDigest", pattern=_SHA256_PATTERN)
    policy_sequence: int = Field(alias="policySequence", strict=True, ge=1, le=2**31 - 1)
    policy_digest: str = Field(alias="policyDigest", pattern=_SHA256_PATTERN)
    admission_sequence: int | None = Field(
        default=None,
        alias="admissionSequence",
        strict=True,
        ge=1,
        le=2**31 - 1,
    )
    admission_digest: str | None = Field(
        default=None,
        alias="admissionDigest",
        pattern=_SHA256_PATTERN,
    )
    transport_admission_current: bool = Field(alias="transportAdmissionCurrent")
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("policy_sequence", "admission_sequence", mode="before")
    @classmethod
    def require_integer_fields(cls, value: object) -> object:
        if value is not None and type(value) is not int:
            raise ValueError("Object Storage admission checkpoint numeric fields must be integers")
        return value

    @field_validator(
        "transport_admission_current",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage admission checkpoint flags must be booleans")
        return value

    @model_validator(mode="after")
    def bind_checkpoint(self) -> Self:
        if (self.admission_sequence is None) != (self.admission_digest is None):
            raise ValueError("Object Storage admission checkpoint admission head is partial")
        if self.transport_admission_current and self.admission_digest is None:
            raise ValueError("Current Object Storage admission checkpoint lacks an admission")
        material = self.model_dump(mode="json", by_alias=True, exclude={"checkpoint_digest"})
        digest = _domain_digest(
            OBJECT_STORAGE_PROVIDER_ADMISSION_CHECKPOINT_API_VERSION,
            material,
        )
        if self.checkpoint_digest and self.checkpoint_digest != digest:
            raise ValueError("Object Storage admission checkpoint digest differs")
        object.__setattr__(self, "checkpoint_digest", digest)
        return self


def compile_object_storage_selected_provider_evidence(
    *,
    inventory: MinioS3ProviderInventory,
    activation: ObjectStorageConcreteProviderActivation,
    report: ObjectStorageProviderConformanceReport,
) -> ObjectStorageSelectedProviderEvidence:
    """Bind the selected provider inventory to the activation and report that observed it."""

    try:
        trusted_inventory = MinioS3ProviderInventory.model_validate(
            inventory.model_dump(mode="json", by_alias=True)
        )
        trusted_activation = ObjectStorageConcreteProviderActivation.model_validate(
            activation.model_dump(mode="json", by_alias=True)
        )
        trusted_report = ObjectStorageProviderConformanceReport.model_validate(
            report.model_dump(mode="json", by_alias=True)
        )
        return ObjectStorageSelectedProviderEvidence(
            inventory=trusted_inventory,
            inventoryDigest=trusted_inventory.inventory_digest,
            activation=trusted_activation,
            activationDigest=trusted_activation.activation_digest,
            report=trusted_report,
            reportDigest=trusted_report.report_digest,
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage selected-provider evidence is invalid"
        ) from exc


def compile_object_storage_provider_admission_policy(
    evidence: ObjectStorageSelectedProviderEvidence,
    *,
    issued_at: datetime,
    previous_policy: ObjectStorageProviderAdmissionPolicy | None = None,
) -> ObjectStorageProviderAdmissionPolicy:
    """Select exact reviewed evidence under the fixed one-hour freshness ceiling."""

    try:
        trusted = ObjectStorageSelectedProviderEvidence.model_validate(
            evidence.model_dump(mode="json", by_alias=True)
        )
        issued = _normalize_timestamp(issued_at, label="Object Storage admission policy issue time")
        previous = (
            None
            if previous_policy is None
            else ObjectStorageProviderAdmissionPolicy.model_validate(
                previous_policy.model_dump(mode="json", by_alias=True)
            )
        )
        checkpoint = trusted.activation.authority_checkpoint
        if previous is not None and (
            previous.deployment_id != checkpoint.deployment_id
            or previous.tenant_id != checkpoint.tenant_id
            or issued < previous.issued_at
        ):
            raise ValueError("Object Storage admission policy successor scope differs")
        if issued < trusted.report.finished_at:
            raise ValueError("Object Storage admission policy predates selected evidence")
        return ObjectStorageProviderAdmissionPolicy(
            sequence=1 if previous is None else previous.sequence + 1,
            previousPolicyDigest=None if previous is None else previous.policy_digest,
            deploymentId=checkpoint.deployment_id,
            tenantId=checkpoint.tenant_id,
            issuedAt=issued,
            admissionEnabled=True,
            selectedEvidenceDigest=trusted.evidence_digest,
            selectedInventoryDigest=trusted.inventory_digest,
            selectedReportDigest=trusted.report_digest,
            selectedActivationDigest=trusted.activation_digest,
            selectedAuthorityCheckpointDigest=checkpoint.checkpoint_digest,
            selectedAdapterDigest=trusted.activation.adapter.adapter_digest,
            selectedDeploymentProfileDigest=(trusted.activation.deployment_profile.profile_digest),
            revokedInventoryDigests=(
                () if previous is None else previous.revoked_inventory_digests
            ),
            revokedReportDigests=(() if previous is None else previous.revoked_report_digests),
            transportAdmissionEligible=True,
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission policy could not select evidence"
        ) from exc


def revoke_object_storage_provider_admission(
    previous_policy: ObjectStorageProviderAdmissionPolicy,
    *,
    issued_at: datetime,
) -> ObjectStorageProviderAdmissionPolicy:
    """Append a deny-all successor that retroactively revokes the selected inventory/report."""

    try:
        previous = ObjectStorageProviderAdmissionPolicy.model_validate(
            previous_policy.model_dump(mode="json", by_alias=True)
        )
        issued = _normalize_timestamp(issued_at, label="Object Storage admission revocation time")
        if not previous.admission_enabled or issued < previous.issued_at:
            raise ValueError("Object Storage admission revocation predecessor differs")
        inventory_digest = previous.selected_inventory_digest
        report_digest = previous.selected_report_digest
        if inventory_digest is None or report_digest is None:
            raise ValueError("Object Storage admission revocation predecessor lacks evidence")
        return ObjectStorageProviderAdmissionPolicy(
            sequence=previous.sequence + 1,
            previousPolicyDigest=previous.policy_digest,
            deploymentId=previous.deployment_id,
            tenantId=previous.tenant_id,
            issuedAt=issued,
            admissionEnabled=False,
            revokedInventoryDigests=tuple(
                sorted(
                    {
                        *previous.revoked_inventory_digests,
                        inventory_digest,
                    }
                )
            ),
            revokedReportDigests=tuple(
                sorted(
                    {
                        *previous.revoked_report_digests,
                        report_digest,
                    }
                )
            ),
            transportAdmissionEligible=False,
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission revocation is invalid"
        ) from exc


class ObjectStorageProviderAdmissionStore:
    """Explicitly provisioned append-only SQLite policy and admission heads."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))

    @classmethod
    def bootstrap(
        cls,
        path: Path,
        *,
        store_id: str,
        policy: ObjectStorageProviderAdmissionPolicy,
        provisioned_at: datetime,
    ) -> ObjectStorageProviderAdmissionStore:
        database = Path(os.path.abspath(path))
        _require_safe_path(database)
        if database.exists():
            raise ObjectStorageProviderAdmissionError(
                "Object Storage provider admission store already exists"
            )
        try:
            trusted_policy = ObjectStorageProviderAdmissionPolicy.model_validate(
                policy.model_dump(mode="json", by_alias=True)
            )
            if trusted_policy.sequence != 1 or trusted_policy.previous_policy_digest is not None:
                raise ValueError("Object Storage admission bootstrap policy is not first")
            identity = ObjectStorageProviderAdmissionStoreIdentity(
                storeId=store_id,
                deploymentId=trusted_policy.deployment_id,
                tenantId=trusted_policy.tenant_id,
                provisionedAt=provisioned_at,
            )
            if identity.provisioned_at > trusted_policy.issued_at:
                raise ValueError("Object Storage admission store postdates its first policy")
            database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _require_safe_path(database)
            connection = _open_connection(database, readonly=False)
            try:
                mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
                if mode is None or str(mode[0]).lower() != "delete":
                    raise ValueError("Object Storage admission journal mode differs")
                connection.executescript(_SCHEMA_SQL)
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    (("schema_version", _SCHEMA_VERSION), ("schema_digest", _SCHEMA_DIGEST)),
                )
                connection.execute(
                    "INSERT INTO identity(singleton, identity_json) VALUES (1, ?)",
                    (identity.model_dump_json(by_alias=True),),
                )
                _insert_policy(connection, trusted_policy)
                connection.commit()
            finally:
                connection.close()
            database.chmod(0o600)
            return cls.open(database)
        except (sqlite3.Error, AttributeError, ValidationError, ValueError) as exc:
            raise ObjectStorageProviderAdmissionError(
                "Object Storage provider admission store could not bootstrap"
            ) from exc

    @classmethod
    def open(cls, path: Path) -> ObjectStorageProviderAdmissionStore:
        database = Path(os.path.abspath(path))
        if not database.exists():
            raise ObjectStorageProviderAdmissionError(
                "Object Storage provider admission store is absent; explicit bootstrap is required"
            )
        store = cls(database)
        with _read_transaction(database):
            pass
        return store

    def identity(self) -> ObjectStorageProviderAdmissionStoreIdentity:
        with _read_transaction(self.path) as connection:
            return _read_identity(connection).model_copy(deep=True)

    def current_policy(self) -> ObjectStorageProviderAdmissionPolicy:
        with _read_transaction(self.path) as connection:
            return _read_policies(connection)[-1].model_copy(deep=True)

    def current_admission(self) -> ObjectStorageProviderDeploymentAdmission | None:
        with _read_transaction(self.path) as connection:
            admissions = _read_admissions(connection)
            return None if not admissions else admissions[-1].model_copy(deep=True)

    def checkpoint(self) -> ObjectStorageProviderAdmissionCheckpoint:
        with _read_transaction(self.path) as connection:
            identity = _read_identity(connection)
            policy = _read_policies(connection)[-1]
            admissions = _read_admissions(connection)
            latest = None if not admissions else admissions[-1]
            current = (
                policy.admission_enabled
                and latest is not None
                and latest.policy_digest == policy.policy_digest
            )
            return ObjectStorageProviderAdmissionCheckpoint(
                storeIdentityDigest=identity.identity_digest,
                policySequence=policy.sequence,
                policyDigest=policy.policy_digest,
                admissionSequence=None if latest is None else latest.sequence,
                admissionDigest=None if latest is None else latest.admission_digest,
                transportAdmissionCurrent=current,
            )

    def rotate_policy(
        self,
        policy: ObjectStorageProviderAdmissionPolicy,
        *,
        expected_checkpoint: ObjectStorageProviderAdmissionCheckpoint,
    ) -> ObjectStorageProviderAdmissionPolicy:
        try:
            candidate = ObjectStorageProviderAdmissionPolicy.model_validate(
                policy.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise ObjectStorageProviderAdmissionError(
                "Object Storage admission policy successor is invalid"
            ) from exc
        with _write_transaction(self.path) as connection:
            _require_checkpoint(connection, expected_checkpoint)
            current = _read_policies(connection)[-1]
            if (
                candidate.sequence != current.sequence + 1
                or candidate.previous_policy_digest != current.policy_digest
                or candidate.deployment_id != current.deployment_id
                or candidate.tenant_id != current.tenant_id
                or candidate.issued_at < current.issued_at
                or not set(current.revoked_inventory_digests).issubset(
                    candidate.revoked_inventory_digests
                )
                or not set(current.revoked_report_digests).issubset(
                    candidate.revoked_report_digests
                )
            ):
                raise ObjectStorageProviderAdmissionError(
                    "Object Storage admission policy transition is invalid"
                )
            _insert_policy(connection, candidate)
        return self.current_policy()

    def admit(
        self,
        evidence: ObjectStorageSelectedProviderEvidence,
        *,
        inventory: MinioS3ProviderInventory,
        authority_store: ObjectStorageAuthorityHeadStore,
        journal: ObjectStorageProviderAttemptJournal,
        expected_checkpoint: ObjectStorageProviderAdmissionCheckpoint,
        evaluated_at: datetime,
    ) -> ObjectStorageProviderDeploymentAdmission:
        trusted_evidence, trusted_inventory, observed = _trusted_admission_inputs(
            evidence,
            inventory,
            evaluated_at,
        )
        with _write_transaction(self.path) as connection:
            _require_checkpoint(connection, expected_checkpoint)
            identity = _read_identity(connection)
            policy = _read_policies(connection)[-1]
            admissions = _read_admissions(connection)
            _require_policy_evidence(policy, trusted_evidence)
            _require_live_provider_context(
                trusted_evidence,
                trusted_inventory,
                authority_store=authority_store,
                journal=journal,
                require_no_pending=True,
            )
            _require_fresh_report(policy, trusted_evidence, observed)
            if admissions:
                current = admissions[-1]
                if (
                    current.policy_digest == policy.policy_digest
                    and current.evidence_digest == trusted_evidence.evidence_digest
                ):
                    _require_admission_time(current, observed)
                    return current.model_copy(deep=True)
            admission = ObjectStorageProviderDeploymentAdmission(
                sequence=len(admissions) + 1,
                previousAdmissionDigest=(
                    None if not admissions else admissions[-1].admission_digest
                ),
                storeIdentityDigest=identity.identity_digest,
                policyDigest=policy.policy_digest,
                deploymentId=policy.deployment_id,
                tenantId=policy.tenant_id,
                evidenceDigest=trusted_evidence.evidence_digest,
                inventoryDigest=trusted_evidence.inventory_digest,
                reportDigest=trusted_evidence.report_digest,
                activationDigest=trusted_evidence.activation_digest,
                authorityCheckpointDigest=(
                    trusted_evidence.activation.authority_checkpoint.checkpoint_digest
                ),
                adapterDigest=trusted_evidence.activation.adapter.adapter_digest,
                deploymentProfileDigest=(
                    trusted_evidence.activation.deployment_profile.profile_digest
                ),
                reportFinishedAt=trusted_evidence.report.finished_at,
                evaluatedAt=observed,
                validUntil=(
                    trusted_evidence.report.finished_at
                    + timedelta(seconds=policy.max_report_age_seconds)
                ),
            )
            _insert_admission(connection, admission)
        committed = self.current_admission()
        if committed != admission:
            raise ObjectStorageProviderAdmissionError(
                "Object Storage deployment admission commit differs"
            )
        return admission

    def require_current(
        self,
        admission: ObjectStorageProviderDeploymentAdmission,
        evidence: ObjectStorageSelectedProviderEvidence,
        *,
        inventory: MinioS3ProviderInventory,
        authority_store: ObjectStorageAuthorityHeadStore,
        journal: ObjectStorageProviderAttemptJournal,
        expected_checkpoint: ObjectStorageProviderAdmissionCheckpoint,
        now: datetime,
    ) -> ObjectStorageProviderDeploymentAdmission:
        try:
            trusted_admission = ObjectStorageProviderDeploymentAdmission.model_validate(
                admission.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise ObjectStorageProviderAdmissionError(
                "Object Storage deployment admission is invalid"
            ) from exc
        trusted_evidence, trusted_inventory, observed = _trusted_admission_inputs(
            evidence,
            inventory,
            now,
        )
        with _read_transaction(self.path) as connection:
            _require_checkpoint(connection, expected_checkpoint)
            policy = _read_policies(connection)[-1]
            admissions = _read_admissions(connection)
            if not admissions or admissions[-1] != trusted_admission:
                raise ObjectStorageProviderAdmissionError(
                    "Object Storage deployment admission is not the current head"
                )
            _require_policy_evidence(policy, trusted_evidence)
            if (
                trusted_admission.policy_digest != policy.policy_digest
                or trusted_admission.evidence_digest != trusted_evidence.evidence_digest
                or trusted_admission.inventory_digest != trusted_evidence.inventory_digest
                or trusted_admission.report_digest != trusted_evidence.report_digest
                or trusted_admission.activation_digest != trusted_evidence.activation_digest
            ):
                raise ObjectStorageProviderAdmissionError(
                    "Object Storage deployment admission identity differs"
                )
            _require_admission_time(trusted_admission, observed)
        _require_live_provider_context(
            trusted_evidence,
            trusted_inventory,
            authority_store=authority_store,
            journal=journal,
            require_no_pending=False,
        )
        return trusted_admission.model_copy(deep=True)


class _AdmissionGatedProvider:
    """Recheck admission immediately before remote work; never gate cleanup/reconciliation."""

    def __init__(
        self,
        provider: RecoverableObjectStorageProviderAdapter,
        *,
        gate: Callable[[], None],
    ) -> None:
        self._provider = provider
        self._gate = gate

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._provider.definition

    @property
    def deployment_profile(self) -> ObjectStorageProviderDeploymentProfile:
        return self._provider.deployment_profile

    def issue_upload_part(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        expires_at: datetime,
        operation_id: str,
    ) -> EphemeralObjectStorageUploadCredential:
        self._gate_or_reject()
        return self._provider.issue_upload_part(
            binding=binding,
            object_key=object_key,
            expires_at=expires_at,
            operation_id=operation_id,
        )

    def complete_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> None:
        self._gate_or_reject()
        return self._provider.complete_upload(binding=binding, operation_id=operation_id)

    def read_object(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        max_bytes: int,
        operation_id: str,
    ) -> bytes:
        self._gate_or_reject()
        return self._provider.read_object(
            binding=binding,
            object_key=object_key,
            max_bytes=max_bytes,
            operation_id=operation_id,
        )

    def cleanup_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageCleanupDisposition:
        return self._provider.cleanup_upload(binding=binding, operation_id=operation_id)

    def reconcile_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageProviderReconciliationDisposition:
        return self._provider.reconcile_upload(binding=binding, operation_id=operation_id)

    def _gate_or_reject(self) -> None:
        try:
            self._gate()
        except ObjectStorageProviderAdmissionError:
            raise ObjectStorageProviderCallRejected(
                "Object Storage provider deployment admission is not current"
            ) from None


class DeploymentAdmittedObjectStorageProviderRuntime:
    """Opt-in runtime that requires current admission at startup and before remote work."""

    def __init__(
        self,
        *,
        admission_store: ObjectStorageProviderAdmissionStore,
        expected_admission_checkpoint: ObjectStorageProviderAdmissionCheckpoint,
        admission: ObjectStorageProviderDeploymentAdmission,
        evidence: ObjectStorageSelectedProviderEvidence,
        inventory: MinioS3ProviderInventory,
        authority_store: ObjectStorageAuthorityHeadStore,
        repository: ManagedArtifactRepository,
        provider: RecoverableObjectStorageProviderAdapter,
        journal: ObjectStorageProviderAttemptJournal,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._admission_store = admission_store
        self._expected_admission_checkpoint = expected_admission_checkpoint.model_copy(deep=True)
        self._admission = admission.model_copy(deep=True)
        self._evidence = evidence.model_copy(deep=True)
        self._inventory = inventory.model_copy(deep=True)
        self._authority_store = authority_store
        self._journal = journal
        self._clock = clock or (lambda: datetime.now(UTC))
        self._require_current(now=self._clock())
        gated = _AdmissionGatedProvider(provider, gate=self._gate_now)
        self._runtime = RecoverableObjectStorageProviderRuntime(
            authority_store=authority_store,
            repository=repository,
            provider=cast(RecoverableObjectStorageProviderAdapter, gated),
            journal=journal,
        )

    def begin_attempt(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        now: datetime,
    ) -> ObjectStorageProviderAttemptSession:
        self._require_current(now=now)
        return self._runtime.begin_attempt(
            binding,
            expected_checkpoint=expected_checkpoint,
            now=now,
        )

    def reconcile_pending(self) -> tuple[str, ...]:
        """Keep cleanup available even after freshness expiry or explicit revocation."""

        return self._runtime.reconcile_pending()

    def _gate_now(self) -> None:
        self._require_current(now=self._clock())

    def _require_current(self, *, now: datetime) -> None:
        self._admission_store.require_current(
            self._admission,
            self._evidence,
            inventory=self._inventory,
            authority_store=self._authority_store,
            journal=self._journal,
            expected_checkpoint=self._expected_admission_checkpoint,
            now=now,
        )


def _trusted_admission_inputs(
    evidence: ObjectStorageSelectedProviderEvidence,
    inventory: MinioS3ProviderInventory,
    now: datetime,
) -> tuple[ObjectStorageSelectedProviderEvidence, MinioS3ProviderInventory, datetime]:
    try:
        trusted_evidence = ObjectStorageSelectedProviderEvidence.model_validate(
            evidence.model_dump(mode="json", by_alias=True)
        )
        trusted_inventory = MinioS3ProviderInventory.model_validate(
            inventory.model_dump(mode="json", by_alias=True)
        )
        observed = _normalize_timestamp(now, label="Object Storage admission evaluation time")
        return trusted_evidence, trusted_inventory, observed
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission input is invalid"
        ) from exc


def _require_policy_evidence(
    policy: ObjectStorageProviderAdmissionPolicy,
    evidence: ObjectStorageSelectedProviderEvidence,
) -> None:
    activation = evidence.activation
    if (
        not policy.admission_enabled
        or not policy.transport_admission_eligible
        or policy.deployment_id != activation.authority_checkpoint.deployment_id
        or policy.tenant_id != activation.authority_checkpoint.tenant_id
        or policy.selected_evidence_digest != evidence.evidence_digest
        or policy.selected_inventory_digest != evidence.inventory_digest
        or policy.selected_report_digest != evidence.report_digest
        or policy.selected_activation_digest != evidence.activation_digest
        or policy.selected_authority_checkpoint_digest
        != activation.authority_checkpoint.checkpoint_digest
        or policy.selected_adapter_digest != activation.adapter.adapter_digest
        or policy.selected_deployment_profile_digest != activation.deployment_profile.profile_digest
        or evidence.inventory_digest in policy.revoked_inventory_digests
        or evidence.report_digest in policy.revoked_report_digests
        or policy.issued_at < evidence.report.finished_at
    ):
        raise ObjectStorageProviderAdmissionError(
            "Object Storage selected evidence is not admitted by the current policy"
        )


def _require_fresh_report(
    policy: ObjectStorageProviderAdmissionPolicy,
    evidence: ObjectStorageSelectedProviderEvidence,
    now: datetime,
) -> None:
    valid_until = evidence.report.finished_at + timedelta(seconds=policy.max_report_age_seconds)
    if now < policy.issued_at or now < evidence.report.finished_at or now >= valid_until:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage conformance report is not fresh for admission"
        )


def _require_admission_time(
    admission: ObjectStorageProviderDeploymentAdmission,
    now: datetime,
) -> None:
    if now < admission.evaluated_at or now >= admission.valid_until:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage deployment admission is not currently fresh"
        )


def _require_live_provider_context(
    evidence: ObjectStorageSelectedProviderEvidence,
    inventory: MinioS3ProviderInventory,
    *,
    authority_store: ObjectStorageAuthorityHeadStore,
    journal: ObjectStorageProviderAttemptJournal,
    require_no_pending: bool,
) -> None:
    if inventory != evidence.inventory:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage runtime inventory differs from admitted evidence"
        )
    try:
        checkpoint = authority_store.checkpoint()
    except ObjectStorageAuthorityHeadStoreError as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage authority checkpoint is unavailable for admission"
        ) from exc
    if checkpoint != evidence.activation.authority_checkpoint:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage authority checkpoint differs from admitted evidence"
        )
    try:
        active = journal.require_active(
            authority_checkpoint=checkpoint,
            adapter=evidence.activation.adapter,
            deployment_profile=evidence.activation.deployment_profile,
        )
        if require_no_pending:
            journal.require_no_pending()
    except ObjectStorageProviderRecoveryError as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage provider activation is not ready for admission"
        ) from exc
    if active != evidence.activation:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage provider activation differs from admitted evidence"
        )


def _insert_policy(
    connection: sqlite3.Connection,
    policy: ObjectStorageProviderAdmissionPolicy,
) -> None:
    raw = policy.model_dump_json(by_alias=True)
    if len(raw.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ObjectStorageProviderAdmissionError("Object Storage admission policy is too large")
    connection.execute(
        "INSERT INTO policies(sequence, policy_digest, policy_json) VALUES (?, ?, ?)",
        (policy.sequence, policy.policy_digest, raw),
    )


def _insert_admission(
    connection: sqlite3.Connection,
    admission: ObjectStorageProviderDeploymentAdmission,
) -> None:
    raw = admission.model_dump_json(by_alias=True)
    if len(raw.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage deployment admission is too large"
        )
    connection.execute(
        "INSERT INTO admissions(sequence, admission_digest, admission_json) VALUES (?, ?, ?)",
        (admission.sequence, admission.admission_digest, raw),
    )


def _read_identity(connection: sqlite3.Connection) -> ObjectStorageProviderAdmissionStoreIdentity:
    rows = connection.execute("SELECT identity_json FROM identity ORDER BY singleton").fetchall()
    if len(rows) != 1:
        raise ObjectStorageProviderAdmissionError("Object Storage admission identity count differs")
    try:
        return ObjectStorageProviderAdmissionStoreIdentity.model_validate_json(str(rows[0][0]))
    except (ValidationError, ValueError) as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission identity is invalid"
        ) from exc


def _read_policies(
    connection: sqlite3.Connection,
) -> tuple[ObjectStorageProviderAdmissionPolicy, ...]:
    rows = connection.execute(
        "SELECT sequence, policy_digest, policy_json FROM policies ORDER BY sequence"
    ).fetchall()
    policies: list[ObjectStorageProviderAdmissionPolicy] = []
    for row in rows:
        try:
            policy = ObjectStorageProviderAdmissionPolicy.model_validate_json(str(row[2]))
        except (ValidationError, ValueError) as exc:
            raise ObjectStorageProviderAdmissionError(
                "Object Storage admission policy record is invalid"
            ) from exc
        expected_previous = None if not policies else policies[-1].policy_digest
        if (
            policy.sequence != len(policies) + 1
            or int(row[0]) != policy.sequence
            or str(row[1]) != policy.policy_digest
            or policy.previous_policy_digest != expected_previous
        ):
            raise ObjectStorageProviderAdmissionError(
                "Object Storage admission policy chain differs"
            )
        if policies and (
            policy.deployment_id != policies[-1].deployment_id
            or policy.tenant_id != policies[-1].tenant_id
            or policy.issued_at < policies[-1].issued_at
            or not set(policies[-1].revoked_inventory_digests).issubset(
                policy.revoked_inventory_digests
            )
            or not set(policies[-1].revoked_report_digests).issubset(policy.revoked_report_digests)
        ):
            raise ObjectStorageProviderAdmissionError(
                "Object Storage admission policy history regressed"
            )
        policies.append(policy)
    if not policies:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission policy history is empty"
        )
    return tuple(policies)


def _read_admissions(
    connection: sqlite3.Connection,
) -> tuple[ObjectStorageProviderDeploymentAdmission, ...]:
    rows = connection.execute(
        "SELECT sequence, admission_digest, admission_json FROM admissions ORDER BY sequence"
    ).fetchall()
    admissions: list[ObjectStorageProviderDeploymentAdmission] = []
    for row in rows:
        try:
            admission = ObjectStorageProviderDeploymentAdmission.model_validate_json(str(row[2]))
        except (ValidationError, ValueError) as exc:
            raise ObjectStorageProviderAdmissionError(
                "Object Storage deployment admission record is invalid"
            ) from exc
        expected_previous = None if not admissions else admissions[-1].admission_digest
        if (
            admission.sequence != len(admissions) + 1
            or int(row[0]) != admission.sequence
            or str(row[1]) != admission.admission_digest
            or admission.previous_admission_digest != expected_previous
        ):
            raise ObjectStorageProviderAdmissionError(
                "Object Storage deployment admission chain differs"
            )
        admissions.append(admission)
    return tuple(admissions)


def _require_checkpoint(
    connection: sqlite3.Connection,
    expected: ObjectStorageProviderAdmissionCheckpoint,
) -> None:
    try:
        trusted = ObjectStorageProviderAdmissionCheckpoint.model_validate(
            expected.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission expected checkpoint is invalid"
        ) from exc
    identity = _read_identity(connection)
    policy = _read_policies(connection)[-1]
    admissions = _read_admissions(connection)
    latest = None if not admissions else admissions[-1]
    actual = ObjectStorageProviderAdmissionCheckpoint(
        storeIdentityDigest=identity.identity_digest,
        policySequence=policy.sequence,
        policyDigest=policy.policy_digest,
        admissionSequence=None if latest is None else latest.sequence,
        admissionDigest=None if latest is None else latest.admission_digest,
        transportAdmissionCurrent=(
            policy.admission_enabled
            and latest is not None
            and latest.policy_digest == policy.policy_digest
        ),
    )
    if actual != trusted:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage provider admission checkpoint is stale"
        )


def _validate_history(connection: sqlite3.Connection) -> None:
    identity = _read_identity(connection)
    policies = _read_policies(connection)
    admissions = _read_admissions(connection)
    first_policy = policies[0]
    if (
        identity.deployment_id != first_policy.deployment_id
        or identity.tenant_id != first_policy.tenant_id
        or identity.provisioned_at > first_policy.issued_at
    ):
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission store identity differs from policy history"
        )

    policies_by_digest = {policy.policy_digest: policy for policy in policies}
    previous_admission: ObjectStorageProviderDeploymentAdmission | None = None
    for admission in admissions:
        policy = policies_by_digest.get(admission.policy_digest)
        if policy is None or not policy.admission_enabled:
            raise ObjectStorageProviderAdmissionError(
                "Object Storage deployment admission references an unavailable policy"
            )
        if (
            admission.store_identity_digest != identity.identity_digest
            or admission.deployment_id != identity.deployment_id
            or admission.tenant_id != identity.tenant_id
            or admission.evidence_digest != policy.selected_evidence_digest
            or admission.inventory_digest != policy.selected_inventory_digest
            or admission.report_digest != policy.selected_report_digest
            or admission.activation_digest != policy.selected_activation_digest
            or admission.authority_checkpoint_digest != policy.selected_authority_checkpoint_digest
            or admission.adapter_digest != policy.selected_adapter_digest
            or admission.deployment_profile_digest != policy.selected_deployment_profile_digest
            or admission.max_report_age_seconds != policy.max_report_age_seconds
            or admission.report_finished_at > policy.issued_at
            or admission.evaluated_at < policy.issued_at
            or (
                previous_admission is not None
                and admission.evaluated_at < previous_admission.evaluated_at
            )
        ):
            raise ObjectStorageProviderAdmissionError(
                "Object Storage deployment admission history differs from policy authority"
            )
        previous_admission = admission


def _validate_database(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchall()
    if [str(row[0]) for row in integrity] != ["ok"]:
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission store integrity check failed"
        )
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission store foreign keys differ"
        )
    if _schema_inventory(connection) != _expected_schema_inventory():
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission store schema inventory differs"
        )
    metadata = dict(connection.execute("SELECT key, value FROM metadata").fetchall())
    if metadata != {"schema_version": _SCHEMA_VERSION, "schema_digest": _SCHEMA_DIGEST}:
        raise ObjectStorageProviderAdmissionError("Object Storage admission store metadata differs")
    _validate_history(connection)


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
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission store ancestor is unsafe"
        )
    if parent.exists() and not parent.is_dir():
        raise ObjectStorageProviderAdmissionError("Object Storage admission store parent is unsafe")
    if (path.exists() or path.is_symlink() or path.is_junction()) and (
        not path.is_file() or path.is_symlink() or path.is_junction() or path.stat().st_nlink != 1
    ):
        raise ObjectStorageProviderAdmissionError(
            "Object Storage admission store is not a single-link regular file"
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
            raise ObjectStorageProviderAdmissionError(
                "Object Storage admission store sidecar is unsafe"
            )
