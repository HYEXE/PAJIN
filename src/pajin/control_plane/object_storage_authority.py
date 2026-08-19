"""Non-executable deployment authority for external Artifact transport."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.control_plane.artifact_transfer import PortableArtifactMultipartManifest
from pajin.domain.models import StrictModel

OBJECT_STORAGE_DEPLOYMENT_AUTHORITY_API_VERSION = (
    "pajin.control-plane.object-storage-deployment-authority/v1"
)
OBJECT_STORAGE_TRANSPORT_BINDING_API_VERSION = (
    "pajin.control-plane.object-storage-transport-binding/v1"
)
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_STAGING_ID_PATTERN = r"^stage_[0-9a-f]{32}$"
_OBJECT_KEY_PREFIX_MAX_BYTES = 512


class ObjectStorageDeploymentAuthorityError(RuntimeError):
    """Raised when external Object Storage deployment authority is not contiguous."""


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


class ObjectStorageDeploymentAuthority(StrictModel):
    """Versioned, transport-only deployment input for a future external adapter.

    The object deliberately cannot activate a provider or admit an Artifact. A future
    adapter must first pin a contiguous authority head and then issue ephemeral upload
    credentials without promoting their URL or object key into finalization authority.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-deployment-authority/v1"] = Field(
        default="pajin.control-plane.object-storage-deployment-authority/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageDeploymentAuthority"] = "ObjectStorageDeploymentAuthority"
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    revision: int = Field(strict=True, ge=1, le=2**31 - 1)
    previous_authority_digest: str | None = Field(
        default=None,
        alias="previousAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    issued_at: datetime = Field(alias="issuedAt")
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    transport_profile: Literal["pajin.control-plane.external-presigned-multipart/v1"] = Field(
        default="pajin.control-plane.external-presigned-multipart/v1",
        alias="transportProfile",
    )
    endpoint_origin: str = Field(alias="endpointOrigin", min_length=9, max_length=512)
    object_key_prefix: str = Field(alias="objectKeyPrefix", min_length=1, max_length=512)
    upload_ttl_seconds: int = Field(
        alias="uploadTtlSeconds",
        strict=True,
        ge=60,
        le=3_600,
    )
    max_file_bytes: Literal[16777216] = Field(
        default=16_777_216,
        alias="maxFileBytes",
    )
    max_total_bytes: Literal[67108864] = Field(
        default=67_108_864,
        alias="maxTotalBytes",
    )
    max_files: Literal[256] = Field(
        default=256,
        alias="maxFiles",
    )
    part_bytes: Literal[1048576] = Field(
        default=1_048_576,
        alias="partBytes",
    )
    artifact_admission_profile: Literal["pajin.control-plane.managed-artifact-repository/v1"] = (
        Field(
            default="pajin.control-plane.managed-artifact-repository/v1",
            alias="artifactAdmissionProfile",
        )
    )
    transport_only: Literal[True] = Field(default=True, alias="transportOnly")
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

    @field_validator("issued_at")
    @classmethod
    def require_utc_offset(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage authority issue time")

    @field_validator(
        "max_file_bytes",
        "max_total_bytes",
        "max_files",
        "part_bytes",
        mode="before",
    )
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Object Storage bounds must be JSON integers")
        return value

    @field_validator(
        "transport_only",
        "provider_integration_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage authority flags must be JSON booleans")
        return value

    @field_validator("endpoint_origin")
    @classmethod
    def require_canonical_https_origin(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Object Storage endpoint origin is invalid") from exc
        host = parsed.hostname
        if (
            parsed.scheme != "https"
            or host is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path
            or not re.fullmatch(r"[a-z0-9.-]+", host)
            or host != host.lower()
            or host.startswith(".")
            or host.endswith(".")
            or ".." in host
            or port == 443
        ):
            raise ValueError("Object Storage endpoint must be one canonical HTTPS origin")
        canonical = f"https://{host}" + (f":{port}" if port is not None else "")
        if value != canonical:
            raise ValueError("Object Storage endpoint must be one canonical HTTPS origin")
        return value

    @field_validator("object_key_prefix")
    @classmethod
    def require_canonical_object_key_prefix(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("Object Storage key prefix must be valid UTF-8") from exc
        path = PurePosixPath(value)
        if (
            len(encoded) > _OBJECT_KEY_PREFIX_MAX_BYTES
            or path.is_absolute()
            or value != path.as_posix()
            or ".." in path.parts
            or any(part in {"", "."} for part in path.parts)
        ):
            raise ValueError("Object Storage key prefix must be canonical and relative")
        return value

    @model_validator(mode="after")
    def bind_revision_and_digest(self) -> Self:
        if (self.revision == 1) != (self.previous_authority_digest is None):
            raise ValueError(
                "Object Storage authority revision one starts the chain and later "
                "revisions bind a predecessor"
            )
        if self.authority_digest and not re.fullmatch(_SHA256_PATTERN, self.authority_digest):
            raise ValueError("Object Storage authority digest must be lowercase SHA-256")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_digest"},
        )
        digest = _domain_digest(OBJECT_STORAGE_DEPLOYMENT_AUTHORITY_API_VERSION, material)
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Object Storage deployment authority digest differs")
        object.__setattr__(self, "authority_digest", digest)
        return self


class ObjectStorageTransportBinding(StrictModel):
    """One exact upload-only binding that cannot finalize or admit an Artifact."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-transport-binding/v1"] = Field(
        default="pajin.control-plane.object-storage-transport-binding/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageTransportBinding"] = "ObjectStorageTransportBinding"
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    deployment: ObjectStorageDeploymentAuthority
    output_staging_id: str = Field(alias="outputStagingId", pattern=_STAGING_ID_PATTERN)
    manifest: PortableArtifactMultipartManifest
    executor_attestation_digest: str = Field(
        alias="executorAttestationDigest",
        pattern=_SHA256_PATTERN,
    )
    issued_at: datetime = Field(alias="issuedAt")
    expires_at: datetime = Field(alias="expiresAt")
    object_key_root: str = Field(alias="objectKeyRoot", min_length=1, max_length=1_024)
    transport_scope: Literal["upload-only"] = Field(
        default="upload-only",
        alias="transportScope",
    )
    transport_only: Literal[True] = Field(default=True, alias="transportOnly")
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

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_utc_offset(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage transport timestamp")

    @field_validator(
        "transport_only",
        "provider_integration_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage transport flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_transport(self) -> Self:
        if self.deployment.provider_integration_eligible is not False:
            raise ValueError("Object Storage provider integration is not activated")
        if (
            self.manifest.file_count > self.deployment.max_files
            or self.manifest.total_bytes > self.deployment.max_total_bytes
            or self.manifest.part_bytes != self.deployment.part_bytes
            or any(item.size > self.deployment.max_file_bytes for item in self.manifest.files)
        ):
            raise ValueError("Object Storage transport manifest exceeds deployment bounds")
        expected_expiry = self.issued_at + timedelta(seconds=self.deployment.upload_ttl_seconds)
        if self.expires_at != expected_expiry:
            raise ValueError("Object Storage transport expiry differs from deployment authority")
        expected_root = _object_key_root(
            self.deployment,
            output_staging_id=self.output_staging_id,
            manifest_sha256=self.manifest.manifest_sha256,
        )
        if self.object_key_root != expected_root:
            raise ValueError("Object Storage key root differs from server-derived authority")
        if self.binding_digest and not re.fullmatch(_SHA256_PATTERN, self.binding_digest):
            raise ValueError("Object Storage transport digest must be lowercase SHA-256")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = _domain_digest(OBJECT_STORAGE_TRANSPORT_BINDING_API_VERSION, material)
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Object Storage transport binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


def select_object_storage_deployment_authority(
    current: ObjectStorageDeploymentAuthority | None,
    candidate: ObjectStorageDeploymentAuthority,
) -> ObjectStorageDeploymentAuthority:
    """Select an exact bootstrap/replay/successor and reject rollback or equivocation."""

    trusted = ObjectStorageDeploymentAuthority.model_validate(
        candidate.model_dump(mode="json", by_alias=True)
    )
    if current is None:
        if trusted.revision != 1 or trusted.previous_authority_digest is not None:
            raise ObjectStorageDeploymentAuthorityError(
                "Object Storage authority bootstrap must start at revision one"
            )
        return trusted
    remembered = ObjectStorageDeploymentAuthority.model_validate(
        current.model_dump(mode="json", by_alias=True)
    )
    if (
        trusted.deployment_id != remembered.deployment_id
        or trusted.tenant_id != remembered.tenant_id
        or trusted.transport_profile != remembered.transport_profile
        or trusted.artifact_admission_profile != remembered.artifact_admission_profile
    ):
        raise ObjectStorageDeploymentAuthorityError(
            "Object Storage authority transition changes deployment identity"
        )
    if trusted.revision == remembered.revision:
        if trusted != remembered:
            raise ObjectStorageDeploymentAuthorityError(
                "Object Storage authority revision equivocation was rejected"
            )
        return remembered
    if (
        trusted.revision != remembered.revision + 1
        or trusted.previous_authority_digest != remembered.authority_digest
        or trusted.issued_at <= remembered.issued_at
    ):
        raise ObjectStorageDeploymentAuthorityError(
            "Object Storage authority rollback, gap, or predecessor mismatch"
        )
    return trusted


def compile_object_storage_transport_binding(
    deployment: ObjectStorageDeploymentAuthority,
    *,
    output_staging_id: str,
    manifest: PortableArtifactMultipartManifest,
    executor_attestation_digest: str,
    issued_at: datetime,
) -> ObjectStorageTransportBinding:
    """Bind existing Replay integrity inputs to an upload-only external namespace."""

    trusted_deployment = ObjectStorageDeploymentAuthority.model_validate(
        deployment.model_dump(mode="json", by_alias=True)
    )
    trusted_manifest = PortableArtifactMultipartManifest.model_validate(
        manifest.model_dump(mode="json", by_alias=True)
    )
    normalized_issue_time = _normalize_timestamp(
        issued_at,
        label="Object Storage transport issue time",
    )
    return ObjectStorageTransportBinding(
        deployment=trusted_deployment,
        outputStagingId=output_staging_id,
        manifest=trusted_manifest,
        executorAttestationDigest=executor_attestation_digest,
        issuedAt=normalized_issue_time,
        expiresAt=normalized_issue_time + timedelta(seconds=trusted_deployment.upload_ttl_seconds),
        objectKeyRoot=_object_key_root(
            trusted_deployment,
            output_staging_id=output_staging_id,
            manifest_sha256=trusted_manifest.manifest_sha256,
        ),
    )


def object_storage_part_key(
    binding: ObjectStorageTransportBinding,
    *,
    file_index: int,
    part_number: int,
) -> str:
    """Derive one exact part key without accepting a caller-selected object key."""

    if type(file_index) is not int or type(part_number) is not int:
        raise ValueError("Object Storage part coordinates must be JSON integers")
    if file_index < 0 or file_index >= len(binding.manifest.files):
        raise ValueError("Object Storage file index is outside the manifest")
    file = binding.manifest.files[file_index]
    part_count = (file.size + binding.manifest.part_bytes - 1) // binding.manifest.part_bytes
    if part_number < 1 or part_number > part_count:
        raise ValueError("Object Storage part number is outside the manifest")
    return f"{binding.object_key_root}/files/{file_index:04d}/parts/{part_number:06d}"


def _object_key_root(
    deployment: ObjectStorageDeploymentAuthority,
    *,
    output_staging_id: str,
    manifest_sha256: str,
) -> str:
    if not re.fullmatch(_STAGING_ID_PATTERN, output_staging_id):
        raise ValueError("output_staging_id is not an opaque server-owned capability")
    if not re.fullmatch(_SHA256_PATTERN, manifest_sha256):
        raise ValueError("Object Storage manifest digest must be lowercase SHA-256")
    return (
        f"{deployment.object_key_prefix}/v1/{deployment.authority_digest}/"
        f"{output_staging_id}/{manifest_sha256}"
    )
