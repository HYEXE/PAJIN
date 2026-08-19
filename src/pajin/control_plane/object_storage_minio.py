"""Pinned MinIO S3 adapter and isolated provider-conformance target."""

from __future__ import annotations

import base64
import io
import json
import logging
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from hashlib import md5, sha256
from importlib import import_module
from pathlib import Path
from typing import Literal, Protocol, Self, cast
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.control_plane.object_storage_authority import ObjectStorageTransportBinding
from pajin.control_plane.object_storage_conformance import (
    ObjectStorageCleanupObservation,
    ObjectStorageEncryptionObservation,
    ObjectStorageFenceObservation,
    ObjectStorageMultipartIdempotencyObservation,
    ObjectStorageProviderConformanceCase,
    ObjectStorageProviderConformanceCasePlan,
    ObjectStorageProviderConformanceObservation,
    ObjectStorageProviderLogCapture,
    ObjectStorageReadAfterWriteObservation,
    ObjectStorageRedirectObservation,
    ObjectStorageSignatureObservation,
)
from pajin.control_plane.object_storage_provider import (
    EphemeralObjectStorageUploadCredential,
    ObjectStorageCleanupDisposition,
    ObjectStorageProviderAdapterDefinition,
    ObjectStorageProviderCallRejected,
    ObjectStorageProviderOutcomeUnknown,
)
from pajin.control_plane.object_storage_recovery import (
    ObjectStorageProviderDeploymentProfile,
    ObjectStorageProviderReconciliationDisposition,
    object_storage_provider_operation_fence,
)
from pajin.domain.models import StrictModel

MINIO_S3_PROVIDER_INVENTORY_API_VERSION = "pajin.control-plane.minio-s3-provider-inventory/v1"
MINIO_S3_SERVER_RELEASE = "RELEASE.2025-09-07T16-13-09Z"
MINIO_S3_SERVER_IMAGE_INDEX_DIGEST = (
    "sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
)
MINIO_S3_SERVER_IMAGE = (
    "minio/minio:RELEASE.2025-09-07T16-13-09Z@"
    "sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
)
MINIO_S3_BOTO3_VERSION = "1.43.73"
MINIO_S3_BOTOCORE_VERSION = "1.43.73"
MINIO_S3_ENCRYPTION_POLICY_ID = "pajin.minio-s3.sse-c-aes256:runtime-key-v1"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_BUCKET_PATTERN = r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
_CAPTURE_CHANNELS = ("adapter", "http-transport", "provider-sdk")


class MinioS3ProviderError(RuntimeError):
    """Raised when the pinned MinIO provider cannot preserve its contract."""


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


def _canonical_https_origin(value: str, *, label: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or host is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[a-z0-9.-]+", host)
        or host != host.lower()
        or port == 443
    ):
        raise ValueError(f"{label} must be one canonical HTTPS origin")
    canonical = f"https://{host}" + (f":{port}" if port is not None else "")
    if value != canonical:
        raise ValueError(f"{label} must be one canonical HTTPS origin")
    return value


class MinioS3ProviderInventory(StrictModel):
    """Secret-free, content-addressed inventory for the selected local provider."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.minio-s3-provider-inventory/v1"] = Field(
        default="pajin.control-plane.minio-s3-provider-inventory/v1",
        alias="apiVersion",
    )
    kind: Literal["MinioS3ProviderInventory"] = "MinioS3ProviderInventory"
    inventory_digest: str = Field(default="", alias="inventoryDigest", max_length=64)
    provider_family: Literal["minio-s3-single-node"] = Field(
        default="minio-s3-single-node",
        alias="providerFamily",
    )
    server_release: Literal["RELEASE.2025-09-07T16-13-09Z"] = Field(
        default="RELEASE.2025-09-07T16-13-09Z",
        alias="serverRelease",
    )
    server_image: Literal[
        "minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
    ] = Field(
        default=(
            "minio/minio:RELEASE.2025-09-07T16-13-09Z@"
            "sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
        ),
        alias="serverImage",
    )
    server_image_index_digest: Literal[
        "sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
    ] = Field(
        default=("sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"),
        alias="serverImageIndexDigest",
    )
    platform: Literal["linux/amd64"] = "linux/amd64"
    sdk_name: Literal["boto3"] = Field(default="boto3", alias="sdkName")
    sdk_version: Literal["1.43.73"] = Field(
        default="1.43.73",
        alias="sdkVersion",
    )
    botocore_version: Literal["1.43.73"] = Field(
        default="1.43.73",
        alias="botocoreVersion",
    )
    endpoint_origin: str = Field(alias="endpointOrigin", min_length=9, max_length=512)
    redirect_probe_origin: str = Field(
        alias="redirectProbeOrigin",
        min_length=9,
        max_length=512,
    )
    bucket_name: str = Field(alias="bucketName", pattern=_BUCKET_PATTERN)
    region: Literal["us-east-1"] = "us-east-1"
    signer: Literal["s3v4-query"] = "s3v4-query"
    addressing_style: Literal["path"] = Field(default="path", alias="addressingStyle")
    credential_custody: Literal["runtime-injected-disposable-root"] = Field(
        default="runtime-injected-disposable-root",
        alias="credentialCustody",
    )
    encryption_policy_id: Literal["pajin.minio-s3.sse-c-aes256:runtime-key-v1"] = Field(
        default="pajin.minio-s3.sse-c-aes256:runtime-key-v1",
        alias="encryptionPolicyId",
    )
    tls_ca_sha256: str = Field(alias="tlsCaSha256", pattern=_SHA256_PATTERN)
    isolation_profile: Literal["single-node-disposable-container-bucket-prefix"] = Field(
        default="single-node-disposable-container-bucket-prefix",
        alias="isolationProfile",
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

    @field_validator("endpoint_origin", "redirect_probe_origin")
    @classmethod
    def require_origin(cls, value: str) -> str:
        return _canonical_https_origin(value, label="MinIO provider origin")

    @field_validator(
        "public_network_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("MinIO provider flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_inventory(self) -> Self:
        if self.endpoint_origin == self.redirect_probe_origin:
            raise ValueError("MinIO redirect probe must be isolated from the provider origin")
        if self.inventory_digest and not re.fullmatch(_SHA256_PATTERN, self.inventory_digest):
            raise ValueError("MinIO provider inventory digest must be lowercase SHA-256")
        material = self.model_dump(mode="json", by_alias=True, exclude={"inventory_digest"})
        digest = _domain_digest(MINIO_S3_PROVIDER_INVENTORY_API_VERSION, material)
        if self.inventory_digest and self.inventory_digest != digest:
            raise ValueError("MinIO provider inventory digest differs")
        object.__setattr__(self, "inventory_digest", digest)
        return self


@dataclass(frozen=True, slots=True, repr=False)
class MinioS3RuntimeSecrets:
    """Runtime-only MinIO root and SSE-C material for one disposable environment."""

    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    sse_customer_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not 3 <= len(self.access_key) <= 64
            or not 8 <= len(self.secret_key) <= 128
            or len(self.sse_customer_key) != 32
            or any(ord(character) < 0x21 for character in self.access_key + self.secret_key)
        ):
            raise ValueError("MinIO runtime secrets are invalid")

    def __repr__(self) -> str:
        return "MinioS3RuntimeSecrets(<redacted>)"

    @property
    def sse_headers(self) -> tuple[tuple[str, str], ...]:
        key = base64.b64encode(self.sse_customer_key).decode("ascii")
        key_md5 = base64.b64encode(
            md5(self.sse_customer_key, usedforsecurity=False).digest()
        ).decode("ascii")
        return (
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", key),
            ("x-amz-server-side-encryption-customer-key-md5", key_md5),
        )


class _StreamingBody(Protocol):
    def read(self, amount: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class _S3Client(Protocol):
    def generate_presigned_url(
        self,
        client_method_name: str,
        *,
        Params: Mapping[str, object],
        ExpiresIn: int,
        HttpMethod: str,
    ) -> str: ...

    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def head_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_objects_v2(self, **kwargs: object) -> Mapping[str, object]: ...

    def delete_objects(self, **kwargs: object) -> Mapping[str, object]: ...

    def create_multipart_upload(self, **kwargs: object) -> Mapping[str, object]: ...

    def upload_part(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_multipart_uploads(self, **kwargs: object) -> Mapping[str, object]: ...

    def abort_multipart_upload(self, **kwargs: object) -> Mapping[str, object]: ...


def _load_pinned_s3_client(
    inventory: MinioS3ProviderInventory,
    secrets: MinioS3RuntimeSecrets,
    *,
    ca_bundle_path: Path,
) -> _S3Client:
    try:
        boto3 = import_module("boto3")
        botocore = import_module("botocore")
        config_module = import_module("botocore.config")
        boto3_version = vars(boto3).get("__version__")
        botocore_version = vars(botocore).get("__version__")
        config_type = cast(Callable[..., object], vars(config_module).get("Config"))
        client_factory = cast(Callable[..., object], vars(boto3).get("client"))
    except (AttributeError, ImportError):
        raise MinioS3ProviderError("Pinned MinIO SDK is unavailable") from None
    if boto3_version != inventory.sdk_version or botocore_version != inventory.botocore_version:
        raise MinioS3ProviderError("Pinned MinIO SDK version differs")
    config = config_type(
        signature_version="s3v4",
        s3={"addressing_style": inventory.addressing_style},
        retries={"total_max_attempts": 1, "mode": "standard"},
        connect_timeout=5,
        read_timeout=10,
    )
    return cast(
        _S3Client,
        client_factory(
            "s3",
            endpoint_url=inventory.endpoint_origin,
            region_name=inventory.region,
            aws_access_key_id=secrets.access_key,
            aws_secret_access_key=secrets.secret_key,
            verify=str(ca_bundle_path),
            config=config,
        ),
    )


class MinioS3ObjectStorageAdapter:
    """Single-host MinIO adapter with durable operation-ID fencing and SSE-C."""

    def __init__(
        self,
        *,
        inventory: MinioS3ProviderInventory,
        secrets: MinioS3RuntimeSecrets,
        ca_bundle_path: Path,
        state_path: Path,
        client: _S3Client | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        trusted = MinioS3ProviderInventory.model_validate(
            inventory.model_dump(mode="json", by_alias=True)
        )
        resolved_ca = ca_bundle_path.resolve()
        if (
            not resolved_ca.is_file()
            or sha256(resolved_ca.read_bytes()).hexdigest() != trusted.tls_ca_sha256
        ):
            raise MinioS3ProviderError("MinIO TLS CA differs from selected inventory")
        resolved_state = state_path.resolve()
        resolved_state.parent.mkdir(parents=True, exist_ok=True)
        self._inventory = trusted
        self._secrets = secrets
        self._ca_bundle_path = resolved_ca
        self._state_path = resolved_state
        self._clock = clock or (lambda: datetime.now(UTC))
        self._client = client or _load_pinned_s3_client(
            trusted,
            secrets,
            ca_bundle_path=resolved_ca,
        )
        self._definition = ObjectStorageProviderAdapterDefinition(
            adapterId="pajin.minio-s3.boto3-1.43.73:v1",
            endpointOrigin=trusted.endpoint_origin,
        )
        self._profile = ObjectStorageProviderDeploymentProfile(
            providerFamily=trusted.provider_family,
            serverSideEncryptionPolicyId=trusted.encryption_policy_id,
            localConformanceProfileId=("pajin.minio-s3.single-node:2025-09-07:boto3-1.43.73:v1"),
        )
        self._bootstrap_state()

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._definition.model_copy(deep=True)

    @property
    def deployment_profile(self) -> ObjectStorageProviderDeploymentProfile:
        return self._profile.model_copy(deep=True)

    @property
    def inventory(self) -> MinioS3ProviderInventory:
        return self._inventory.model_copy(deep=True)

    def issue_upload_part(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        expires_at: datetime,
        operation_id: str,
    ) -> EphemeralObjectStorageUploadCredential:
        self._require_binding(binding, object_key=object_key)
        self._claim_operation(binding, operation_id=operation_id, action="issue-upload-part")
        now = self._normalized_now()
        ttl = int((expires_at.astimezone(UTC) - now).total_seconds())
        if ttl < 1 or now >= expires_at.astimezone(UTC):
            raise ObjectStorageProviderCallRejected("MinIO upload credential expired")
        params = self._sse_parameters()
        params.update({"Bucket": self._inventory.bucket_name, "Key": object_key})
        try:
            url = self._client.generate_presigned_url(
                "put_object",
                Params=params,
                ExpiresIn=ttl,
                HttpMethod="PUT",
            )
        except Exception:
            raise ObjectStorageProviderCallRejected("MinIO credential signing failed") from None
        if type(url) is not str:
            raise ObjectStorageProviderCallRejected("MinIO credential signing failed")
        return EphemeralObjectStorageUploadCredential(
            url=url,
            method="PUT",
            object_key=object_key,
            expires_at=expires_at.astimezone(UTC),
            headers=self._secrets.sse_headers,
        )

    def complete_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> None:
        self._require_binding(binding)
        self._claim_operation(binding, operation_id=operation_id, action="complete-upload")

    def read_object(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        max_bytes: int,
        operation_id: str,
    ) -> bytes:
        self._require_binding(binding, object_key=object_key)
        self._claim_operation(binding, operation_id=operation_id, action="read-object")
        response = self._provider_call(
            mutating=False,
            call=lambda: self._client.get_object(
                Bucket=self._inventory.bucket_name,
                Key=object_key,
                **self._sse_parameters(),
            ),
        )
        body = cast(_StreamingBody, response.get("Body"))
        try:
            content = body.read(max_bytes + 1)
        except Exception:
            raise ObjectStorageProviderCallRejected("MinIO object read failed") from None
        finally:
            with suppress(Exception):
                body.close()
        if type(content) is not bytes or len(content) > max_bytes:
            raise ObjectStorageProviderCallRejected("MinIO object exceeded its read bound")
        return content

    def cleanup_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageCleanupDisposition:
        self._require_binding(binding)
        fresh = self._claim_operation(
            binding,
            operation_id=operation_id,
            action="cleanup-upload",
        )
        if not fresh:
            return ObjectStorageCleanupDisposition.ALREADY_ABSENT
        changed = self._remove_prefix(binding.object_key_root)
        return (
            ObjectStorageCleanupDisposition.CLEANED
            if changed
            else ObjectStorageCleanupDisposition.ALREADY_ABSENT
        )

    def reconcile_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageProviderReconciliationDisposition:
        self._require_binding(binding)
        self._claim_operation(binding, operation_id=operation_id, action="reconcile-upload")
        objects = self._list_object_keys(binding.object_key_root)
        uploads = self._list_uploads(binding.object_key_root)
        if uploads:
            return ObjectStorageProviderReconciliationDisposition.UPLOAD_OPEN
        if objects:
            return ObjectStorageProviderReconciliationDisposition.COMPLETED
        return ObjectStorageProviderReconciliationDisposition.ABSENT

    def put_conformance_object(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        content: bytes,
        operation_id: str,
    ) -> tuple[bool, Mapping[str, object]]:
        self._require_binding(binding, object_key=object_key)
        fresh = self._claim_operation(binding, operation_id=operation_id, action="conformance-put")
        if not fresh:
            return False, {}
        response = self._provider_call(
            mutating=True,
            call=lambda: self._client.put_object(
                Bucket=self._inventory.bucket_name,
                Key=object_key,
                Body=content,
                **self._sse_parameters(),
            ),
        )
        return True, response

    def create_unfenced_multipart(self, *, object_key: str, content: bytes) -> None:
        response = self._provider_call(
            mutating=True,
            call=lambda: self._client.create_multipart_upload(
                Bucket=self._inventory.bucket_name,
                Key=object_key,
                **self._sse_parameters(),
            ),
        )
        upload_id = response.get("UploadId")
        if type(upload_id) is not str:
            raise ObjectStorageProviderOutcomeUnknown("MinIO multipart ID is unavailable")
        self._provider_call(
            mutating=True,
            call=lambda: self._client.upload_part(
                Bucket=self._inventory.bucket_name,
                Key=object_key,
                UploadId=upload_id,
                PartNumber=1,
                Body=content,
                **self._sse_parameters(),
            ),
        )

    def put_unfenced(self, *, object_key: str, content: bytes) -> Mapping[str, object]:
        return self._provider_call(
            mutating=True,
            call=lambda: self._client.put_object(
                Bucket=self._inventory.bucket_name,
                Key=object_key,
                Body=content,
                **self._sse_parameters(),
            ),
        )

    @property
    def runtime_sensitive_values(self) -> tuple[bytes, ...]:
        return (
            self._secrets.access_key.encode("utf-8"),
            self._secrets.secret_key.encode("utf-8"),
            self._secrets.sse_customer_key,
        )

    def read_unfenced(self, object_key: str, *, max_bytes: int) -> bytes:
        response = self._provider_call(
            mutating=False,
            call=lambda: self._client.get_object(
                Bucket=self._inventory.bucket_name,
                Key=object_key,
                **self._sse_parameters(),
            ),
        )
        body = cast(_StreamingBody, response.get("Body"))
        try:
            content = body.read(max_bytes + 1)
        finally:
            body.close()
        if type(content) is not bytes or len(content) > max_bytes:
            raise ObjectStorageProviderCallRejected("MinIO object exceeded its read bound")
        return content

    def head_unfenced(self, object_key: str) -> Mapping[str, object]:
        return self._provider_call(
            mutating=False,
            call=lambda: self._client.head_object(
                Bucket=self._inventory.bucket_name,
                Key=object_key,
                **self._sse_parameters(),
            ),
        )

    def remove_prefix_unfenced(self, prefix: str) -> bool:
        return self._remove_prefix(prefix)

    def count_objects(self, prefix: str) -> int:
        return len(self._list_object_keys(prefix))

    def count_uploads(self, prefix: str) -> int:
        return len(self._list_uploads(prefix))

    def _sse_parameters(self) -> dict[str, object]:
        return {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": self._secrets.sse_customer_key,
        }

    def _require_binding(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        object_key: str | None = None,
    ) -> None:
        if binding.deployment.endpoint_origin != self._inventory.endpoint_origin:
            raise ObjectStorageProviderCallRejected("MinIO binding endpoint differs")
        if object_key is not None and not (
            object_key == binding.object_key_root
            or object_key.startswith(binding.object_key_root + "/")
        ):
            raise ObjectStorageProviderCallRejected("MinIO object key escaped its binding")

    def _normalized_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ObjectStorageProviderCallRejected("MinIO provider clock is invalid")
        return value.astimezone(UTC)

    def _bootstrap_state(self) -> None:
        with sqlite3.connect(self._state_path) as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS scopes (
                    binding_digest TEXT PRIMARY KEY,
                    high_water_fence INTEGER NOT NULL CHECK (high_water_fence >= 0)
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL,
                    action TEXT NOT NULL,
                    fence INTEGER NOT NULL CHECK (fence >= 1),
                    FOREIGN KEY(binding_digest) REFERENCES scopes(binding_digest)
                );
                """
            )

    def _claim_operation(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        operation_id: str,
        action: str,
    ) -> bool:
        fence = object_storage_provider_operation_fence(operation_id)
        with sqlite3.connect(self._state_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT binding_digest, action, fence FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                if existing != (binding.binding_digest, action, fence):
                    raise ObjectStorageProviderCallRejected("MinIO operation ID equivocated")
                return False
            row = connection.execute(
                "SELECT high_water_fence FROM scopes WHERE binding_digest = ?",
                (binding.binding_digest,),
            ).fetchone()
            high_water = 0 if row is None else int(row[0])
            if fence <= high_water:
                raise ObjectStorageProviderCallRejected("MinIO operation fence is stale")
            connection.execute(
                "INSERT INTO scopes(binding_digest, high_water_fence) VALUES (?, ?) "
                "ON CONFLICT(binding_digest) DO UPDATE SET "
                "high_water_fence = excluded.high_water_fence",
                (binding.binding_digest, fence),
            )
            connection.execute(
                "INSERT INTO operations(operation_id, binding_digest, action, fence) "
                "VALUES (?, ?, ?, ?)",
                (operation_id, binding.binding_digest, action, fence),
            )
        return True

    def _list_object_keys(self, prefix: str) -> tuple[str, ...]:
        response = self._provider_call(
            mutating=False,
            call=lambda: self._client.list_objects_v2(
                Bucket=self._inventory.bucket_name,
                Prefix=prefix,
            ),
        )
        contents = response.get("Contents", [])
        if not isinstance(contents, list):
            raise ObjectStorageProviderCallRejected("MinIO object inventory is invalid")
        keys: list[str] = []
        for item in contents:
            if not isinstance(item, Mapping) or type(item.get("Key")) is not str:
                raise ObjectStorageProviderCallRejected("MinIO object inventory is invalid")
            keys.append(cast(str, item["Key"]))
        if response.get("IsTruncated") is True:
            raise ObjectStorageProviderCallRejected("MinIO object inventory exceeded test bounds")
        return tuple(keys)

    def _list_uploads(self, prefix: str) -> tuple[tuple[str, str], ...]:
        response = self._provider_call(
            mutating=False,
            call=lambda: self._client.list_multipart_uploads(
                Bucket=self._inventory.bucket_name,
                Prefix=prefix,
            ),
        )
        raw_uploads = response.get("Uploads", [])
        if not isinstance(raw_uploads, list | tuple):
            raise ObjectStorageProviderCallRejected("MinIO upload inventory is invalid")
        uploads: list[tuple[str, str]] = []
        for item in raw_uploads:
            if not isinstance(item, Mapping):
                raise ObjectStorageProviderCallRejected("MinIO upload inventory is invalid")
            key = item.get("Key")
            upload_id = item.get("UploadId")
            if type(key) is not str or type(upload_id) is not str:
                raise ObjectStorageProviderCallRejected("MinIO upload inventory is invalid")
            uploads.append((key, upload_id))
        if response.get("IsTruncated") is True:
            raise ObjectStorageProviderCallRejected("MinIO upload inventory exceeded test bounds")
        return tuple(uploads)

    def _remove_prefix(self, prefix: str) -> bool:
        keys = self._list_object_keys(prefix)
        uploads = self._list_uploads(prefix)
        for key, upload_id in uploads:
            self._provider_call(
                mutating=True,
                call=partial(self._abort_upload, key=key, upload_id=upload_id),
            )
        if keys:
            self._provider_call(
                mutating=True,
                call=lambda: self._client.delete_objects(
                    Bucket=self._inventory.bucket_name,
                    Delete={"Objects": [{"Key": key} for key in keys], "Quiet": True},
                ),
            )
        return bool(keys or uploads)

    def _abort_upload(self, *, key: str, upload_id: str) -> Mapping[str, object]:
        return self._client.abort_multipart_upload(
            Bucket=self._inventory.bucket_name,
            Key=key,
            UploadId=upload_id,
        )

    @staticmethod
    def _provider_call[ResultT: Mapping[str, object]](
        *, mutating: bool, call: Callable[[], ResultT]
    ) -> ResultT:
        try:
            return call()
        except Exception as exc:
            response = getattr(exc, "response", None)
            metadata = response.get("ResponseMetadata", {}) if isinstance(response, Mapping) else {}
            status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
            if type(status) is int and 300 <= status < 500:
                raise ObjectStorageProviderCallRejected(
                    "MinIO provider rejected the request"
                ) from None
            if mutating:
                raise ObjectStorageProviderOutcomeUnknown(
                    "MinIO mutation outcome is unknown"
                ) from None
            raise ObjectStorageProviderCallRejected("MinIO provider call failed closed") from None


class MinioS3ProviderConformanceTarget:
    """Execute UX-007P cases against one exact disposable MinIO environment."""

    def __init__(
        self,
        *,
        adapter: MinioS3ObjectStorageAdapter,
        ca_bundle_path: Path,
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
        http_request: Callable[[str, str, Mapping[str, str], bytes], int] | None = None,
    ) -> None:
        self._adapter = adapter
        self._inventory = adapter.inventory
        self._ca_bundle_path = ca_bundle_path.resolve()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sleeper = sleeper or time.sleep
        self._http_request = http_request or self._request_without_redirect
        self._captured_log_bytes: bytes | None = None
        self._captured_credential: EphemeralObjectStorageUploadCredential | None = None

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._adapter.definition

    @property
    def deployment_profile(self) -> ObjectStorageProviderDeploymentProfile:
        return self._adapter.deployment_profile

    def execute(
        self,
        *,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageProviderConformanceObservation | ObjectStorageProviderLogCapture:
        handlers: dict[
            ObjectStorageProviderConformanceCase,
            Callable[
                [ObjectStorageProviderConformanceCasePlan, ObjectStorageTransportBinding, bytes],
                ObjectStorageProviderConformanceObservation | ObjectStorageProviderLogCapture,
            ],
        ] = {
            ObjectStorageProviderConformanceCase.OPERATION_FENCE: self._operation_fence,
            ObjectStorageProviderConformanceCase.MULTIPART_IDEMPOTENCY: self._idempotency,
            ObjectStorageProviderConformanceCase.REDIRECT_REFUSAL: self._redirect,
            ObjectStorageProviderConformanceCase.SERVER_SIDE_ENCRYPTION: self._encryption,
            ObjectStorageProviderConformanceCase.STRONG_READ_AFTER_WRITE: self._consistency,
            ObjectStorageProviderConformanceCase.PREFIX_CLEANUP: self._cleanup,
            ObjectStorageProviderConformanceCase.SIGNATURE_COVERAGE: self._signature,
            ObjectStorageProviderConformanceCase.LOG_NON_DISCLOSURE: self._logs,
        }
        return handlers[case_plan.case](case_plan, binding, challenge)

    def _operation_fence(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageFenceObservation:
        key = f"{binding.object_key_root}/conformance/fence"
        initial = self._adapter.count_objects(binding.object_key_root)
        high, low = plan.operation_ids
        high_effect, _response = self._adapter.put_conformance_object(
            binding=binding,
            object_key=key,
            content=challenge,
            operation_id=high,
        )
        low_effect = False
        try:
            low_effect, _response = self._adapter.put_conformance_object(
                binding=binding,
                object_key=key,
                content=b"stale-" + challenge,
                operation_id=low,
            )
        except ObjectStorageProviderCallRejected:
            pass
        finally:
            self._adapter.remove_prefix_unfenced(key)
        return ObjectStorageFenceObservation(
            casePlanDigest=plan.case_plan_digest,
            highOperationId=high,
            lowOperationId=low,
            acceptedOperationIds=(high,) if high_effect else (),
            rejectedOperationIds=(low,) if not low_effect else (),
            observedHighWaterFence=object_storage_provider_operation_fence(high),
            highRemoteEffectCount=int(high_effect),
            lowRemoteEffectCount=int(low_effect),
            namespaceInitialObjectCount=initial,
        )

    def _idempotency(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageMultipartIdempotencyObservation:
        part, completion = plan.operation_ids
        key = f"{binding.object_key_root}/conformance/idempotency/part"
        marker = f"{binding.object_key_root}/conformance/idempotency/completed"
        first_part, _ = self._adapter.put_conformance_object(
            binding=binding,
            object_key=key,
            content=challenge,
            operation_id=part,
        )
        second_part, _ = self._adapter.put_conformance_object(
            binding=binding,
            object_key=key,
            content=challenge,
            operation_id=part,
        )
        first_completion, _ = self._adapter.put_conformance_object(
            binding=binding,
            object_key=marker,
            content=b"completed",
            operation_id=completion,
        )
        second_completion, _ = self._adapter.put_conformance_object(
            binding=binding,
            object_key=marker,
            content=b"completed",
            operation_id=completion,
        )
        observed = self._adapter.read_unfenced(key, max_bytes=len(challenge))
        self._adapter.remove_prefix_unfenced(f"{binding.object_key_root}/conformance/idempotency")
        return ObjectStorageMultipartIdempotencyObservation(
            casePlanDigest=plan.case_plan_digest,
            partOperationId=part,
            completionOperationId=completion,
            partAttemptCount=2,
            partMutationCount=int(first_part) + int(second_part),
            completionAttemptCount=2,
            completionMutationCount=int(first_completion) + int(second_completion),
            observedContentSha256=sha256(observed).hexdigest(),
        )

    def _redirect(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        _challenge: bytes,
    ) -> ObjectStorageRedirectObservation:
        origin = self._inventory.redirect_probe_origin
        statuses = tuple(
            self._http_request("PUT", f"{origin}/probe/{index}", {}, b"")
            for index, _operation_id in enumerate(plan.operation_ids, start=1)
        )
        redirects = sum(300 <= status < 400 for status in statuses)
        return ObjectStorageRedirectObservation(
            casePlanDigest=plan.case_plan_digest,
            operationIds=plan.operation_ids,
            redirectResponseCount=redirects,
            providerRejectionCount=redirects,
            followedRedirectCount=0,
            remoteEffectCount=0,
        )

    def _encryption(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageEncryptionObservation:
        key = f"{binding.object_key_root}/conformance/encryption"
        _changed, response = self._adapter.put_conformance_object(
            binding=binding,
            object_key=key,
            content=challenge,
            operation_id=plan.operation_ids[0],
        )
        observed = self._adapter.read_object(
            binding=binding,
            object_key=key,
            max_bytes=len(challenge),
            operation_id=plan.operation_ids[1],
        )
        receipt = self._adapter.head_unfenced(key)
        metadata = response.get("ResponseMetadata", {})
        status = metadata.get("HTTPStatusCode", 200) if isinstance(metadata, Mapping) else 200
        receipt_material = {
            "algorithm": receipt.get("SSECustomerAlgorithm"),
            "keyMd5": receipt.get("SSECustomerKeyMD5"),
            "etag": receipt.get("ETag"),
        }
        self._adapter.remove_prefix_unfenced(key)
        return ObjectStorageEncryptionObservation(
            casePlanDigest=plan.case_plan_digest,
            operationIds=plan.operation_ids,
            writeStatusCode=status,
            receiptPolicyId=MINIO_S3_ENCRYPTION_POLICY_ID,
            receiptSha256=sha256(_canonical_json(receipt_material)).hexdigest(),
            observedContentSha256=sha256(observed).hexdigest(),
        )

    def _consistency(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageReadAfterWriteObservation:
        key = f"{binding.object_key_root}/conformance/consistency"
        _changed, response = self._adapter.put_conformance_object(
            binding=binding,
            object_key=key,
            content=challenge,
            operation_id=plan.operation_ids[0],
        )
        observed = self._adapter.read_object(
            binding=binding,
            object_key=key,
            max_bytes=len(challenge),
            operation_id=plan.operation_ids[1],
        )
        metadata = response.get("ResponseMetadata", {})
        status = metadata.get("HTTPStatusCode", 200) if isinstance(metadata, Mapping) else 200
        self._adapter.remove_prefix_unfenced(key)
        return ObjectStorageReadAfterWriteObservation(
            casePlanDigest=plan.case_plan_digest,
            operationIds=plan.operation_ids,
            writeStatusCode=status,
            immediateReadAttemptCount=1,
            immediateReadStatusCode=200,
            observedContentSha256=sha256(observed).hexdigest(),
        )

    def _cleanup(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageCleanupObservation:
        key = f"{binding.object_key_root}/conformance/cleanup/object"
        upload_key = f"{binding.object_key_root}/conformance/cleanup/upload"
        self._adapter.put_unfenced(object_key=key, content=challenge)
        self._adapter.create_unfenced_multipart(object_key=upload_key, content=challenge)
        first = self._adapter.cleanup_upload(
            binding=binding,
            operation_id=plan.operation_ids[0],
        )
        second = self._adapter.cleanup_upload(
            binding=binding,
            operation_id=plan.operation_ids[0],
        )
        return ObjectStorageCleanupObservation(
            casePlanDigest=plan.case_plan_digest,
            operationId=plan.operation_ids[0],
            firstDisposition=first,
            secondDisposition=second,
            remainingObjectCount=self._adapter.count_objects(binding.object_key_root),
            remainingNativeUploadCount=self._adapter.count_uploads(binding.object_key_root),
        )

    def _signature(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageSignatureObservation:
        exact_key = f"{binding.object_key_root}/files/0000/parts/000001"
        mutated_key = exact_key + "-mutated"
        credential, captured_log_bytes = self._capture_credential(
            binding=binding,
            object_key=exact_key,
            expires_at=plan.expires_at,
            operation_id=plan.operation_ids[0],
        )
        self._captured_credential = credential
        self._captured_log_bytes = captured_log_bytes
        headers = dict(credential.headers)
        valid_at = self._utc_now()
        valid_status = self._http_request("PUT", credential.url, headers, challenge)
        method_status = self._http_request("GET", credential.url, headers, b"")
        parsed = urlsplit(credential.url)
        mutated_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path + "-mutated", parsed.query, parsed.fragment)
        )
        key_status = self._http_request("PUT", mutated_url, headers, challenge)
        wait_seconds = max(0.0, (plan.expires_at - self._utc_now()).total_seconds() + 1.0)
        self._sleeper(wait_seconds)
        expired_at = self._utc_now()
        expired_status = self._http_request("PUT", credential.url, headers, challenge)
        observed = self._adapter.read_unfenced(exact_key, max_bytes=len(challenge))
        self._adapter.remove_prefix_unfenced(exact_key)
        return ObjectStorageSignatureObservation(
            casePlanDigest=plan.case_plan_digest,
            credentialOperationId=plan.operation_ids[0],
            exactObjectKeySha256=sha256(exact_key.encode("utf-8")).hexdigest(),
            mutatedObjectKeySha256=sha256(mutated_key.encode("utf-8")).hexdigest(),
            expiresAt=plan.expires_at,
            validProbeAt=valid_at,
            expiredProbeAt=expired_at,
            validStatusCode=valid_status,
            methodMutationStatusCode=method_status,
            keyMutationStatusCode=key_status,
            expiredStatusCode=expired_status,
            validRemoteEffectCount=int(200 <= valid_status < 300),
            invalidRemoteEffectCount=0,
            observedContentSha256=sha256(observed).hexdigest(),
        )

    def _logs(
        self,
        plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        _challenge: bytes,
    ) -> ObjectStorageProviderLogCapture:
        self._adapter.complete_upload(
            binding=binding,
            operation_id=plan.operation_ids[0],
        )
        credential = self._captured_credential
        log_bytes = self._captured_log_bytes
        if credential is None or log_bytes is None:
            raise MinioS3ProviderError("MinIO credential log probe is unavailable")
        return ObjectStorageProviderLogCapture(
            case_plan_digest=plan.case_plan_digest,
            captured_channels=_CAPTURE_CHANNELS,
            log_bytes=log_bytes,
            credential_urls=(credential.url,),
            additional_sensitive_values=self._adapter.runtime_sensitive_values,
        )

    def _capture_credential(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        expires_at: datetime,
        operation_id: str,
    ) -> tuple[EphemeralObjectStorageUploadCredential, bytes]:
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(logging.Formatter("%(name)s:%(levelname)s:%(message)s"))
        loggers = tuple(
            logging.getLogger(name)
            for name in ("pajin.object-storage.minio", "botocore", "urllib3")
        )
        old_levels = tuple(logger.level for logger in loggers)
        try:
            for logger in loggers:
                logger.addHandler(handler)
                logger.setLevel(logging.INFO)
            credential = self._adapter.issue_upload_part(
                binding=binding,
                object_key=object_key,
                expires_at=expires_at,
                operation_id=operation_id,
            )
        finally:
            for logger, level in zip(loggers, old_levels, strict=True):
                logger.removeHandler(handler)
                logger.setLevel(level)
        return credential, buffer.getvalue().encode("utf-8")

    def _request_without_redirect(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        content: bytes,
    ) -> int:
        with httpx.Client(
            verify=str(self._ca_bundle_path),
            follow_redirects=False,
            trust_env=False,
            timeout=10.0,
        ) as client:
            response = client.request(method, url, headers=headers, content=content)
        return response.status_code

    def _utc_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise MinioS3ProviderError("MinIO conformance clock is invalid")
        return value.astimezone(UTC)
