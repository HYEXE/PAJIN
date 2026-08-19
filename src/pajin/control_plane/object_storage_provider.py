"""Provider-neutral external Object Storage transport with local revalidation."""

from __future__ import annotations

import base64
import json
import re
from abc import abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from functools import partial
from hashlib import sha256
from typing import Literal, Protocol, Self, TypeVar
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.control_plane.artifact_transfer import (
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    PortableArtifactMultipartPart,
    PortableArtifactMultipartTransportReceipt,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.artifacts import (
    ArtifactRepositoryError,
    ManagedArtifactRepository,
)
from pajin.control_plane.object_storage_activation import (
    ObjectStorageAuthorityHeadCheckpoint,
    ObjectStorageAuthorityHeadStore,
    ObjectStorageAuthorityHeadStoreError,
)
from pajin.control_plane.object_storage_authority import (
    ObjectStorageTransportBinding,
    object_storage_part_key,
)
from pajin.domain.models import StrictModel

OBJECT_STORAGE_PROVIDER_ADAPTER_API_VERSION = (
    "pajin.control-plane.object-storage-provider-adapter/v1"
)
OBJECT_STORAGE_PROVIDER_OPERATION_API_VERSION = (
    "pajin.control-plane.object-storage-provider-operation/v1"
)
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_MAX_EPHEMERAL_URL_CHARACTERS = 8_192
_T = TypeVar("_T")


class ObjectStorageProviderIntegrationError(RuntimeError):
    """Raised when provider transport cannot be proven safe for local admission."""


class ObjectStorageProviderCallRejected(RuntimeError):
    """A provider-confirmed rejection with no successful remote operation."""


class ObjectStorageProviderOutcomeUnknown(RuntimeError):
    """A remote mutation may have happened and requires explicit reconciliation."""


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


def _require_canonical_https_origin(value: str, *, label: str) -> str:
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
        raise ValueError(f"{label} must be one canonical HTTPS origin")
    canonical = f"https://{host}" + (f":{port}" if port is not None else "")
    if value != canonical:
        raise ValueError(f"{label} must be one canonical HTTPS origin")
    return value


class ObjectStorageProviderAdapterDefinition(StrictModel):
    """Non-secret identity for one trusted, provider-specific implementation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-adapter/v1"] = Field(
        default="pajin.control-plane.object-storage-provider-adapter/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageProviderAdapterDefinition"] = (
        "ObjectStorageProviderAdapterDefinition"
    )
    adapter_id: str = Field(alias="adapterId", pattern=_IDENTIFIER_PATTERN)
    adapter_digest: str = Field(default="", alias="adapterDigest", max_length=64)
    endpoint_origin: str = Field(alias="endpointOrigin", min_length=9, max_length=512)
    transport_profile: Literal["pajin.control-plane.external-presigned-multipart/v1"] = Field(
        default="pajin.control-plane.external-presigned-multipart/v1",
        alias="transportProfile",
    )
    operation_profile: Literal["pajin.control-plane.object-key-parts/v1"] = Field(
        default="pajin.control-plane.object-key-parts/v1",
        alias="operationProfile",
    )
    caller_locator_eligible: Literal[False] = Field(
        default=False,
        alias="callerLocatorEligible",
    )
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("endpoint_origin")
    @classmethod
    def require_endpoint_origin(cls, value: str) -> str:
        return _require_canonical_https_origin(value, label="Object Storage adapter endpoint")

    @field_validator(
        "caller_locator_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage adapter flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_definition(self) -> Self:
        if self.adapter_digest and not re.fullmatch(_SHA256_PATTERN, self.adapter_digest):
            raise ValueError("Object Storage adapter digest must be lowercase SHA-256")
        material = self.model_dump(mode="json", by_alias=True, exclude={"adapter_digest"})
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_ADAPTER_API_VERSION, material)
        if self.adapter_digest and self.adapter_digest != digest:
            raise ValueError("Object Storage adapter digest differs")
        object.__setattr__(self, "adapter_digest", digest)
        return self


@dataclass(frozen=True, slots=True, repr=False)
class EphemeralObjectStorageUploadCredential:
    """Runtime-only upload credential that deliberately has no durable wire model."""

    url: str = field(repr=False, compare=False)
    method: str
    object_key: str
    expires_at: datetime
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False, compare=False)

    def __repr__(self) -> str:
        return (
            "EphemeralObjectStorageUploadCredential("
            "url=<redacted>, "
            f"method={self.method!r}, object_key={self.object_key!r}, "
            f"expires_at={self.expires_at!r}, headers=<redacted>)"
        )


class ObjectStorageCleanupDisposition(StrEnum):
    """Provider observation for an idempotent remote-prefix cleanup."""

    CLEANED = "cleaned"
    ALREADY_ABSENT = "already-absent"
    UNKNOWN = "unknown"


class ObjectStorageProviderAdapter(Protocol):
    """Deployment-supplied provider implementation behind the authority gate.

    Native upload IDs and credentials remain private to the implementation. Every
    mutating method must use ``operation_id`` idempotently. It must not follow HTTP
    redirects across origins and must bind a returned credential to the exact key and
    expiry passed by the runtime.
    """

    @property
    @abstractmethod
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        """Return the exact non-secret implementation identity."""

    @abstractmethod
    def issue_upload_part(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        expires_at: datetime,
        operation_id: str,
    ) -> EphemeralObjectStorageUploadCredential:
        """Issue one ephemeral upload-only credential."""

    @abstractmethod
    def complete_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> None:
        """Close provider upload state without granting Artifact authority."""

    @abstractmethod
    def read_object(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        max_bytes: int,
        operation_id: str,
    ) -> bytes:
        """Read one exact server-derived object without redirecting origins."""

    @abstractmethod
    def cleanup_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageCleanupDisposition:
        """Idempotently remove all remote state under the binding root."""


class ObjectStorageProviderRuntime:
    """Move remote parts into existing managed staging without granting admission."""

    def __init__(
        self,
        *,
        authority_store: ObjectStorageAuthorityHeadStore,
        repository: ManagedArtifactRepository,
        provider: ObjectStorageProviderAdapter,
    ) -> None:
        try:
            definition = ObjectStorageProviderAdapterDefinition.model_validate(
                provider.definition.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValueError) as exc:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage provider definition is invalid"
            ) from exc
        self._authority_store = authority_store
        self._repository = repository
        self._provider = provider
        self._definition = definition

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._definition.model_copy(deep=True)

    def issue_upload_part(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        file_index: int,
        part_number: int,
        now: datetime,
    ) -> EphemeralObjectStorageUploadCredential:
        """Issue a checked URL only while the exact binding head remains current."""

        trusted = self._require_binding(binding)
        self._require_unexpired(trusted, now=now)
        try:
            object_key = object_storage_part_key(
                trusted,
                file_index=file_index,
                part_number=part_number,
            )
        except ValueError as exc:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage upload part coordinate is invalid"
            ) from exc
        operation_id = _operation_id(
            self._definition,
            trusted,
            action="issue-upload-part",
            object_key=object_key,
        )
        raw = self._provider_call(
            trusted,
            expected_checkpoint=expected_checkpoint,
            operation="upload credential issuance",
            call=lambda: self._provider.issue_upload_part(
                binding=trusted,
                object_key=object_key,
                expires_at=trusted.expires_at,
                operation_id=operation_id,
            ),
            mutating=True,
        )
        return _verify_ephemeral_credential(
            raw,
            binding=trusted,
            object_key=object_key,
        )

    def complete_and_stage(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        now: datetime,
    ) -> PortableArtifactMultipartTransportReceipt:
        """Re-read and hash every remote byte before publishing managed staging."""

        trusted = self._require_binding(binding)
        self._require_unexpired(trusted, now=now)
        completion_operation_id = _operation_id(
            self._definition,
            trusted,
            action="complete-upload",
        )
        completion = self._provider_call(
            trusted,
            expected_checkpoint=expected_checkpoint,
            operation="upload completion",
            call=partial(
                self._provider.complete_upload,
                binding=trusted,
                operation_id=completion_operation_id,
            ),
            mutating=True,
        )
        if completion is not None:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage provider completion returned unsupported authority metadata"
            )

        verified_files = self._read_and_verify_remote_files(
            trusted,
            expected_checkpoint=expected_checkpoint,
        )
        try:
            self._repository.begin_portable_multipart_upload(
                staging_id=trusted.output_staging_id,
                manifest=trusted.manifest,
                executor_attestation_digest=trusted.executor_attestation_digest,
            )
            for file_index, content in enumerate(verified_files):
                for offset in range(0, len(content), trusted.manifest.part_bytes):
                    part_content = content[offset : offset + trusted.manifest.part_bytes]
                    part = PortableArtifactMultipartPart(
                        file_index=file_index,
                        part_number=(offset // trusted.manifest.part_bytes) + 1,
                        sha256=sha256(part_content).hexdigest(),
                        content_base64=base64.b64encode(part_content).decode("ascii"),
                    )
                    self._repository.put_portable_multipart_part(
                        staging_id=trusted.output_staging_id,
                        manifest_sha256=trusted.manifest.manifest_sha256,
                        part=part,
                    )
            return self._repository.materialize_portable_multipart_upload(
                staging_id=trusted.output_staging_id,
                manifest=trusted.manifest,
                executor_attestation_digest=trusted.executor_attestation_digest,
            )
        except (ArtifactRepositoryError, ValueError) as exc:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage remote bytes failed authoritative local staging"
            ) from exc

    def cleanup_upload(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
    ) -> ObjectStorageCleanupDisposition:
        """Clean an expired or abandoned current-head upload without automatic retry."""

        trusted = self._require_binding(binding)
        cleanup_operation_id = _operation_id(
            self._definition,
            trusted,
            action="cleanup-upload",
        )
        disposition = self._provider_call(
            trusted,
            expected_checkpoint=expected_checkpoint,
            operation="upload cleanup",
            call=partial(
                self._provider.cleanup_upload,
                binding=trusted,
                operation_id=cleanup_operation_id,
            ),
            mutating=True,
        )
        if type(disposition) is not ObjectStorageCleanupDisposition:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage provider returned an invalid cleanup disposition"
            )
        if disposition is ObjectStorageCleanupDisposition.UNKNOWN:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage cleanup outcome is unknown; operator reconciliation is required"
            )
        return disposition

    def _read_and_verify_remote_files(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
    ) -> tuple[bytes, ...]:
        contents: list[bytes] = []
        observed_files: list[PortableArtifactManifestFile] = []
        for file_index, expected_file in enumerate(binding.manifest.files):
            collected = bytearray()
            part_count = (
                expected_file.size + binding.manifest.part_bytes - 1
            ) // binding.manifest.part_bytes
            for part_number in range(1, part_count + 1):
                remaining = expected_file.size - len(collected)
                expected_size = min(binding.manifest.part_bytes, remaining)
                object_key = object_storage_part_key(
                    binding,
                    file_index=file_index,
                    part_number=part_number,
                )
                raw = self._provider_call(
                    binding,
                    expected_checkpoint=expected_checkpoint,
                    operation="remote object read",
                    call=partial(
                        self._provider.read_object,
                        binding=binding,
                        object_key=object_key,
                        max_bytes=expected_size,
                        operation_id=_operation_id(
                            self._definition,
                            binding,
                            action="read-object",
                            object_key=object_key,
                        ),
                    ),
                    mutating=False,
                )
                if type(raw) is not bytes or len(raw) != expected_size:
                    raise ObjectStorageProviderIntegrationError(
                        "Object Storage remote object differs from its bounded part size"
                    )
                collected.extend(raw)
            content = bytes(collected)
            observed_files.append(
                PortableArtifactManifestFile(
                    path=expected_file.path,
                    size=len(content),
                    sha256=sha256(content).hexdigest(),
                )
            )
            contents.append(content)
        observed_manifest = PortableArtifactMultipartManifest(
            files=observed_files,
            file_count=len(observed_files),
            total_bytes=sum(len(item) for item in contents),
            part_bytes=binding.manifest.part_bytes,
            manifest_sha256=portable_artifact_manifest_sha256(observed_files),
        )
        if observed_manifest != binding.manifest:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage remote bytes differ from the canonical manifest"
            )
        return tuple(contents)

    def _require_binding(
        self,
        binding: ObjectStorageTransportBinding,
    ) -> ObjectStorageTransportBinding:
        try:
            trusted = ObjectStorageTransportBinding.model_validate(
                binding.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValueError) as exc:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage transport binding is invalid"
            ) from exc
        if (
            self._definition.endpoint_origin != trusted.deployment.endpoint_origin
            or self._definition.transport_profile != trusted.deployment.transport_profile
        ):
            raise ObjectStorageProviderIntegrationError(
                "Object Storage provider differs from deployment authority"
            )
        return trusted

    @staticmethod
    def _require_unexpired(
        binding: ObjectStorageTransportBinding,
        *,
        now: datetime,
    ) -> None:
        try:
            observed = _normalize_timestamp(now, label="Object Storage operation time")
        except ValueError as exc:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage operation time is invalid"
            ) from exc
        if observed < binding.issued_at or observed >= binding.expires_at:
            raise ObjectStorageProviderIntegrationError(
                "Object Storage upload binding is not currently usable"
            )

    def _provider_call(
        self,
        binding: ObjectStorageTransportBinding,
        *,
        expected_checkpoint: ObjectStorageAuthorityHeadCheckpoint,
        operation: str,
        call: Callable[[], _T],
        mutating: bool,
    ) -> _T:
        try:
            self._authority_store.require_current(
                binding.deployment,
                expected_checkpoint=expected_checkpoint,
            )
        except ObjectStorageAuthorityHeadStoreError as exc:
            raise ObjectStorageProviderIntegrationError(
                f"Object Storage {operation} lacks the durable current authority head"
            ) from exc
        try:
            return call()
        except ObjectStorageProviderCallRejected:
            raise ObjectStorageProviderIntegrationError(
                f"Object Storage provider rejected {operation}"
            ) from None
        except ObjectStorageProviderOutcomeUnknown:
            raise ObjectStorageProviderIntegrationError(
                f"Object Storage {operation} outcome is unknown; explicit cleanup is required"
            ) from None
        except Exception:
            suffix = (
                "outcome is unknown; explicit cleanup is required" if mutating else "failed closed"
            )
            raise ObjectStorageProviderIntegrationError(
                f"Object Storage {operation} {suffix}"
            ) from None


def _verify_ephemeral_credential(
    credential: object,
    *,
    binding: ObjectStorageTransportBinding,
    object_key: str,
) -> EphemeralObjectStorageUploadCredential:
    if not isinstance(credential, EphemeralObjectStorageUploadCredential):
        raise ObjectStorageProviderIntegrationError(
            "Object Storage provider returned an invalid ephemeral credential"
        )
    try:
        expiry = _normalize_timestamp(
            credential.expires_at,
            label="Object Storage credential expiry",
        )
        parsed = urlsplit(credential.url)
        port = parsed.port
    except (AttributeError, TypeError, ValueError):
        raise ObjectStorageProviderIntegrationError(
            "Object Storage provider returned an invalid ephemeral credential"
        ) from None
    host = parsed.hostname
    headers = credential.headers
    if (
        type(headers) is not tuple
        or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            or item[0] != item[0].lower()
            or not re.fullmatch(r"[a-z0-9-]{1,100}", item[0])
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item[1])
            for item in headers
        )
        or len({name for name, _value in headers}) != len(headers)
    ):
        raise ObjectStorageProviderIntegrationError(
            "Object Storage provider returned invalid runtime-only credential headers"
        )
    origin = (
        f"https://{host}" + (f":{port}" if port is not None else "") if host is not None else ""
    )
    if (
        type(credential.url) is not str
        or not 9 <= len(credential.url) <= _MAX_EPHEMERAL_URL_CHARACTERS
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in credential.url)
        or credential.method != "PUT"
        or credential.object_key != object_key
        or expiry != binding.expires_at
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
        or origin != binding.deployment.endpoint_origin
    ):
        raise ObjectStorageProviderIntegrationError(
            "Object Storage upload credential differs from pinned transport authority"
        )
    return credential


def _operation_id(
    definition: ObjectStorageProviderAdapterDefinition,
    binding: ObjectStorageTransportBinding,
    *,
    action: str,
    object_key: str | None = None,
) -> str:
    material: dict[str, object] = {
        "action": action,
        "adapterDigest": definition.adapter_digest,
        "bindingDigest": binding.binding_digest,
    }
    if object_key is not None:
        material["objectKey"] = object_key
    digest = _domain_digest(OBJECT_STORAGE_PROVIDER_OPERATION_API_VERSION, material)
    return f"object-storage-operation_{digest}"
