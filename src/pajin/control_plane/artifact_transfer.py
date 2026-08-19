"""Bounded, content-addressed transport for sealed Replay Run trees."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from pajin.domain.models import StrictModel

MAX_PORTABLE_ARTIFACT_FILE_BYTES = 1 * 1024 * 1024
MAX_PORTABLE_ARTIFACT_TOTAL_BYTES = 2 * 1024 * 1024
MAX_PORTABLE_ARTIFACT_FILES = 256
MAX_PORTABLE_ARTIFACT_DEPTH = 24
MAX_PORTABLE_ARTIFACT_PATH_BYTES = 1_024
MAX_MULTIPART_ARTIFACT_FILE_BYTES = 16 * 1024 * 1024
MAX_MULTIPART_ARTIFACT_TOTAL_BYTES = 64 * 1024 * 1024
MULTIPART_ARTIFACT_PART_BYTES = 1 * 1024 * 1024
MAX_MULTIPART_ARTIFACT_PARTS = (
    MAX_PORTABLE_ARTIFACT_FILES
    + (
        MAX_MULTIPART_ARTIFACT_TOTAL_BYTES
        + MULTIPART_ARTIFACT_PART_BYTES
        - 1
    )
    // MULTIPART_ARTIFACT_PART_BYTES
)


def _canonical_manifest_bytes(entries: list[dict[str, object]]) -> bytes:
    return json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _canonical_base64(value: str, *, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{label} must be canonical base64")
    return decoded


class PortableArtifactManifestFile(StrictModel):
    """Content-addressed metadata for one regular portable Artifact file."""

    path: str = Field(min_length=1, max_length=MAX_PORTABLE_ARTIFACT_PATH_BYTES)
    size: int = Field(strict=True, ge=0, le=MAX_MULTIPART_ARTIFACT_FILE_BYTES)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("path")
    @classmethod
    def require_canonical_relative_path(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("portable Artifact paths must be valid UTF-8") from exc
        path = PurePosixPath(value)
        if (
            len(encoded) > MAX_PORTABLE_ARTIFACT_PATH_BYTES
            or path.is_absolute()
            or value != path.as_posix()
            or len(path.parts) > MAX_PORTABLE_ARTIFACT_DEPTH
            or ".." in path.parts
            or any(part in {"", "."} for part in path.parts)
        ):
            raise ValueError("portable Artifact paths must be canonical bounded relatives")
        return value

    @property
    def manifest_entry(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }


class PortableArtifactFile(PortableArtifactManifestFile):
    """One regular file carried by the bounded inline portable transport."""

    size: int = Field(strict=True, ge=0, le=MAX_PORTABLE_ARTIFACT_FILE_BYTES)
    content_base64: str = Field(
        min_length=0,
        max_length=((MAX_PORTABLE_ARTIFACT_FILE_BYTES + 2) // 3) * 4,
        pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    )

    @model_validator(mode="after")
    def require_exact_content(self) -> Self:
        content = _canonical_base64(
            self.content_base64,
            label="portable Artifact file content",
        )
        if len(content) != self.size or sha256(content).hexdigest() != self.sha256:
            raise ValueError("portable Artifact file content differs from its manifest")
        return self

    @property
    def content(self) -> bytes:
        return _canonical_base64(
            self.content_base64,
            label="portable Artifact file content",
        )


def _require_canonical_manifest(
    files: Sequence[PortableArtifactManifestFile],
    *,
    file_count: int,
    total_bytes: int,
    manifest_sha256: str,
) -> None:
    paths = [item.path for item in files]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("portable Artifact files must be uniquely and canonically sorted")
    path_set = set(paths)
    if any(
        parent.as_posix() in path_set
        for item in files
        for parent in PurePosixPath(item.path).parents
        if parent != PurePosixPath(".")
    ):
        raise ValueError("portable Artifact file paths cannot contain prefix collisions")
    if file_count != len(files):
        raise ValueError("portable Artifact file count is inconsistent")
    if total_bytes != sum(item.size for item in files):
        raise ValueError("portable Artifact total byte count is inconsistent")
    expected = portable_artifact_manifest_sha256(files)
    if manifest_sha256 != expected:
        raise ValueError("portable Artifact manifest digest is inconsistent")


class PortableArtifactBundle(StrictModel):
    """A small sealed Run carried inline by a separate Replay Worker host."""

    api_version: Literal["pajin.control-plane.portable-artifact-bundle/v1"] = (
        "pajin.control-plane.portable-artifact-bundle/v1"
    )
    files: list[PortableArtifactFile] = Field(
        min_length=1,
        max_length=MAX_PORTABLE_ARTIFACT_FILES,
    )
    file_count: int = Field(strict=True, ge=1, le=MAX_PORTABLE_ARTIFACT_FILES)
    total_bytes: int = Field(strict=True, ge=1, le=MAX_PORTABLE_ARTIFACT_TOTAL_BYTES)
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_canonical_manifest(self) -> Self:
        _require_canonical_manifest(
            self.files,
            file_count=self.file_count,
            total_bytes=self.total_bytes,
            manifest_sha256=self.manifest_sha256,
        )
        return self


class PortableArtifactMultipartManifest(StrictModel):
    """A large portable Artifact tree whose bytes travel as resumable parts."""

    api_version: Literal["pajin.control-plane.portable-artifact-multipart-manifest/v1"] = (
        "pajin.control-plane.portable-artifact-multipart-manifest/v1"
    )
    files: list[PortableArtifactManifestFile] = Field(
        min_length=1,
        max_length=MAX_PORTABLE_ARTIFACT_FILES,
    )
    file_count: int = Field(strict=True, ge=1, le=MAX_PORTABLE_ARTIFACT_FILES)
    total_bytes: int = Field(strict=True, ge=1, le=MAX_MULTIPART_ARTIFACT_TOTAL_BYTES)
    part_bytes: Literal[1048576] = 1_048_576
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_canonical_manifest(self) -> Self:
        _require_canonical_manifest(
            self.files,
            file_count=self.file_count,
            total_bytes=self.total_bytes,
            manifest_sha256=self.manifest_sha256,
        )
        return self

    @property
    def part_count(self) -> int:
        return sum((item.size + self.part_bytes - 1) // self.part_bytes for item in self.files)


class PortableArtifactMultipartPart(StrictModel):
    """One fixed-position, independently verified multipart object."""

    file_index: int = Field(strict=True, ge=0, lt=MAX_PORTABLE_ARTIFACT_FILES)
    part_number: int = Field(strict=True, ge=1, le=MAX_MULTIPART_ARTIFACT_PARTS)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content_base64: str = Field(
        min_length=4,
        max_length=((MULTIPART_ARTIFACT_PART_BYTES + 2) // 3) * 4,
        pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    )

    @model_validator(mode="after")
    def require_exact_content(self) -> Self:
        content = self.content
        if not content or len(content) > MULTIPART_ARTIFACT_PART_BYTES:
            raise ValueError("portable Artifact multipart part has an invalid size")
        if sha256(content).hexdigest() != self.sha256:
            raise ValueError("portable Artifact multipart part differs from its digest")
        return self

    @property
    def content(self) -> bytes:
        return _canonical_base64(
            self.content_base64,
            label="portable Artifact multipart part",
        )


class PortableArtifactMultipartUploadView(StrictModel):
    """Idempotent server observation of an initialized multipart upload."""

    api_version: Literal["pajin.control-plane.portable-artifact-multipart-upload/v1"] = (
        "pajin.control-plane.portable-artifact-multipart-upload/v1"
    )
    output_staging_id: str = Field(pattern=r"^stage_[0-9a-f]{32}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_count: int = Field(strict=True, ge=1, le=MAX_PORTABLE_ARTIFACT_FILES)
    total_bytes: int = Field(strict=True, ge=1, le=MAX_MULTIPART_ARTIFACT_TOTAL_BYTES)
    part_count: int = Field(strict=True, ge=1, le=MAX_MULTIPART_ARTIFACT_PARTS)
    executor_attestation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class PortableArtifactMultipartPartView(StrictModel):
    """Idempotent server receipt for one accepted multipart part."""

    api_version: Literal["pajin.control-plane.portable-artifact-multipart-part/v1"] = (
        "pajin.control-plane.portable-artifact-multipart-part/v1"
    )
    output_staging_id: str = Field(pattern=r"^stage_[0-9a-f]{32}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_index: int = Field(strict=True, ge=0, lt=MAX_PORTABLE_ARTIFACT_FILES)
    part_number: int = Field(strict=True, ge=1, le=MAX_MULTIPART_ARTIFACT_PARTS)
    part_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class PortableArtifactMultipartTransportReceipt(StrictModel):
    """Control Plane observation that multipart objects became a staging tree."""

    api_version: Literal["pajin.control-plane.portable-artifact-multipart-transport-receipt/v1"] = (
        "pajin.control-plane.portable-artifact-multipart-transport-receipt/v1"
    )
    object_store_profile: Literal["pajin.control-plane.local-object-store/v1"] = (
        "pajin.control-plane.local-object-store/v1"
    )
    output_staging_id: str = Field(pattern=r"^stage_[0-9a-f]{32}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_count: int = Field(strict=True, ge=1, le=MAX_PORTABLE_ARTIFACT_FILES)
    total_bytes: int = Field(strict=True, ge=1, le=MAX_MULTIPART_ARTIFACT_TOTAL_BYTES)
    part_count: int = Field(strict=True, ge=1, le=MAX_MULTIPART_ARTIFACT_PARTS)
    executor_attestation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class PortableArtifactTransportReceipt(StrictModel):
    """Control Plane observation that one inline bundle became a staging tree."""

    api_version: Literal["pajin.control-plane.portable-artifact-transport-receipt/v1"] = (
        "pajin.control-plane.portable-artifact-transport-receipt/v1"
    )
    output_staging_id: str = Field(pattern=r"^stage_[0-9a-f]{32}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_count: int = Field(strict=True, ge=1, le=MAX_PORTABLE_ARTIFACT_FILES)
    total_bytes: int = Field(strict=True, ge=1, le=MAX_PORTABLE_ARTIFACT_TOTAL_BYTES)


PortableArtifactTransportReceiptType = (
    PortableArtifactTransportReceipt | PortableArtifactMultipartTransportReceipt
)


def parse_portable_artifact_transport_receipt(
    value: object,
) -> PortableArtifactTransportReceiptType:
    """Validate one receipt serialized with the artifact transport model contract."""

    if not isinstance(value, dict):
        raise ValueError("portable Replay transport is not an object")
    api_version = value.get("api_version")
    if api_version == "pajin.control-plane.portable-artifact-transport-receipt/v1":
        return PortableArtifactTransportReceipt.model_validate(value)
    if api_version == "pajin.control-plane.portable-artifact-multipart-transport-receipt/v1":
        return PortableArtifactMultipartTransportReceipt.model_validate(value)
    raise ValueError("portable Replay transport version is unsupported")


def portable_artifact_manifest_sha256(
    files: Sequence[PortableArtifactManifestFile],
) -> str:
    """Return the canonical content-address for an already sorted file list."""

    return sha256(_canonical_manifest_bytes([item.manifest_entry for item in files])).hexdigest()
