"""Closed, externally pinned inputs and receipts for one local recovery set."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.runtime.host_gate import HostGateIdentity
from pajin.runtime.host_recovery_models import HostRecoveryInventory
from pajin.supervision.run_binding import SupervisorRunBinding

MAX_CHECKPOINT_BYTES = 256 * 1024 * 1024
MAX_CHECKPOINT_FILES = 4096
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
Digest = Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")]
Identifier = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")]


class HostCheckpointError(RuntimeError):
    """A recovery set cannot be copied, authenticated or restored as declared."""


def canonical(value: BaseModel) -> bytes:
    return json.dumps(
        value.model_dump(mode="json", by_alias=True), sort_keys=True, ensure_ascii=False,
        allow_nan=False, separators=(",", ":"),
    ).encode("utf-8")


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value or len(value.encode("utf-8")) > 512 or path.is_absolute()
        or path.as_posix() != value or ".." in path.parts or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or value == "."
    ):
        raise ValueError("checkpoint paths must be canonical relative file paths")
    return value


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class HostCheckpointMember(_Model):
    """One required file below the host's state/ directory, never an arbitrary loader."""

    path: Annotated[str, Field(strict=True)]
    kind: Literal["control-plane-sqlite", "graph-sqlite", "supervisor-sqlite", "artifact"]
    campaign_id: str | None = Field(default=None, alias="campaignId")
    run_binding: SupervisorRunBinding | None = Field(default=None, alias="runBinding")
    artifact_sha256: Digest | None = Field(default=None, alias="artifactSha256")

    _path = field_validator("path")(relative_path)

    @model_validator(mode="after")
    def require_kind_binding(self) -> Self:
        if (self.kind == "graph-sqlite") != (self.campaign_id is not None):
            raise ValueError("only Graph members require a Campaign ID")
        if self.campaign_id is not None:
            import re

            if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,79}", self.campaign_id) is None:
                raise ValueError("Graph Campaign ID is invalid")
        if (self.kind == "supervisor-sqlite") != (self.run_binding is not None):
            raise ValueError("only Supervisor members require an exact Run binding")
        if (self.kind == "artifact") != (self.artifact_sha256 is not None):
            raise ValueError("only artifact members require an expected content digest")
        return self


class HostCheckpointPlan(_Model):
    api_version: Literal[
        "pajin.dev/host-checkpoint-plan/v1", "pajin.dev/host-checkpoint-plan/v2",
    ] = Field(
        default="pajin.dev/host-checkpoint-plan/v1", alias="apiVersion",
    )
    recovery_set_id: Identifier = Field(alias="recoverySetId")
    gate: HostGateIdentity
    enrollment: HostRecoveryInventory | None = Field(
        default=None, exclude_if=lambda value: value is None,
    )
    members: Annotated[tuple[HostCheckpointMember, ...], Field(
        min_length=1, max_length=MAX_CHECKPOINT_FILES,
    )]

    @model_validator(mode="after")
    def require_complete_partition(self) -> Self:
        if (self.api_version == "pajin.dev/host-checkpoint-plan/v2") != (
            self.enrollment is not None
        ):
            raise ValueError("only checkpoint plan v2 requires first-work enrollment")
        if self.enrollment is not None and self.enrollment.gate != self.gate:
            raise ValueError("checkpoint enrollment belongs to another host gate")
        paths = [member.path for member in self.members]
        if paths != sorted(set(paths)):
            raise ValueError("checkpoint members must be unique and sorted by path")
        if sum(member.kind == "control-plane-sqlite" for member in self.members) != 1:
            raise ValueError("a recovery set requires exactly one Control Plane database")
        occupied = set(paths)
        for member in self.members:
            if any(str(parent) in occupied for parent in PurePosixPath(member.path).parents):
                raise ValueError("checkpoint members cannot overlap")
            if member.kind != "artifact" and any(
                member.path + suffix in occupied for suffix in ("-wal", "-shm", "-journal")
            ):
                raise ValueError("SQLite sidecars cannot be separate checkpoint members")
        run_ids = [
            member.run_binding.control_plane_run_id for member in self.members
            if member.run_binding is not None
        ]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("each Control Plane Run must have one complete budget journal")
        return self

    @property
    def digest(self) -> str:
        return sha256(canonical(self)).hexdigest()


class HostCheckpointObject(_Model):
    path: str
    sha256: Digest
    size: Annotated[int, Field(strict=True, ge=0, le=MAX_CHECKPOINT_BYTES)]

    _path = field_validator("path")(relative_path)


class HostCheckpointStatement(_Model):
    api_version: Literal["pajin.dev/host-checkpoint/v1"] = Field(
        default="pajin.dev/host-checkpoint/v1", alias="apiVersion",
    )
    plan: HostCheckpointPlan
    created_at: datetime = Field(alias="createdAt")
    encryption_key_id: Identifier = Field(alias="encryptionKeyId")
    nonce_hex: Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{24}$")] = Field(
        alias="nonceHex",
    )
    objects: Annotated[tuple[HostCheckpointObject, ...], Field(
        min_length=1, max_length=MAX_CHECKPOINT_FILES * 2,
    )]
    ciphertext_sha256: Digest = Field(alias="ciphertextSha256")
    ciphertext_bytes: Annotated[int, Field(strict=True, ge=17, le=MAX_CHECKPOINT_BYTES + 16)] = (
        Field(alias="ciphertextBytes")
    )

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("checkpoint creation time must be UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_unique_objects(self) -> Self:
        paths = [item.path for item in self.objects]
        if paths != sorted(set(paths)) or sum(item.size for item in self.objects) > (
            MAX_CHECKPOINT_BYTES
        ):
            raise ValueError("checkpoint object inventory is invalid or too large")
        return self


class HostCheckpointManifest(_Model):
    statement: HostCheckpointStatement
    signing_key_id: Identifier = Field(alias="signingKeyId")
    signature_hex: Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{128}$")] = Field(
        alias="signatureHex",
    )

    @property
    def digest(self) -> str:
        """Retain independently; a signature alone does not reject an older valid backup."""
        return sha256(canonical(self)).hexdigest()
