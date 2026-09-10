"""Pinned configuration for one managed Linux/Docker PostgreSQL recovery boundary."""

from __future__ import annotations

import json
from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.runtime.host_checkpoint_models import relative_path
from pajin.supervision.run_binding import SupervisorRunBinding

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ContainerID = Digest
Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")]
ImageID = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 4096


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


def canonical(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return sha256(canonical(value)).hexdigest()


class GraphMember(Model):
    path: str
    campaign_id: str
    _path = field_validator("path")(relative_path)


class JournalMember(Model):
    path: str
    binding: SupervisorRunBinding
    _path = field_validator("path")(relative_path)


class RunMember(Model):
    path: str
    run_id: str
    _path = field_validator("path")(relative_path)


class Writer(Model):
    container_id: ContainerID
    image_id: ImageID
    role: Literal["control-plane", "worker", "postgres"]


class ResumeSigner(Model):
    public_key_hex: str = Field(pattern=r"^[a-f0-9]{64}$")
    subject: str = Field(min_length=1, max_length=200)


class Deployment(Model):
    version: Literal["pajin-hybrid-deployment-v1"] = "pajin-hybrid-deployment-v1"
    deployment_id: Identifier
    writer_label: str = Field(pattern=r"^pajin\.[a-z0-9.-]{1,80}$")
    writer_owner: Identifier
    writers: tuple[Writer, ...] = Field(min_length=1, max_length=32)
    postgres: Writer
    postgres_label: str = Field(pattern=r"^pajin\.[a-z0-9.-]{1,80}$")
    postgres_owner: Identifier
    database: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")
    database_user: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")
    graphs: tuple[GraphMember, ...] = Field(min_length=1, max_length=32)
    journals: tuple[JournalMember, ...] = Field(max_length=1024)
    runs: tuple[RunMember, ...] = Field(max_length=2048)
    checkpoint_key_commitments: dict[str, Digest]
    code_sha256: Digest
    state_root_sha256: Digest
    resume_signers: dict[Identifier, ResumeSigner] = Field(min_length=1, max_length=32)
    operator_api_origin: str = Field(pattern=r"^https://(?:127\.0\.0\.1|localhost):[0-9]{1,5}$")
    operator_ca_sha256: Digest

    @model_validator(mode="after")
    def require_unique_members(self) -> Self:
        ids = [w.container_id for w in (*self.writers, self.postgres)]
        paths = (
            [m.path for m in self.graphs]
            + [m.path for m in self.journals]
            + [m.path for m in self.runs]
        )
        if len(set(ids)) != len(ids) or len(set(paths)) != len(paths):
            raise ValueError("recovery members and containers must be distinct")
        if any(a.startswith(b + "/") for a in paths for b in paths if a != b):
            raise ValueError("recovery member paths must not overlap")
        run_ids = [m.binding.control_plane_run_id for m in self.journals]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("each Run requires one original accounting journal")
        if not self.checkpoint_key_commitments:
            raise ValueError("independent original checkpoint key commitments are required")
        if (
            self.postgres.role != "postgres"
            or sum(writer.role == "control-plane" for writer in self.writers) != 1
            or any(writer.role == "postgres" for writer in self.writers)
        ):
            raise ValueError(
                "recovery requires one control-only API and distinct execution Workers"
            )
        return self


class FileObject(Model):
    path: str
    sha256: Digest
    content: str
    _path = field_validator("path")(relative_path)


class Checkpoint(Model):
    version: Literal["pajin-hybrid-cold-checkpoint-v1"] = "pajin-hybrid-cold-checkpoint-v1"
    deployment: Deployment
    source_database_identity: Digest
    state_summary: dict[str, object]
    postgres_dump: FileObject
    files: tuple[FileObject, ...] = Field(min_length=1, max_length=MAX_FILES)
    created_at: datetime
    execution_authorized: Literal[False] = False


class ResumeAuthorization(Model):
    version: Literal["pajin-hybrid-resume-authorization-v1"] = (
        "pajin-hybrid-resume-authorization-v1"
    )
    checkpoint_sha256: Digest
    verification_sha256: Digest
    target_database_identity: Digest
    target_state_sha256: Digest
    checkpoint_id: Identifier
    approval_id: Identifier
    expires_at: datetime
    operator_subject: str = Field(min_length=1, max_length=200)
    key_id: Identifier
    signature_hex: str = Field(pattern=r"^[a-f0-9]{128}$")

    def signed_bytes(self) -> bytes:
        return b"pajin.hybrid-resume/v1\0" + canonical(
            self.model_dump(mode="json", exclude={"signature_hex"})
        )
