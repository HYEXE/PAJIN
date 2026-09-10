"""Exact APP-002 input and structural result contracts."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator

from pajin.domain.models import StrictModel

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
TOOL_ID = "application.elf-header-read"
CAPABILITY_ID = "pajin.application.elf-header-read"
ORIGIN = "https://application-scope.pajin.invalid/elf/"


def digest(value: object) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


class ELFInput(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    artifact_sha256: Digest = Field(alias="artifactSha256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=64, le=262_144)

    @property
    def target(self) -> str:
        return ORIGIN + self.artifact_sha256


class ELFHeader(ELFInput):
    schema_version: Literal["pajin.application.elf-header.v1"] = Field(alias="schema")
    elf_class: Literal[64] = Field(alias="class")
    byte_order: Literal["little"] = Field(alias="byteOrder")
    os_abi: int = Field(alias="osAbi", strict=True, ge=0, le=255)
    abi_version: int = Field(alias="abiVersion", strict=True, ge=0, le=255)
    elf_type: Literal["relocatable", "executable", "shared-object"] = Field(alias="type")
    machine: Literal["x86-64", "aarch64"]
    entry_point: str = Field(alias="entryPoint", pattern=r"^0x[0-9a-f]{16}$")
    flags: str = Field(pattern=r"^0x[0-9a-f]{8}$")
    program_header_count: int = Field(alias="programHeaderCount", strict=True, ge=0, le=65534)
    section_header_count: int = Field(alias="sectionHeaderCount", strict=True, ge=0, le=65535)
    section_name_index: int = Field(alias="sectionNameIndex", strict=True, ge=0, le=65534)


class ELFRuntimeObservation(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)
    effective_capabilities: int = Field(alias="effectiveCapabilities", ge=0, le=0)
    no_new_privileges: int = Field(alias="noNewPrivileges", ge=1, le=1)
    active_interfaces: list[Literal["lo"]] = Field(
        alias="activeInterfaces", min_length=1, max_length=1
    )
    inactive_interface_count: int = Field(alias="inactiveInterfaceCount", ge=0, le=4096)
    non_loopback_routes: int = Field(alias="nonLoopbackRoutes", ge=0, le=0)
    root_read_only: Literal[True] = Field(alias="rootReadOnly")
    workspace_no_exec: Literal[True] = Field(alias="workspaceNoExec")
    tmp_no_exec: Literal[True] = Field(alias="tmpNoExec")

    @field_validator("root_read_only", "workspace_no_exec", "tmp_no_exec", mode="before")
    @classmethod
    def require_json_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("ELF runtime flags must be JSON booleans")
        return value


class ELFWorkerOutput(StrictModel):
    header: ELFHeader
    parser_sha256: Digest = Field(alias="parserSha256")
    uid: Literal[65532]
    runtime: ELFRuntimeObservation

    @field_validator("uid", mode="before")
    @classmethod
    def require_integer_uid(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("ELF Worker UID must be an integer")
        return value


class ELFRunReference(StrictModel):
    run_id: str = Field(pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    root_digest: Digest
