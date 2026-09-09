"""Immutable first-use registration records, not execution authorities."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.runtime.host_gate import HostGateIdentity
from pajin.runtime.inventory import RuntimeComponentFingerprint
from pajin.supervision.run_binding import SupervisorRunBinding


def recovery_bytes(value: BaseModel) -> bytes:
    return json.dumps(
        value.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def recovery_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or len(value.encode()) > 512
        or value == "."
        or path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("recovery registration requires a canonical relative path")
    return value


class RecoveryRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    path: str
    kind: Literal["control-plane-sqlite", "graph-sqlite", "supervisor-sqlite", "run-store"]
    campaign_id: str | None = Field(default=None, alias="campaignId")
    run_id: str | None = Field(default=None, alias="runId")
    run_binding: SupervisorRunBinding | None = Field(default=None, alias="runBinding")

    _path = field_validator("path")(recovery_path)

    @model_validator(mode="after")
    def require_kind_binding(self) -> Self:
        if (self.kind == "graph-sqlite") != (self.campaign_id is not None):
            raise ValueError("Graph registration requires its Campaign ID")
        if (self.kind == "supervisor-sqlite") != (self.run_binding is not None):
            raise ValueError("Supervisor registration requires a complete Run binding")
        if (self.kind == "run-store") != (self.run_id is not None):
            raise ValueError("RunStore registration requires its exact Run ID")
        return self

    @property
    def digest(self) -> str:
        return sha256(recovery_bytes(self)).hexdigest()


class HostRecoveryInventory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    api_version: Literal["pajin.dev/host-recovery-inventory/v1"] = Field(
        default="pajin.dev/host-recovery-inventory/v1",
        alias="apiVersion",
    )
    gate: HostGateIdentity
    components: Annotated[tuple[RuntimeComponentFingerprint, ...], Field(max_length=64)]
    registrations: Annotated[tuple[RecoveryRegistration, ...], Field(max_length=4096)]

    @model_validator(mode="after")
    def require_unique_inventory(self) -> Self:
        ids = [item.component_id for item in self.components]
        paths = [item.path for item in self.registrations]
        if ids != sorted(set(ids)) or paths != sorted(set(paths)):
            raise ValueError("recovery inventory must be unique and sorted")
        for registration in self.registrations:
            if any(str(parent) in paths for parent in PurePosixPath(registration.path).parents):
                raise ValueError("recovery registrations must not overlap")
        return self

    @property
    def digest(self) -> str:
        return sha256(recovery_bytes(self)).hexdigest()
