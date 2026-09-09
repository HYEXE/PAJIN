"""Immutable Control Plane Run identity for an explicitly scoped local journal."""

from __future__ import annotations

import json
import sqlite3
from typing import Annotated, Literal

from pydantic import ConfigDict, Field

from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes

RUN_BOUND_JOURNAL_VERSION = 3
_Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class SupervisorRunBinding(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    api_version: Literal["pajin.dev/supervisor-journal-run-binding/v1"] = Field(
        default="pajin.dev/supervisor-journal-run-binding/v1", alias="apiVersion",
    )
    control_plane_run_id: str = Field(
        alias="controlPlaneRunId", pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
    )
    campaign_digest: _Digest = Field(alias="campaignDigest")
    input_digest: _Digest = Field(alias="inputDigest")
    budget_mode: Literal["campaign-only", "campaign-and-supervisor"] = Field(alias="budgetMode")

    def canonical(self) -> str:
        return json.dumps(
            self.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":"),
        )


def stored_run_binding(connection: sqlite3.Connection) -> SupervisorRunBinding | None:
    row = connection.execute(
        "SELECT value FROM supervisor_invocation_metadata WHERE key = 'run_binding'",
    ).fetchone()
    if row is None:
        return None
    if type(row[0]) is not str:
        raise ValueError("journal Run binding must be canonical JSON text")
    binding = SupervisorRunBinding.model_validate(parse_strict_json_bytes(
        row[0].encode("utf-8"), label="journal Run binding", max_bytes=4096,
    ))
    if binding.canonical() != row[0]:
        raise ValueError("journal Run binding is not canonical")
    return binding


def require_run_binding(
    connection: sqlite3.Connection, expected: SupervisorRunBinding | None,
) -> None:
    if stored_run_binding(connection) != expected:
        raise ValueError("journal differs from the trusted Control Plane Run binding")
