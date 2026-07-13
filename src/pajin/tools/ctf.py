"""Fixed Web discovery Tool for the synthetic local CTF lab."""

from __future__ import annotations

import json
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.modes.ctf.models import (
    CTF_WEB_BACKUP_PATH,
    CTF_WEB_LAB_HOST,
    CTF_WEB_LAB_PORT,
    CTFScenario,
)
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolSpec

CTF_WEB_BACKUP_TOOL_ID = "ctf.web-backup-probe"


class CTFWebBackupProbeInput(StrictModel):
    challenge_id: str = Field(alias="challengeId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    scenario_id: Literal[CTFScenario.WEB_EXPOSED_BACKUP_CONFIG] = Field(alias="scenarioId")


class CTFWebBackupProbeOutput(StrictModel):
    target: str
    challenge_id: str = Field(alias="challengeId")
    scenario_id: Literal[CTFScenario.WEB_EXPOSED_BACKUP_CONFIG] = Field(alias="scenarioId")
    status: int = Field(ge=100, le=599)
    discovered: bool
    candidate_flag: str | None = Field(
        default=None,
        alias="candidateFlag",
        pattern=r"^PAJIN\{[A-Za-z0-9_-]{1,128}\}$",
    )
    body_sha256: str = Field(alias="bodySha256", pattern=r"^[a-f0-9]{64}$")
    synthetic: bool
    network_performed: bool = Field(alias="networkPerformed")

    @model_validator(mode="after")
    def require_consistent_discovery(self) -> CTFWebBackupProbeOutput:
        if self.discovered != (self.status == 200 and self.candidate_flag is not None):
            raise ValueError("CTF Web discovery state is inconsistent")
        if not self.synthetic:
            raise ValueError("CTF Web probe accepts only a synthetic lab response")
        return self


def validate_ctf_web_target(target: str) -> None:
    parsed = urlsplit(target)
    if parsed.scheme != "http":
        raise ValueError("CTF Web probe requires the local HTTP lab")
    if parsed.hostname != CTF_WEB_LAB_HOST or parsed.port != CTF_WEB_LAB_PORT:
        raise ValueError("CTF Web probe target must use host.docker.internal:8780")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("CTF Web probe target authority, query, or fragment is invalid")
    if parsed.path != CTF_WEB_BACKUP_PATH:
        raise ValueError(f"CTF Web probe is fixed to {CTF_WEB_BACKUP_PATH}")


class CTFWebBackupProbeTool(Tool):
    """Fetch one fixed synthetic backup path without accepting an agent-authored path."""

    spec = ToolSpec(
        tool_id=CTF_WEB_BACKUP_TOOL_ID,
        version="1.0.0",
        description="Fetch the fixed backup configuration path in the local CTF Web lab",
        risk_tier=ToolRiskTier.T1,
        categories={"ctf", "discovery", "http", "web"},
        evidence_types={"http-observation", "json"},
        network_access=True,
        network_request_cost=1,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "GET":
            raise ValueError("CTF Web backup probe requires GET")
        validate_ctf_web_target(request.target)
        probe = CTFWebBackupProbeInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["ctf-web-backup-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "challengeId": probe.challenge_id,
                    "scenarioId": probe.scenario_id,
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=f"worker {result.status.value}: {result.stderr or 'no error detail'}",
            )
        try:
            raw = json.loads(result.stdout)
            output = CTFWebBackupProbeOutput.model_validate(raw)
            probe = CTFWebBackupProbeInput.model_validate(request.arguments)
            if (
                output.target != request.target
                or output.challenge_id != probe.challenge_id
                or output.scenario_id != probe.scenario_id
            ):
                raise ValueError("worker output identity does not match the Tool request")
            if not output.network_performed:
                raise ValueError("worker did not attest network execution")
        except (json.JSONDecodeError, ValueError) as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=f"invalid CTF Web probe output: {exc}",
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=output.model_dump(mode="json", by_alias=True),
        )
