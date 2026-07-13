"""Fixed, minimum-impact probes for the Bug Bounty local lab profile."""

from __future__ import annotations

import json
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolSpec

BOOLEAN_SQLI_SCENARIO: Literal["bug-bounty.api.boolean-sqli-lab"] = (
    "bug-bounty.api.boolean-sqli-lab"
)


class BooleanSQLiProbeInput(StrictModel):
    scenario_id: Literal["bug-bounty.api.boolean-sqli-lab"] = BOOLEAN_SQLI_SCENARIO


class BooleanSQLiObservation(StrictModel):
    name: Literal["baseline", "negative-control", "boolean-probe"]
    status: int = Field(ge=100, le=599)
    record_count: int = Field(alias="recordCount", ge=0, le=100)
    synthetic: bool


class BooleanSQLiChecks(StrictModel):
    baseline_single_record: bool = Field(alias="baselineSingleRecord")
    negative_control_empty: bool = Field(alias="negativeControlEmpty")
    boolean_probe_expanded: bool = Field(alias="booleanProbeExpanded")
    synthetic_lab_only: bool = Field(alias="syntheticLabOnly")


class BooleanSQLiProbeOutput(StrictModel):
    target: str
    scenario_id: Literal["bug-bounty.api.boolean-sqli-lab"] = Field(alias="scenarioId")
    vulnerable: bool
    checks: BooleanSQLiChecks
    observations: list[BooleanSQLiObservation] = Field(min_length=3, max_length=3)
    network_performed: bool = Field(alias="networkPerformed")

    @model_validator(mode="after")
    def require_complete_observation_set(self) -> BooleanSQLiProbeOutput:
        names = [observation.name for observation in self.observations]
        if set(names) != {"baseline", "negative-control", "boolean-probe"}:
            raise ValueError("SQLi probe output requires the three fixed observations")
        if len(names) != len(set(names)):
            raise ValueError("SQLi probe observations must be unique")
        return self


class BooleanSQLiProbeTool(Tool):
    """Run three fixed GET comparisons without accepting an agent-authored payload."""

    spec = ToolSpec(
        tool_id="bug-bounty.boolean-sqli-probe",
        version="1.0.0",
        description="Compare fixed baseline, negative-control, and boolean SQLi lab requests",
        risk_tier=ToolRiskTier.T2,
        categories={"active-test", "bug-bounty", "http", "injection"},
        evidence_types={"json", "http-observation"},
        network_access=True,
        network_request_cost=3,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "GET":
            raise ValueError("boolean SQLi lab probe requires GET")
        parsed = urlsplit(request.target)
        if parsed.query or parsed.fragment:
            raise ValueError("boolean SQLi target must not contain a query or fragment")
        if not parsed.path.endswith("/v1/users/lookup"):
            raise ValueError("boolean SQLi probe is fixed to the lab lookup endpoint")
        probe = BooleanSQLiProbeInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["bug-bounty-sqli-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
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
            output = BooleanSQLiProbeOutput.model_validate(raw)
            probe = BooleanSQLiProbeInput.model_validate(request.arguments)
            if output.target != request.target or output.scenario_id != probe.scenario_id:
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
                error=f"invalid boolean SQLi probe output: {exc}",
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=output.model_dump(mode="json", by_alias=True),
        )
