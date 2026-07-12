"""Safe worker-backed tool for validating the orchestration boundary."""

import json

from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolSpec


class MockAgentProbe(Tool):
    """Return a configured observation without making a network request."""

    spec = ToolSpec(
        tool_id="mock.agent-probe",
        version="1.0.0",
        description="Safe simulated probe for an agentic AI target",
        risk_tier=ToolRiskTier.T2,
        categories={"active-test", "ai-redteam"},
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return WorkerJob(
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "simulation": request.arguments.get("simulation", {}),
                }
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
            data = json.loads(result.stdout)
            if not isinstance(data, dict):
                raise TypeError("worker output must be a JSON object")
        except (json.JSONDecodeError, TypeError) as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=f"invalid worker output: {exc}",
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
        )


class SleepCheckTool(Tool):
    """Bounded verification tool used to exercise cooperative campaign cancellation."""

    spec = ToolSpec(
        tool_id="mock.sleep-check",
        version="1.0.0",
        description="Sleep inside the isolated Worker for cancellation verification",
        risk_tier=ToolRiskTier.T0,
        categories={"verification"},
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        seconds = float(request.arguments.get("seconds", 5))
        if not 0.1 <= seconds <= 30:
            raise ValueError("sleep duration must be between 0.1 and 30 seconds")
        return WorkerJob(
            image="pajin-worker:dev",
            command=["sleep-check"],
            stdin=json.dumps({"seconds": seconds}),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        succeeded = result.status is WorkerStatus.SUCCEEDED
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=succeeded,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data={"target": request.target, "slept": succeeded},
            error=None if succeeded else f"worker {result.status.value}: {result.stderr}",
        )
