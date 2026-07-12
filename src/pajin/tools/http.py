"""Worker-backed HTTP tools with mandatory egress-proxy routing."""

import json

from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolSpec


class HTTPGetTool(Tool):
    spec = ToolSpec(
        tool_id="http.get",
        version="1.0.0",
        description="Fetch an authorized HTTP(S) target through the PAJIN egress proxy",
        risk_tier=ToolRiskTier.T2,
        categories={"active-test", "http"},
        network_access=True,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            stdin=json.dumps({"target": request.target}),
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
        status = int(data.get("status", 0))
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=200 <= status < 400,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
            error=None if 200 <= status < 400 else f"HTTP status {status}",
        )
