"""Registered MCP tool adapters executed only inside the PAJIN Worker."""

import json

from pydantic import BaseModel, ConfigDict, Field

from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolSpec


class MCPToolRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str
    server_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    remote_tool_name: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    description: str
    risk_tier: ToolRiskTier
    categories: set[str] = Field(default_factory=lambda: {"mcp"})


class RegisteredMCPTool(Tool):
    """Call one pre-registered MCP tool without exposing its process command."""

    def __init__(self, registration: MCPToolRegistration) -> None:
        self.registration = registration
        self.spec = ToolSpec(
            tool_id=registration.tool_id,
            version="1.0.0",
            description=registration.description,
            risk_tier=registration.risk_tier,
            categories=registration.categories | {"mcp"},
            network_access=False,
        )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return WorkerJob(
            image="pajin-worker:dev",
            command=["mcp-call"],
            stdin=json.dumps(
                {
                    "serverId": self.registration.server_id,
                    "toolName": self.registration.remote_tool_name,
                    "arguments": request.arguments,
                }
            ),
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
            response = json.loads(result.stdout)
            if not isinstance(response, dict):
                raise TypeError("MCP bridge output must be a JSON object")
            structured = response.get("structuredContent")
            data = dict(structured) if isinstance(structured, dict) else {}
            data.update(
                {
                    "target": request.target,
                    "mcpServerId": self.registration.server_id,
                    "mcpToolName": self.registration.remote_tool_name,
                    "mcpContent": response.get("content", []),
                }
            )
            is_error = bool(response.get("isError", False))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=f"invalid MCP bridge output: {exc}",
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=not is_error,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
            error="MCP tool returned isError=true" if is_error else None,
        )


def demo_mcp_tool() -> RegisteredMCPTool:
    return RegisteredMCPTool(
        MCPToolRegistration(
            tool_id="mcp.demo-security.inspect-text",
            server_id="demo-security",
            remote_tool_name="inspect_text",
            description="Inspect text using the registered demo MCP security server",
            risk_tier=ToolRiskTier.T0,
            categories={"mcp", "ai-redteam", "analysis"},
        )
    )
