"""Tool abstraction used for MCP, CLI, browser, and sandbox adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerResult


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str
    version: str
    description: str
    risk_tier: ToolRiskTier
    categories: set[str] = Field(default_factory=set)
    evidence_types: set[str] = Field(default_factory=lambda: {"json"})
    network_access: bool = False
    network_request_cost: int = Field(default=1, ge=1, le=100)
    parallel_safe: bool = False


class Tool(ABC):
    spec: ToolSpec

    def network_request_cost(self, request: ToolRequest) -> int:
        """Return trusted request units; multi-request adapters may override this floor."""

        del request
        return self.spec.network_request_cost

    @abstractmethod
    def prepare(self, request: ToolRequest) -> WorkerJob:
        """Translate a canonical request into an isolated worker job."""

    @abstractmethod
    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        """Translate bounded worker output into a canonical tool result."""


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.spec.tool_id in self._tools:
            raise ValueError(f"tool already registered: {tool.spec.tool_id}")
        self._tools[tool.spec.tool_id] = tool

    def spec(self, tool_id: str) -> ToolSpec:
        return self._get(tool_id).spec

    def tool(self, tool_id: str) -> Tool:
        return self._get(tool_id)

    def tool_ids(self) -> set[str]:
        return set(self._tools)

    def _get(self, tool_id: str) -> Tool:
        try:
            return self._tools[tool_id]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {tool_id}") from exc
