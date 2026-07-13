"""Canonical PAJIN tool contracts and safe built-in tools."""

from pajin.tools.ai import (
    AIChatProbeInput,
    AIChatProbeTool,
    AIChatRegressionInput,
    AIChatRegressionTool,
    ChatMessage,
    ProbeCheck,
    ProbeTurn,
)
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import MCPToolRegistration, RegisteredMCPTool, demo_mcp_tool
from pajin.tools.mock import MockAgentProbe

__all__ = [
    "AIChatProbeInput",
    "AIChatProbeTool",
    "AIChatRegressionInput",
    "AIChatRegressionTool",
    "ChatMessage",
    "HTTPGetTool",
    "MCPToolRegistration",
    "MockAgentProbe",
    "ProbeCheck",
    "ProbeTurn",
    "RegisteredMCPTool",
    "Tool",
    "ToolRegistry",
    "ToolSpec",
    "demo_mcp_tool",
]
