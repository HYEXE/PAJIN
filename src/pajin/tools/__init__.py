"""Canonical PAJIN tool contracts and safe built-in tools."""

from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import MCPToolRegistration, RegisteredMCPTool, demo_mcp_tool
from pajin.tools.mock import MockAgentProbe

__all__ = [
    "HTTPGetTool",
    "MCPToolRegistration",
    "MockAgentProbe",
    "RegisteredMCPTool",
    "Tool",
    "ToolRegistry",
    "ToolSpec",
    "demo_mcp_tool",
]
