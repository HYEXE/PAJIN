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
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    BooleanSQLiChecks,
    BooleanSQLiObservation,
    BooleanSQLiProbeInput,
    BooleanSQLiProbeOutput,
    BooleanSQLiProbeTool,
)
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import (
    MCPDiscoveryRegistration,
    MCPToolRegistration,
    RegisteredMCPDiscoveryTool,
    RegisteredMCPTool,
    demo_mcp_discovery_tool,
    demo_mcp_tool,
)
from pajin.tools.mock import MockAgentProbe
from pajin.tools.network import (
    MAX_NETWORK_SERVICE_BANNER_BYTES,
    NETWORK_PASSIVE_BANNER_PROFILE,
    NetworkServiceIdentificationInput,
    NetworkServiceIdentificationTool,
    network_service_scope_allow_rule,
    network_service_scope_target,
)

__all__ = [
    "BOOLEAN_SQLI_SCENARIO",
    "MAX_NETWORK_SERVICE_BANNER_BYTES",
    "NETWORK_PASSIVE_BANNER_PROFILE",
    "AIChatProbeInput",
    "AIChatProbeTool",
    "AIChatRegressionInput",
    "AIChatRegressionTool",
    "BooleanSQLiChecks",
    "BooleanSQLiObservation",
    "BooleanSQLiProbeInput",
    "BooleanSQLiProbeOutput",
    "BooleanSQLiProbeTool",
    "ChatMessage",
    "HTTPGetTool",
    "MCPDiscoveryRegistration",
    "MCPToolRegistration",
    "MockAgentProbe",
    "NetworkServiceIdentificationInput",
    "NetworkServiceIdentificationTool",
    "ProbeCheck",
    "ProbeTurn",
    "RegisteredMCPDiscoveryTool",
    "RegisteredMCPTool",
    "Tool",
    "ToolRegistry",
    "ToolSpec",
    "demo_mcp_discovery_tool",
    "demo_mcp_tool",
    "network_service_scope_allow_rule",
    "network_service_scope_target",
]
