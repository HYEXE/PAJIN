"""Call an allowlisted stdio MCP server using the official MCP Python SDK."""

import asyncio
import json
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

MAX_BRIDGE_INPUT_BYTES = 1_000_000

SERVER_CATALOG: dict[str, dict[str, Any]] = {
    "demo-security": {
        "command": "/usr/local/bin/python",
        "args": ["/app/demo_mcp_server.py"],
        "tools": {"inspect_text"},
    }
}


class MCPRegistrationRejection(ValueError):
    """One stable catalog rejection that is safe to return as typed data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _read_payload() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_BRIDGE_INPUT_BYTES + 1)
    if len(raw) > MAX_BRIDGE_INPUT_BYTES:
        raise ValueError("MCP bridge input exceeded byte limit")
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("MCP bridge input is not strict JSON") from exc
    if not isinstance(payload, dict):
        raise TypeError("MCP bridge input must be an object")
    if set(payload) != {"serverId", "toolName", "arguments"}:
        raise ValueError("MCP bridge input fields do not match the registered call envelope")
    return payload


def _required_identifier(payload: dict[str, Any], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str) or not 1 <= len(value) <= 200:
        raise TypeError(f"MCP bridge {key} must be a bounded string")
    return value


async def call_registered_tool(payload: dict[str, Any]) -> dict[str, Any]:
    server_id = _required_identifier(payload, "serverId")
    tool_name = _required_identifier(payload, "toolName")
    arguments = payload["arguments"]
    if not isinstance(arguments, dict):
        raise TypeError("MCP bridge arguments must be an object")
    registration = SERVER_CATALOG.get(server_id)
    if registration is None:
        raise MCPRegistrationRejection("server-not-registered")
    if tool_name not in registration["tools"]:
        raise MCPRegistrationRejection("tool-not-registered")
    parameters = StdioServerParameters(
        command=registration["command"],
        args=registration["args"],
        # Deliberately pass a minimal environment. An empty mapping would remove
        # PYTHONPATH and make the bundled SDK unavailable to the child server.
        env={"PYTHONPATH": "/opt/pajin-vendor", "PYTHONUNBUFFERED": "1"},
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        available = await session.list_tools()
        if tool_name not in {tool.name for tool in available.tools}:
            raise ValueError("registered MCP tool is not advertised by server")
        result = await session.call_tool(tool_name, arguments=arguments)
    content: list[dict[str, Any]] = []
    for item in result.content:
        if isinstance(item, types.TextContent):
            content.append({"type": "text", "text": item.text})
        elif isinstance(item, types.ImageContent):
            content.append({"type": "image", "mimeType": item.mimeType, "bytes": len(item.data)})
        else:
            content.append({"type": item.type})
    return {
        "isError": bool(result.isError),
        "structuredContent": result.structuredContent,
        "content": content,
    }


async def main() -> None:
    payload = _read_payload()
    try:
        result = await call_registered_tool(payload)
    except MCPRegistrationRejection as rejection:
        result = {
            "isError": True,
            "structuredContent": {"rejectionCode": rejection.code},
            "content": [],
        }
    json.dump(result, sys.stdout, separators=(",", ":"), allow_nan=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    asyncio.run(main())
