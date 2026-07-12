"""Call an allowlisted stdio MCP server using the official MCP Python SDK."""

import asyncio
import json
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

SERVER_CATALOG: dict[str, dict[str, Any]] = {
    "demo-security": {
        "command": "/usr/local/bin/python",
        "args": ["/app/demo_mcp_server.py"],
        "tools": {"inspect_text"},
    }
}


async def call_registered_tool(payload: dict[str, Any]) -> dict[str, Any]:
    server_id = str(payload["serverId"])
    tool_name = str(payload["toolName"])
    arguments = payload.get("arguments", {})
    registration = SERVER_CATALOG.get(server_id)
    if registration is None:
        raise ValueError("MCP server ID is not registered")
    if tool_name not in registration["tools"]:
        raise ValueError("MCP tool is not registered for this server")
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
    payload = json.load(sys.stdin)
    result = await call_registered_tool(payload)
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    asyncio.run(main())
