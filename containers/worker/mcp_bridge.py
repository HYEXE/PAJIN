"""Call an allowlisted stdio MCP server using the official MCP Python SDK."""

import asyncio
import json
import re
import sys
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

MAX_BRIDGE_INPUT_BYTES = 1_000_000
MAX_DISCOVERY_ITEMS = 64
MAX_DISCOVERY_PAGES = 8
MAX_PROMPT_ARGUMENTS = 32
MAX_DISCOVERY_VALUE_BYTES = 64 * 1024
_MCP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MCP_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]{0,31}$")
_MCP_PROTOCOL_VERSION = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")

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
    if set(payload) not in (
        {"serverId"},
        {"serverId", "toolName", "arguments"},
    ):
        raise ValueError("MCP bridge input fields do not match a registered envelope")
    return payload


def _required_identifier(payload: dict[str, Any], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str) or not 1 <= len(value) <= 200:
        raise TypeError(f"MCP bridge {key} must be a bounded string")
    return value


def _server_parameters(registration: dict[str, Any]) -> StdioServerParameters:
    return StdioServerParameters(
        command=registration["command"],
        args=registration["args"],
        # Deliberately pass a minimal environment. An empty mapping would remove
        # PYTHONPATH and make the bundled SDK unavailable to the child server.
        env={"PYTHONPATH": "/opt/pajin-vendor", "PYTHONUNBUFFERED": "1"},
    )


def _bounded_name(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _MCP_NAME.fullmatch(value) is None:
        raise ValueError(f"{label} is not a bounded portable name")
    return value


def _canonical_digest(value: Any, *, label: str) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical JSON") from exc
    if len(encoded) > MAX_DISCOVERY_VALUE_BYTES:
        raise ValueError(f"{label} exceeded byte limit")
    return sha256(encoded).hexdigest()


def _uri_identity(value: Any, *, label: str) -> tuple[str, str]:
    raw = str(value)
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc
    if not 1 <= len(encoded) <= MAX_DISCOVERY_VALUE_BYTES:
        raise ValueError(f"{label} exceeded byte limit")
    scheme = urlsplit(raw).scheme
    if _MCP_SCHEME.fullmatch(scheme) is None:
        raise ValueError(f"{label} has an invalid URI scheme")
    return scheme, sha256(encoded).hexdigest()


async def _collect_pages(
    method: Any,
    *,
    item_attribute: str,
    label: str,
) -> list[Any]:
    items: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _page_number in range(MAX_DISCOVERY_PAGES):
        params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
        result = await method(params=params)
        page_items = getattr(result, item_attribute, None)
        if not isinstance(page_items, list):
            raise TypeError(f"MCP {label} page is malformed")
        items.extend(page_items)
        if len(items) > MAX_DISCOVERY_ITEMS:
            raise ValueError(f"MCP {label} exceeded item limit")
        next_cursor = getattr(result, "nextCursor", None)
        if next_cursor is None:
            return items
        if (
            not isinstance(next_cursor, str)
            or not 1 <= len(next_cursor) <= 1_024
            or next_cursor in seen_cursors
        ):
            raise ValueError(f"MCP {label} cursor is invalid")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise ValueError(f"MCP {label} exceeded page limit")


def _sorted_unique(
    items: list[dict[str, Any]],
    *,
    identity: Any,
    label: str,
) -> list[dict[str, Any]]:
    keys = [identity(item) for item in items]
    if len(keys) != len(set(keys)):
        raise ValueError(f"MCP {label} contains duplicate entries")
    return sorted(items, key=identity)


async def discover_registered_server(payload: dict[str, Any]) -> dict[str, Any]:
    server_id = _required_identifier(payload, "serverId")
    registration = SERVER_CATALOG.get(server_id)
    if registration is None:
        raise MCPRegistrationRejection("server-not-registered")
    async with (
        stdio_client(_server_parameters(registration)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        initialized = await session.initialize()
        protocol_version = initialized.protocolVersion
        if (
            not isinstance(protocol_version, str)
            or _MCP_PROTOCOL_VERSION.fullmatch(protocol_version) is None
        ):
            raise ValueError("MCP protocol version is invalid")
        capabilities: list[str] = []
        server_capabilities = initialized.capabilities
        if server_capabilities.prompts is not None:
            capabilities.append("prompts")
        if server_capabilities.resources is not None:
            capabilities.append("resources")
        if server_capabilities.tools is not None:
            capabilities.append("tools")

        raw_tools = (
            await _collect_pages(
                session.list_tools,
                item_attribute="tools",
                label="tools",
            )
            if "tools" in capabilities
            else []
        )
        raw_resources = (
            await _collect_pages(
                session.list_resources,
                item_attribute="resources",
                label="resources",
            )
            if "resources" in capabilities
            else []
        )
        raw_templates = (
            await _collect_pages(
                session.list_resource_templates,
                item_attribute="resourceTemplates",
                label="resource templates",
            )
            if "resources" in capabilities
            else []
        )
        raw_prompts = (
            await _collect_pages(
                session.list_prompts,
                item_attribute="prompts",
                label="prompts",
            )
            if "prompts" in capabilities
            else []
        )

    tools: list[dict[str, Any]] = []
    for item in raw_tools:
        output_schema = getattr(item, "outputSchema", None)
        normalized = {
            "name": _bounded_name(getattr(item, "name", None), label="MCP tool name"),
            "inputSchemaDigest": _canonical_digest(
                getattr(item, "inputSchema", None),
                label="MCP tool input schema",
            ),
        }
        if output_schema is not None:
            normalized["outputSchemaDigest"] = _canonical_digest(
                output_schema,
                label="MCP tool output schema",
            )
        tools.append(normalized)

    resources: list[dict[str, Any]] = []
    for item in raw_resources:
        scheme, digest = _uri_identity(
            getattr(item, "uri", None),
            label="MCP resource URI",
        )
        resources.append({"uriScheme": scheme, "uriSha256": digest})

    resource_templates: list[dict[str, Any]] = []
    for item in raw_templates:
        scheme, digest = _uri_identity(
            getattr(item, "uriTemplate", None),
            label="MCP resource URI template",
        )
        resource_templates.append({"uriScheme": scheme, "templateSha256": digest})

    prompts: list[dict[str, Any]] = []
    for item in raw_prompts:
        raw_arguments = getattr(item, "arguments", None) or []
        if not isinstance(raw_arguments, list) or len(raw_arguments) > MAX_PROMPT_ARGUMENTS:
            raise ValueError("MCP prompt arguments exceeded their shape limit")
        arguments = [
            {
                "name": _bounded_name(
                    getattr(argument, "name", None),
                    label="MCP prompt argument name",
                ),
                "required": getattr(argument, "required", None) is True,
            }
            for argument in raw_arguments
        ]
        argument_names = [argument["name"] for argument in arguments]
        if len(argument_names) != len(set(argument_names)):
            raise ValueError("MCP prompt contains duplicate arguments")
        prompts.append(
            {
                "name": _bounded_name(
                    getattr(item, "name", None),
                    label="MCP prompt name",
                ),
                "arguments": sorted(arguments, key=lambda argument: argument["name"]),
            }
        )

    return {
        "protocolVersion": protocol_version,
        "capabilities": capabilities,
        "tools": _sorted_unique(
            tools,
            identity=lambda item: item["name"],
            label="tools",
        ),
        "resources": _sorted_unique(
            resources,
            identity=lambda item: (item["uriScheme"], item["uriSha256"]),
            label="resources",
        ),
        "resourceTemplates": _sorted_unique(
            resource_templates,
            identity=lambda item: (item["uriScheme"], item["templateSha256"]),
            label="resource templates",
        ),
        "prompts": _sorted_unique(
            prompts,
            identity=lambda item: item["name"],
            label="prompts",
        ),
    }


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
    parameters = _server_parameters(registration)
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
        result = (
            await discover_registered_server(payload)
            if set(payload) == {"serverId"}
            else await call_registered_tool(payload)
        )
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
