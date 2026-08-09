"""Registered MCP tool adapters executed only inside the PAJIN Worker."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import cast

from pydantic import ConfigDict, Field, JsonValue, StrictBool, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerLimits, WorkerResult, WorkerStatus
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
)

_MAX_MCP_BRIDGE_OUTPUT_BYTES = 1_000_000
_MAX_MCP_JSON_DEPTH = 32
_MAX_MCP_JSON_NODES = 20_000
_MAX_MCP_CONTENT_ITEMS = 1_000
_MAX_MCP_DISCOVERY_ITEMS = 64
_MAX_MCP_PROMPT_ARGUMENTS = 32
_MAX_MCP_DISCOVERY_PAGES = 8
_RESERVED_RESULT_KEYS = frozenset({"target", "mcpServerId", "mcpToolName", "mcpContent"})


class MCPToolRegistration(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    tool_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    server_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    remote_tool_name: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    description: str = Field(min_length=1, max_length=5_000)
    risk_tier: ToolRiskTier
    categories: set[str] = Field(default_factory=lambda: {"mcp"}, max_length=100)


class MCPDiscoveryRegistration(StrictModel):
    """Sealed identity of one code-registered MCP server boundary."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    tool_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    server_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    description: str = Field(min_length=1, max_length=5_000)


class _MCPDiscoveredURLArgument(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    required: StrictBool


class _MCPDiscoveredTool(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    input_schema_digest: str = Field(
        alias="inputSchemaDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    output_schema_digest: str | None = Field(
        default=None,
        alias="outputSchemaDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    url_arguments: list[_MCPDiscoveredURLArgument] | None = Field(
        default=None,
        alias="urlArguments",
        max_length=32,
    )

    @model_validator(mode="after")
    def validate_url_arguments(self) -> _MCPDiscoveredTool:
        if self.url_arguments is None:
            return self
        names = [argument.name for argument in self.url_arguments]
        if not names or names != sorted(set(names)):
            raise ValueError("MCP URL Tool arguments must be non-empty, unique, and sorted")
        return self


class _MCPDiscoveredResource(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    uri_scheme: str = Field(
        alias="uriScheme",
        min_length=1,
        max_length=32,
        pattern=r"^[a-z][a-z0-9+.-]*$",
    )
    uri_sha256: str = Field(alias="uriSha256", pattern=r"^[a-f0-9]{64}$")


class _MCPDiscoveredResourceTemplate(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    uri_scheme: str = Field(
        alias="uriScheme",
        min_length=1,
        max_length=32,
        pattern=r"^[a-z][a-z0-9+.-]*$",
    )
    template_sha256: str = Field(
        alias="templateSha256",
        pattern=r"^[a-f0-9]{64}$",
    )


class _MCPDiscoveredPromptArgument(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    required: StrictBool


class _MCPDiscoveredPrompt(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    arguments: list[_MCPDiscoveredPromptArgument] = Field(
        default_factory=list,
        max_length=_MAX_MCP_PROMPT_ARGUMENTS,
    )

    @model_validator(mode="after")
    def validate_arguments(self) -> _MCPDiscoveredPrompt:
        names = [argument.name for argument in self.arguments]
        if names != sorted(set(names)):
            raise ValueError("MCP prompt arguments must be unique and sorted")
        return self


class _MCPDiscoveryResponse(StrictModel):
    """Exact digest-only discovery envelope emitted by the Worker bridge."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    protocol_version: str = Field(
        alias="protocolVersion",
        min_length=10,
        max_length=10,
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    )
    capabilities: list[str] = Field(max_length=3)
    tools: list[_MCPDiscoveredTool] = Field(max_length=_MAX_MCP_DISCOVERY_ITEMS)
    resources: list[_MCPDiscoveredResource] = Field(max_length=_MAX_MCP_DISCOVERY_ITEMS)
    resource_templates: list[_MCPDiscoveredResourceTemplate] = Field(
        alias="resourceTemplates",
        max_length=_MAX_MCP_DISCOVERY_ITEMS,
    )
    prompts: list[_MCPDiscoveredPrompt] = Field(max_length=_MAX_MCP_DISCOVERY_ITEMS)

    @model_validator(mode="after")
    def validate_canonical_boundary(self) -> _MCPDiscoveryResponse:
        allowed_capabilities = {"prompts", "resources", "tools"}
        if any(
            item not in allowed_capabilities for item in self.capabilities
        ) or self.capabilities != sorted(set(self.capabilities)):
            raise ValueError("MCP discovery capabilities must be supported, unique, and sorted")
        tool_names = [item.name for item in self.tools]
        resource_keys = [(item.uri_scheme, item.uri_sha256) for item in self.resources]
        template_keys = [
            (item.uri_scheme, item.template_sha256) for item in self.resource_templates
        ]
        prompt_names = [item.name for item in self.prompts]
        if (
            tool_names != sorted(set(tool_names))
            or resource_keys != sorted(set(resource_keys))
            or template_keys != sorted(set(template_keys))
            or prompt_names != sorted(set(prompt_names))
        ):
            raise ValueError("MCP discovery entries must be unique and sorted")
        if self.tools and "tools" not in self.capabilities:
            raise ValueError("MCP discovery tools require their advertised capability")
        if (self.resources or self.resource_templates) and "resources" not in self.capabilities:
            raise ValueError("MCP discovery resources require their advertised capability")
        if self.prompts and "prompts" not in self.capabilities:
            raise ValueError("MCP discovery prompts require their advertised capability")
        return self


class _MCPBridgeContent(StrictModel):
    """Bounded content shape emitted by the fixed Worker bridge."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    type: str = Field(min_length=1, max_length=100)
    text: str | None = Field(default=None, max_length=_MAX_MCP_BRIDGE_OUTPUT_BYTES)
    mime_type: str | None = Field(
        default=None,
        alias="mimeType",
        min_length=1,
        max_length=1_000,
    )
    byte_count: int | None = Field(default=None, alias="bytes", strict=True, ge=0)

    @model_validator(mode="after")
    def validate_content_shape(self) -> _MCPBridgeContent:
        if self.type == "text":
            if self.text is None or self.mime_type is not None or self.byte_count is not None:
                raise ValueError("text MCP content requires only a text field")
            return self
        if self.type == "image":
            if self.text is not None or self.mime_type is None or self.byte_count is None:
                raise ValueError("image MCP content requires mimeType and bytes fields")
            return self
        if self.text is not None or self.mime_type is not None or self.byte_count is not None:
            raise ValueError("opaque MCP content may contain only its type")
        return self


class _MCPBridgeResponse(StrictModel):
    """Exact response envelope shared by the Worker entry point and host adapter."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    is_error: StrictBool = Field(alias="isError")
    structured_content: dict[str, JsonValue] | None = Field(
        alias="structuredContent",
        max_length=1_000,
    )
    content: list[_MCPBridgeContent] = Field(max_length=_MAX_MCP_CONTENT_ITEMS)

    @model_validator(mode="after")
    def reject_reserved_structured_keys(self) -> _MCPBridgeResponse:
        collisions = _RESERVED_RESULT_KEYS.intersection(self.structured_content or {})
        if collisions:
            names = ", ".join(sorted(collisions))
            raise ValueError(f"structuredContent contains reserved identity fields: {names}")
        return self


@dataclass(slots=True)
class _MCPJSONBudget:
    nodes: int = 0


def _validate_mcp_json(value: object, *, budget: _MCPJSONBudget, depth: int = 0) -> None:
    """Reject coercible or resource-exhausting JSON before Pydantic normalization."""

    budget.nodes += 1
    if budget.nodes > _MAX_MCP_JSON_NODES:
        raise ValueError("MCP bridge output exceeds the JSON node-count limit")
    if depth > _MAX_MCP_JSON_DEPTH:
        raise ValueError("MCP bridge output exceeds the JSON nesting-depth limit")
    if value is None or type(value) is bool or type(value) is str:
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("MCP bridge output integer is outside the signed 64-bit range")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("MCP bridge output numbers must be finite")
        return
    if type(value) is list:
        for item in cast(list[object], value):
            _validate_mcp_json(item, budget=budget, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise ValueError("MCP bridge output object keys must be strings")
            budget.nodes += 1
            if budget.nodes > _MAX_MCP_JSON_NODES:
                raise ValueError("MCP bridge output exceeds the JSON node-count limit")
            _validate_mcp_json(item, budget=budget, depth=depth + 1)
        return
    raise ValueError("MCP bridge output contains a non-JSON value")


def _reject_duplicate_mcp_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate MCP bridge output field: {key}")
        value[key] = item
    return value


def _reject_nonfinite_mcp_constant(value: str) -> None:
    raise ValueError(f"non-finite MCP bridge output constant is forbidden: {value}")


class RegisteredMCPTool(Tool):
    """Call one pre-registered MCP tool without exposing its process command."""

    def __init__(self, registration: MCPToolRegistration) -> None:
        self._registration = MCPToolRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        self.spec = ToolSpec(
            tool_id=self._registration.tool_id,
            version="1.0.0",
            description=self._registration.description,
            risk_tier=self._registration.risk_tier,
            categories=frozenset(self._registration.categories | {"mcp"}),
            network_access=False,
        )

    @property
    def registration(self) -> MCPToolRegistration:
        """Return a detached observation of the sealed MCP registration."""

        return self._registration.model_copy(deep=True)

    def stable_execution_context(self) -> dict[str, object]:
        return {
            **self._stable_spec_context(),
            "registration": self._registration.model_dump(mode="python"),
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._validate_request_identity(request)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["mcp-call"],
            stdin=json.dumps(
                {
                    "serverId": self._registration.server_id,
                    "toolName": self._registration.remote_tool_name,
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
                error=audit_safe_worker_failure(result),
            )
        try:
            self._validate_request_identity(request)
            if result.stdout_truncated or result.stderr_truncated:
                raise ValueError("successful Worker output was truncated")
            try:
                encoded = result.stdout.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("MCP bridge output is not valid UTF-8 text") from exc
            if len(encoded) > _MAX_MCP_BRIDGE_OUTPUT_BYTES:
                raise ValueError("MCP bridge output exceeded byte limit")
            try:
                raw_response = json.loads(
                    result.stdout,
                    object_pairs_hook=_reject_duplicate_mcp_keys,
                    parse_constant=_reject_nonfinite_mcp_constant,
                )
            except (json.JSONDecodeError, RecursionError, ValueError) as exc:
                raise ValueError("MCP bridge output is not valid JSON") from exc
            _validate_mcp_json(raw_response, budget=_MCPJSONBudget())
            response = _MCPBridgeResponse.model_validate(raw_response)
            data = dict(response.structured_content or {})
            data.update(
                {
                    "target": request.target,
                    "mcpServerId": self._registration.server_id,
                    "mcpToolName": self._registration.remote_tool_name,
                    "mcpContent": [
                        item.model_dump(mode="json", by_alias=True, exclude_none=True)
                        for item in response.content
                    ],
                }
            )
            is_error = response.is_error
        except ValueError as exc:
            return self._invalid_bridge_output(request, result, exc)
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=not is_error,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
            error="MCP tool returned isError=true" if is_error else None,
        )

    def _validate_request_identity(self, request: ToolRequest) -> None:
        if request.tool_id != self._registration.tool_id:
            raise ValueError("request tool ID differs from the sealed MCP registration")
        if request.method != "POST":
            raise ValueError("registered MCP tools require POST")

    @staticmethod
    def _invalid_bridge_output(
        request: ToolRequest,
        result: WorkerResult,
        error: BaseException,
    ) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=False,
            started_at=result.started_at,
            finished_at=result.finished_at,
            error=audit_safe_tool_interpretation_failure(
                "invalid MCP bridge output",
                error,
            ),
        )


class RegisteredMCPDiscoveryTool(Tool):
    """Enumerate one registered MCP server without exposing process or raw interface data."""

    def __init__(self, registration: MCPDiscoveryRegistration) -> None:
        self._registration = MCPDiscoveryRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        self.spec = ToolSpec(
            tool_id=self._registration.tool_id,
            version="1.0.0",
            description=self._registration.description,
            risk_tier=ToolRiskTier.T0,
            categories=frozenset({"discovery", "mcp"}),
            network_access=False,
        )

    @property
    def registration(self) -> MCPDiscoveryRegistration:
        """Return a detached observation of the sealed server registration."""

        return self._registration.model_copy(deep=True)

    def stable_execution_context(self) -> dict[str, object]:
        return {
            **self._stable_spec_context(),
            "registration": self._registration.model_dump(mode="python"),
            "boundary": {
                "maxItemsPerCategory": _MAX_MCP_DISCOVERY_ITEMS,
                "maxOutputBytes": _MAX_MCP_BRIDGE_OUTPUT_BYTES,
                "maxPagesPerCategory": _MAX_MCP_DISCOVERY_PAGES,
                "maxPromptArguments": _MAX_MCP_PROMPT_ARGUMENTS,
                "retainsRawResourceUris": False,
                "retainsRawSchemas": False,
                "retainsURLArgumentNames": True,
                "retainsDescriptions": False,
                "retainsPromptValues": False,
            },
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._validate_request_identity(request)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["mcp-discover"],
            stdin=json.dumps({"serverId": self._registration.server_id}),
            limits=WorkerLimits(stdout_bytes=_MAX_MCP_BRIDGE_OUTPUT_BYTES),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_worker_failure(result),
            )
        try:
            self._validate_request_identity(request)
            if result.stdout_truncated or result.stderr_truncated:
                raise ValueError("successful Worker output was truncated")
            try:
                encoded = result.stdout.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("MCP discovery output is not valid UTF-8 text") from exc
            if len(encoded) > _MAX_MCP_BRIDGE_OUTPUT_BYTES:
                raise ValueError("MCP discovery output exceeded byte limit")
            try:
                raw_response = json.loads(
                    result.stdout,
                    object_pairs_hook=_reject_duplicate_mcp_keys,
                    parse_constant=_reject_nonfinite_mcp_constant,
                )
            except (json.JSONDecodeError, RecursionError, ValueError) as exc:
                raise ValueError("MCP discovery output is not valid JSON") from exc
            _validate_mcp_json(raw_response, budget=_MCPJSONBudget())
            response = _MCPDiscoveryResponse.model_validate(raw_response)
            data = response.model_dump(mode="json", by_alias=True, exclude_none=True)
            data.update(
                {
                    "target": request.target,
                    "mcpServerId": self._registration.server_id,
                }
            )
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_tool_interpretation_failure(
                    "invalid MCP discovery output",
                    exc,
                ),
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
        )

    def _validate_request_identity(self, request: ToolRequest) -> None:
        if request.tool_id != self._registration.tool_id:
            raise ValueError("request tool ID differs from the sealed MCP discovery registration")
        if request.method != "POST":
            raise ValueError("registered MCP discovery requires POST")
        if request.arguments:
            raise ValueError("registered MCP discovery does not accept agent-selected arguments")


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


def demo_mcp_discovery_tool() -> RegisteredMCPDiscoveryTool:
    """Return the fixed read-only discovery boundary for the demo MCP server."""

    return RegisteredMCPDiscoveryTool(
        MCPDiscoveryRegistration(
            tool_id="mcp.demo-security.discover",
            server_id="demo-security",
            description="Discover the bounded interfaces of the registered demo MCP server",
        )
    )
