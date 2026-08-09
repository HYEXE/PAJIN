"""Digest-only Surface adapter for one code-registered MCP server."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import ConfigDict, Field, StrictBool, model_validator

from pajin.discovery.adapters import DiscoverySurfaceKind
from pajin.discovery.admission import SurfaceCandidate
from pajin.discovery.models import (
    MCPPromptArgument,
    MCPURLArgument,
    SurfaceLocator,
    mcp_prompt_surface_locator,
    mcp_resource_surface_locator,
    mcp_resource_template_surface_locator,
    mcp_server_surface_locator,
    mcp_tool_surface_locator,
    mcp_url_tool_surface_locator,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.tools.mcp import RegisteredMCPDiscoveryTool

_MAX_ITEMS = 64
_MAX_PROMPT_ARGUMENTS = 32
_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SCHEME_PATTERN = r"^[a-z][a-z0-9+.-]{0,31}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"


class _MCPURLArgumentBoundary(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=_NAME_PATTERN)
    required: StrictBool


class _MCPToolBoundary(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=_NAME_PATTERN)
    input_schema_digest: str = Field(
        alias="inputSchemaDigest",
        pattern=_SHA256_PATTERN,
    )
    output_schema_digest: str | None = Field(
        default=None,
        alias="outputSchemaDigest",
        pattern=_SHA256_PATTERN,
    )
    url_arguments: list[_MCPURLArgumentBoundary] | None = Field(
        default=None,
        alias="urlArguments",
        max_length=32,
    )

    @model_validator(mode="after")
    def validate_url_arguments(self) -> _MCPToolBoundary:
        if self.url_arguments is None:
            return self
        names = [argument.name for argument in self.url_arguments]
        if not names or names != sorted(set(names)):
            raise ValueError("MCP URL Tool arguments must be non-empty, unique, and sorted")
        return self


class _MCPResourceBoundary(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    uri_scheme: str = Field(
        alias="uriScheme",
        min_length=1,
        max_length=32,
        pattern=_SCHEME_PATTERN,
    )
    uri_sha256: str = Field(alias="uriSha256", pattern=_SHA256_PATTERN)


class _MCPResourceTemplateBoundary(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    uri_scheme: str = Field(
        alias="uriScheme",
        min_length=1,
        max_length=32,
        pattern=_SCHEME_PATTERN,
    )
    template_sha256: str = Field(alias="templateSha256", pattern=_SHA256_PATTERN)


class _MCPPromptArgumentBoundary(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=_NAME_PATTERN)
    required: StrictBool


class _MCPPromptBoundary(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=128, pattern=_NAME_PATTERN)
    arguments: list[_MCPPromptArgumentBoundary] = Field(
        max_length=_MAX_PROMPT_ARGUMENTS,
    )

    @model_validator(mode="after")
    def validate_arguments(self) -> _MCPPromptBoundary:
        names = [argument.name for argument in self.arguments]
        if names != sorted(set(names)):
            raise ValueError("MCP prompt arguments must be unique and sorted")
        return self


class _MCPBoundaryData(StrictModel):
    """Exact host-visible discovery result; raw MCP values are not representable."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    target: str = Field(min_length=1, max_length=2_000)
    server_id: str = Field(
        alias="mcpServerId",
        min_length=1,
        max_length=200,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    protocol_version: str = Field(
        alias="protocolVersion",
        min_length=10,
        max_length=10,
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    )
    capabilities: list[Literal["prompts", "resources", "tools"]] = Field(max_length=3)
    tools: list[_MCPToolBoundary] = Field(max_length=_MAX_ITEMS)
    resources: list[_MCPResourceBoundary] = Field(max_length=_MAX_ITEMS)
    resource_templates: list[_MCPResourceTemplateBoundary] = Field(
        alias="resourceTemplates",
        max_length=_MAX_ITEMS,
    )
    prompts: list[_MCPPromptBoundary] = Field(max_length=_MAX_ITEMS)

    @model_validator(mode="after")
    def validate_canonical_boundary(self) -> _MCPBoundaryData:
        if self.capabilities != sorted(set(self.capabilities)):
            raise ValueError("MCP capabilities must be unique and sorted")
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
            raise ValueError("MCP boundary entries must be unique and sorted")
        if self.tools and "tools" not in self.capabilities:
            raise ValueError("MCP tools require their advertised capability")
        if (self.resources or self.resource_templates) and "resources" not in self.capabilities:
            raise ValueError("MCP resources require their advertised capability")
        if self.prompts and "prompts" not in self.capabilities:
            raise ValueError("MCP prompts require their advertised capability")
        return self


class MCPBoundarySurfaceAdapter:
    """Map one digest-only Worker result into non-executable MCP Surfaces."""

    def __init__(self, *, tool: RegisteredMCPDiscoveryTool) -> None:
        if not isinstance(tool, RegisteredMCPDiscoveryTool):
            raise TypeError("MCP boundary adapter requires a RegisteredMCPDiscoveryTool")
        registration = tool.registration
        self.tool_id = tool.spec.tool_id
        self.adapter_id = f"pajin.discovery.mcp-boundary:{self.tool_id}"
        self.adapter_version = "1.0.0"
        self.producer_id = f"pajin.discovery.mcp-boundary.v1:{self.tool_id}"
        self.supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = (
            "mcp-prompt",
            "mcp-resource",
            "mcp-resource-template",
            "mcp-server",
            "mcp-tool",
            "mcp-url-tool",
        )
        self.requires_trusted_network_receipt = False
        self._tool_version = tool.spec.version
        self._server_id = registration.server_id

    def stable_execution_context(self) -> Mapping[str, object]:
        """Bind the sealed server and every host-retention rule."""

        return {
            "toolId": self.tool_id,
            "toolVersion": self._tool_version,
            "serverId": self._server_id,
            "maxItemsPerCategory": _MAX_ITEMS,
            "maxPromptArguments": _MAX_PROMPT_ARGUMENTS,
            "retainsRawResourceUris": False,
            "retainsRawSchemas": False,
            "retainsURLArgumentNames": True,
            "retainsDescriptions": False,
            "retainsPromptValues": False,
        }

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        if (
            request.tool_id != self.tool_id
            or result.tool_id != self.tool_id
            or result.request_id != request.request_id
            or request.method != "POST"
            or request.arguments
            or not result.success
            or result.error is not None
        ):
            raise ValueError("MCP boundary result identity is invalid")
        boundary = _MCPBoundaryData.model_validate(result.data)
        if boundary.target != request.target or boundary.server_id != self._server_id:
            raise ValueError("MCP boundary result differs from its sealed registration")

        locators: list[SurfaceLocator] = [
            mcp_server_surface_locator(
                server_id=self._server_id,
                protocol_version=boundary.protocol_version,
                capabilities=tuple(boundary.capabilities),
            ),
            *(
                mcp_tool_surface_locator(
                    server_id=self._server_id,
                    tool_name=item.name,
                    input_schema_digest=item.input_schema_digest,
                    output_schema_digest=item.output_schema_digest,
                )
                for item in boundary.tools
            ),
            *(
                mcp_url_tool_surface_locator(
                    server_id=self._server_id,
                    tool_name=item.name,
                    input_schema_digest=item.input_schema_digest,
                    url_arguments=tuple(
                        MCPURLArgument(
                            name=argument.name,
                            required=argument.required,
                        )
                        for argument in item.url_arguments or ()
                    ),
                )
                for item in boundary.tools
                if item.url_arguments
            ),
            *(
                mcp_resource_surface_locator(
                    server_id=self._server_id,
                    uri_scheme=item.uri_scheme,
                    uri_sha256=item.uri_sha256,
                )
                for item in boundary.resources
            ),
            *(
                mcp_resource_template_surface_locator(
                    server_id=self._server_id,
                    uri_scheme=item.uri_scheme,
                    template_sha256=item.template_sha256,
                )
                for item in boundary.resource_templates
            ),
            *(
                mcp_prompt_surface_locator(
                    server_id=self._server_id,
                    prompt_name=item.name,
                    arguments=tuple(
                        MCPPromptArgument(
                            name=argument.name,
                            required=argument.required,
                        )
                        for argument in item.arguments
                    ),
                )
                for item in boundary.prompts
            ),
        ]
        return [SurfaceCandidate(locator=locator, confidence=1.0) for locator in locators]
