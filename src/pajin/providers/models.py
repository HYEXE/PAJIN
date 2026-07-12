"""Canonical provider contracts independent of any model SDK."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import AnyHttpUrl, Field, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.tools.ai import ChatRole


class ProviderRegistration(StrictModel):
    provider_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    endpoint: AnyHttpUrl
    model: str = Field(min_length=1, max_length=200)
    secret_ref: str = Field(min_length=1, max_length=200)
    allow_streaming: bool = True
    allowed_function_tools: set[str] = Field(default_factory=set, max_length=100)
    lease_ttl_seconds: int = Field(default=30, ge=1, le=300)
    allow_private_networks: bool = False
    input_cost_per_million_usd: float = Field(default=0, ge=0, le=1_000_000)
    output_cost_per_million_usd: float = Field(default=0, ge=0, le=1_000_000)


class ProviderFunctionCall(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    arguments: str = Field(min_length=2, max_length=1_000_000)


class ProviderAssistantToolCall(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    type: Literal["function"] = "function"
    function: ProviderFunctionCall


class ProviderMessage(StrictModel):
    role: ChatRole
    content: str | None = Field(default=None, min_length=1, max_length=65_536)
    tool_call_id: str | None = Field(default=None, max_length=200)
    tool_calls: list[ProviderAssistantToolCall] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def validate_tool_call_id(self) -> ProviderMessage:
        if self.role is ChatRole.TOOL and not self.tool_call_id:
            raise ValueError("tool messages require tool_call_id")
        if self.role is not ChatRole.TOOL and self.tool_call_id is not None:
            raise ValueError("tool_call_id is allowed only on tool messages")
        if self.tool_calls and self.role is not ChatRole.ASSISTANT:
            raise ValueError("tool_calls are allowed only on assistant messages")
        if self.content is None and not (self.role is ChatRole.ASSISTANT and self.tool_calls):
            raise ValueError("message content is required unless assistant tool_calls are present")
        return self


class FunctionDefinition(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    description: str | None = Field(default=None, max_length=1_024)
    parameters: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    strict: bool = True

    @model_validator(mode="after")
    def validate_strict_schema(self) -> FunctionDefinition:
        if self.strict:
            self._validate_object_schema(self.parameters, path="$parameters")
        return self

    @classmethod
    def _validate_object_schema(cls, schema: dict[str, Any], *, path: str) -> None:
        if schema.get("type") != "object":
            raise ValueError(f"{path} must have type object")
        if schema.get("additionalProperties") is not False:
            raise ValueError(f"{path} must reject additional properties")
        properties = schema.get("properties")
        required = schema.get("required")
        if not isinstance(properties, dict) or set(required or []) != set(properties):
            raise ValueError(f"{path} must require every declared property")
        for name, value in properties.items():
            if not isinstance(value, dict):
                raise ValueError(f"{path}.{name} must be a schema object")
            if value.get("type") == "object":
                cls._validate_object_schema(value, path=f"{path}.{name}")


class FunctionTool(StrictModel):
    type: Literal["function"] = "function"
    function: FunctionDefinition


class JSONSchemaDefinition(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    description: str | None = Field(default=None, max_length=1_024)
    schema_: dict[str, Any] = Field(alias="schema")
    strict: Literal[True] = True

    @field_validator("schema_")
    @classmethod
    def require_object_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("type") != "object":
            raise ValueError("structured output root schema must have type object")
        if value.get("additionalProperties") is not False:
            raise ValueError("structured output root must reject additional properties")
        return value


class JSONSchemaResponseFormat(StrictModel):
    type: Literal["json_schema"] = "json_schema"
    json_schema: JSONSchemaDefinition


class ProviderChatRequest(StrictModel):
    messages: list[ProviderMessage] = Field(min_length=1, max_length=100)
    stream: bool = False
    tools: list[FunctionTool] = Field(default_factory=list, max_length=50)
    tool_choice: Literal["auto", "none", "required"] = "auto"
    max_completion_tokens: int | None = Field(default=None, ge=1, le=131_072)
    response_format: JSONSchemaResponseFormat | None = None
    parallel_tool_calls: bool | None = None

    @model_validator(mode="after")
    def validate_tools(self) -> ProviderChatRequest:
        names = [tool.function.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("function tool names must be unique")
        if self.tool_choice == "required" and not self.tools:
            raise ValueError("required tool choice needs at least one function tool")
        return self


class NormalizedToolCall(StrictModel):
    call_id: str
    name: str
    arguments_json: str
    arguments: dict[str, Any] | None = None
    arguments_valid: bool


class ProviderUsage(StrictModel):
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class ProviderChatResult(StrictModel):
    provider_id: str
    response_id: str
    model: str
    content: str | None = None
    refusal: str | None = None
    finish_reason: str | None = None
    tool_calls: list[NormalizedToolCall] = Field(default_factory=list)
    usage: ProviderUsage | None = None
    streamed: bool
    chunks: int = Field(ge=1)
    target: str

    @field_validator("content", "refusal")
    @classmethod
    def bound_optional_text(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 1_000_000:
            raise ValueError("provider output text exceeds limit")
        return value
