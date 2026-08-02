"""Canonical provider contracts independent of any model SDK."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterator, Mapping
from contextlib import suppress
from ipaddress import ip_address
from types import MappingProxyType
from typing import Any, Literal, cast

from pydantic import (
    AnyHttpUrl,
    ConfigDict,
    Field,
    JsonValue,
    SkipValidation,
    field_serializer,
    field_validator,
    model_validator,
)

from pajin.domain.models import StrictModel
from pajin.tools.ai import ChatRole

_MAX_PROVIDER_SCHEMA_DEPTH = 32
_MAX_PROVIDER_SCHEMA_NODES = 20_000
_MAX_PROVIDER_SCHEMA_BYTES = 262_144


class _FrozenJSONObject(Mapping[str, object]):
    """A recursively immutable JSON object detached from caller-owned containers."""

    __slots__ = ("__values",)

    def __init__(self, values: Mapping[str, object]) -> None:
        self.__values = MappingProxyType(dict(values))

    def __getitem__(self, key: str) -> object:
        return self.__values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.__values)

    def __len__(self) -> int:
        return len(self.__values)

    def __repr__(self) -> str:
        return repr(dict(self.__values))

    def __deepcopy__(self, _memo: dict[int, object]) -> _FrozenJSONObject:
        return self


class _BoundedProviderSchemaWalker:
    """Validate and freeze a decoded JSON graph before Pydantic can recurse into it."""

    __slots__ = ("_active_containers", "_label", "_node_count", "_text_bytes")

    def __init__(self, *, label: str) -> None:
        self._active_containers: set[int] = set()
        self._label = label
        self._node_count = 0
        self._text_bytes = 0

    def freeze(self, value: object, *, depth: int = 0) -> object:
        self._count_node(depth)
        if value is None or type(value) is bool:
            return value
        if type(value) is str:
            self._count_text(value)
            return value
        if type(value) is int:
            integer = value
            if not -(2**63) <= integer <= 2**63 - 1:
                raise ValueError(f"{self._label} integer is outside the signed 64-bit JSON range")
            return integer
        if type(value) is float:
            number = value
            if not math.isfinite(number):
                raise ValueError(f"{self._label} numbers must be finite")
            return number
        if type(value) is list:
            return self._freeze_container(
                value,
                freeze_values=lambda: tuple(
                    self.freeze(item, depth=depth + 1) for item in cast(list[object], value)
                ),
            )
        if type(value) is dict:
            mapping = cast(dict[object, object], value)
            return self._freeze_container(
                value,
                freeze_values=lambda: self._freeze_object(mapping, depth=depth),
            )
        raise ValueError(f"{self._label} contains a non-JSON value")

    def _freeze_object(
        self,
        mapping: dict[object, object],
        *,
        depth: int,
    ) -> _FrozenJSONObject:
        frozen: dict[str, object] = {}
        for raw_key, item in mapping.items():
            self._count_node(depth + 1)
            if type(raw_key) is not str:
                raise ValueError(f"{self._label} object keys must be strings")
            key = raw_key
            self._count_text(key)
            frozen[key] = self.freeze(item, depth=depth + 1)
        return _FrozenJSONObject(frozen)

    def _freeze_container(
        self,
        value: object,
        *,
        freeze_values: Callable[[], object],
    ) -> object:
        identity = id(value)
        if identity in self._active_containers:
            raise ValueError(f"{self._label} cannot contain Python container cycles")
        self._active_containers.add(identity)
        try:
            return freeze_values()
        finally:
            self._active_containers.remove(identity)

    def _count_node(self, depth: int) -> None:
        self._node_count += 1
        if self._node_count > _MAX_PROVIDER_SCHEMA_NODES:
            raise ValueError(f"{self._label} exceeds the JSON node-count limit")
        if depth > _MAX_PROVIDER_SCHEMA_DEPTH:
            raise ValueError(f"{self._label} exceeds the JSON nesting-depth limit")

    def _count_text(self, value: str) -> None:
        if len(value) > _MAX_PROVIDER_SCHEMA_BYTES:
            raise ValueError(f"{self._label} exceeds the canonical byte limit")
        try:
            byte_count = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError(f"{self._label} contains invalid UTF-8 text") from exc
        self._text_bytes += byte_count
        if self._text_bytes > _MAX_PROVIDER_SCHEMA_BYTES:
            raise ValueError(f"{self._label} exceeds the canonical byte limit")


def _thaw_provider_schema(value: object) -> object:
    if isinstance(value, _FrozenJSONObject):
        return {key: _thaw_provider_schema(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_provider_schema(item) for item in cast(tuple[object, ...], value)]
    return value


def _freeze_bounded_provider_schema(value: object, *, label: str) -> _FrozenJSONObject:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    frozen = _BoundedProviderSchemaWalker(label=label).freeze(value)
    if not isinstance(frozen, _FrozenJSONObject):
        raise ValueError(f"{label} must be a JSON object")
    try:
        canonical = json.dumps(
            _thaw_provider_schema(frozen),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(canonical) > _MAX_PROVIDER_SCHEMA_BYTES:
        raise ValueError(f"{label} exceeds the canonical byte limit")
    return frozen


def _empty_strict_object_schema() -> dict[str, JsonValue]:
    return {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }


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

    @model_validator(mode="after")
    def require_safe_bearer_transport(self) -> ProviderRegistration:
        endpoint = self.endpoint
        if endpoint.username is not None or endpoint.password is not None:
            raise ValueError("provider endpoint must not contain URL credentials")
        if endpoint.fragment is not None:
            raise ValueError("provider endpoint must not contain a URL fragment")
        if endpoint.scheme == "https":
            return self

        host = (endpoint.host or "").removeprefix("[").removesuffix("]").rstrip(".").lower()
        local_lab_host = host in {"localhost", "host.docker.internal"}
        with suppress(ValueError):
            local_lab_host = local_lab_host or ip_address(host).is_loopback
        if not local_lab_host:
            raise ValueError(
                "provider Bearer endpoints require HTTPS except for fixed local-lab hosts"
            )
        if not self.allow_private_networks:
            raise ValueError(
                "local-lab HTTP provider endpoints require explicit allow_private_networks"
            )
        return self


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
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        validate_default=True,
    )

    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    description: str | None = Field(default=None, max_length=1_024)
    parameters: SkipValidation[dict[str, JsonValue]] = Field(
        default_factory=_empty_strict_object_schema
    )
    strict: bool = True

    @field_validator("parameters", mode="before")
    @classmethod
    def freeze_parameters(cls, value: object) -> _FrozenJSONObject:
        return _freeze_bounded_provider_schema(value, label="function parameters schema")

    @field_serializer("parameters")
    def serialize_parameters(self, value: object) -> object:
        return _thaw_provider_schema(value)

    @model_validator(mode="after")
    def validate_strict_schema(self) -> FunctionDefinition:
        if self.strict:
            self._validate_object_schema(self.parameters, path="$parameters")
        return self

    @classmethod
    def _validate_object_schema(cls, schema: Mapping[str, object], *, path: str) -> None:
        if schema.get("type") != "object":
            raise ValueError(f"{path} must have type object")
        if schema.get("additionalProperties") is not False:
            raise ValueError(f"{path} must reject additional properties")
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            not isinstance(properties, Mapping)
            or type(required) is not tuple
            or any(type(item) is not str for item in required)
            or len(required) != len(set(required))
            or set(required) != set(properties)
        ):
            raise ValueError(f"{path} must require every declared property")
        for name, value in properties.items():
            if not isinstance(value, Mapping):
                raise ValueError(f"{path}.{name} must be a schema object")
            if value.get("type") == "object":
                cls._validate_object_schema(value, path=f"{path}.{name}")


class FunctionTool(StrictModel):
    type: Literal["function"] = "function"
    function: FunctionDefinition


class JSONSchemaDefinition(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
    )

    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    description: str | None = Field(default=None, max_length=1_024)
    schema_: SkipValidation[dict[str, JsonValue]] = Field(alias="schema")
    strict: Literal[True] = True

    @field_validator("schema_", mode="before")
    @classmethod
    def freeze_and_require_object_schema(cls, value: object) -> _FrozenJSONObject:
        frozen = _freeze_bounded_provider_schema(
            value,
            label="structured output schema",
        )
        if frozen.get("type") != "object":
            raise ValueError("structured output root schema must have type object")
        if frozen.get("additionalProperties") is not False:
            raise ValueError("structured output root must reject additional properties")
        return frozen

    @field_serializer("schema_")
    def serialize_schema(self, value: object) -> object:
        return _thaw_provider_schema(value)


class JSONSchemaResponseFormat(StrictModel):
    type: Literal["json_schema"] = "json_schema"
    json_schema: JSONSchemaDefinition


class ProviderChatRequest(StrictModel):
    messages: list[ProviderMessage] = Field(min_length=1, max_length=100)
    stream: bool = False
    tools: list[FunctionTool] = Field(default_factory=list, max_length=50)
    tool_choice: Literal["auto", "none", "required"] = "auto"
    max_completion_tokens: int | None = Field(default=None, ge=1, le=131_072)
    temperature: float | None = Field(default=None, ge=0, le=2, allow_inf_nan=False)
    top_p: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    seed: int | None = Field(default=None, ge=0, le=2**63 - 1)
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
    # Provider usage is untrusted observation, not budget authority. Keep it
    # resource-bounded before recording it in an audit event.
    prompt_tokens: int | None = Field(default=None, ge=0, le=1_000_000_000)
    completion_tokens: int | None = Field(default=None, ge=0, le=1_000_000_000)
    total_tokens: int | None = Field(default=None, ge=0, le=1_000_000_000)


class ProviderChatResult(StrictModel):
    provider_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    response_id: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=200)
    content: str | None = None
    refusal: str | None = None
    finish_reason: str | None = Field(default=None, max_length=100)
    tool_calls: list[NormalizedToolCall] = Field(default_factory=list, max_length=8)
    usage: ProviderUsage | None = None
    streamed: bool
    chunks: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=2_000)

    @field_validator("content", "refusal")
    @classmethod
    def bound_optional_text(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 1_000_000:
            raise ValueError("provider output text exceeds limit")
        return value
