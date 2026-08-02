"""Strict, secret-free raw model/tool trace for governed single-agent runs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderUsage
from pajin.runtime.worker import WorkerResult

MODEL_TOOL_TRACE_FORMAT: Literal["pajin-model-tool-trace-jsonl/v1"] = (
    "pajin-model-tool-trace-jsonl/v1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_TRACE_BYTES = 16 * 1024 * 1024
_MAX_TRACE_RECORDS = 10_000


class ModelToolTraceEvent(StrEnum):
    IDENTITY = "identity"
    MODEL_REQUEST = "modelRequest"
    MODEL_RESULT = "modelResult"
    PROVIDER_USAGE = "providerUsage"
    TOOL_REQUEST = "toolRequest"
    TOOL_RECEIPT = "toolReceipt"
    TOOL_RESULT = "toolResult"
    CLEANUP = "cleanup"


class ModelToolTraceIdentity(StrictModel):
    """The eight P0-E3A identities required before a raw trace is admissible."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    trace_format: Literal["pajin-model-tool-trace-jsonl/v1"] = Field(
        default=MODEL_TOOL_TRACE_FORMAT,
        alias="traceFormat",
    )
    agent_implementation_id: str = Field(
        alias="agentImplementationId", min_length=1, max_length=200
    )
    agent_implementation_version: str = Field(
        alias="agentImplementationVersion", min_length=1, max_length=200
    )
    agent_implementation_digest: _Sha256 = Field(alias="agentImplementationDigest")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    model_revision: str = Field(alias="modelRevision", min_length=1, max_length=200)
    prompt_bundle_digest: _Sha256 = Field(alias="promptBundleDigest")
    tool_catalog_digest: _Sha256 = Field(alias="toolCatalogDigest")
    runtime_configuration_digest: _Sha256 = Field(alias="runtimeConfigurationDigest")


class ModelRequestTracePayload(StrictModel):
    attempt: int = Field(ge=1, le=1_000)
    request: ProviderChatRequest


class ModelResultTracePayload(StrictModel):
    attempt: int = Field(ge=1, le=1_000)
    result: ProviderChatResult


class ProviderUsageTracePayload(StrictModel):
    attempt: int = Field(ge=1, le=1_000)
    usage: ProviderUsage


class ToolRequestTracePayload(StrictModel):
    call_id: str = Field(alias="callId", min_length=1, max_length=200)
    request: ToolRequest


class ToolReceiptTracePayload(StrictModel):
    call_id: str = Field(alias="callId", min_length=1, max_length=200)
    executed: bool
    worker_result: WorkerResult | None = Field(alias="workerResult")
    network_log_trusted: bool = Field(alias="networkLogTrusted")
    result_identity_valid: bool = Field(alias="resultIdentityValid")


class ToolResultTracePayload(StrictModel):
    call_id: str = Field(alias="callId", min_length=1, max_length=200)
    result: ToolResult


class CleanupTracePayload(StrictModel):
    status: str = Field(min_length=1, max_length=100)
    worker_execution_count: int = Field(alias="workerExecutionCount", ge=0, le=10_000)
    active_secret_lease_count: Literal[0] = Field(default=0, alias="activeSecretLeaseCount")


_PAYLOAD_TYPES: dict[ModelToolTraceEvent, type[StrictModel]] = {
    ModelToolTraceEvent.IDENTITY: ModelToolTraceIdentity,
    ModelToolTraceEvent.MODEL_REQUEST: ModelRequestTracePayload,
    ModelToolTraceEvent.MODEL_RESULT: ModelResultTracePayload,
    ModelToolTraceEvent.PROVIDER_USAGE: ProviderUsageTracePayload,
    ModelToolTraceEvent.TOOL_REQUEST: ToolRequestTracePayload,
    ModelToolTraceEvent.TOOL_RECEIPT: ToolReceiptTracePayload,
    ModelToolTraceEvent.TOOL_RESULT: ToolResultTracePayload,
    ModelToolTraceEvent.CLEANUP: CleanupTracePayload,
}


class ModelToolTraceRecord(StrictModel):
    """One canonical line in ``pajin-model-tool-trace-jsonl/v1``."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    sequence: int = Field(ge=1, le=_MAX_TRACE_RECORDS)
    recorded_at: datetime = Field(alias="recordedAt")
    event: ModelToolTraceEvent
    payload: dict[str, Any]

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        if self.recorded_at.tzinfo is None or self.recorded_at.utcoffset() is None:
            raise ValueError("model/tool trace timestamps require an explicit UTC offset")
        payload_type = _PAYLOAD_TYPES[self.event]
        payload = payload_type.model_validate(self.payload)
        canonical = payload.model_dump(mode="json", by_alias=True, exclude_none=False)
        _reject_secret_material(canonical)
        object.__setattr__(self, "recorded_at", self.recorded_at.astimezone(UTC))
        object.__setattr__(self, "payload", canonical)
        return self


def model_tool_trace_record(
    records: list[ModelToolTraceRecord],
    event: ModelToolTraceEvent,
    payload: StrictModel,
) -> ModelToolTraceRecord:
    """Append one typed record while preserving an exact monotonic sequence."""

    expected = _PAYLOAD_TYPES[event]
    if not isinstance(payload, expected):
        raise TypeError(f"{event.value} trace payload has the wrong type")
    record = ModelToolTraceRecord(
        sequence=len(records) + 1,
        recordedAt=datetime.now(UTC),
        event=event,
        payload=payload.model_dump(mode="json", by_alias=True, exclude_none=False),
    )
    records.append(record)
    return record


def encode_model_tool_trace(records: list[ModelToolTraceRecord]) -> bytes:
    """Encode strict records as canonical, newline-terminated JSONL."""

    _validate_trace_sequence(records)
    raw = b"".join((_encode_record(record) + "\n").encode("utf-8") for record in records)
    if not 1 <= len(raw) <= _MAX_TRACE_BYTES:
        raise ValueError("model/tool trace exceeds its byte bound")
    return raw


def parse_model_tool_trace(
    raw: bytes,
    *,
    expected_identity: ModelToolTraceIdentity,
) -> tuple[ModelToolTraceRecord, ...]:
    """Reject non-canonical, duplicate-key, secret-bearing, or incomplete JSONL."""

    if not 1 <= len(raw) <= _MAX_TRACE_BYTES or not raw.endswith(b"\n"):
        raise ValueError("model/tool trace is empty, oversized, or not newline terminated")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("model/tool trace is not UTF-8") from exc
    lines = text.splitlines()
    if not 1 <= len(lines) <= _MAX_TRACE_RECORDS:
        raise ValueError("model/tool trace record count is invalid")
    records: list[ModelToolTraceRecord] = []
    for line in lines:
        if not line:
            raise ValueError("model/tool trace contains a blank record")
        value = json.loads(line, object_pairs_hook=_strict_json_object)
        record = ModelToolTraceRecord.model_validate(value)
        canonical = _encode_record(record)
        if line != canonical:
            raise ValueError("model/tool trace record is not canonical JSON")
        records.append(record)
    _validate_trace_sequence(records)
    identity = ModelToolTraceIdentity.model_validate(records[0].payload)
    if identity != expected_identity:
        raise ValueError("model/tool trace identity differs")
    return tuple(record.model_copy(deep=True) for record in records)


def _validate_trace_sequence(records: list[ModelToolTraceRecord]) -> None:
    if not records or records[0].event is not ModelToolTraceEvent.IDENTITY:
        raise ValueError("model/tool trace must start with identity")
    if records[-1].event is not ModelToolTraceEvent.CLEANUP:
        raise ValueError("model/tool trace must end with cleanup")
    if [record.sequence for record in records] != list(range(1, len(records) + 1)):
        raise ValueError("model/tool trace sequence differs")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("model/tool trace contains a duplicate JSON key")
        value[key] = item
    return value


def _encode_record(record: ModelToolTraceRecord) -> str:
    return json.dumps(
        record.model_dump(mode="json", by_alias=True),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _reject_secret_material(value: object) -> None:
    forbidden = {"apikey", "authorization", "password", "secretvalue", "token"}
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = "".join(character for character in key.lower() if character.isalnum())
            if normalized in forbidden:
                raise ValueError("model/tool trace contains a forbidden secret field")
            _reject_secret_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_material(item)
