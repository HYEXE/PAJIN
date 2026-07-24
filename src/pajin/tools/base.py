"""Tool abstraction used for MCP, CLI, browser, and sandbox adapters."""

from __future__ import annotations

import json
import math
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Literal, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.worker import WorkerJob, WorkerResult

EGRESS_HTTP_RECEIPT_VERSION = "pajin.dev/egress-http-json-receipt/v1"
EGRESS_HTTPS_CONNECT_RECEIPT_VERSION = "pajin.dev/egress-https-connect-receipt/v1"
MAX_TRUSTED_NETWORK_LOG_BYTES = 256_000
_MAX_TOOL_JSON_DEPTH = 64
_MAX_TOOL_JSON_NODES = 20_000
_MAX_WORKER_OUTPUT_JSON_BYTES = 10_000_000


def _parse_tool_json_bytes(content: bytes, *, label: str, max_bytes: int) -> object:
    """Apply the one bounded strict-JSON policy shared by Tool trust boundaries."""

    try:
        decoded = parse_strict_json_bytes(
            content,
            label=label,
            max_bytes=max_bytes,
            max_depth=_MAX_TOOL_JSON_DEPTH,
            max_nodes=_MAX_TOOL_JSON_NODES,
        )
    except ValueError as exc:
        raise ValueError(f"{label} is not strict JSON: {_strict_json_failure_reason(exc)}") from exc
    _validate_tool_json_scalars(decoded, label=label)
    return decoded


def _strict_json_failure_reason(error: ValueError) -> str:
    """Classify parser failures without reflecting attacker-controlled JSON text."""

    current: BaseException | None = error
    messages: list[str] = []
    while current is not None:
        messages.append(str(current))
        current = current.__cause__
    combined = " ".join(messages)
    for marker, reason in (
        ("duplicate JSON object key", "duplicate JSON object key"),
        ("non-finite JSON", "non-finite JSON constant"),
        ("nesting-depth limit", "JSON nesting-depth limit exceeded"),
        ("node-count limit", "JSON node-count limit exceeded"),
        ("byte limit", "JSON byte limit exceeded"),
    ):
        if marker in combined:
            return reason
    return "syntax or value violation"


def _validate_tool_json_scalars(value: object, *, label: str) -> None:
    """Iteratively reject decoded values that cannot be canonical UTF-8 JSON."""

    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            mapping = cast(dict[object, object], item)
            for key, child in mapping.items():
                if type(key) is not str:
                    raise ValueError(f"{label} object keys must be strings")
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ValueError(f"{label} contains invalid UTF-8 text") from exc
                pending.append(child)
            continue
        if type(item) is list:
            pending.extend(cast(list[object], item))
            continue
        if type(item) is str:
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(f"{label} contains invalid UTF-8 text") from exc
            continue
        if type(item) is int:
            if not -(2**63) <= item <= 2**63 - 1:
                raise ValueError(f"{label} integer is outside the signed 64-bit range")
            continue
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError(f"{label} numbers must be finite")
            continue
        if item is None or type(item) is bool:
            continue
        raise ValueError(f"{label} contains a non-JSON value")


def decode_strict_worker_json_object(
    result: WorkerResult,
    *,
    label: str,
) -> dict[str, object]:
    """Decode one complete Worker stdout object without last-wins ambiguity."""

    if result.stdout_truncated or result.stderr_truncated:
        raise ValueError("successful Worker output was truncated")
    try:
        content = result.stdout.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} contains invalid UTF-8 text") from exc
    try:
        decoded = _parse_tool_json_bytes(
            content,
            label=label,
            max_bytes=_MAX_WORKER_OUTPUT_JSON_BYTES,
        )
    except ValueError as exc:
        if "duplicate JSON object key" in str(exc):
            raise ValueError("duplicate Worker output JSON field") from exc
        raise
    if type(decoded) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    return cast(dict[str, object], decoded)


def audit_safe_worker_failure(result: WorkerResult) -> str:
    """Summarize a failed Worker without copying its attacker-controlled stderr."""

    failure_code = result.failure_code.value if result.failure_code is not None else "unspecified"
    return (
        "Worker execution did not succeed "
        f"(status={result.status.value}, failureCode={failure_code})"
    )


def audit_safe_tool_interpretation_failure(label: str, error: BaseException) -> str:
    """Classify an adapter failure without reflecting Worker/provider values."""

    # Keep a small, fixed taxonomy for operationally useful parser failures.
    # We inspect exception text only to choose a constant; no source text is
    # copied into the returned diagnostic.
    current: BaseException | None = error
    visited: set[int] = set()
    messages: list[str] = []
    while current is not None and len(visited) < 16 and id(current) not in visited:
        visited.add(id(current))
        with suppress(BaseException):
            messages.append(str(current))
        current = current.__cause__
    combined = " ".join(messages)
    for marker, reason in (
        ("duplicate Worker output JSON field", "duplicate Worker output JSON field"),
        ("duplicate MCP bridge output field", "duplicate MCP bridge output field"),
        ("successful Worker output was truncated", "successful Worker output was truncated"),
        ("nesting-depth limit", "JSON nesting-depth limit exceeded"),
        ("node-count limit", "JSON node-count limit exceeded"),
        ("non-finite JSON constant", "non-finite JSON constant"),
        ("invalid UTF-8 text", "invalid UTF-8 text"),
        ("not valid UTF-8 text", "invalid UTF-8 text"),
        ("byte limit", "JSON byte limit exceeded"),
        ("regressionPassed", "regressionPassed validation failed"),
    ):
        if marker in combined:
            return f"{label}; reason={reason}"
    return f"{label}; " + audit_safe_exception_diagnostic(
        error,
        stage="tool-interpretation",
    )


class HTTPJSONProxyReceipt(StrictModel):
    """Host-observed plaintext HTTP JSON exchange from the isolated proxy."""

    model_config = ConfigDict(frozen=True)

    event: Literal["allow"]
    receipt_version: Literal["pajin.dev/egress-http-json-receipt/v1"] = Field(
        alias="receiptVersion"
    )
    sequence: int = Field(strict=True, ge=1, le=100)
    method: Literal["GET", "POST"]
    target: str = Field(min_length=1, max_length=2_000)
    target_sha256: str = Field(alias="targetSha256", pattern=r"^[a-f0-9]{64}$")
    address: str = Field(min_length=1, max_length=100)
    status: int = Field(strict=True, ge=100, le=599)
    response_body_sha256: str = Field(
        alias="responseBodySha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    response_json_sha256: str | None = Field(
        default=None,
        alias="responseJsonSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    request_json_sha256: str | None = Field(
        default=None,
        alias="requestJsonSha256",
        pattern=r"^[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_method_and_redaction(self) -> HTTPJSONProxyReceipt:
        query = urlsplit(self.target).query
        if query and query != "<redacted>":
            raise ValueError("proxy receipt target contains an unredacted query")
        if self.method == "POST" and self.request_json_sha256 is None:
            raise ValueError("POST proxy receipt requires a request JSON digest")
        if self.method == "GET" and self.request_json_sha256 is not None:
            raise ValueError("GET proxy receipt cannot include a request JSON digest")
        return self


class HTTPSConnectProxyReceipt(StrictModel):
    """Host-observed TLS tunnel route without claiming application plaintext visibility."""

    model_config = ConfigDict(frozen=True)

    event: Literal["allow"]
    receipt_version: Literal["pajin.dev/egress-https-connect-receipt/v1"] = Field(
        alias="receiptVersion"
    )
    sequence: int = Field(strict=True, ge=1, le=100)
    method: Literal["CONNECT"]
    authority: str = Field(min_length=3, max_length=300)
    authority_sha256: str = Field(alias="authoritySha256", pattern=r"^[a-f0-9]{64}$")
    address: str = Field(min_length=1, max_length=100)
    application_visibility: Literal["opaque"] = Field(alias="applicationVisibility")
    method_enforcement: Literal["trusted-worker-only"] = Field(alias="methodEnforcement")
    path_enforcement: Literal["authority-only"] = Field(alias="pathEnforcement")

    @model_validator(mode="after")
    def validate_canonical_authority(self) -> HTTPSConnectProxyReceipt:
        try:
            parsed = urlsplit(f"//{self.authority}")
            port = parsed.port
        except ValueError as exc:
            raise ValueError("HTTPS CONNECT receipt authority is invalid") from exc
        if (
            not parsed.hostname
            or port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("HTTPS CONNECT receipt requires a bare host:port authority")
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        host = f"[{hostname}]" if ":" in hostname else hostname
        canonical = f"{host}:{port}"
        if self.authority != canonical:
            raise ValueError("HTTPS CONNECT receipt authority is not canonical")
        if self.authority_sha256 != sha256(canonical.encode("utf-8")).hexdigest():
            raise ValueError("HTTPS CONNECT receipt authority digest is inconsistent")
        return self


def audit_http_target(target: str) -> str:
    """Return a URL suitable for logs without recording raw query values."""

    # Local import avoids the policy package's ToolSpec import cycle while still
    # using the same canonical URL contract as authorization.
    from pajin.policy.scope import normalize_target_url

    parsed = urlsplit(normalize_target_url(target))
    query = "<redacted>" if parsed.query else ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def http_target_sha256(target: str) -> str:
    """Bind a receipt to the full URL while keeping query values out of logs."""

    return sha256(target.encode("utf-8")).hexdigest()


def https_connect_authority(target: str) -> str:
    """Return the canonical host:port authority used by an HTTPS CONNECT tunnel."""

    from pajin.policy.scope import normalize_target_url

    parsed = urlsplit(normalize_target_url(target))
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("HTTPS CONNECT authority requires an HTTPS target")
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{host}:{parsed.port or 443}"


def decode_bounded_json_response(
    encoded_body: str,
    *,
    max_bytes: int,
) -> tuple[bytes, dict[str, object], str]:
    """Decode exact response bytes and return their strict canonical JSON digest."""

    body = decode_bounded_response_body(encoded_body, max_bytes=max_bytes)
    try:
        response = _parse_tool_json_bytes(
            body,
            label="HTTP response body",
            max_bytes=max_bytes,
        )
        if type(response) is not dict:
            raise ValueError("HTTP response body must be a JSON object")
        canonical = json.dumps(
            response,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (UnicodeError, TypeError, ValueError) as exc:
        raise ValueError("HTTP response body is not a strict JSON object") from exc
    return body, cast(dict[str, object], response), sha256(canonical).hexdigest()


def decode_bounded_response_body(encoded_body: str, *, max_bytes: int) -> bytes:
    """Decode one canonical base64 response body under an exact byte limit."""

    if max_bytes < 1 or len(encoded_body) > ((max_bytes + 2) // 3) * 4:
        raise ValueError("encoded HTTP response body exceeds its byte limit")
    try:
        body = b64decode(encoded_body, validate=True)
    except (BinasciiError, ValueError) as exc:
        raise ValueError("HTTP response body is not canonical base64") from exc
    if len(body) > max_bytes or b64encode(body).decode("ascii") != encoded_body:
        raise ValueError("HTTP response body is not canonical bounded base64")
    return body


def _strict_proxy_log_object(raw: str) -> dict[str, object]:
    try:
        content = raw.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Docker egress proxy log contains malformed JSON") from exc
    try:
        value = _parse_tool_json_bytes(
            content,
            label="Docker egress proxy log event",
            max_bytes=MAX_TRUSTED_NETWORK_LOG_BYTES,
        )
    except ValueError as exc:
        raise ValueError("Docker egress proxy log contains malformed JSON") from exc
    if type(value) is not dict:
        raise ValueError("Docker egress proxy log event must be an object")
    return cast(dict[str, object], value)


@dataclass
class _ProxyReceiptLogState:
    http_receipts: list[HTTPJSONProxyReceipt] = field(default_factory=list)
    https_connect_receipts: list[HTTPSConnectProxyReceipt] = field(default_factory=list)
    non_receipt_allows: int = 0
    ready_seen: bool = False
    exchange_seen: bool = False


def host_observed_http_receipts(
    worker_result: WorkerResult,
    *,
    network_log_trusted: bool,
) -> list[HTTPJSONProxyReceipt] | None:
    """Parse a complete ordered proxy log only when its capture is host-trusted."""

    if not network_log_trusted:
        return None
    network_log = _trusted_docker_network_log(worker_result)
    if network_log is None:
        return None
    state = _parse_proxy_network_log(network_log)
    _validate_proxy_receipt_log(state)
    return state.http_receipts or None


def host_observed_https_connect_receipts(
    worker_result: WorkerResult,
    *,
    network_log_trusted: bool,
) -> list[HTTPSConnectProxyReceipt] | None:
    """Parse complete ordered HTTPS CONNECT routes from one host-trusted proxy log."""

    if not network_log_trusted:
        return None
    network_log = _trusted_docker_network_log(worker_result)
    if network_log is None:
        return None
    state = _parse_proxy_network_log(network_log)
    _validate_proxy_receipt_log(state)
    return state.https_connect_receipts or None


def _trusted_docker_network_log(worker_result: WorkerResult) -> str | None:
    try:
        worker_result.network_log.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Docker egress proxy log is not valid UTF-8 text") from exc
    try:
        snapshot = WorkerResult.model_validate(worker_result.model_dump(mode="python"))
    except Exception as exc:
        raise ValueError("trusted proxy receipts require a valid Worker result") from exc
    if snapshot.backend != "docker":
        raise ValueError("trusted proxy receipts require the host Docker backend")
    network_log = snapshot.network_log
    if not network_log.strip():
        return None
    try:
        network_log_bytes = network_log.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Docker egress proxy log is not valid UTF-8 text") from exc
    if len(network_log_bytes) > MAX_TRUSTED_NETWORK_LOG_BYTES:
        raise ValueError("Docker egress proxy log exceeds the trusted byte limit")
    return network_log


def _parse_proxy_network_log(network_log: str) -> _ProxyReceiptLogState:
    state = _ProxyReceiptLogState()
    for raw_line in network_log.splitlines():
        if not raw_line.strip():
            continue
        _consume_proxy_event(state, _strict_proxy_log_object(raw_line))
    return state


def _consume_proxy_event(state: _ProxyReceiptLogState, event: dict[str, object]) -> None:
    event_name = event.get("event")
    if event_name == "ready":
        if state.ready_seen or state.exchange_seen:
            raise ValueError("Docker egress proxy log has a duplicate or late ready event")
        state.ready_seen = True
        return
    if not state.ready_seen:
        raise ValueError("Docker egress proxy log is missing its initial ready event")
    state.exchange_seen = True
    if event_name in {"deny", "error"}:
        raise ValueError("Docker egress proxy recorded a denied or failed exchange")
    if event_name != "allow":
        raise ValueError("Docker egress proxy log contains an unknown event")
    if "receiptVersion" not in event:
        state.non_receipt_allows += 1
        return
    try:
        receipt_version = event["receiptVersion"]
        if receipt_version == EGRESS_HTTP_RECEIPT_VERSION:
            state.http_receipts.append(HTTPJSONProxyReceipt.model_validate(event))
        elif receipt_version == EGRESS_HTTPS_CONNECT_RECEIPT_VERSION:
            state.https_connect_receipts.append(HTTPSConnectProxyReceipt.model_validate(event))
        else:
            raise ValueError("unknown proxy receipt version")
    except ValueError as exc:
        raise ValueError("Docker egress proxy receipt is invalid") from exc


def _validate_proxy_receipt_log(state: _ProxyReceiptLogState) -> None:
    if not state.ready_seen:
        raise ValueError("Docker egress proxy log is missing its initial ready event")
    if not state.http_receipts and not state.https_connect_receipts:
        return
    if state.non_receipt_allows or (state.http_receipts and state.https_connect_receipts):
        raise ValueError("Docker egress proxy log mixes observable and opaque exchanges")
    sequences = [receipt.sequence for receipt in state.http_receipts] + [
        receipt.sequence for receipt in state.https_connect_receipts
    ]
    if len(sequences) != len(set(sequences)) or sequences != list(range(1, len(sequences) + 1)):
        raise ValueError("Docker egress proxy receipt sequence is duplicate or incomplete")


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    version: str
    description: str
    risk_tier: ToolRiskTier
    categories: frozenset[str] = Field(default_factory=frozenset)
    evidence_types: frozenset[str] = Field(default_factory=lambda: frozenset({"json"}))
    network_access: bool = False
    network_request_cost: int = Field(default=1, ge=1, le=100)
    parallel_safe: bool = False


class Tool(ABC):
    spec: ToolSpec

    def _stable_spec_context(self) -> dict[str, object]:
        """Return the common context for adapters whose behavior is fully described by spec."""

        return {
            "implementationVersion": "pajin.tool-adapter/v1",
            "spec": self.spec.model_dump(mode="python"),
        }

    def network_request_cost(self, request: ToolRequest) -> int:
        """Return trusted request units; multi-request adapters may override this floor."""

        del request
        return self.spec.network_request_cost

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        """Validate a successful result against sealed input and host observations."""

        del request, result, worker_result, network_log_trusted

    @abstractmethod
    def prepare(self, request: ToolRequest) -> WorkerJob:
        """Translate a canonical request into an isolated worker job."""

    @abstractmethod
    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        """Translate bounded worker output into a canonical tool result."""


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._specs: dict[str, ToolSpec] = {}

    def register(self, tool: Tool) -> None:
        spec = self._snapshot_spec(tool)
        if spec.tool_id in self._tools:
            raise ValueError(f"tool already registered: {spec.tool_id}")
        self._tools[spec.tool_id] = tool
        self._specs[spec.tool_id] = spec

    def spec(self, tool_id: str) -> ToolSpec:
        self._get(tool_id)
        return self._specs[tool_id].model_copy(deep=True)

    def tool(self, tool_id: str) -> Tool:
        tool = self._get(tool_id)
        if self._snapshot_spec(tool) != self._specs[tool_id]:
            raise RuntimeError(f"registered tool contract changed after registration: {tool_id}")
        return tool

    def tool_ids(self) -> set[str]:
        return set(self._tools)

    def _get(self, tool_id: str) -> Tool:
        try:
            return self._tools[tool_id]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {tool_id}") from exc

    @staticmethod
    def _snapshot_spec(tool: Tool) -> ToolSpec:
        try:
            return ToolSpec.model_validate(tool.spec.model_dump(mode="python"))
        except Exception as exc:
            raise ValueError("tool does not expose a valid PAJIN ToolSpec") from exc
