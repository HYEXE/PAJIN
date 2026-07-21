"""Canonicalize host Worker receipts and project them into trusted Tool results.

This module owns the pure execution-output boundary.  It validates the host
receipt against the sealed Worker job, removes leased secret material, decides
whether network observations have host provenance, and gives Tool adapters a
bounded canonical result to interpret.  Event ordering and durable writes stay
in :mod:`pajin.tools.gateway`.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import cast

from pajin.domain.models import ToolRequest, ToolResult
from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.secrets import (
    SecretBroker,
    SecretMaterial,
    redact_text,
    redact_value,
)
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import Tool

_MAX_GATEWAY_ERROR_BYTES = 16_384
_MAX_TOOL_RESULT_JSON_BYTES = 10_000_000
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 100_000
_SAFE_TOOL_RESULT_CONTRACT_DETAILS = frozenset(
    {
        "Tool returned a malformed result model",
        "Tool result identity differs from its request",
        "Tool result timestamps are not comparable",
        "Tool result finished_at precedes started_at",
        "successful Tool result cannot include an error",
        "failed Tool result requires a non-empty error",
        "Tool Adapter cannot inject evidence references",
        "Tool result is not strict canonical JSON",
        "Tool result exceeds the bounded canonical JSON size",
    }
)


@dataclass(frozen=True)
class NormalizedHostReceipt:
    """One Worker receipt rebound to the sealed job and scrubbed of secrets."""

    worker_result: WorkerResult
    network_log_trusted: bool
    redaction_failed: bool


@dataclass(frozen=True)
class ToolReceiptProjection:
    """Canonical Tool result derived from one normalized host receipt."""

    result: ToolResult
    result_identity_valid: bool


@dataclass
class _StrictJSONWalker:
    """Validate an already-decoded object graph without coercing Python values."""

    label: str
    active_containers: set[int]
    node_count: int = 0

    def visit(self, item: object, *, depth: int = 0) -> None:
        self._count_node(depth)
        if item is None or type(item) is bool:
            return
        if type(item) is str:
            self._validate_text(item)
            return
        if type(item) is int:
            self._validate_integer(item)
            return
        if type(item) is float:
            self._validate_float(item)
            return
        if type(item) is list:
            self._visit_list(cast(list[object], item), depth=depth)
            return
        if type(item) is dict:
            self._visit_object(cast(dict[object, object], item), depth=depth)
            return
        raise ValueError(f"{self.label} contains a non-JSON value")

    def _count_node(self, depth: int) -> None:
        self.node_count += 1
        if self.node_count > _MAX_JSON_NODES:
            raise ValueError(f"{self.label} exceeds the JSON node-count limit")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError(f"{self.label} exceeds the JSON nesting-depth limit")

    def _visit_list(self, item: list[object], *, depth: int) -> None:
        self._visit_container(item, depth=depth, values=item)

    def _visit_object(self, item: dict[object, object], *, depth: int) -> None:
        for key in item:
            self._count_node(depth + 1)
            if type(key) is not str:
                raise ValueError(f"{self.label} object keys must be strings")
            self._validate_text(key)
        self._visit_container(item, depth=depth, values=item.values())

    def _visit_container(
        self,
        item: list[object] | dict[object, object],
        *,
        depth: int,
        values: Iterable[object],
    ) -> None:
        identity = id(item)
        if identity in self.active_containers:
            raise ValueError(f"{self.label} cannot contain cycles")
        self.active_containers.add(identity)
        try:
            for nested in values:
                self.visit(nested, depth=depth + 1)
        finally:
            self.active_containers.remove(identity)

    def _validate_text(self, value: str) -> None:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{self.label} contains invalid UTF-8 text") from exc

    def _validate_integer(self, value: int) -> None:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError(f"{self.label} integer is outside the signed 64-bit range")

    def _validate_float(self, value: float) -> None:
        if not math.isfinite(value):
            raise ValueError(f"{self.label} numbers must be finite")


def validate_strict_json(value: object, *, label: str) -> None:
    """Validate a decoded value as bounded canonical JSON without coercion."""

    _StrictJSONWalker(label=label, active_containers=set()).visit(value)


def normalize_host_receipt(
    *,
    backend: WorkerBackend,
    job: WorkerJob,
    result: WorkerResult,
    materials: list[SecretMaterial],
) -> NormalizedHostReceipt:
    """Bind a Worker result to its job, redact it, and classify host provenance."""

    try:
        normalized = _validate_worker_result(job, result)
    except ValueError:
        normalized = _contract_failed_worker_result(
            job,
            "worker result contract validation failed",
        )
        return NormalizedHostReceipt(
            worker_result=normalized,
            network_log_trusted=False,
            redaction_failed=False,
        )
    try:
        normalized = redact_worker_result(normalized, materials, job)
    except Exception:
        normalized = _contract_failed_worker_result(
            job,
            "worker result redaction failed",
        )
        return NormalizedHostReceipt(
            worker_result=normalized,
            network_log_trusted=False,
            redaction_failed=True,
        )
    return NormalizedHostReceipt(
        worker_result=normalized,
        network_log_trusted=host_network_log_is_trusted(backend, job, normalized),
        redaction_failed=False,
    )


def project_tool_result(
    *,
    request: ToolRequest,
    tool: Tool,
    receipt: NormalizedHostReceipt,
    materials: list[SecretMaterial],
) -> ToolReceiptProjection:
    """Interpret a normalized receipt and return one canonical, redacted Tool result."""

    worker_result = receipt.worker_result
    candidate, adapter_provided = _interpret_worker_result(
        request,
        tool,
        worker_result,
        redaction_failed=receipt.redaction_failed,
    )
    result, identity_valid, contract_valid = _validated_result_or_failure(request, candidate)
    if adapter_provided and contract_valid:
        result = _without_adapter_error_detail(result, worker_result)
    if result.success and worker_result.status is not WorkerStatus.SUCCEEDED:
        result = failed_tool_result(
            request,
            "Tool Adapter cannot report success for an unsuccessful Worker execution",
        )
    result, trusted_identity = _validate_trusted_result(
        request,
        tool,
        worker_result,
        result,
        network_log_trusted=receipt.network_log_trusted,
    )
    identity_valid = identity_valid and trusted_identity
    try:
        result = _redact_tool_result(result, materials)
    except Exception:
        result = failed_tool_result(request, "tool result redaction failed")
    result, redacted_identity, _ = _validated_result_or_failure(request, result)
    return ToolReceiptProjection(
        result=result,
        result_identity_valid=identity_valid and redacted_identity,
    )


def _interpret_worker_result(
    request: ToolRequest,
    tool: Tool,
    worker_result: WorkerResult,
    *,
    redaction_failed: bool,
) -> tuple[object, bool]:
    if redaction_failed:
        return failed_tool_result(request, "worker result redaction failed"), False
    if worker_result.status is WorkerStatus.SUCCEEDED and (
        worker_result.stdout_truncated or worker_result.stderr_truncated
    ):
        return (
            failed_tool_result(
                request,
                "successful Worker output was truncated and cannot be trusted",
            ),
            False,
        )
    try:
        candidate = tool.interpret(
            request.model_copy(deep=True),
            worker_result.model_copy(deep=True),
        )
    except Exception as exc:
        return (
            failed_tool_result(
                request,
                "tool result interpretation failed; "
                + audit_safe_exception_diagnostic(exc, stage="tool-interpretation"),
            ),
            False,
        )
    return candidate, True


def _without_adapter_error_detail(
    result: ToolResult,
    worker_result: WorkerResult,
) -> ToolResult:
    """Keep authoritative transcripts while dropping their diagnostic copies."""

    if result.success:
        return result
    if worker_result.status is WorkerStatus.SUCCEEDED:
        error = "Tool Adapter rejected the Worker result"
    else:
        error = f"Worker execution did not succeed (status={worker_result.status.value})"
    return result.model_copy(update={"error": error}, deep=True)


def _validated_result_or_failure(
    request: ToolRequest,
    candidate: object,
) -> tuple[ToolResult, bool, bool]:
    try:
        return _validate_tool_result(request, candidate), True, True
    except ValueError as exc:
        identity_valid = not isinstance(candidate, ToolResult) or (
            candidate.request_id == request.request_id and candidate.tool_id == request.tool_id
        )
        detail = str(exc)
        if detail not in _SAFE_TOOL_RESULT_CONTRACT_DETAILS:
            detail = "Tool result contract is invalid"
        return (
            failed_tool_result(
                request,
                f"tool result contract validation failed: {detail}",
            ),
            identity_valid,
            False,
        )


def _validate_trusted_result(
    request: ToolRequest,
    tool: Tool,
    worker_result: WorkerResult,
    result: ToolResult,
    *,
    network_log_trusted: bool,
) -> tuple[ToolResult, bool]:
    if not result.success:
        return result, True
    try:
        tool.validate_trusted_execution(
            request.model_copy(deep=True),
            result.model_copy(deep=True),
            worker_result.model_copy(deep=True),
            network_log_trusted=network_log_trusted,
        )
    except Exception as exc:
        return (
            failed_tool_result(
                request,
                "trusted execution validation failed; "
                + audit_safe_exception_diagnostic(
                    exc,
                    stage="trusted-execution-validation",
                ),
            ),
            True,
        )
    validated, identity_valid, _ = _validated_result_or_failure(request, result)
    return validated, identity_valid


def host_network_log_is_trusted(
    backend: WorkerBackend,
    job: WorkerJob | None,
    worker_result: WorkerResult | None,
) -> bool:
    """Trust proxy logs only when the host-owned Docker backend captured them."""

    return (
        type(backend) is DockerWorkerBackend
        and job is not None
        and job.network is NetworkMode.EGRESS_PROXY
        and worker_result is not None
        and worker_result.backend == DockerWorkerBackend.name
    )


def _validate_worker_result(job: WorkerJob, result: object) -> WorkerResult:
    try:
        result = WorkerResult.model_validate(result.model_dump())  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Worker returned a malformed result model") from exc
    if result.execution_id != job.execution_id:
        raise ValueError("Worker result execution identity differs from its job")
    return result


def _validate_tool_result(request: ToolRequest, result: object) -> ToolResult:
    try:
        result = ToolResult.model_validate(result.model_dump())  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Tool returned a malformed result model") from exc
    if result.request_id != request.request_id or result.tool_id != request.tool_id:
        raise ValueError("Tool result identity differs from its request")
    try:
        timestamps_reversed = result.finished_at < result.started_at
    except TypeError as exc:
        raise ValueError("Tool result timestamps are not comparable") from exc
    if timestamps_reversed:
        raise ValueError("Tool result finished_at precedes started_at")
    if result.success and result.error is not None:
        raise ValueError("successful Tool result cannot include an error")
    if not result.success and (result.error is None or not result.error.strip()):
        raise ValueError("failed Tool result requires a non-empty error")
    if result.evidence:
        raise ValueError("Tool Adapter cannot inject evidence references")
    try:
        validate_strict_json(result.data, label="Tool result data")
        serialized = json.dumps(
            result.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise ValueError("Tool result is not strict canonical JSON") from exc
    if len(serialized) > _MAX_TOOL_RESULT_JSON_BYTES:
        raise ValueError("Tool result exceeds the bounded canonical JSON size")
    return result.model_copy(deep=True)


def safe_job_metadata(
    request: ToolRequest,
    job: WorkerJob,
    *,
    lease_ids: list[str] | None = None,
) -> dict[str, object]:
    """Project a Worker job into non-secret host audit metadata."""

    stdin_bytes = job.stdin.encode("utf-8")
    return {
        "requestId": request.request_id,
        "executionId": job.execution_id,
        "image": job.image,
        "command": job.command,
        "network": job.network.value,
        "egressPolicy": (job.egress_policy.model_dump(mode="json") if job.egress_policy else None),
        "limits": job.limits.model_dump(mode="json"),
        "stdinBytes": len(stdin_bytes),
        "stdinSha256": sha256(stdin_bytes).hexdigest(),
        "secretRequests": [
            {
                "binding": item.binding,
                "secretRefFingerprint": SecretBroker.fingerprint(item.secret_ref),
                "ttlSeconds": item.ttl_seconds,
            }
            for item in job.secret_requests
        ],
        "secretLeaseIds": lease_ids or [],
    }


def _contract_failed_worker_result(job: WorkerJob, error: str) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id=job.execution_id,
        backend="backend-error",
        status=WorkerStatus.FAILED,
        exit_code=None,
        stderr=error,
        started_at=now,
        finished_at=now,
    )


def redact_worker_result(
    result: WorkerResult,
    materials: list[SecretMaterial],
    job: WorkerJob,
) -> WorkerResult:
    """Redact and jointly bound all untrusted Worker transcript channels."""

    stdout = redact_text(result.stdout, materials) if materials else result.stdout
    stderr = redact_text(result.stderr, materials) if materials else result.stderr
    network_log = redact_text(result.network_log, materials) if materials else result.network_log
    total_limit = job.limits.stdout_bytes + job.limits.stderr_bytes
    stdout, stdout_truncated = bound_utf8(
        stdout,
        min(job.limits.stdout_bytes, total_limit),
    )
    remaining = total_limit - len(stdout.encode("utf-8"))
    stderr, stderr_truncated = bound_utf8(
        stderr,
        min(job.limits.stderr_bytes, remaining),
    )
    remaining -= len(stderr.encode("utf-8"))
    network_log, network_log_truncated = bound_utf8(
        network_log,
        min(job.limits.stderr_bytes, remaining),
    )
    if network_log_truncated:
        # A prefix of proxy events is not a complete host observation. Drop it
        # rather than allowing a syntactically complete prefix to be trusted.
        network_log = ""
    return WorkerResult.model_validate(
        result.model_copy(
            update={
                "stdout": stdout,
                "stderr": stderr,
                "network_log": network_log,
                "stdout_truncated": result.stdout_truncated or stdout_truncated,
                "stderr_truncated": (
                    result.stderr_truncated or stderr_truncated or network_log_truncated
                ),
            }
        ).model_dump()
    )


def bound_utf8(value: str, byte_limit: int) -> tuple[str, bool]:
    """Bound text by encoded UTF-8 bytes without returning an invalid suffix."""

    encoded = value.encode("utf-8")
    if len(encoded) <= byte_limit:
        return value, False
    return encoded[:byte_limit].decode("utf-8", errors="ignore"), True


def _redact_tool_result(
    result: ToolResult,
    materials: list[SecretMaterial],
) -> ToolResult:
    if not materials:
        return result
    return result.model_copy(
        update={
            "data": redact_value(result.data, materials),
            "error": redact_text(result.error, materials) if result.error else None,
        },
        deep=True,
    )


def failed_tool_result(request: ToolRequest, error: str) -> ToolResult:
    """Build one bounded Gateway-owned failure result."""

    now = datetime.now(UTC)
    try:
        error, _ = bound_utf8(error, _MAX_GATEWAY_ERROR_BYTES)
    except (AttributeError, UnicodeEncodeError):
        error = "Gateway failure diagnostic could not be represented safely"
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=False,
        started_at=now,
        finished_at=now,
        error=error,
    )
