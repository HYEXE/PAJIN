"""Worker-backed HTTP tools with mandatory egress-proxy routing."""

from __future__ import annotations

import json
from hashlib import sha256
from hmac import compare_digest

from pydantic import ConfigDict, Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_http_target,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
    decode_bounded_response_body,
    decode_strict_worker_json_object,
    host_observed_http_receipts,
    http_target_sha256,
)

MAX_HTTP_GET_RESPONSE_BYTES = 4_096
MAX_HTTP_GET_RESPONSE_BASE64_CHARS = ((MAX_HTTP_GET_RESPONSE_BYTES + 2) // 3) * 4


class _HTTPGetOutput(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    target: str = Field(min_length=1, max_length=2_000)
    status: int = Field(ge=0, le=599)
    content_type: str | None = Field(default=None, alias="contentType", max_length=1_000)
    body_preview: str | None = Field(default=None, alias="bodyPreview", max_length=4_096)
    body_sha256: str | None = Field(
        default=None,
        alias="bodySha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    response_body_base64: str | None = Field(
        default=None,
        alias="responseBodyBase64",
        max_length=MAX_HTTP_GET_RESPONSE_BASE64_CHARS,
    )
    error: str | None = Field(default=None, max_length=5_000)

    @model_validator(mode="after")
    def validate_status_shape(self) -> _HTTPGetOutput:
        if self.status == 0 and not self.error:
            raise ValueError("status 0 requires an error")
        if self.status == 0 and (
            self.body_sha256 is not None or self.response_body_base64 is not None
        ):
            raise ValueError("status 0 cannot include an HTTP response body")
        if self.status != 0 and (self.body_sha256 is None or self.response_body_base64 is None):
            raise ValueError("HTTP response status requires exact body evidence")
        if 200 <= self.status < 300 and self.error is not None:
            raise ValueError("successful status cannot include an error")
        return self


class HTTPGetTool(Tool):
    spec = ToolSpec(
        tool_id="http.get",
        version="1.0.0",
        description="Fetch an authorized HTTP(S) target through the PAJIN egress proxy",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"active-test", "http"}),
        network_access=True,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "GET":
            raise ValueError("http.get requires GET")
        return WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            stdin=json.dumps({"target": request.target}),
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
            output = _HTTPGetOutput.model_validate(
                decode_strict_worker_json_object(result, label="HTTP GET output")
            )
            if output.target != request.target:
                raise ValueError("worker output target differs from request target")
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_tool_interpretation_failure(
                    "invalid worker output",
                    exc,
                ),
            )
        success = 200 <= output.status < 300
        data = output.model_dump(mode="json", by_alias=True, exclude_none=True)
        safe_failure = (
            "redirect response was not followed"
            if 300 <= output.status < 400
            else "HTTP target was unavailable"
            if output.status == 0
            else f"HTTP status {output.status}"
        )
        if output.error is not None:
            data["error"] = safe_failure
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=success,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
            error=None if success else safe_failure,
        )

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        output = _HTTPGetOutput.model_validate(result.data)
        receipts = host_observed_http_receipts(
            worker_result,
            network_log_trusted=network_log_trusted,
        )
        if receipts is None or len(receipts) != 1:
            raise ValueError("http.get requires exactly one host-observed HTTP receipt")
        receipt = receipts[0]
        if output.response_body_base64 is None or output.body_sha256 is None:
            raise ValueError("http.get successful output lacks exact body evidence")
        body = decode_bounded_response_body(
            output.response_body_base64,
            max_bytes=MAX_HTTP_GET_RESPONSE_BYTES,
        )
        body_sha256 = sha256(body).hexdigest()
        if (
            receipt.sequence != 1
            or receipt.method != "GET"
            or receipt.target != audit_http_target(request.target)
            or receipt.target_sha256 != http_target_sha256(request.target)
            or receipt.status != output.status
            or not compare_digest(receipt.response_body_sha256, body_sha256)
            or not compare_digest(output.body_sha256, body_sha256)
            or output.body_preview != body.decode("utf-8", errors="replace")
        ):
            raise ValueError("http.get output differs from its host-observed HTTP receipt")
