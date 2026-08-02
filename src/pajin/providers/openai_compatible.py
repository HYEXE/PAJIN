"""Registered OpenAI-compatible Chat Completions Tool Adapter."""

from __future__ import annotations

import json

from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.providers.models import (
    ProviderChatRequest,
    ProviderChatResult,
    ProviderRegistration,
)
from pajin.runtime.worker import (
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
    decode_strict_worker_json_object,
)


class OpenAICompatibleChatTool(Tool):
    """Translate canonical messages to one pre-registered provider endpoint."""

    def __init__(self, registration: ProviderRegistration) -> None:
        self._registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        self.spec = ToolSpec(
            tool_id=f"provider.{self._registration.provider_id}.chat",
            version="1.0.0",
            description=(
                f"Call registered OpenAI-compatible provider {self._registration.provider_id}"
            ),
            risk_tier=ToolRiskTier.T1,
            categories=frozenset({"model-provider", "chat-completions"}),
            evidence_types=frozenset({"json", "provider-response"}),
            network_access=True,
        )

    @property
    def registration(self) -> ProviderRegistration:
        """Return a detached observation of the sealed provider registration."""

        return self._registration.model_copy(deep=True)

    def stable_execution_context(self) -> dict[str, object]:
        return {
            **self._stable_spec_context(),
            "registration": self._registration.model_dump(mode="python"),
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "POST":
            raise ValueError("provider chat calls require POST")
        target = str(self._registration.endpoint)
        if request.target != target:
            raise ValueError("provider request target differs from registered endpoint")
        chat = ProviderChatRequest.model_validate(request.arguments)
        if chat.stream and not self._registration.allow_streaming:
            raise ValueError("provider registration does not allow streaming")
        requested_tools = {tool.function.name for tool in chat.tools}
        if not requested_tools <= self._registration.allowed_function_tools:
            raise ValueError("request contains an unregistered provider function tool")
        provider_request: dict[str, object] = {
            "model": self._registration.model,
            "messages": [
                message.model_dump(mode="json", exclude_none=True) for message in chat.messages
            ],
            "stream": chat.stream,
        }
        if chat.tools:
            provider_request["tools"] = [tool.model_dump(mode="json") for tool in chat.tools]
            provider_request["tool_choice"] = chat.tool_choice
            if chat.parallel_tool_calls is not None:
                provider_request["parallel_tool_calls"] = chat.parallel_tool_calls
        if chat.max_completion_tokens is not None:
            provider_request["max_completion_tokens"] = chat.max_completion_tokens
        if chat.temperature is not None:
            provider_request["temperature"] = chat.temperature
        if chat.top_p is not None:
            provider_request["top_p"] = chat.top_p
        if chat.seed is not None:
            provider_request["seed"] = chat.seed
        if chat.response_format is not None:
            provider_request["response_format"] = chat.response_format.model_dump(
                mode="json", by_alias=True, exclude_none=True
            )
        return WorkerJob(
            image="pajin-worker:dev",
            command=["openai-chat-completion"],
            stdin=json.dumps(
                {
                    "providerId": self._registration.provider_id,
                    "target": target,
                    "request": provider_request,
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
            secret_requests=[
                WorkerSecretRequest(
                    secret_ref=self._registration.secret_ref,
                    binding="provider-api-key",
                    ttl_seconds=self._registration.lease_ttl_seconds,
                )
            ],
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
            normalized = ProviderChatResult.model_validate(
                decode_strict_worker_json_object(
                    result,
                    label="provider response",
                )
            )
            if normalized.provider_id != self._registration.provider_id:
                raise ValueError("provider response ID differs from registration")
            if normalized.model != self._registration.model:
                raise ValueError("provider response model differs from registration")
            if normalized.target != request.target:
                raise ValueError("provider response target differs from request")
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_tool_interpretation_failure(
                    "invalid provider response",
                    exc,
                ),
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=normalized.model_dump(mode="json"),
        )
