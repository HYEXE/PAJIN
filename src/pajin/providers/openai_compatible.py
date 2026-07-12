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
from pajin.tools.base import Tool, ToolSpec


class OpenAICompatibleChatTool(Tool):
    """Translate canonical messages to one pre-registered provider endpoint."""

    def __init__(self, registration: ProviderRegistration) -> None:
        self.registration = registration
        self.spec = ToolSpec(
            tool_id=f"provider.{registration.provider_id}.chat",
            version="1.0.0",
            description=(f"Call registered OpenAI-compatible provider {registration.provider_id}"),
            risk_tier=ToolRiskTier.T1,
            categories={"model-provider", "chat-completions"},
            evidence_types={"json", "provider-response"},
            network_access=True,
        )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "POST":
            raise ValueError("provider chat calls require POST")
        target = str(self.registration.endpoint)
        if request.target != target:
            raise ValueError("provider request target differs from registered endpoint")
        chat = ProviderChatRequest.model_validate(request.arguments)
        if chat.stream and not self.registration.allow_streaming:
            raise ValueError("provider registration does not allow streaming")
        requested_tools = {tool.function.name for tool in chat.tools}
        if not requested_tools <= self.registration.allowed_function_tools:
            raise ValueError("request contains an unregistered provider function tool")
        provider_request: dict[str, object] = {
            "model": self.registration.model,
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
        if chat.response_format is not None:
            provider_request["response_format"] = chat.response_format.model_dump(
                mode="json", by_alias=True, exclude_none=True
            )
        return WorkerJob(
            image="pajin-worker:dev",
            command=["openai-chat-completion"],
            stdin=json.dumps(
                {
                    "providerId": self.registration.provider_id,
                    "target": target,
                    "request": provider_request,
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
            secret_requests=[
                WorkerSecretRequest(
                    secret_ref=self.registration.secret_ref,
                    binding="provider-api-key",
                    ttl_seconds=self.registration.lease_ttl_seconds,
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
                error=f"worker {result.status.value}: {result.stderr or 'no error detail'}",
            )
        try:
            normalized = ProviderChatResult.model_validate_json(result.stdout)
            if normalized.provider_id != self.registration.provider_id:
                raise ValueError("provider response ID differs from registration")
            if normalized.target != request.target:
                raise ValueError("provider response target differs from request")
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=f"invalid provider response: {exc}",
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=normalized.model_dump(mode="json"),
        )
