"""Pure conservative Provider usage bounds shared by planning and receipts."""

from __future__ import annotations

import json
from dataclasses import dataclass

from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.runtime.control import BudgetExceeded

_PROMPT_CANONICAL_BYTE_TOKEN_FACTOR = 4
_PROMPT_BASE_FRAMING_TOKENS = 1_024
_PROMPT_MESSAGE_FRAMING_TOKENS = 64
_PROMPT_TOOL_FRAMING_TOKENS = 256
_PROMPT_ASSISTANT_TOOL_CALL_FRAMING_TOKENS = 64
_PROMPT_RESPONSE_FORMAT_FRAMING_TOKENS = 512


@dataclass(frozen=True, slots=True)
class ProviderModelUsageBound:
    """Conservative pre-dispatch usage bound shared by governed model callers."""

    prompt_tokens: int
    completion_tokens: int
    cost_usd: float


def provider_model_usage_upper_bound(
    registration: ProviderRegistration,
    chat: ProviderChatRequest,
) -> ProviderModelUsageBound:
    """Return the exact conservative bound used by ``PolicyBoundProviderPort``."""

    canonical_registration = ProviderRegistration.model_validate(
        registration.model_dump(mode="python")
    )
    canonical_chat = ProviderChatRequest.model_validate(chat.model_dump(mode="python"))
    max_completion_tokens = canonical_chat.max_completion_tokens
    if max_completion_tokens is None:
        raise BudgetExceeded(
            "provider model calls require max_completion_tokens for budget reservation"
        )
    canonical_request_bytes = json.dumps(
        {
            "model": canonical_registration.model,
            "request": canonical_chat.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    assistant_tool_calls = sum(len(message.tool_calls) for message in canonical_chat.messages)
    framing_tokens = (
        _PROMPT_BASE_FRAMING_TOKENS
        + len(canonical_chat.messages) * _PROMPT_MESSAGE_FRAMING_TOKENS
        + len(canonical_chat.tools) * _PROMPT_TOOL_FRAMING_TOKENS
        + assistant_tool_calls * _PROMPT_ASSISTANT_TOOL_CALL_FRAMING_TOKENS
        + (
            _PROMPT_RESPONSE_FORMAT_FRAMING_TOKENS
            if canonical_chat.response_format is not None
            else 0
        )
    )
    prompt_tokens = (
        len(canonical_request_bytes) * _PROMPT_CANONICAL_BYTE_TOKEN_FACTOR + framing_tokens
    )
    cost_usd = (
        prompt_tokens * canonical_registration.input_cost_per_million_usd
        + max_completion_tokens * canonical_registration.output_cost_per_million_usd
    ) / 1_000_000
    return ProviderModelUsageBound(
        prompt_tokens=prompt_tokens,
        completion_tokens=max_completion_tokens,
        cost_usd=cost_usd,
    )
