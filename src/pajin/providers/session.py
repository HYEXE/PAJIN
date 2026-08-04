"""Run-scoped Provider Gateway port for model-backed PAJIN roles."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pajin.agents.base import ModelCallFailure, StructuredModelPort
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest
from pajin.policy.capability import CapabilityError, CapabilityLedger, CapabilityRecord
from pajin.providers.models import (
    JSONSchemaDefinition,
    JSONSchemaResponseFormat,
    ProviderChatRequest,
    ProviderChatResult,
    ProviderMessage,
    ProviderRegistration,
)
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    DualModelUsageBudget,
    DualModelUsageReservation,
    ModelUsageReservation,
)
from pajin.runtime.error_safety import audit_safe_exception_type
from pajin.runtime.store import RunStore
from pajin.tools.gateway import GatewayOutcome, ToolGateway

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


@dataclass(frozen=True, slots=True)
class _ProviderCall:
    role: str
    attempt: int
    chat: ProviderChatRequest
    request: ToolRequest
    used_calls: int
    remaining_calls_before: int
    schema_name: str | None
    function_tools: tuple[str, ...]
    reservation: ModelUsageReservation | DualModelUsageReservation


class PolicyBoundProviderPort(StructuredModelPort):
    """Dispatch role model calls through ToolGateway and one attenuated capability."""

    # ProviderChatRequest contains only text and JSON. Reserving four tokens for every canonical
    # UTF-8 byte intentionally covers tokenizer/serialization expansion; the separate terms cover
    # provider-side framing that is not represented by those bytes.
    def __init__(
        self,
        *,
        registration: ProviderRegistration,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        ledger: CapabilityLedger,
        budget: BudgetController,
        gateway: ToolGateway,
        store: RunStore,
        dual_model_usage_budget: DualModelUsageBudget | None = None,
    ) -> None:
        try:
            registration_snapshot = ProviderRegistration.model_validate(
                registration.model_dump(mode="python")
            )
            campaign_snapshot = CampaignManifest.model_validate(campaign.model_dump(mode="python"))
            supplied_grant = grant.model_copy(deep=True)
        except Exception as exc:
            raise ValueError("provider session inputs are invalid") from exc
        authoritative = ledger.record(supplied_grant.grant_id).grant
        if authoritative != supplied_grant:
            raise CapabilityError("provider capability differs from the ledger authority")
        self._registration = registration_snapshot
        self._campaign = self._provider_policy_campaign(
            campaign_snapshot,
            registration_snapshot,
        )
        self._grant = authoritative.model_copy(deep=True)
        self._ledger = ledger
        self._budget = budget
        if (
            dual_model_usage_budget is not None
            and not dual_model_usage_budget.binds_campaign_budget(budget)
        ):
            raise ValueError(
                "provider dual model budget must charge the supplied Campaign budget"
            )
        self._dual_model_usage_budget = dual_model_usage_budget
        self._gateway = gateway
        self._store = store

    async def complete(
        self,
        *,
        role: str,
        attempt: int,
        messages: list[Any],
        schema_name: str,
        schema: dict[str, object],
        max_completion_tokens: int,
    ) -> ProviderChatResult:
        chat = ProviderChatRequest(
            messages=[ProviderMessage.model_validate(message) for message in messages],
            max_completion_tokens=max_completion_tokens,
            response_format=JSONSchemaResponseFormat(
                json_schema=JSONSchemaDefinition.model_validate(
                    {
                        "name": schema_name,
                        "description": f"Strict structured output for the PAJIN {role} role.",
                        "schema": schema,
                        "strict": True,
                    }
                )
            ),
        )
        return await self.chat(role=role, attempt=attempt, chat=chat)

    async def chat(
        self,
        *,
        role: str,
        attempt: int,
        chat: ProviderChatRequest,
    ) -> ProviderChatResult:
        """Dispatch one canonical chat request through the complete policy boundary."""

        call = self._prepare_call(role=role, attempt=attempt, chat=chat)
        self._record_call_started(call)
        self._consume_capability(call)
        try:
            async with asyncio.timeout(self._model_usage_remaining_seconds()):
                outcome = await self._gateway.execute(
                    self._campaign,
                    self._grant,
                    call.request,
                    used_calls=call.used_calls,
                )
        except TimeoutError as exc:
            failure = BudgetExceeded("maximum campaign duration exceeded")
            self._commit_failure_preserving_audit(
                call,
                error="maximum campaign duration exceeded during provider model call",
                original=failure,
            )
            raise failure from exc
        except asyncio.CancelledError as exc:
            self._commit_failure_preserving_audit(
                call,
                error="provider model call was cancelled after reservation",
                original=exc,
            )
            raise
        except Exception as exc:
            self._commit_failure_preserving_audit(
                call,
                error=f"provider gateway raised {audit_safe_exception_type(exc)}",
                original=exc,
            )
            raise
        return self._finalize_gateway_outcome(call, outcome)

    def _prepare_call(
        self,
        *,
        role: str,
        attempt: int,
        chat: ProviderChatRequest,
    ) -> _ProviderCall:
        try:
            chat_snapshot = ProviderChatRequest.model_validate(chat.model_dump(mode="python"))
        except Exception as exc:
            raise ModelCallFailure("provider chat request is invalid") from exc
        self._validate_chat_contract(chat_snapshot)
        audited_role = self._audit_text(role, fallback="provider-role", max_length=100)
        canonical_attempt = self._canonical_attempt(attempt)
        schema = chat_snapshot.response_format
        function_tools = tuple(tool.function.name for tool in chat_snapshot.tools)
        self._check_model_usage_calls()
        record = self._current_capability_record()
        used_calls = self._grant.max_calls - record.remaining_calls
        request = self._provider_request(chat_snapshot)
        reservation = self._reserve_model_usage(chat_snapshot)
        return _ProviderCall(
            role=audited_role,
            attempt=canonical_attempt,
            chat=chat_snapshot,
            request=request,
            used_calls=used_calls,
            remaining_calls_before=record.remaining_calls,
            schema_name=schema.json_schema.name if schema is not None else None,
            function_tools=function_tools,
            reservation=reservation,
        )

    def _validate_chat_contract(self, chat: ProviderChatRequest) -> None:
        if chat.max_completion_tokens is None:
            raise BudgetExceeded(
                "provider model calls require max_completion_tokens for budget reservation"
            )
        if chat.stream and not self._registration.allow_streaming:
            raise ModelCallFailure("provider registration does not allow streaming")
        requested_tools = {tool.function.name for tool in chat.tools}
        if not requested_tools <= self._registration.allowed_function_tools:
            raise ModelCallFailure("provider request contains an unregistered function tool")

    def _current_capability_record(self) -> CapabilityRecord:
        record = self._ledger.record(self._grant.grant_id)
        if record.grant != self._grant:
            raise CapabilityError("provider capability differs from the ledger authority")
        if (
            isinstance(record.remaining_calls, bool)
            or not isinstance(record.remaining_calls, int)
            or not 0 <= record.remaining_calls <= self._grant.max_calls
        ):
            raise CapabilityError("provider capability usage is invalid")
        if not self._ledger.can_consume(self._grant.grant_id):
            raise CapabilityError("model capability has no remaining authorized call")
        return record

    def _provider_request(self, chat: ProviderChatRequest) -> ToolRequest:
        return ToolRequest(
            agent_id=self._grant.subject,
            tool_id=f"provider.{self._registration.provider_id}.chat",
            target=str(self._registration.endpoint),
            method="POST",
            arguments=chat.model_dump(mode="json", by_alias=True),
        )

    def _record_call_started(self, call: _ProviderCall) -> None:
        try:
            self._store.append_event(
                "model.call.started",
                {
                    "role": call.role,
                    "attempt": call.attempt,
                    "agentId": self._grant.subject,
                    "providerId": self._registration.provider_id,
                    "model": self._registration.model,
                    "schema": call.schema_name,
                    "functionTools": list(call.function_tools),
                    "reservedPromptTokens": call.reservation.prompt_tokens,
                    "reservedCompletionTokens": call.reservation.completion_tokens,
                    "reservedCostUsd": call.reservation.cost_usd,
                },
            )
        except Exception:
            self._release_model_usage_reservation(call.reservation)
            raise

    def _consume_capability(self, call: _ProviderCall) -> None:
        try:
            self._ledger.consume(self._grant.grant_id)
            remaining = self._ledger.record(self._grant.grant_id).remaining_calls
            if remaining != call.remaining_calls_before - 1:
                raise CapabilityError("provider capability was not consumed exactly once")
        except Exception as exc:
            self._release_model_usage_reservation(call.reservation)
            self._record_failure_preserving(
                call,
                error="provider capability could not be consumed before dispatch",
                original=exc,
            )
            raise

    def _finalize_gateway_outcome(
        self,
        call: _ProviderCall,
        untrusted_outcome: GatewayOutcome,
    ) -> ProviderChatResult:
        try:
            outcome = GatewayOutcome.model_validate(untrusted_outcome.model_dump(mode="python"))
        except Exception as exc:
            self._commit_failed_call(call, error="provider gateway returned an invalid outcome")
            raise ModelCallFailure("provider gateway returned an invalid outcome") from exc
        contract_error = self._gateway_outcome_contract_error(call, outcome)
        if contract_error is not None:
            self._commit_failed_call(call, error=contract_error, evidence=outcome.result.evidence)
            raise ModelCallFailure(contract_error)
        if not outcome.executed:
            self._release_model_usage_reservation(call.reservation)
            error = "provider gateway did not execute the request"
            self._record_failed_call(call, error=error, evidence=outcome.result.evidence)
            raise ModelCallFailure(error)
        self._commit_model_usage_reservation(call.reservation)
        if not outcome.result.success:
            error = "provider model call failed"
            self._record_failed_call(call, error=error, evidence=outcome.result.evidence)
            raise ModelCallFailure(error)
        return self._validated_provider_result(call, outcome)

    @staticmethod
    def _gateway_outcome_contract_error(
        call: _ProviderCall,
        outcome: GatewayOutcome,
    ) -> str | None:
        result = outcome.result
        if not outcome.result_identity_valid:
            return "provider gateway could not bind the result identity"
        if result.request_id != call.request.request_id or result.tool_id != call.request.tool_id:
            return "provider gateway result identity differs from the request"
        if outcome.executed and not outcome.decision.allowed:
            return "provider gateway executed a policy-denied request"
        if result.success and (not outcome.executed or not outcome.decision.allowed):
            return "provider gateway reported an unauthorized success"
        return None

    def _validated_provider_result(
        self,
        call: _ProviderCall,
        outcome: GatewayOutcome,
    ) -> ProviderChatResult:
        try:
            result = ProviderChatResult.model_validate(outcome.result.data)
            self._validate_provider_result_binding(call, result)
            prompt_tokens, completion_tokens, total_tokens = self._validated_usage(result)
        except ValueError as exc:
            failure = self._provider_result_failure_message(exc)
            self._record_failed_call(
                call,
                error=failure,
                evidence=outcome.result.evidence,
            )
            raise ModelCallFailure(failure) from exc
        reported_cost = (
            prompt_tokens * self._registration.input_cost_per_million_usd
            + completion_tokens * self._registration.output_cost_per_million_usd
        ) / 1_000_000
        self._record_completed_call(
            call,
            result,
            outcome,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            reported_cost=reported_cost,
        )
        return result

    def _validate_provider_result_binding(
        self,
        call: _ProviderCall,
        result: ProviderChatResult,
    ) -> None:
        if result.provider_id != self._registration.provider_id:
            raise ValueError("provider result ID differs from the registration")
        if result.model != self._registration.model:
            raise ValueError("provider result model differs from the registration")
        if result.target != call.request.target:
            raise ValueError("provider result target differs from the sealed request")
        if result.streamed != call.chat.stream:
            raise ValueError("provider result streaming mode differs from the request")
        if not 1 <= len(result.response_id) <= 500 or not 1 <= len(result.model) <= 200:
            raise ValueError("provider result identity exceeds its audit bound")
        requested_tools = set(call.function_tools)
        if any(tool.name not in requested_tools for tool in result.tool_calls):
            raise ValueError("provider returned an undeclared function tool call")

    @staticmethod
    def _validated_usage(result: ProviderChatResult) -> tuple[int, int, int]:
        usage = result.usage
        if (
            usage is None
            or usage.prompt_tokens is None
            or usage.completion_tokens is None
            or usage.total_tokens is None
        ):
            raise ValueError("provider model call did not return complete token usage")
        prompt_tokens = usage.prompt_tokens
        completion_tokens = usage.completion_tokens
        total_tokens = usage.total_tokens
        if total_tokens != prompt_tokens + completion_tokens:
            raise ValueError("provider token usage totals are inconsistent")
        return prompt_tokens, completion_tokens, total_tokens

    @staticmethod
    def _provider_result_failure_message(error: ValueError) -> str:
        detail = str(error)
        public_errors = {
            "provider model call did not return complete token usage",
            "provider token usage totals are inconsistent",
        }
        if detail in public_errors:
            return detail
        return "provider model call returned an invalid result"

    def _reserve_model_usage(
        self,
        chat: ProviderChatRequest,
    ) -> ModelUsageReservation | DualModelUsageReservation:
        bound = provider_model_usage_upper_bound(self._registration, chat)
        if self._dual_model_usage_budget is not None:
            return self._dual_model_usage_budget.reserve_model_usage(
                prompt_tokens=bound.prompt_tokens,
                completion_tokens=bound.completion_tokens,
                cost_usd=bound.cost_usd,
            )
        return self._budget.reserve_model_usage(
            prompt_tokens=bound.prompt_tokens,
            completion_tokens=bound.completion_tokens,
            cost_usd=bound.cost_usd,
        )

    def _model_usage_remaining_seconds(self) -> float:
        if self._dual_model_usage_budget is not None:
            return self._dual_model_usage_budget.remaining_seconds
        return self._budget.remaining_seconds

    def _check_model_usage_calls(self) -> None:
        if self._dual_model_usage_budget is not None:
            self._dual_model_usage_budget.check_tool_call()
            self._dual_model_usage_budget.check_model_call()
            return
        self._budget.check_tool_call()
        self._budget.check_model_call()

    def _commit_model_usage_reservation(
        self,
        reservation: ModelUsageReservation | DualModelUsageReservation,
    ) -> None:
        if isinstance(reservation, DualModelUsageReservation):
            if self._dual_model_usage_budget is None:
                raise ValueError("provider dual model reservation has no budget authority")
            self._dual_model_usage_budget.commit_model_usage_reservation(reservation)
            return
        if self._dual_model_usage_budget is not None:
            raise ValueError("provider Campaign-only reservation bypasses its dual budget")
        self._budget.commit_model_usage_reservation(reservation)

    def _release_model_usage_reservation(
        self,
        reservation: ModelUsageReservation | DualModelUsageReservation,
    ) -> None:
        if isinstance(reservation, DualModelUsageReservation):
            if self._dual_model_usage_budget is None:
                raise ValueError("provider dual model reservation has no budget authority")
            self._dual_model_usage_budget.release_model_usage_reservation(reservation)
            return
        if self._dual_model_usage_budget is not None:
            raise ValueError("provider Campaign-only reservation bypasses its dual budget")
        self._budget.release_model_usage_reservation(reservation)

    def _prompt_token_upper_bound(self, chat: ProviderChatRequest) -> int:
        """Return a deliberately over-reserved prompt bound for the complete provider contract."""

        return provider_model_usage_upper_bound(self._registration, chat).prompt_tokens

    def _record_completed_call(
        self,
        call: _ProviderCall,
        result: ProviderChatResult,
        outcome: GatewayOutcome,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        reported_cost: float,
    ) -> None:
        self._store.append_event(
            "model.call.completed",
            {
                "role": call.role,
                "attempt": call.attempt,
                "agentId": self._grant.subject,
                "providerId": self._registration.provider_id,
                "model": self._registration.model,
                "reportedModel": result.model,
                "responseId": result.response_id,
                "promptTokens": prompt_tokens,
                "completionTokens": completion_tokens,
                "totalTokens": total_tokens,
                "costUsd": reported_cost,
                "usageTrust": "provider-reported-untrusted",
                "chargedPromptTokens": call.reservation.prompt_tokens,
                "chargedCompletionTokens": call.reservation.completion_tokens,
                "chargedCostUsd": call.reservation.cost_usd,
                "evidence": self._bounded_evidence(outcome.result.evidence),
            },
        )

    def _commit_failed_call(
        self,
        call: _ProviderCall,
        *,
        error: str | None,
        evidence: list[str] | None = None,
    ) -> None:
        self._commit_model_usage_reservation(call.reservation)
        self._record_failed_call(call, error=error, evidence=evidence)

    def _commit_failure_preserving_audit(
        self,
        call: _ProviderCall,
        *,
        error: str,
        original: BaseException,
    ) -> None:
        self._commit_model_usage_reservation(call.reservation)
        try:
            self._record_failed_call(call, error=error)
        except Exception as audit_error:
            original.add_note(
                f"provider failure audit also failed: {audit_safe_exception_type(audit_error)}"
            )

    def _record_failed_call(
        self,
        call: _ProviderCall,
        *,
        error: str | None,
        evidence: list[str] | None = None,
    ) -> None:
        self._store.append_event(
            "model.call.failed",
            {
                "role": call.role,
                "attempt": call.attempt,
                "agentId": self._grant.subject,
                "error": self._audit_text(error, fallback="provider call failed"),
                "evidence": self._bounded_evidence(evidence),
            },
        )

    def _record_failure_preserving(
        self,
        call: _ProviderCall,
        *,
        error: str,
        original: Exception,
    ) -> None:
        try:
            self._record_failed_call(call, error=error)
        except Exception as audit_error:
            original.add_note(
                f"provider failure audit also failed: {audit_safe_exception_type(audit_error)}"
            )

    @staticmethod
    def _canonical_attempt(attempt: int) -> int:
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise ValueError("provider call attempt must be a positive integer")
        return attempt

    @staticmethod
    def _audit_text(
        value: object,
        *,
        fallback: str,
        max_length: int = 500,
    ) -> str:
        if not isinstance(value, str):
            return fallback
        text = value.encode("utf-8", errors="replace").decode("utf-8")
        text = "".join(character if character >= " " else " " for character in text).strip()
        return text[:max_length] or fallback

    @classmethod
    def _bounded_evidence(cls, evidence: list[str] | None) -> list[str]:
        return [
            cls._audit_text(item, fallback="invalid-evidence", max_length=1_000)
            for item in (evidence or [])[:100]
        ]

    def record_fallback(self, *, role: str, reason: str) -> None:
        # ``reason`` originates at a model/provider exception boundary.  It is
        # intentionally not trusted even when the current in-tree caller already
        # supplies a secret-free classification.
        del reason
        self._store.append_event(
            "model.fallback.activated",
            {
                "role": self._audit_text(role, fallback="provider-role", max_length=100),
                "agentId": self._grant.subject,
                "reason": "provider role output failed; deterministic fallback activated",
            },
        )

    @staticmethod
    def _provider_policy_campaign(
        campaign: CampaignManifest,
        registration: ProviderRegistration,
    ) -> CampaignManifest:
        endpoint = str(registration.endpoint)
        allow = [endpoint]
        if registration.endpoint.scheme == "https":
            parsed = urlsplit(endpoint)
            allow.append(urlunsplit((parsed.scheme, parsed.netloc, "/**", "", "")))
        scope = campaign.spec.scope.model_copy(update={"allow": allow, "deny": []})
        rules = campaign.spec.rules_of_engagement.model_copy(
            update={
                "allowed_methods": {"POST"},
                "allow_private_networks": registration.allow_private_networks,
            }
        )
        spec = campaign.spec.model_copy(update={"scope": scope, "rules_of_engagement": rules})
        policy_campaign = campaign.model_copy(update={"spec": spec})
        return CampaignManifest.model_validate(policy_campaign.model_dump(mode="python"))
