"""Run-scoped Provider Gateway port for model-backed PAJIN roles."""

from __future__ import annotations

from typing import Any

from pajin.agents.base import ModelCallFailure, StructuredModelPort
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.providers.models import (
    JSONSchemaDefinition,
    JSONSchemaResponseFormat,
    ProviderChatRequest,
    ProviderChatResult,
    ProviderMessage,
    ProviderRegistration,
)
from pajin.runtime.control import BudgetController
from pajin.runtime.store import RunStore
from pajin.tools.gateway import ToolGateway


class PolicyBoundProviderPort(StructuredModelPort):
    """Dispatch role model calls through ToolGateway and one attenuated capability."""

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
    ) -> None:
        self._registration = registration
        self._campaign = self._provider_policy_campaign(campaign, registration)
        self._grant = grant
        self._ledger = ledger
        self._budget = budget
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

        self._budget.check_tool_call()
        self._budget.check_model_call()
        if not self._ledger.can_consume(self._grant.grant_id):
            raise CapabilityError("model capability has no remaining authorized call")
        request = ToolRequest(
            agent_id=self._grant.subject,
            tool_id=f"provider.{self._registration.provider_id}.chat",
            target=str(self._registration.endpoint),
            method="POST",
            arguments=chat.model_dump(mode="json", by_alias=True),
        )
        used_calls = (
            self._grant.max_calls - self._ledger.record(self._grant.grant_id).remaining_calls
        )
        schema_name = (
            chat.response_format.json_schema.name if chat.response_format is not None else None
        )
        self._store.append_event(
            "model.call.started",
            {
                "role": role,
                "attempt": attempt,
                "agentId": self._grant.subject,
                "providerId": self._registration.provider_id,
                "model": self._registration.model,
                "schema": schema_name,
                "functionTools": [tool.function.name for tool in chat.tools],
            },
        )
        outcome = await self._gateway.execute(
            self._campaign,
            self._grant,
            request,
            used_calls=used_calls,
        )
        if outcome.executed:
            self._ledger.consume(self._grant.grant_id)
            self._budget.record_tool_call()
            self._budget.record_model_call()
        if not outcome.result.success:
            self._store.append_event(
                "model.call.failed",
                {
                    "role": role,
                    "attempt": attempt,
                    "agentId": self._grant.subject,
                    "error": outcome.result.error,
                    "evidence": outcome.result.evidence,
                },
            )
            raise ModelCallFailure(outcome.result.error or "provider model call failed")
        result = ProviderChatResult.model_validate(outcome.result.data)
        usage = result.usage
        if (
            usage is None
            or usage.prompt_tokens is None
            or usage.completion_tokens is None
            or usage.total_tokens is None
        ):
            raise ModelCallFailure("provider model call did not return complete token usage")
        if usage.total_tokens != usage.prompt_tokens + usage.completion_tokens:
            raise ModelCallFailure("provider token usage totals are inconsistent")
        cost = (
            usage.prompt_tokens * self._registration.input_cost_per_million_usd
            + usage.completion_tokens * self._registration.output_cost_per_million_usd
        ) / 1_000_000
        self._budget.record_model_usage(
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            cost_usd=cost,
        )
        self._store.append_event(
            "model.call.completed",
            {
                "role": role,
                "attempt": attempt,
                "agentId": self._grant.subject,
                "providerId": result.provider_id,
                "model": result.model,
                "responseId": result.response_id,
                "promptTokens": usage.prompt_tokens,
                "completionTokens": usage.completion_tokens,
                "totalTokens": usage.total_tokens,
                "costUsd": cost,
                "evidence": outcome.result.evidence,
            },
        )
        return result

    def record_fallback(self, *, role: str, reason: str) -> None:
        self._store.append_event(
            "model.fallback.activated",
            {
                "role": role,
                "agentId": self._grant.subject,
                "reason": reason[:500],
            },
        )

    @staticmethod
    def _provider_policy_campaign(
        campaign: CampaignManifest,
        registration: ProviderRegistration,
    ) -> CampaignManifest:
        scope = campaign.spec.scope.model_copy(
            update={"allow": [str(registration.endpoint)], "deny": []}
        )
        rules = campaign.spec.rules_of_engagement.model_copy(
            update={
                "allowed_methods": {"POST"},
                "allow_private_networks": registration.allow_private_networks,
            }
        )
        spec = campaign.spec.model_copy(update={"scope": scope, "rules_of_engagement": rules})
        return campaign.model_copy(update={"spec": spec})
