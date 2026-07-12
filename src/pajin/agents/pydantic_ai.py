"""Optional PydanticAI adapter for model-backed planning and validation."""

from __future__ import annotations

import json

from pydantic_ai import Agent, UsageLimits
from pydantic_ai.models import KnownModelName, Model

from pajin.domain.models import AgentPlan, CampaignManifest, Finding, ToolResult


class PydanticAIAgentRuntime:
    """Use PydanticAI while keeping PAJIN's domain state outside the framework."""

    agent_id = "agent:planner-pydantic-ai"

    def __init__(self, model: Model | KnownModelName | str) -> None:
        self._planner = Agent(
            model,
            name="pajin_planner",
            instructions=(
                "Create a minimal security validation plan. Use only the supplied target, scope, "
                "and mock.agent-probe tool. Every ToolRequest agent_id must be "
                "'agent:planner-pydantic-ai'. Never invent authorization or additional targets."
            ),
            output_type=AgentPlan,
        )
        self._validator = Agent(
            model,
            name="pajin_validator",
            instructions=(
                "Independently assess the supplied tool results. Return findings only when direct "
                "evidence demonstrates the issue. Mark confirmed findings as validated."
            ),
            output_type=list[Finding],
        )

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        result = await self._planner.run(
            campaign.model_dump_json(by_alias=True),
            usage_limits=UsageLimits(request_limit=5, tool_calls_limit=0),
        )
        return result.output

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        payload = {
            "campaign": campaign.model_dump(mode="json", by_alias=True),
            "plan": plan.model_dump(mode="json"),
            "results": [result.model_dump(mode="json") for result in results],
        }
        result = await self._validator.run(
            json.dumps(payload),
            usage_limits=UsageLimits(request_limit=5, tool_calls_limit=0),
        )
        return result.output
