import asyncio

from pydantic_ai.models.test import TestModel

from pajin.agents.pydantic_ai import PydanticAIAgentRuntime
from pajin.domain.models import AgentPlan, CampaignManifest


def test_pydantic_ai_planner_returns_typed_plan(sample_campaign: CampaignManifest) -> None:
    runtime = PydanticAIAgentRuntime(TestModel())

    plan = asyncio.run(runtime.plan(sample_campaign))

    assert isinstance(plan, AgentPlan)
    assert plan.steps
