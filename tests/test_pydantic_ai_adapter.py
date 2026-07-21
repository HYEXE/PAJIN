import asyncio

import pytest
from pydantic_ai.models.test import TestModel

import pajin.agents.pydantic_ai as pydantic_ai_adapter
from pajin.agents.pydantic_ai import PydanticAIAgentRuntime
from pajin.domain.models import AgentPlan, CampaignManifest


class _TestModelSubclass(TestModel):
    pass


def test_pydantic_ai_planner_returns_typed_plan(sample_campaign: CampaignManifest) -> None:
    runtime = PydanticAIAgentRuntime(TestModel())

    plan = asyncio.run(runtime.plan(sample_campaign))

    assert isinstance(plan, AgentPlan)
    assert plan.steps


def test_pydantic_ai_adapter_rejects_network_model_before_agent_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_constructed = False

    def fail_if_agent_is_constructed(*args: object, **kwargs: object) -> None:
        del args, kwargs
        nonlocal agent_constructed
        agent_constructed = True
        raise AssertionError("unsafe model reached PydanticAI Agent construction")

    monkeypatch.setattr(pydantic_ai_adapter, "Agent", fail_if_agent_is_constructed)

    with pytest.raises(TypeError, match="ProviderAgentRuntime"):
        PydanticAIAgentRuntime("openai:gpt-4o-mini")

    assert agent_constructed is False


def test_pydantic_ai_adapter_rejects_test_model_subclasses() -> None:
    with pytest.raises(TypeError, match="exact PydanticAI TestModel"):
        PydanticAIAgentRuntime(_TestModelSubclass())
