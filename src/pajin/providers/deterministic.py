"""Deterministic provider validation plan for local and CI checks."""

from __future__ import annotations

from pajin.domain.models import AgentPlan, CampaignManifest, PlannedStep, ToolRequest
from pajin.providers.models import (
    FunctionDefinition,
    FunctionTool,
    ProviderChatRequest,
    ProviderMessage,
    ProviderRegistration,
)
from pajin.tools.ai import ChatRole


class ProviderValidationPlanner:
    def __init__(self, registration: ProviderRegistration) -> None:
        self._registration = registration

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        target = campaign.spec.targets[0]
        if target.endpoint != str(self._registration.endpoint):
            raise ValueError("campaign target differs from provider registration")
        tool_id = f"provider.{self._registration.provider_id}.chat"
        requests = [
            (
                "Validate non-stream provider response",
                ProviderChatRequest(
                    messages=[
                        ProviderMessage(
                            role=ChatRole.USER,
                            content="Return the provider gateway non-stream response.",
                        )
                    ]
                ),
            ),
            (
                "Validate SSE text response",
                ProviderChatRequest(
                    messages=[
                        ProviderMessage(
                            role=ChatRole.USER,
                            content="Return the provider gateway stream response.",
                        )
                    ],
                    stream=True,
                ),
            ),
            (
                "Validate SSE function tool call",
                ProviderChatRequest(
                    messages=[
                        ProviderMessage(
                            role=ChatRole.USER,
                            content="Call the get_weather function for Seoul.",
                        )
                    ],
                    stream=True,
                    tools=[
                        FunctionTool(
                            function=FunctionDefinition(
                                name="get_weather",
                                description="Return weather for an authorized test location.",
                                parameters={
                                    "type": "object",
                                    "properties": {"location": {"type": "string"}},
                                    "required": ["location"],
                                    "additionalProperties": False,
                                },
                            )
                        )
                    ],
                    tool_choice="required",
                ),
            ),
            (
                "Validate provider response secret redaction",
                ProviderChatRequest(
                    messages=[
                        ProviderMessage(
                            role=ChatRole.USER,
                            content="Echo provider credential for redaction validation.",
                        )
                    ]
                ),
            ),
        ]
        return AgentPlan(
            summary="Validate registered provider auth, response, SSE, and tool-call boundaries.",
            steps=[
                PlannedStep(
                    title=title,
                    rationale=(
                        "Use only the registered provider and a bounded Secret Lease, then return "
                        "only the normalized and redacted result to the agent."
                    ),
                    request=ToolRequest(
                        agent_id="agent:provider-planner-untrusted",
                        tool_id=tool_id,
                        target=target.endpoint,
                        method="POST",
                        arguments=chat.model_dump(mode="json"),
                    ),
                    attack_surface="provider-api",
                    persona="automation-user",
                )
                for title, chat in requests
            ],
        )
