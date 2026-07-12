"""Framework-independent agent runtime port."""

from __future__ import annotations

from typing import Protocol

from pajin.domain.models import AgentPlan, CampaignManifest, Finding, ToolResult


class AgentRuntime(Protocol):
    agent_id: str

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        """Produce a typed plan for the authorized campaign."""

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        """Independently validate tool observations into findings."""


class PlannerRuntime(Protocol):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        """Produce a typed plan without executing privileged tools."""


class ValidatorRuntime(Protocol):
    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        """Validate observations independently from the executing specialist."""
