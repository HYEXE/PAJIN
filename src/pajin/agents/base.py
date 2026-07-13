"""Framework-independent agent runtime port."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pajin.domain.models import AgentPlan, CampaignManifest, Finding, StrictModel, ToolResult


class ModelCallFailure(RuntimeError):
    """A bounded provider attempt failed and may use the configured fallback."""


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


class AgentReportNarrative(StrictModel):
    summary: str
    risk_overview: str
    recommendations: list[str]
    limitations: list[str]


class ReporterRuntime(Protocol):
    async def report(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        findings: list[Finding],
    ) -> AgentReportNarrative:
        """Produce a bounded narrative supplement to the canonical report."""


class StructuredModelPort(Protocol):
    async def complete(
        self,
        *,
        role: str,
        attempt: int,
        messages: list[Any],
        schema_name: str,
        schema: dict[str, object],
        max_completion_tokens: int,
    ) -> Any:
        """Call one policy-bound model provider and return a normalized result."""

    def record_fallback(self, *, role: str, reason: str) -> None:
        """Audit a deterministic fallback without storing provider secrets."""


@runtime_checkable
class ModelBoundRuntime(Protocol):
    model_provider_registration: Any
    model_provider_tool_id: str
    model_provider_endpoint: str
    model_max_attempts: int

    def bind_model_port(self, port: StructuredModelPort) -> None:
        """Bind a run- and role-scoped provider port before invoking this runtime."""
