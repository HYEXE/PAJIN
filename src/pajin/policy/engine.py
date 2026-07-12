"""Deterministic policy engine placed in front of all tool execution."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest
from pajin.policy.scope import InvalidScopeURL, scope_matches
from pajin.tools.base import ToolSpec


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    policy: str


class PolicyEngine:
    """Evaluate campaign, scope, capability, and tool-risk policies."""

    def evaluate_tool_request(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        tool: ToolSpec,
        *,
        used_calls: int,
        now: datetime | None = None,
    ) -> PolicyDecision:
        evaluated_at = now or datetime.now(UTC)
        if not campaign.spec.authorization.is_active(evaluated_at):
            return self._deny("campaign authorization is not active", "authorization")
        if grant.campaign != campaign.metadata.name or grant.subject != request.agent_id:
            return self._deny(
                "capability grant does not belong to this agent and campaign", "grant"
            )
        grant_expiry = grant.expires_at
        if grant_expiry.tzinfo is None:
            grant_expiry = grant_expiry.replace(tzinfo=UTC)
        if evaluated_at >= grant_expiry:
            return self._deny("capability grant has expired", "grant")
        if request.tool_id not in grant.tools:
            return self._deny("tool is not included in capability grant", "capability")
        if request.target not in grant.targets:
            return self._deny("target is not included in capability grant", "capability")
        if used_calls >= min(grant.max_calls, campaign.spec.budgets.max_tool_calls):
            return self._deny("tool-call budget exhausted", "budget")
        if tool.risk_tier > grant.max_risk_tier:
            return self._deny("tool risk exceeds capability grant", "risk")
        if tool.risk_tier > campaign.spec.rules_of_engagement.max_tool_risk_tier:
            return self._deny("tool risk exceeds campaign rules of engagement", "risk")
        if request.method not in campaign.spec.rules_of_engagement.allowed_methods:
            return self._deny("HTTP method is not allowed by rules of engagement", "method")
        prohibited = tool.categories & campaign.spec.rules_of_engagement.prohibit
        if prohibited:
            return self._deny(
                f"tool belongs to prohibited categories: {', '.join(sorted(prohibited))}",
                "prohibited-action",
            )
        try:
            if any(scope_matches(rule, request.target) for rule in campaign.spec.scope.deny):
                return self._deny("target matches an explicit deny rule", "scope-deny")
            if not any(scope_matches(rule, request.target) for rule in campaign.spec.scope.allow):
                return self._deny("target is outside the allow scope", "scope-allow")
        except InvalidScopeURL as exc:
            return self._deny(f"scope could not be evaluated safely: {exc}", "scope-invalid")
        return PolicyDecision(allowed=True, reason="all policy checks passed", policy="allow")

    @staticmethod
    def _deny(reason: str, policy: str) -> PolicyDecision:
        return PolicyDecision(allowed=False, reason=reason, policy=policy)
