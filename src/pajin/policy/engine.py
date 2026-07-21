"""Deterministic policy engine placed in front of all tool execution."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest
from pajin.policy.scope import InvalidScopeURL, scope_matches
from pajin.tools.base import ToolSpec


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason: str
    policy: str


class PolicyEngine:
    """Evaluate campaign, scope, capability, and tool-risk policies."""

    def stable_execution_context(self) -> dict[str, object]:
        """Bind checkpoints to this stateless policy implementation contract."""

        return {"implementationVersion": "pajin.policy-engine/v1"}

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
        inputs = self._snapshot_inputs(campaign, grant, request, tool)
        if inputs is None:
            return self._deny("policy inputs could not be validated safely", "policy-input")
        campaign, grant, request, tool = inputs

        evaluated_at = self._evaluation_time(now)
        if evaluated_at is None:
            return self._deny("authorization evaluation timestamp is invalid", "authorization")
        try:
            decision = self._authorization_decision(campaign, evaluated_at)
            if decision is None:
                decision = self._grant_decision(campaign, grant, request, evaluated_at)
            if decision is None:
                decision = self._capability_decision(campaign, grant, request, used_calls)
            if decision is None:
                decision = self._tool_contract_decision(campaign, grant, request, tool)
            if decision is None:
                decision = self._scope_decision(campaign, request)
        except Exception:
            return self._deny("policy inputs could not be evaluated safely", "policy-input")
        return decision or self._allow()

    def _authorization_decision(
        self,
        campaign: CampaignManifest,
        evaluated_at: datetime,
    ) -> PolicyDecision | None:
        try:
            authorization_active = campaign.spec.authorization.is_active(evaluated_at)
            testing_windows = campaign.spec.rules_of_engagement.testing_windows
            testing_window_active = not testing_windows or any(
                window.is_active(evaluated_at) for window in testing_windows
            )
        except (OverflowError, TypeError, ValueError):
            return self._deny("authorization evaluation timestamp is invalid", "authorization")
        if not authorization_active:
            return self._deny("campaign authorization is not active", "authorization")
        if not testing_window_active:
            return self._deny("request is outside the approved testing window", "testing-window")
        return None

    def _grant_decision(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        evaluated_at: datetime,
    ) -> PolicyDecision | None:
        if grant.campaign != campaign.metadata.name or grant.subject != request.agent_id:
            return self._deny(
                "capability grant does not belong to this agent and campaign", "grant"
            )
        try:
            grant_expiry = self._aware_utc(grant.expires_at)
            grant_issued_at = self._aware_utc(grant.issued_at)
        except (OverflowError, TypeError, ValueError):
            return self._deny("capability grant timestamp is invalid", "grant")
        if evaluated_at < grant_issued_at:
            return self._deny("capability grant is not active yet", "grant")
        if evaluated_at >= grant_expiry:
            return self._deny("capability grant has expired", "grant")
        return None

    def _capability_decision(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        used_calls: int,
    ) -> PolicyDecision | None:
        if request.tool_id not in grant.tools:
            return self._deny("tool is not included in capability grant", "capability")
        if request.target not in grant.targets:
            return self._deny("target is not included in capability grant", "capability")
        if type(used_calls) is not int or used_calls < 0:
            return self._deny("tool-call usage is invalid", "budget")
        if used_calls >= min(grant.max_calls, campaign.spec.budgets.max_tool_calls):
            return self._deny("tool-call budget exhausted", "budget")
        return None

    def _tool_contract_decision(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        tool: ToolSpec,
    ) -> PolicyDecision | None:
        if tool.tool_id != request.tool_id:
            return self._deny("tool specification does not match requested tool", "tool")
        if tool.risk_tier > grant.max_risk_tier:
            return self._deny("tool risk exceeds capability grant", "risk")
        if tool.risk_tier > campaign.spec.rules_of_engagement.max_tool_risk_tier:
            return self._deny("tool risk exceeds campaign rules of engagement", "risk")
        if request.method not in campaign.spec.rules_of_engagement.allowed_methods:
            return self._deny("HTTP method is not allowed by rules of engagement", "method")
        allowed_categories = campaign.spec.rules_of_engagement.allowed_tool_categories
        if allowed_categories and not tool.categories <= allowed_categories:
            disallowed = tool.categories - allowed_categories
            return self._deny(
                f"tool categories are not allowlisted: {', '.join(sorted(disallowed))}",
                "tool-category-allowlist",
            )
        prohibited = tool.categories & campaign.spec.rules_of_engagement.prohibit
        if prohibited:
            return self._deny(
                f"tool belongs to prohibited categories: {', '.join(sorted(prohibited))}",
                "prohibited-action",
            )
        return None

    def _scope_decision(
        self,
        campaign: CampaignManifest,
        request: ToolRequest,
    ) -> PolicyDecision | None:
        try:
            if any(scope_matches(rule, request.target) for rule in campaign.spec.scope.deny):
                return self._deny("target matches an explicit deny rule", "scope-deny")
            if not any(scope_matches(rule, request.target) for rule in campaign.spec.scope.allow):
                return self._deny("target is outside the allow scope", "scope-allow")
        except InvalidScopeURL:
            return self._deny("scope could not be evaluated safely", "scope-invalid")
        return None

    @staticmethod
    def _snapshot_inputs(
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        tool: ToolSpec,
    ) -> tuple[CampaignManifest, CapabilityGrant, ToolRequest, ToolSpec] | None:
        if not (
            isinstance(campaign, CampaignManifest)
            and isinstance(grant, CapabilityGrant)
            and isinstance(request, ToolRequest)
            and isinstance(tool, ToolSpec)
        ):
            return None
        try:
            return (
                campaign.model_copy(deep=True),
                grant.model_copy(deep=True),
                request.model_copy(deep=True),
                tool.model_copy(deep=True),
            )
        except Exception:
            return None

    @staticmethod
    def _evaluation_time(now: datetime | None) -> datetime | None:
        evaluated_at = datetime.now(UTC) if now is None else now
        try:
            return PolicyEngine._aware_utc(evaluated_at)
        except (OverflowError, TypeError, ValueError):
            return None

    @staticmethod
    def _aware_utc(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a UTC offset")
        return value.astimezone(UTC)

    @staticmethod
    def _allow() -> PolicyDecision:
        return PolicyDecision(allowed=True, reason="all policy checks passed", policy="allow")

    @staticmethod
    def _deny(reason: str, policy: str) -> PolicyDecision:
        return PolicyDecision(allowed=False, reason=reason, policy=policy)
