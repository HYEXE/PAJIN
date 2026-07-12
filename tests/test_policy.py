from datetime import UTC, datetime

from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    ToolRiskTier,
)
from pajin.policy.engine import PolicyEngine
from pajin.tools.mock import MockAgentProbe


def _grant(campaign: CampaignManifest) -> CapabilityGrant:
    return CapabilityGrant(
        subject="agent:planner-local",
        campaign=campaign.metadata.name,
        tools={"mock.agent-probe"},
        targets={campaign.spec.targets[0].endpoint},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=5,
        expires_at=campaign.spec.authorization.expires_at,
        delegable=True,
    )


def test_policy_allows_authorized_request(sample_campaign: CampaignManifest) -> None:
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=sample_campaign.spec.targets[0].endpoint,
        method="POST",
    )

    decision = PolicyEngine().evaluate_tool_request(
        sample_campaign,
        _grant(sample_campaign),
        request,
        MockAgentProbe.spec,
        used_calls=0,
    )

    assert decision.allowed


def test_explicit_deny_rule_wins(sample_campaign: CampaignManifest) -> None:
    denied_target = "https://staging.example.invalid/api/admin/delete"
    grant = _grant(sample_campaign).model_copy(update={"targets": {denied_target}})
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=denied_target,
        method="POST",
    )

    decision = PolicyEngine().evaluate_tool_request(
        sample_campaign,
        grant,
        request,
        MockAgentProbe.spec,
        used_calls=0,
    )

    assert not decision.allowed
    assert decision.policy == "scope-deny"


def test_expired_capability_is_denied(sample_campaign: CampaignManifest) -> None:
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=sample_campaign.spec.targets[0].endpoint,
        method="POST",
    )
    grant = _grant(sample_campaign).model_copy(
        update={"expires_at": datetime(2026, 1, 1, tzinfo=UTC)}
    )

    decision = PolicyEngine().evaluate_tool_request(
        sample_campaign,
        grant,
        request,
        MockAgentProbe.spec,
        used_calls=0,
    )

    assert not decision.allowed
    assert decision.policy == "grant"
