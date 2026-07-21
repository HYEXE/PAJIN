from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    ToolRiskTier,
    WeeklyTestingWindow,
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
        issued_at=campaign.spec.authorization.approved_at,
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


def test_encoded_unreserved_path_cannot_bypass_explicit_deny(
    sample_campaign: CampaignManifest,
) -> None:
    denied_target = "https://staging.example.invalid/api/%61dmin/delete"
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


def test_future_issued_capability_is_denied(sample_campaign: CampaignManifest) -> None:
    evaluated_at = datetime(2026, 7, 18, tzinfo=UTC)
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=sample_campaign.spec.targets[0].endpoint,
        method="POST",
    )
    grant = _grant(sample_campaign).model_copy(
        update={"issued_at": evaluated_at + timedelta(minutes=1)}
    )

    decision = PolicyEngine().evaluate_tool_request(
        sample_campaign,
        grant,
        request,
        MockAgentProbe.spec,
        used_calls=0,
        now=evaluated_at,
    )

    assert not decision.allowed
    assert decision.policy == "grant"
    assert decision.reason == "capability grant is not active yet"


def test_policy_fails_closed_for_bypassed_naive_authority_timestamps(
    sample_campaign: CampaignManifest,
) -> None:
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=sample_campaign.spec.targets[0].endpoint,
        method="POST",
    )
    grant = _grant(sample_campaign).model_copy(update={"issued_at": datetime(2026, 7, 18)})

    grant_decision = PolicyEngine().evaluate_tool_request(
        sample_campaign,
        grant,
        request,
        MockAgentProbe.spec,
        used_calls=0,
        now=datetime(2026, 7, 18, tzinfo=UTC),
    )
    time_decision = PolicyEngine().evaluate_tool_request(
        sample_campaign,
        _grant(sample_campaign),
        request,
        MockAgentProbe.spec,
        used_calls=0,
        now=datetime(2026, 7, 18),
    )

    assert not grant_decision.allowed
    assert grant_decision.policy == "grant"
    assert grant_decision.reason == "capability grant timestamp is invalid"
    assert not time_decision.allowed
    assert time_decision.policy == "authorization"


def test_testing_window_is_enforced_in_campaign_timezone(
    sample_campaign: CampaignManifest,
) -> None:
    rules = sample_campaign.spec.rules_of_engagement.model_copy(
        update={
            "testing_windows": [
                WeeklyTestingWindow(
                    days={"monday"},
                    startTime="09:00:00",
                    endTime="11:00:00",
                    timezone="Asia/Seoul",
                )
            ]
        }
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"rules_of_engagement": rules})}
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=campaign.spec.targets[0].endpoint,
        method="POST",
    )

    allowed = PolicyEngine().evaluate_tool_request(
        campaign,
        _grant(campaign),
        request,
        MockAgentProbe.spec,
        used_calls=0,
        now=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )
    denied = PolicyEngine().evaluate_tool_request(
        campaign,
        _grant(campaign),
        request,
        MockAgentProbe.spec,
        used_calls=0,
        now=datetime(2026, 7, 13, 12, tzinfo=UTC),
    )

    assert allowed.allowed
    assert not denied.allowed
    assert denied.policy == "testing-window"


def test_overnight_testing_window_uses_previous_start_day() -> None:
    window = WeeklyTestingWindow(
        days={"monday"},
        startTime="22:00:00",
        endTime="02:00:00",
        timezone="Asia/Seoul",
    )

    assert window.is_active(datetime(2026, 7, 13, 14, tzinfo=UTC))
    assert window.is_active(datetime(2026, 7, 13, 16, tzinfo=UTC))
    assert not window.is_active(datetime(2026, 7, 14, 2, tzinfo=UTC))


def test_tool_category_allowlist_fails_closed(sample_campaign: CampaignManifest) -> None:
    rules = sample_campaign.spec.rules_of_engagement.model_copy(
        update={"allowed_tool_categories": {"active-test"}}
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"rules_of_engagement": rules})}
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=campaign.spec.targets[0].endpoint,
        method="POST",
    )

    decision = PolicyEngine().evaluate_tool_request(
        campaign,
        _grant(campaign),
        request,
        MockAgentProbe.spec,
        used_calls=0,
    )

    assert not decision.allowed
    assert decision.policy == "tool-category-allowlist"


def test_policy_binds_the_evaluated_spec_to_the_requested_tool(
    sample_campaign: CampaignManifest,
) -> None:
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=sample_campaign.spec.targets[0].endpoint,
        method="POST",
    )
    unrelated_spec = MockAgentProbe.spec.model_copy(update={"tool_id": "mock.unrelated"})

    decision = PolicyEngine().evaluate_tool_request(
        sample_campaign,
        _grant(sample_campaign),
        request,
        unrelated_spec,
        used_calls=0,
    )

    assert not decision.allowed
    assert decision.policy == "tool"


@pytest.mark.parametrize("used_calls", [-1, True])
def test_policy_rejects_noncanonical_tool_usage(
    sample_campaign: CampaignManifest,
    used_calls: int,
) -> None:
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
        used_calls=used_calls,
    )

    assert not decision.allowed
    assert decision.policy == "budget"


def test_policy_decisions_are_immutable(sample_campaign: CampaignManifest) -> None:
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

    with pytest.raises(ValidationError, match="frozen"):
        decision.allowed = False
