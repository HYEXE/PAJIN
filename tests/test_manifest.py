import pytest
from pydantic import ValidationError

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CampaignMode,
    PlannedStep,
    ToolRequest,
    ToolRiskTier,
)


def test_sample_manifest_is_valid(sample_campaign: CampaignManifest) -> None:
    assert sample_campaign.spec.mode is CampaignMode.AI_REDTEAM
    assert sample_campaign.spec.authorization.is_active()
    assert sample_campaign.spec.rules_of_engagement.max_tool_risk_tier is ToolRiskTier.T2
    assert sample_campaign.spec.threat_classes == ["A01", "A02", "A04"]


def test_manifest_rejects_unknown_fields(sample_campaign: CampaignManifest) -> None:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["unexpectedPrivilege"] = True

    try:
        CampaignManifest.model_validate(payload)
    except ValueError as exc:
        assert "unexpectedPrivilege" in str(exc)
    else:
        raise AssertionError("unknown security-sensitive field was accepted")


def test_agent_plan_rejects_duplicate_tool_request_ids() -> None:
    request = ToolRequest(
        request_id="tool_duplicate",
        agent_id="agent:planner:1",
        tool_id="mock.agent-probe",
        target="https://target.example/api/chat",
    )

    with pytest.raises(ValidationError, match="agent plan request IDs must be unique"):
        AgentPlan(
            summary="Duplicate request identity is ambiguous for evidence provenance.",
            steps=[
                PlannedStep(
                    title="First request",
                    rationale="Exercise the first bounded request.",
                    request=request,
                ),
                PlannedStep(
                    title="Duplicate request",
                    rationale="This duplicate identity must fail closed.",
                    request=request.model_copy(),
                ),
            ],
        )
