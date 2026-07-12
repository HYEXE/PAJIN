from pajin.domain.models import CampaignManifest, CampaignMode, ToolRiskTier


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
