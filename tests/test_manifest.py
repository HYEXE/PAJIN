import pytest
from pydantic import ValidationError

from pajin.domain.models import (
    AgentPlan,
    Budgets,
    CampaignManifest,
    CampaignMode,
    PlannedStep,
    Target,
    ToolRequest,
    ToolRiskTier,
)


def test_sample_manifest_is_valid(sample_campaign: CampaignManifest) -> None:
    assert sample_campaign.spec.mode is CampaignMode.AI_REDTEAM
    assert sample_campaign.spec.authorization.is_active()
    assert sample_campaign.spec.rules_of_engagement.max_tool_risk_tier is ToolRiskTier.T2
    assert sample_campaign.spec.threat_classes == ["A01", "A02", "A04"]


def test_campaign_set_fields_have_deterministic_json_order(
    sample_campaign: CampaignManifest,
) -> None:
    payload = sample_campaign.model_dump(mode="python", by_alias=True)
    rules = payload["spec"]["rulesOfEngagement"]
    rules["allowedMethods"] = {"POST", "GET", "HEAD"}
    rules["allowedToolCategories"] = {"model-provider", "chat-completions"}
    rules["prohibit"] = {"real-user-data-access", "denial-of-service"}
    rules["stopOn"] = {"out-of-scope-attempt", "sensitive-data-exposure"}
    rules["testingWindows"] = [
        {
            "days": {"wednesday", "monday", "friday"},
            "startTime": "09:00:00",
            "endTime": "17:00:00",
            "timezone": "UTC",
        }
    ]

    serialized = CampaignManifest.model_validate(payload).model_dump(
        mode="json",
        by_alias=True,
    )["spec"]["rulesOfEngagement"]

    assert serialized["allowedMethods"] == ["GET", "HEAD", "POST"]
    assert serialized["allowedToolCategories"] == [
        "chat-completions",
        "model-provider",
    ]
    assert serialized["prohibit"] == ["denial-of-service", "real-user-data-access"]
    assert serialized["stopOn"] == [
        "out-of-scope-attempt",
        "sensitive-data-exposure",
    ]
    assert serialized["testingWindows"][0]["days"] == [
        "friday",
        "monday",
        "wednesday",
    ]


def test_manifest_rejects_unknown_fields(sample_campaign: CampaignManifest) -> None:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["unexpectedPrivilege"] = True

    try:
        CampaignManifest.model_validate(payload)
    except ValueError as exc:
        assert "unexpectedPrivilege" in str(exc)
    else:
        raise AssertionError("unknown security-sensitive field was accepted")


@pytest.mark.parametrize(
    "field",
    (
        "durationSeconds",
        "maxCostUsd",
        "maxAgents",
        "maxSpawnDepth",
        "maxToolCalls",
        "maxModelCalls",
        "maxModelTokens",
    ),
)
def test_campaign_budgets_reject_boolean_number_coercion(field: str) -> None:
    with pytest.raises(ValidationError, match="cannot use boolean values"):
        Budgets.model_validate({field: True})


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


@pytest.mark.parametrize(
    "request_id",
    [
        "../campaign",
        "nested/request",
        r"nested\\request",
        ".hidden",
        "request id",
        "request:nonportable",
    ],
)
def test_tool_request_rejects_path_capable_identifiers(request_id: str) -> None:
    with pytest.raises(ValidationError, match="request_id"):
        ToolRequest(
            request_id=request_id,
            agent_id="agent:planner:1",
            tool_id="mock.agent-probe",
            target="https://target.example/api/chat",
        )


def test_campaign_manifest_rejects_unbounded_collection_cardinality(
    sample_campaign: CampaignManifest,
) -> None:
    payload = sample_campaign.model_dump(mode="python", by_alias=True)
    target = payload["spec"]["targets"][0]

    oversized_values = {
        "targets": [target] * 101,
        "objectives": ["bounded objective"] * 101,
        "threatClasses": ["A01"] * 101,
        "outputs": ["json-findings"] * 101,
    }
    for field, value in oversized_values.items():
        candidate = sample_campaign.model_dump(mode="python", by_alias=True)
        candidate["spec"][field] = value
        with pytest.raises(ValidationError, match=field):
            CampaignManifest.model_validate(candidate)

    oversized_scope = sample_campaign.model_dump(mode="python", by_alias=True)
    oversized_scope["spec"]["scope"]["allow"] = ["https://target.example/**"] * 501
    with pytest.raises(ValidationError, match="allow"):
        CampaignManifest.model_validate(oversized_scope)

    window = {
        "days": ["monday"],
        "startTime": "09:00:00",
        "endTime": "17:00:00",
        "timezone": "UTC",
    }
    oversized_windows = sample_campaign.model_dump(mode="python", by_alias=True)
    oversized_windows["spec"]["rulesOfEngagement"]["testingWindows"] = [window] * 101
    with pytest.raises(ValidationError, match="testingWindows"):
        CampaignManifest.model_validate(oversized_windows)

    oversized_policy_sets = sample_campaign.model_dump(mode="python", by_alias=True)
    oversized_policy_sets["spec"]["rulesOfEngagement"]["allowedToolCategories"] = [
        "duplicate"
    ] * 101
    with pytest.raises(ValidationError, match="100-item limit"):
        CampaignManifest.model_validate(oversized_policy_sets)

    oversized_methods = sample_campaign.model_dump(mode="python", by_alias=True)
    oversized_methods["spec"]["rulesOfEngagement"]["allowedMethods"] = ["GET"] * 21
    with pytest.raises(ValidationError, match="20-item limit"):
        CampaignManifest.model_validate(oversized_methods)

    oversized_days = sample_campaign.model_dump(mode="python", by_alias=True)
    oversized_days["spec"]["rulesOfEngagement"]["testingWindows"] = [
        {**window, "days": ["monday"] * 8}
    ]
    with pytest.raises(ValidationError, match="7-item limit"):
        CampaignManifest.model_validate(oversized_days)


@pytest.mark.parametrize(
    ("simulation", "message"),
    [
        ({"value": float("nan")}, "numbers must be finite"),
        ({1: "value"}, "object keys must be strings"),
        ({"value": object()}, "non-JSON value"),
        ({"value": 2**63}, "signed 64-bit range"),
        ({"value": "x" * 65_536}, "canonical byte limit"),
    ],
)
def test_target_rejects_non_json_or_oversized_simulation(
    simulation: dict[object, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        Target(
            type="mock-agent",
            id="target",
            endpoint="https://target.example/api/chat",
            simulation=simulation,
        )


def test_target_rejects_cyclic_deep_and_fanout_simulation() -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    with pytest.raises(ValidationError, match="cannot contain cycles"):
        Target(
            type="mock-agent",
            id="cycle",
            endpoint="https://target.example/api/chat",
            simulation=cycle,
        )

    deep: object = "leaf"
    for _ in range(33):
        deep = {"next": deep}
    with pytest.raises(ValidationError, match="nesting-depth limit"):
        Target(
            type="mock-agent",
            id="deep",
            endpoint="https://target.example/api/chat",
            simulation={"root": deep},
        )

    shared = {"value": "leaf"}
    with pytest.raises(ValidationError, match="node-count limit"):
        Target(
            type="mock-agent",
            id="fanout",
            endpoint="https://target.example/api/chat",
            simulation={"items": [shared] * 10_000},
        )


def test_campaign_manifest_rejects_oversized_canonical_form(
    sample_campaign: CampaignManifest,
) -> None:
    payload = sample_campaign.model_dump(mode="python", by_alias=True)
    original = payload["spec"]["targets"][0]
    payload["spec"]["targets"] = [
        {
            **original,
            "id": f"target-{index}",
            "simulation": {"text": "x" * 60_000},
        }
        for index in range(18)
    ]

    with pytest.raises(ValidationError, match="campaign manifest exceeds the canonical byte limit"):
        CampaignManifest.model_validate(payload)


def test_target_accepts_bounded_json_simulation() -> None:
    target = Target(
        type="mock-agent",
        id="target",
        endpoint="https://target.example/api/chat",
        simulation={
            "unauthorizedToolCall": False,
            "messages": ["first", "second"],
            "metadata": {"attempt": 1, "confidence": 0.5, "optional": None},
        },
    )

    assert target.model_dump(mode="json")["simulation"]["metadata"]["attempt"] == 1
