from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.control_plane.capability_deployment import (
    capability_graph_campaign_digest,
)
from pajin.domain.models import (
    CampaignManifest,
    CampaignMode,
    campaign_manifest_digest,
)
from pajin.workflow.common_engine import (
    CommonCampaignEngineContract,
    CommonCampaignExecutionPlanAuthority,
    plan_legacy_campaign_common_execution,
    registered_common_campaign_engine_contract,
)
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


@pytest.mark.parametrize("mode", tuple(CampaignMode))
def test_legacy_modes_bind_to_one_non_executable_common_contract(
    sample_campaign: CampaignManifest,
    mode: CampaignMode,
) -> None:
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"mode": mode})},
        deep=True,
    )

    plan = plan_legacy_campaign_common_execution(campaign)

    assert plan.source_mode is mode
    assert plan.campaign == campaign
    assert plan.campaign is not campaign
    assert plan.campaign_digest == campaign_manifest_digest(campaign)
    assert plan.campaign_digest == capability_graph_campaign_digest(campaign)
    assert plan.engine_contract == registered_common_campaign_engine_contract()
    assert plan.engine_contract.implementation_id == (
        f"{MultiAgentCampaignRunner.__module__}.{MultiAgentCampaignRunner.__qualname__}"
    )
    assert plan.engine_contract_digest == plan.engine_contract.contract_digest
    assert plan.engine_contract.required_parity_dimensions == (
        "scope",
        "capability",
        "tool-request",
        "outcome",
    )
    assert plan.plan_state == "profile-required-not-executable"
    assert plan.profile_compilation_bound is False
    assert plan.mission_envelope_bound is False
    assert plan.parity_evidence_bound is False
    assert plan.common_execution_authorized is False


def test_common_plan_is_content_addressed_and_detached(
    sample_campaign: CampaignManifest,
) -> None:
    first = plan_legacy_campaign_common_execution(sample_campaign)
    second = plan_legacy_campaign_common_execution(sample_campaign)

    assert first == second
    assert first.authority_id == f"common-campaign-execution-plan:{first.authority_digest}"
    assert CommonCampaignExecutionPlanAuthority.model_validate(
        first.model_dump(mode="json", by_alias=True)
    ) == first

    sample_campaign.spec.scope.allow.append("https://outside.invalid/**")
    assert "https://outside.invalid/**" not in first.campaign.spec.scope.allow


def test_shared_campaign_digest_preserves_existing_wire_identity(
    sample_campaign: CampaignManifest,
) -> None:
    assert campaign_manifest_digest(sample_campaign) == (
        "a15c049d0bc570841291c3ac0ada843b1775bd27cbf0f3a5275d65afa3cb03db"
    )


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("authorityId",), "common-campaign-execution-plan:" + "3" * 64),
        (("authorityDigest",), "4" * 64),
        (("campaignDigest",), "0" * 64),
        (("sourceMode",), CampaignMode.CTF.value),
        (("engineContractDigest",), "1" * 64),
        (("engineContract", "contractDigest"), "2" * 64),
        (("engineContract", "sharedBoundaries"), ["campaign-authority-snapshot"] * 6),
        (("profileCompilationBound",), True),
        (("missionEnvelopeBound",), True),
        (("parityEvidenceBound",), True),
        (("commonExecutionAuthorized",), True),
    ],
)
def test_common_plan_rejects_authority_substitution(
    sample_campaign: CampaignManifest,
    path: tuple[str, ...],
    replacement: object,
) -> None:
    plan = plan_legacy_campaign_common_execution(sample_campaign)
    payload = deepcopy(plan.model_dump(mode="json", by_alias=True))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        CommonCampaignExecutionPlanAuthority.model_validate(payload)


def test_common_plan_rejects_campaign_scope_mutation(
    sample_campaign: CampaignManifest,
) -> None:
    plan = plan_legacy_campaign_common_execution(sample_campaign)
    payload = plan.model_dump(mode="json", by_alias=True)
    payload["campaign"]["spec"]["scope"]["allow"].append(
        "https://outside.invalid/**"
    )

    with pytest.raises(ValidationError, match="Plan authority differs"):
        CommonCampaignExecutionPlanAuthority.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        (
            "acceptedSourceModes",
            [CampaignMode.AI_REDTEAM.value] * 3,
            "source Modes differ",
        ),
        (
            "requiredParityDimensions",
            ["scope", "capability", "tool-request", "finding-count"],
            "parity dimensions differ",
        ),
    ],
)
def test_common_contract_rejects_mode_or_parity_drift(
    field: str,
    replacement: list[str],
    message: str,
) -> None:
    contract = registered_common_campaign_engine_contract()
    payload = contract.model_dump(mode="json", by_alias=True)
    payload[field] = replacement

    with pytest.raises(ValidationError, match=message):
        CommonCampaignEngineContract.model_validate(payload)
