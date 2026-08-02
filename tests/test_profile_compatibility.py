from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.domain.models import CampaignManifest, CampaignMode, campaign_manifest_digest
from pajin.workflow.profile_compatibility import (
    CampaignProfileCompatibilityError,
    LegacyCampaignProfileCompilationAuthority,
    LegacyModeProfileCompiler,
    compile_legacy_campaign_profile,
    registered_legacy_mode_profile_compiler,
)

_EXPECTED_PROFILES = {
    CampaignMode.AI_REDTEAM: "pajin.profile.ai-assessment",
    CampaignMode.BUG_BOUNTY: "pajin.profile.bug-hunt",
    CampaignMode.CTF: "pajin.profile.ctf",
}


@pytest.mark.parametrize("mode", tuple(CampaignMode))
def test_legacy_modes_compile_to_exact_non_executable_profiles(
    sample_campaign: CampaignManifest,
    mode: CampaignMode,
) -> None:
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"mode": mode})},
        deep=True,
    )

    compilation = compile_legacy_campaign_profile(campaign)

    assert compilation.source_campaign == campaign
    assert compilation.source_campaign is not campaign
    assert compilation.input_digest == campaign_manifest_digest(campaign)
    assert compilation.source_mode is mode
    assert compilation.profile.profile_id == _EXPECTED_PROFILES[mode]
    assert compilation.profile_digest == compilation.profile.profile_digest
    assert compilation.projection.source_campaign_digest == compilation.input_digest
    assert compilation.projection.source_mode is mode
    assert compilation.projection.profile_digest == compilation.profile_digest
    assert compilation.output_digest == compilation.projection.projection_digest
    assert compilation.projection.legacy_input_preserved is True
    assert compilation.projection.campaign_mutation_applied is False
    assert compilation.projection.roe_defaults_applied is False
    assert compilation.projection.mission_envelope_compiled is False
    assert compilation.projection.common_execution_authorized is False
    assert compilation.mission_envelope_compiled is False
    assert compilation.common_execution_authorized is False


def test_compilation_is_content_addressed_and_detached(
    sample_campaign: CampaignManifest,
) -> None:
    first = compile_legacy_campaign_profile(sample_campaign)
    second = compile_legacy_campaign_profile(sample_campaign)

    assert first == second
    assert first.authority_id == (
        f"legacy-campaign-profile-compilation:{first.authority_digest}"
    )
    assert LegacyCampaignProfileCompilationAuthority.model_validate(
        first.model_dump(mode="json", by_alias=True)
    ) == first

    sample_campaign.spec.scope.allow.append("https://outside.invalid/**")
    assert "https://outside.invalid/**" not in first.source_campaign.spec.scope.allow


def test_compiler_maps_only_existing_modes_and_never_selects_pentest() -> None:
    compiler = registered_legacy_mode_profile_compiler()

    assert tuple(mapping.source_mode for mapping in compiler.mappings) == tuple(CampaignMode)
    assert tuple(mapping.profile_id for mapping in compiler.mappings) == (
        "pajin.profile.ai-assessment",
        "pajin.profile.bug-hunt",
        "pajin.profile.ctf",
    )
    assert all(mapping.profile_id != "pajin.profile.pentest" for mapping in compiler.mappings)
    assert compiler.campaign_mutation_allowed is False
    assert compiler.roe_defaults_application_authorized is False
    assert compiler.pentest_auto_selection_authorized is False
    assert compiler.mission_envelope_compilation_authorized is False
    assert compiler.common_execution_authorized is False


def test_compiler_rejects_unregistered_campaign_api_version(
    sample_campaign: CampaignManifest,
) -> None:
    campaign = sample_campaign.model_copy(update={"api_version": "pajin.dev/v1beta1"}, deep=True)

    with pytest.raises(CampaignProfileCompatibilityError, match="API version"):
        compile_legacy_campaign_profile(campaign)


def test_compilation_wire_rejects_unregistered_campaign_api_version(
    sample_campaign: CampaignManifest,
) -> None:
    compilation = compile_legacy_campaign_profile(sample_campaign)
    payload = compilation.model_dump(mode="json", by_alias=True)
    payload["sourceCampaign"]["apiVersion"] = "pajin.dev/v1beta1"
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""

    with pytest.raises(ValidationError, match="API version"):
        LegacyCampaignProfileCompilationAuthority.model_validate(payload)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("authorityId",), "legacy-campaign-profile-compilation:" + "0" * 64),
        (("authorityDigest",), "1" * 64),
        (("inputDigest",), "2" * 64),
        (("sourceMode",), CampaignMode.CTF.value),
        (("compilerDigest",), "3" * 64),
        (("compiler", "compilerDigest"), "4" * 64),
        (("profileCatalogDigest",), "5" * 64),
        (("profileDigest",), "6" * 64),
        (("profile", "profileId"), "pajin.profile.pentest"),
        (("projection", "profileId"), "pajin.profile.pentest"),
        (("projection", "campaignMutationApplied"), True),
        (("projection", "roeDefaultsApplied"), True),
        (("projection", "missionEnvelopeCompiled"), True),
        (("projection", "commonExecutionAuthorized"), True),
        (("outputDigest",), "7" * 64),
        (("missionEnvelopeCompiled",), True),
        (("commonExecutionAuthorized",), True),
    ],
)
def test_compilation_rejects_substitution_or_authority_escalation(
    sample_campaign: CampaignManifest,
    path: tuple[str, ...],
    replacement: object,
) -> None:
    compilation = compile_legacy_campaign_profile(sample_campaign)
    payload = deepcopy(compilation.model_dump(mode="json", by_alias=True))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        LegacyCampaignProfileCompilationAuthority.model_validate(payload)


def test_compilation_rejects_campaign_mutation_under_retained_input_digest(
    sample_campaign: CampaignManifest,
) -> None:
    compilation = compile_legacy_campaign_profile(sample_campaign)
    payload = compilation.model_dump(mode="json", by_alias=True)
    payload["sourceCampaign"]["spec"]["scope"]["allow"].append(
        "https://outside.invalid/**"
    )

    with pytest.raises(ValidationError, match="authority differs"):
        LegacyCampaignProfileCompilationAuthority.model_validate(payload)


def test_compiler_rejects_mapping_drift() -> None:
    compiler = registered_legacy_mode_profile_compiler()
    payload = compiler.model_dump(mode="json", by_alias=True)
    payload["mappings"][0]["profileId"] = "pajin.profile.pentest"
    payload["mappings"][0]["mappingDigest"] = ""
    payload["compilerDigest"] = ""

    with pytest.raises(ValidationError, match="mapping differs"):
        LegacyModeProfileCompiler.model_validate(payload)
