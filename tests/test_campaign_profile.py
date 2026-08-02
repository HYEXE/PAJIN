from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.workflow.campaign_profile import (
    CampaignProfileCatalog,
    CampaignProfileError,
    CampaignProfilePurpose,
    RegisteredCampaignProfile,
    registered_campaign_profile_catalog,
    resolve_registered_campaign_profile,
)
from pajin.workflow.common_engine import registered_common_campaign_engine_contract


def test_registered_profile_catalog_binds_four_non_executable_profiles() -> None:
    catalog = registered_campaign_profile_catalog()
    contract = registered_common_campaign_engine_contract()

    assert tuple(profile.profile_id for profile in catalog.profiles) == (
        "pajin.profile.ai-assessment",
        "pajin.profile.bug-hunt",
        "pajin.profile.ctf",
        "pajin.profile.pentest",
    )
    assert tuple(profile.purpose for profile in catalog.profiles) == (
        CampaignProfilePurpose.AI_ASSESSMENT,
        CampaignProfilePurpose.BUG_HUNT,
        CampaignProfilePurpose.CTF,
        CampaignProfilePurpose.PENTEST,
    )
    assert catalog.common_engine_contract == contract
    assert catalog.common_engine_contract_digest == contract.contract_digest
    assert catalog.legacy_mode_compilation_authorized is False
    assert catalog.mission_envelope_compilation_authorized is False
    assert catalog.common_execution_authorized is False
    assert all(
        profile.roe_defaults_policy == "campaign-authority-only"
        for profile in catalog.profiles
    )
    assert all(profile.legacy_compatibility_adapter_bound is False for profile in catalog.profiles)
    assert all(profile.mission_envelope_compiler_bound is False for profile in catalog.profiles)
    assert all(profile.benchmark_measurement_authorized is False for profile in catalog.profiles)
    assert all(profile.external_submission_authorized is False for profile in catalog.profiles)
    assert all(profile.profile_execution_authorized is False for profile in catalog.profiles)


def test_profile_catalog_is_content_addressed_and_round_trips() -> None:
    first = registered_campaign_profile_catalog()
    second = registered_campaign_profile_catalog()

    assert first == second
    assert CampaignProfileCatalog.model_validate(
        first.model_dump(mode="json", by_alias=True)
    ) == first
    assert all(len(profile.profile_digest) == 64 for profile in first.profiles)
    assert len({profile.profile_digest for profile in first.profiles}) == 4


@pytest.mark.parametrize(
    "profile_id",
    (
        "pajin.profile.pentest",
        "pajin.profile.bug-hunt",
        "pajin.profile.ctf",
        "pajin.profile.ai-assessment",
    ),
)
def test_exact_profile_resolution_grants_no_campaign_selection(
    profile_id: str,
) -> None:
    profile = resolve_registered_campaign_profile(profile_id, "1.0.0")

    assert profile.profile_id == profile_id
    assert profile.profile_execution_authorized is False
    assert "campaign" not in RegisteredCampaignProfile.model_fields
    assert "source_mode" not in RegisteredCampaignProfile.model_fields
    assert "mission_envelope" not in RegisteredCampaignProfile.model_fields


@pytest.mark.parametrize(
    ("profile_id", "profile_version"),
    [
        ("pajin.profile.unknown", "1.0.0"),
        ("pajin.profile.pentest", "latest"),
        ("pajin.profile.pentest", "2.0.0"),
    ],
)
def test_profile_resolution_rejects_unknown_id_or_version(
    profile_id: str,
    profile_version: str,
) -> None:
    with pytest.raises(CampaignProfileError, match="not registered"):
        resolve_registered_campaign_profile(profile_id, profile_version)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("catalogDigest",), "0" * 64),
        (("commonEngineContractDigest",), "1" * 64),
        (("profiles", 0, "profileDigest"), "2" * 64),
        (("profiles", 0, "purpose"), "pentest"),
        (("profiles", 0, "reportingSemantics"), "technical-assessment"),
        (("profiles", 0, "benchmarkExpectation"), "fixed-lab-ground-truth"),
        (("profiles", 0, "requiredOperatingControls"), ["claim-validation"] * 3),
        (("profiles", 0, "authorityConstraints"), ["campaign-budget-ceiling"] * 5),
        (("profiles", 0, "legacyCompatibilityAdapterBound"), True),
        (("profiles", 0, "missionEnvelopeCompilerBound"), True),
        (("profiles", 0, "benchmarkMeasurementAuthorized"), True),
        (("profiles", 0, "externalSubmissionAuthorized"), True),
        (("profiles", 0, "profileExecutionAuthorized"), True),
        (("profiles",), "reverse"),
        (("legacyModeCompilationAuthorized",), True),
        (("missionEnvelopeCompilationAuthorized",), True),
        (("commonExecutionAuthorized",), True),
    ],
)
def test_profile_catalog_rejects_substitution_or_authority_escalation(
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    catalog = registered_campaign_profile_catalog()
    payload = deepcopy(catalog.model_dump(mode="json", by_alias=True))
    if replacement == "reverse":
        replacement = list(reversed(payload["profiles"]))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        CampaignProfileCatalog.model_validate(payload)


def test_standalone_profile_cannot_substitute_for_code_owned_catalog() -> None:
    catalog = registered_campaign_profile_catalog()
    source = catalog.profiles[0]
    payload = source.model_dump(mode="json", by_alias=True)
    payload["profileId"] = "pajin.profile.unregistered"
    payload["profileDigest"] = ""
    unregistered = RegisteredCampaignProfile.model_validate(payload)
    catalog_payload = catalog.model_dump(mode="json", by_alias=True)
    catalog_payload["profiles"][0] = unregistered.model_dump(mode="json", by_alias=True)
    catalog_payload["catalogDigest"] = ""

    with pytest.raises(ValidationError, match="differs from code authority"):
        CampaignProfileCatalog.model_validate(catalog_payload)
