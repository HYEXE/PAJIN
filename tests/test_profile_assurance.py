from __future__ import annotations

import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.discovery import ValidationDepth, resolve_validation_depth_requirement
from pajin.workflow.campaign_profile import registered_campaign_profile_catalog
from pajin.workflow.profile_assurance import (
    PROFILE_ASSURANCE_FLOOR_API_VERSION,
    PROFILE_ASSURANCE_FLOOR_POLICY_API_VERSION,
    ProfileAssuranceFloor,
    ProfileAssuranceFloorError,
    ProfileAssuranceFloorPolicy,
    registered_profile_assurance_floor_policy,
    resolve_profile_assurance_floor,
    validation_depth_requirement_meets_profile_floor,
)

_EXPECTED_DEPTHS = {
    "pajin.profile.ai-assessment": ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY,
    "pajin.profile.bug-hunt": ValidationDepth.CONTROLLED_VALIDITY_REPLAY,
    "pajin.profile.ctf": ValidationDepth.SINGLE_VALIDITY_REPLAY,
    "pajin.profile.pentest": ValidationDepth.CONTROLLED_VALIDITY_REPLAY,
}


def test_registered_profile_assurance_policy_binds_exact_profile_floors() -> None:
    policy = registered_profile_assurance_floor_policy()
    profiles = registered_campaign_profile_catalog().profiles

    assert policy.api_version == PROFILE_ASSURANCE_FLOOR_POLICY_API_VERSION
    assert policy.policy_id == "val-003:profile-assurance-floor"
    assert policy.campaign_mode_constraint == "none"
    assert tuple(floor.profile_id for floor in policy.floors) == tuple(
        profile.profile_id for profile in profiles
    )
    assert {floor.profile_id: floor.minimum_depth for floor in policy.floors} == _EXPECTED_DEPTHS
    for profile, floor in zip(profiles, policy.floors, strict=True):
        requirement = resolve_validation_depth_requirement(floor.minimum_depth)
        assert floor.api_version == PROFILE_ASSURANCE_FLOOR_API_VERSION
        assert floor.profile == profile
        assert floor.profile_digest == profile.profile_digest
        assert floor.minimum_requirement == requirement
        assert floor.minimum_depth_ordinal == requirement.depth_ordinal
        assert floor.minimum_requirement_digest == requirement.requirement_digest


def test_profile_assurance_policy_round_trips_with_both_exact_catalogs() -> None:
    first = registered_profile_assurance_floor_policy()
    second = registered_profile_assurance_floor_policy()

    assert first == second
    assert (
        ProfileAssuranceFloorPolicy.model_validate(first.model_dump(mode="json", by_alias=True))
        == first
    )
    assert first.profile_catalog_digest == first.profile_catalog.catalog_digest
    assert first.validation_depth_policy_digest == first.validation_depth_policy.policy_digest
    assert len(first.policy_digest) == 64
    assert len({floor.floor_digest for floor in first.floors}) == 4


def test_profile_assurance_floor_resolution_does_not_select_a_campaign_profile() -> None:
    for profile_id, expected_depth in _EXPECTED_DEPTHS.items():
        floor = resolve_profile_assurance_floor(profile_id, "1.0.0")

        assert floor.minimum_depth is expected_depth
        assert floor.floor_registered is True
        assert floor.higher_depth_requirement_acceptable is True
        assert floor.profile_selection_authorized is False
        assert floor.campaign_mutation_authorized is False
        assert floor.evidence_evaluation_authorized is False
        assert floor.execution_authorized is False
        assert floor.confirmation_authorized is False
        assert floor.finding_confirmed is False

    for forbidden in (
        "campaign",
        "campaign_id",
        "source_mode",
        "claim_replay",
        "control_receipts",
        "validation_decision",
        "finding",
    ):
        assert forbidden not in ProfileAssuranceFloor.model_fields
        assert forbidden not in ProfileAssuranceFloorPolicy.model_fields


@pytest.mark.parametrize(
    ("profile_id", "accepted_depths"),
    [
        (
            "pajin.profile.ai-assessment",
            {ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY},
        ),
        (
            "pajin.profile.bug-hunt",
            {
                ValidationDepth.CONTROLLED_VALIDITY_REPLAY,
                ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY,
            },
        ),
        ("pajin.profile.ctf", set(ValidationDepth)),
        (
            "pajin.profile.pentest",
            {
                ValidationDepth.CONTROLLED_VALIDITY_REPLAY,
                ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY,
            },
        ),
    ],
)
def test_registered_requirement_comparison_is_monotonic_without_evidence_evaluation(
    profile_id: str,
    accepted_depths: set[ValidationDepth],
) -> None:
    for depth in ValidationDepth:
        assert validation_depth_requirement_meets_profile_floor(
            profile_id,
            "1.0.0",
            depth,
        ) is (depth in accepted_depths)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("policyDigest",), "0" * 64),
        (("profileCatalogDigest",), "1" * 64),
        (("profileCatalog", "profiles", 0, "purpose"), "ctf"),
        (("validationDepthPolicyDigest",), "2" * 64),
        (
            (
                "validationDepthPolicy",
                "requirements",
                0,
                "minimumReplayRepetitions",
            ),
            2,
        ),
        (("floors",), "reverse"),
        (("floors", 0, "floorDigest"), "3" * 64),
        (("floors", 0, "minimumDepth"), "single-validity-replay"),
        (("floors", 0, "minimumDepthOrdinal"), 1),
        (("floors", 0, "minimumRequirementDigest"), "4" * 64),
        (("floors", 0, "minimumRequirement", "minimumReplayRepetitions"), 1),
        (("floors", 0, "profileDigest"), "5" * 64),
        (("floors", 0, "profileId"), "pajin.profile.ctf"),
        (("floorMappingRegistered",), False),
        (("profileSelectionAuthorized",), True),
        (("campaignMutationAuthorized",), True),
        (("evidenceEvaluationAuthorized",), True),
        (("executionAuthorized",), True),
        (("confirmationAuthorized",), True),
        (("findingConfirmed",), True),
    ],
)
def test_profile_assurance_policy_rejects_substitution_or_escalation(
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    payload = deepcopy(
        registered_profile_assurance_floor_policy().model_dump(
            mode="json",
            by_alias=True,
        )
    )
    if replacement == "reverse":
        replacement = list(reversed(payload["floors"]))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        ProfileAssuranceFloorPolicy.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("floorRegistered", 1),
        ("higherDepthRequirementAcceptable", "true"),
        ("profileSelectionAuthorized", 0),
        ("campaignMutationAuthorized", "false"),
        ("evidenceEvaluationAuthorized", 0),
        ("executionAuthorized", "false"),
        ("confirmationAuthorized", 0),
        ("findingConfirmed", "false"),
    ],
)
def test_profile_assurance_floor_rejects_boolean_coercion(
    field: str,
    replacement: object,
) -> None:
    payload = resolve_profile_assurance_floor(
        "pajin.profile.ctf",
        "1.0.0",
    ).model_dump(mode="json", by_alias=True)
    payload[field] = replacement

    with pytest.raises(ValidationError):
        ProfileAssuranceFloor.model_validate(payload)


def test_standalone_floor_cannot_weaken_code_owned_profile_mapping() -> None:
    floor = resolve_profile_assurance_floor("pajin.profile.ai-assessment", "1.0.0")
    payload = floor.model_dump(mode="json", by_alias=True)
    weaker = resolve_validation_depth_requirement(ValidationDepth.SINGLE_VALIDITY_REPLAY)
    payload.update(
        {
            "floorId": "",
            "floorDigest": "",
            "minimumDepth": weaker.depth,
            "minimumDepthOrdinal": weaker.depth_ordinal,
            "minimumRequirementDigest": weaker.requirement_digest,
            "minimumRequirement": weaker.model_dump(mode="json", by_alias=True),
        }
    )

    with pytest.raises(ValidationError, match="code-owned depth mapping"):
        ProfileAssuranceFloor.model_validate(payload)


@pytest.mark.parametrize(
    ("profile_id", "profile_version"),
    [
        ("pajin.profile.unknown", "1.0.0"),
        ("pajin.profile.ctf", "latest"),
        ("pajin.profile.ctf", "2.0.0"),
    ],
)
def test_profile_assurance_resolution_rejects_unknown_profile_or_version(
    profile_id: str,
    profile_version: str,
) -> None:
    with pytest.raises(ProfileAssuranceFloorError, match="not registered"):
        resolve_profile_assurance_floor(profile_id, profile_version)


@pytest.mark.parametrize("depth", ("latest", "validity", "impact-replay", ""))
def test_profile_floor_comparison_rejects_unknown_depth(depth: str) -> None:
    with pytest.raises(ProfileAssuranceFloorError, match="not registered"):
        validation_depth_requirement_meets_profile_floor(
            "pajin.profile.ctf",
            "1.0.0",
            depth,
        )


@pytest.mark.parametrize(
    "script",
    (
        ("import pajin.modes.ai_redteam.replay; import pajin.workflow.profile_assurance"),
        ("import pajin.workflow.profile_assurance; import pajin.modes.ai_redteam.replay"),
    ),
)
def test_profile_assurance_import_orders_do_not_cycle(script: str) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    existing_pythonpath = environment.get("PYTHONPATH")
    source_root = str(repository_root / "src")
    environment["PYTHONPATH"] = (
        source_root
        if not existing_pythonpath
        else f"{source_root}{os.pathsep}{existing_pythonpath}"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
