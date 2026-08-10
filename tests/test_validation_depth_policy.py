from __future__ import annotations

from copy import deepcopy
from typing import cast

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    VALIDATION_DEPTH_POLICY_API_VERSION,
    ValidationDepth,
    ValidationDepthPolicy,
    ValidationDepthPolicyError,
    ValidationDepthRequirement,
    registered_validation_depth_policy,
    resolve_validation_depth_requirement,
)
from pajin.domain.validation import AtomicClaimType, ClaimReplayStatus
from pajin.domain.validation_controls import (
    ValidationControlContrast,
    ValidationControlKind,
)


def test_registered_validation_depth_policy_is_bounded_and_monotonic() -> None:
    policy = registered_validation_depth_policy()

    assert policy.api_version == VALIDATION_DEPTH_POLICY_API_VERSION
    assert policy.policy_id == "val-002:validation-depth-policy"
    assert policy.campaign_mode_constraint == "none"
    assert policy.supported_claim_types == (AtomicClaimType.VALIDITY,)
    assert policy.replay_repetition_ceiling == 20
    assert tuple(item.depth for item in policy.requirements) == tuple(ValidationDepth)
    assert tuple(item.depth_ordinal for item in policy.requirements) == (1, 2, 3)
    assert tuple(item.minimum_replay_repetitions for item in policy.requirements) == (
        1,
        1,
        2,
    )
    assert all(
        item.required_claim_types == (AtomicClaimType.VALIDITY,)
        and item.required_claim_replay_status is ClaimReplayStatus.REPRODUCED
        and item.independence_scope == "fresh-execution-lineage"
        for item in policy.requirements
    )

    single, controlled, repeated = policy.requirements
    assert single.required_control_kinds == ()
    assert single.minimum_control_executions_per_kind == 0
    assert single.required_control_contrast is None
    for requirement in (controlled, repeated):
        assert requirement.required_control_kinds == tuple(ValidationControlKind)
        assert requirement.minimum_control_executions_per_kind == 1
        assert requirement.required_control_contrast is ValidationControlContrast.OBSERVED


def test_validation_depth_policy_round_trips_and_resolves_exact_versions() -> None:
    first = registered_validation_depth_policy()
    second = registered_validation_depth_policy()

    assert first == second
    assert (
        ValidationDepthPolicy.model_validate(first.model_dump(mode="json", by_alias=True)) == first
    )
    assert len(first.policy_digest) == 64
    assert len({item.requirement_digest for item in first.requirements}) == 3
    for requirement in first.requirements:
        assert resolve_validation_depth_requirement(requirement.depth) == requirement
        assert resolve_validation_depth_requirement(requirement.depth.value) == requirement


def test_validation_depth_policy_grants_no_evidence_or_execution_authority() -> None:
    policy = registered_validation_depth_policy()

    assert policy.profile_assurance_floor_bound is False
    assert policy.evidence_evaluation_authorized is False
    assert policy.execution_authorized is False
    assert policy.confirmation_authorized is False
    assert policy.finding_confirmed is False
    assert all(
        item.fresh_session_per_replay_required
        and item.fresh_capability_per_execution_required
        and item.distinct_request_per_execution_required
        and item.evidence_lineage_required
        and item.policy_only
        and not item.evidence_evaluation_authorized
        and not item.execution_authorized
        and not item.confirmation_authorized
        and not item.finding_confirmed
        for item in policy.requirements
    )
    for forbidden in (
        "campaign",
        "profile",
        "claim_replay",
        "control_receipts",
        "validation_decision",
        "finding",
    ):
        assert forbidden not in ValidationDepthPolicy.model_fields


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("policyDigest",), "0" * 64),
        (("supportedClaimTypes",), ["impact"]),
        (("requirements",), "reverse"),
        (("requirements", 0, "requirementDigest"), "1" * 64),
        (("requirements", 0, "depthOrdinal"), 2),
        (("requirements", 0, "minimumReplayRepetitions"), 2),
        (("requirements", 0, "requiredControlKinds"), ["baseline"]),
        (("requirements", 1, "requiredControlKinds"), []),
        (("requirements", 1, "requiredControlContrast"), None),
        (("requirements", 2, "minimumReplayRepetitions"), 1),
        (("profileAssuranceFloorBound",), True),
        (("evidenceEvaluationAuthorized",), True),
        (("executionAuthorized",), True),
        (("confirmationAuthorized",), True),
        (("findingConfirmed",), True),
    ],
)
def test_validation_depth_policy_rejects_substitution_or_escalation(
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    payload = deepcopy(registered_validation_depth_policy().model_dump(mode="json", by_alias=True))
    if replacement == "reverse":
        replacement = list(reversed(payload["requirements"]))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        ValidationDepthPolicy.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("freshSessionPerReplayRequired", 1),
        ("freshCapabilityPerExecutionRequired", "true"),
        ("distinctRequestPerExecutionRequired", 1),
        ("evidenceLineageRequired", "true"),
        ("policyOnly", 1),
        ("evidenceEvaluationAuthorized", 0),
        ("executionAuthorized", "false"),
        ("confirmationAuthorized", 0),
        ("findingConfirmed", "false"),
    ],
)
def test_validation_depth_requirement_rejects_boolean_coercion(
    field: str,
    replacement: object,
) -> None:
    payload = resolve_validation_depth_requirement(
        ValidationDepth.SINGLE_VALIDITY_REPLAY
    ).model_dump(mode="json", by_alias=True)
    payload[field] = replacement

    with pytest.raises(ValidationError):
        ValidationDepthRequirement.model_validate(payload)


def test_standalone_requirement_cannot_rewrite_code_owned_policy() -> None:
    policy = registered_validation_depth_policy()
    requirement_payload = policy.requirements[0].model_dump(mode="json", by_alias=True)
    requirement_payload["minimumReplayRepetitions"] = 2
    requirement_payload["requirementDigest"] = ""
    substituted = ValidationDepthRequirement.model_validate(requirement_payload)
    policy_payload = policy.model_dump(mode="json", by_alias=True)
    policy_payload["requirements"][0] = substituted.model_dump(mode="json", by_alias=True)
    policy_payload["policyDigest"] = ""

    with pytest.raises(ValidationError, match="differ from code authority"):
        ValidationDepthPolicy.model_validate(policy_payload)


@pytest.mark.parametrize(
    "depth",
    ("latest", "validity", "impact-replay", "", 1, None),
)
def test_validation_depth_resolution_rejects_aliases_or_unknown_values(
    depth: object,
) -> None:
    with pytest.raises(ValidationDepthPolicyError, match="not registered"):
        resolve_validation_depth_requirement(cast(ValidationDepth | str, depth))
