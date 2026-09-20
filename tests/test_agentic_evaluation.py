from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from pajin.agentic.evaluation import (
    AGENTIC_EVALUATION_ARM_ORDER,
    AGENTIC_EVALUATION_METRIC_ORDER,
    AGENTIC_EVALUATION_TARGET_ROLE_ORDER,
    AgenticCampaignEvaluationPlan,
    AgenticEvaluationArm,
    AgenticEvaluationArmId,
    AgenticEvaluationArmPairId,
    AgenticEvaluationImprovementDirection,
    AgenticEvaluationMetric,
    AgenticEvaluationMetricUnit,
    AgenticEvaluationMetricValue,
    AgenticEvaluationRunProtocol,
    AgenticEvaluationTargetClass,
    AgenticEvaluationTargetRole,
    ExactEvaluationRef,
    ExternalEvaluationAuthorityBoundary,
    FrozenEvaluationTargetCoordinate,
    required_agentic_evaluation_arm_pairs,
    required_agentic_evaluation_metric_specs,
)


def _ref(_label: str, ordinal: int) -> ExactEvaluationRef:
    digest = f"{ordinal:064x}"
    return ExactEvaluationRef(
        refId=f"evaluation-ref_{digest}",
        refVersion="1.0.0",
        refDigest=digest,
    )


def _target(
    role: AgenticEvaluationTargetRole,
    target_class: AgenticEvaluationTargetClass,
    ordinal: int,
) -> FrozenEvaluationTargetCoordinate:
    return FrozenEvaluationTargetCoordinate(
        role=role,
        targetClass=target_class,
        targetFactoryRef=_ref(f"factory-{ordinal}", ordinal),
        targetProfileRef=_ref(f"profile-{ordinal}", ordinal + 1),
        providerProfileRef=_ref(f"provider-{ordinal}", ordinal + 2),
        adapterRef=_ref(f"adapter-{ordinal}", ordinal + 3),
        resetProfileRef=_ref(f"reset-{ordinal}", ordinal + 4),
        privateEvaluatorCommitmentRef=_ref(f"evaluator-{ordinal}", ordinal + 5),
        groundTruthCommitmentDigest=f"{ordinal + 6:064x}",
    )


def _plan() -> AgenticCampaignEvaluationPlan:
    targets = (
        _target(
            AgenticEvaluationTargetRole.DEVELOPMENT_REGRESSION,
            AgenticEvaluationTargetClass.OWASP_JUICE_SHOP,
            1,
        ),
        _target(
            AgenticEvaluationTargetRole.SEPARATE_AUTHORIZED,
            AgenticEvaluationTargetClass.SEPARATE_AUTHORIZED_WEB,
            8,
        ),
        _target(
            AgenticEvaluationTargetRole.PRIVATE_HOLDOUT,
            AgenticEvaluationTargetClass.PRIVATE_HOLDOUT_WEB,
            16,
        ),
    )
    arms = (
        AgenticEvaluationArm(
            armId=AgenticEvaluationArmId.FIXED_CODE_BASELINE,
            implementationRef=_ref("fixed", 24),
            modelRuntimeExpected=False,
            adaptiveReplanningExpected=False,
            dynamicSupervisorExpected=False,
        ),
        AgenticEvaluationArm(
            armId=AgenticEvaluationArmId.SINGLE_TURN_NO_REPLAN,
            implementationRef=_ref("single", 25),
            modelRuntimeExpected=True,
            adaptiveReplanningExpected=False,
            dynamicSupervisorExpected=False,
        ),
        AgenticEvaluationArm(
            armId=AgenticEvaluationArmId.DYNAMIC_REPLAN,
            implementationRef=_ref("dynamic", 26),
            modelRuntimeExpected=True,
            adaptiveReplanningExpected=True,
            dynamicSupervisorExpected=True,
        ),
    )
    return AgenticCampaignEvaluationPlan(
        targetCoordinates=targets,
        arms=arms,
        protocol=AgenticEvaluationRunProtocol(
            protocolRef=_ref("protocol", 27),
            seeds=(101, 202),
            repetitionsPerSeed=2,
            timeoutSeconds=900,
            maxRequests=500,
            maxModelCalls=50,
            maxTotalTokens=500_000,
            maxCostMicrousd=50_000_000,
        ),
        externalAuthority=ExternalEvaluationAuthorityBoundary(
            approvalContractRef=_ref("approval-contract", 28),
            permitContractRef=_ref("permit-contract", 29),
            privateEvaluatorContractRef=_ref("evaluator-contract", 30),
        ),
    )


def _wire(plan: AgenticCampaignEvaluationPlan) -> dict[str, Any]:
    return plan.model_dump(mode="json", by_alias=True)


def test_plan_is_deterministic_exact_three_arm_and_non_authoritative() -> None:
    first = _plan()
    second = AgenticCampaignEvaluationPlan.model_validate(_wire(first))

    assert first == second
    assert first.plan_id == f"agentic-evaluation-plan_{first.plan_digest}"
    assert tuple(target.role for target in first.target_coordinates) == (
        AGENTIC_EVALUATION_TARGET_ROLE_ORDER
    )
    assert tuple(arm.arm_id for arm in first.arms) == AGENTIC_EVALUATION_ARM_ORDER
    assert tuple(spec.metric for spec in first.protocol.metric_specs) == (
        AGENTIC_EVALUATION_METRIC_ORDER
    )
    assert first.arm_pairs == required_agentic_evaluation_arm_pairs()
    wire = _wire(first)
    assert wire["targetCoordinates"][0]["targetClass"] == "owasp-juice-shop"
    assert wire["developmentTargetGeneralizationEligible"] is False
    assert wire["externalAuthority"]["authorityMaterialEmbedded"] is False
    assert all(
        wire[field] is False
        for field in (
            "liveMeasurementCompleted",
            "scopeAuthority",
            "capabilityAuthority",
            "approvalAuthority",
            "permitAuthority",
            "executionAuthority",
            "findingAuthority",
            "graphAuthority",
            "evaluatorAuthority",
        )
    )


def test_public_plan_contains_only_commitments_not_ground_truth_or_locators() -> None:
    wire = _wire(_plan())
    serialized = str(wire)

    assert "groundTruthCommitmentDigest" in serialized
    assert "groundTruthCases" not in serialized
    assert "matcherIds" not in serialized
    assert "targetLocator" not in serialized
    assert "approvalToken" not in serialized
    assert "actionPermit" not in serialized
    assert "privateEvaluatorSecret" not in serialized
    assert all(
        target["groundTruthContentIncluded"] is False
        and target["publicLocatorIncluded"] is False
        and target["approvalEmbedded"] is False
        and target["permitEmbedded"] is False
        and target["evaluatorAuthorityEmbedded"] is False
        for target in wire["targetCoordinates"]
    )


def test_latest_unknown_and_private_ground_truth_fields_fail_closed() -> None:
    digest = "1" * 64
    with pytest.raises(ValidationError, match="refVersion"):
        ExactEvaluationRef(
            refId=f"evaluation-ref_{digest}",
            refVersion="latest",
            refDigest=digest,
        )

    with pytest.raises(ValidationError, match="refId"):
        ExactEvaluationRef(
            refId="127.0.0.1:3000",
            refVersion="1.0.0",
            refDigest=digest,
        )

    target = _plan().target_coordinates[0].model_dump(mode="json", by_alias=True)
    target["groundTruthCases"] = [{"finding": "not-public"}]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        FrozenEvaluationTargetCoordinate.model_validate(target)


@pytest.mark.parametrize(
    ("role", "target_class"),
    (
        (
            AgenticEvaluationTargetRole.DEVELOPMENT_REGRESSION,
            AgenticEvaluationTargetClass.SEPARATE_AUTHORIZED_WEB,
        ),
        (
            AgenticEvaluationTargetRole.SEPARATE_AUTHORIZED,
            AgenticEvaluationTargetClass.OWASP_JUICE_SHOP,
        ),
        (
            AgenticEvaluationTargetRole.PRIVATE_HOLDOUT,
            AgenticEvaluationTargetClass.OWASP_JUICE_SHOP,
        ),
    ),
)
def test_target_roles_are_non_interchangeable(
    role: AgenticEvaluationTargetRole,
    target_class: AgenticEvaluationTargetClass,
) -> None:
    with pytest.raises(ValidationError, match="non-interchangeable role"):
        _target(role, target_class, 1)


def test_target_and_arm_reordering_or_substitution_fails_closed() -> None:
    plan = _plan()
    wire = _wire(plan)

    swapped_targets = deepcopy(wire)
    swapped_targets["targetCoordinates"][0], swapped_targets["targetCoordinates"][1] = (
        swapped_targets["targetCoordinates"][1],
        swapped_targets["targetCoordinates"][0],
    )
    swapped_targets["planId"] = ""
    swapped_targets["planDigest"] = ""
    with pytest.raises(ValidationError, match="canonical order"):
        AgenticCampaignEvaluationPlan.model_validate(swapped_targets)

    swapped_arms = deepcopy(wire)
    swapped_arms["arms"][1], swapped_arms["arms"][2] = (
        swapped_arms["arms"][2],
        swapped_arms["arms"][1],
    )
    swapped_arms["planId"] = ""
    swapped_arms["planDigest"] = ""
    with pytest.raises(ValidationError, match="canonical three-arm order"):
        AgenticCampaignEvaluationPlan.model_validate(swapped_arms)

    forged_digest = deepcopy(wire)
    forged_digest["planDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Plan Digest differs"):
        AgenticCampaignEvaluationPlan.model_validate(forged_digest)


def test_role_relabelling_cannot_reuse_target_identity_or_ground_truth() -> None:
    wire = _wire(_plan())
    same_identity = deepcopy(wire)
    source = same_identity["targetCoordinates"][0]
    destination = same_identity["targetCoordinates"][1]
    for field in (
        "targetFactoryRef",
        "targetProfileRef",
        "providerProfileRef",
        "adapterRef",
    ):
        destination[field] = deepcopy(source[field])
    destination["targetIdentityDigest"] = ""
    destination["coordinateId"] = ""
    destination["coordinateDigest"] = ""
    same_identity["planId"] = ""
    same_identity["planDigest"] = ""
    with pytest.raises(ValidationError, match="target identities must be distinct"):
        AgenticCampaignEvaluationPlan.model_validate(same_identity)

    same_truth = deepcopy(wire)
    same_truth["targetCoordinates"][1]["groundTruthCommitmentDigest"] = source[
        "groundTruthCommitmentDigest"
    ]
    same_truth["targetCoordinates"][1]["coordinateId"] = ""
    same_truth["targetCoordinates"][1]["coordinateDigest"] = ""
    same_truth["planId"] = ""
    same_truth["planDigest"] = ""
    with pytest.raises(ValidationError, match="Ground Truth commitments must be distinct"):
        AgenticCampaignEvaluationPlan.model_validate(same_truth)


def test_arm_semantics_and_pairs_cannot_be_relabelled() -> None:
    with pytest.raises(ValidationError, match="frozen three-arm design"):
        AgenticEvaluationArm(
            armId=AgenticEvaluationArmId.SINGLE_TURN_NO_REPLAN,
            implementationRef=_ref("wrong-single", 31),
            modelRuntimeExpected=True,
            adaptiveReplanningExpected=True,
            dynamicSupervisorExpected=True,
        )

    raw = required_agentic_evaluation_arm_pairs()[0].model_dump(mode="json", by_alias=True)
    raw["candidateArmId"] = AgenticEvaluationArmId.DYNAMIC_REPLAN.value
    with pytest.raises(ValidationError, match="frozen causal comparison"):
        type(required_agentic_evaluation_arm_pairs()[0]).model_validate(raw)
    assert required_agentic_evaluation_arm_pairs()[1].pair_id is (
        AgenticEvaluationArmPairId.SINGLE_TURN_VS_DYNAMIC
    )


def test_protocol_rejects_unpaired_or_incomplete_metric_contracts() -> None:
    plan = _plan()
    raw = plan.protocol.model_dump(mode="json", by_alias=True)

    raw["metricSpecs"] = raw["metricSpecs"][:-1]
    with pytest.raises(ValidationError):
        AgenticEvaluationRunProtocol.model_validate(raw)

    raw = plan.protocol.model_dump(mode="json", by_alias=True)
    raw["metricSpecs"][0]["unit"] = AgenticEvaluationMetricUnit.COUNT.value
    with pytest.raises(ValidationError, match="wrong unit"):
        AgenticEvaluationRunProtocol.model_validate(raw)

    raw = plan.protocol.model_dump(mode="json", by_alias=True)
    raw["pairedArmCoordinates"] = False
    with pytest.raises(ValidationError, match="literal true"):
        AgenticEvaluationRunProtocol.model_validate(raw)

    raw = plan.protocol.model_dump(mode="json", by_alias=True)
    raw["seeds"] = [202, 101]
    with pytest.raises(ValidationError, match="canonically sorted"):
        AgenticEvaluationRunProtocol.model_validate(raw)

    raw = plan.protocol.model_dump(mode="json", by_alias=True)
    raw["metricSpecs"][0]["formula"] = "caller-selected-formula"
    raw["metricSpecs"][0]["definitionDigest"] = ""
    with pytest.raises(ValidationError, match="changed calculation definition"):
        AgenticEvaluationRunProtocol.model_validate(raw)


def test_metric_specs_cover_quality_path_negative_replay_efficiency_and_safety() -> None:
    specs = required_agentic_evaluation_metric_specs()
    by_metric = {spec.metric: spec for spec in specs}

    assert tuple(by_metric) == AGENTIC_EVALUATION_METRIC_ORDER
    assert by_metric[AgenticEvaluationMetric.FINDING_RECALL].unit is (
        AgenticEvaluationMetricUnit.RATIO
    )
    assert by_metric[AgenticEvaluationMetric.VALID_ATTACK_PATH_PRECISION].unit is (
        AgenticEvaluationMetricUnit.RATIO
    )
    assert (
        by_metric[
            AgenticEvaluationMetric.DEFENDED_NEGATIVE_FALSE_POSITIVE_RATE
        ].improvement_direction
        is AgenticEvaluationImprovementDirection.LOWER_IS_BETTER
    )
    assert by_metric[AgenticEvaluationMetric.COVERAGE_AUC].paired_by_exact_coordinate is True
    assert by_metric[AgenticEvaluationMetric.REPLANNING_LIFT].unit is (
        AgenticEvaluationMetricUnit.RATIO_DELTA
    )
    assert by_metric[AgenticEvaluationMetric.VALID_PATHS_PER_REQUEST].unit is (
        AgenticEvaluationMetricUnit.RATE
    )
    assert by_metric[AgenticEvaluationMetric.VALID_PATHS_PER_THOUSAND_TOKENS].unit is (
        AgenticEvaluationMetricUnit.RATE
    )
    assert by_metric[AgenticEvaluationMetric.VALID_PATHS_PER_MINUTE].unit is (
        AgenticEvaluationMetricUnit.RATE
    )
    assert by_metric[AgenticEvaluationMetric.VALID_PATHS_PER_USD].unit is (
        AgenticEvaluationMetricUnit.RATE
    )
    assert (
        by_metric[AgenticEvaluationMetric.ACTUAL_AUTHORITY_VIOLATION_COUNT].improvement_direction
        is AgenticEvaluationImprovementDirection.ZERO_REQUIRED
    )
    assert all(len(spec.definition_digest) == 64 for spec in specs)


@pytest.mark.parametrize(
    ("metric", "unit", "value", "message"),
    (
        (
            AgenticEvaluationMetric.FINDING_RECALL,
            AgenticEvaluationMetricUnit.RATIO,
            1.01,
            "between zero and one",
        ),
        (
            AgenticEvaluationMetric.REPLANNING_LIFT,
            AgenticEvaluationMetricUnit.RATIO_DELTA,
            -1.01,
            "minus one and one",
        ),
        (
            AgenticEvaluationMetric.FORBIDDEN_PROPOSAL_COUNT,
            AgenticEvaluationMetricUnit.COUNT,
            1.5,
            "must be an integer",
        ),
        (
            AgenticEvaluationMetric.ACTUAL_AUTHORITY_VIOLATION_COUNT,
            AgenticEvaluationMetricUnit.COUNT,
            1.0,
            "must be zero",
        ),
    ),
)
def test_metric_values_are_bounded_and_authority_violations_must_be_zero(
    metric: AgenticEvaluationMetric,
    unit: AgenticEvaluationMetricUnit,
    value: float,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        AgenticEvaluationMetricValue(metric=metric, unit=unit, value=value)

    zero = AgenticEvaluationMetricValue(
        metric=AgenticEvaluationMetric.ACTUAL_AUTHORITY_VIOLATION_COUNT,
        unit=AgenticEvaluationMetricUnit.COUNT,
        value=0.0,
    )
    assert zero.value == 0
    assert zero.private_evaluator_evidence is False
    assert zero.finding_authority is False
    assert zero.graph_authority is False


def test_forged_authority_flags_and_mutation_fail_closed() -> None:
    plan = _plan()
    wire = _wire(plan)
    wire["executionAuthority"] = True
    with pytest.raises(ValidationError, match="literal false"):
        AgenticCampaignEvaluationPlan.model_validate(wire)

    with pytest.raises(ValidationError):
        plan.live_measurement_completed = True  # type: ignore[assignment]

    with pytest.raises(TypeError, match="forbid unchecked model_copy updates"):
        plan.model_copy(update={"execution_authority": True})

    forged_plan = BaseModel.model_copy(
        plan,
        update={"execution_authority": True, "live_measurement_completed": True},
    )
    with pytest.raises(ValidationError, match="literal false"):
        AgenticCampaignEvaluationPlan.model_validate(forged_plan)

    metric = AgenticEvaluationMetricValue(
        metric=AgenticEvaluationMetric.ACTUAL_AUTHORITY_VIOLATION_COUNT,
        unit=AgenticEvaluationMetricUnit.COUNT,
        value=0.0,
    )
    with pytest.raises(TypeError, match="forbid unchecked model_copy updates"):
        metric.model_copy(update={"value": 7.0})
    forged_metric = BaseModel.model_copy(metric, update={"value": 7.0})
    with pytest.raises(ValidationError, match="must be zero"):
        AgenticEvaluationMetricValue.model_validate(forged_metric)


def test_no_fixture_claims_to_be_a_real_or_completed_plan() -> None:
    plan = _plan()
    assert plan.live_measurement_completed is False
    assert all(
        component.ref_id == f"evaluation-ref_{component.ref_digest}"
        for target in plan.target_coordinates
        for component in (
            target.target_factory_ref,
            target.target_profile_ref,
            target.provider_profile_ref,
            target.adapter_ref,
            target.reset_profile_ref,
            target.private_evaluator_commitment_ref,
        )
    )
