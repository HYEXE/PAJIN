from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkNotApplicableReason,
    DomainValidationStrategy,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.redteam import RedteamGroundTruthClass
from pajin.domain.models import CampaignMode
from pajin.domain.security_domain import SecurityDomain
from pajin.domain.validation_controls import ValidationControlKind
from pajin.modes.ai_redteam.catalog import SYSTEM_PROMPT_DISCLOSURE_SCENARIO
from pajin.modes.ai_redteam.validation_controls import (
    KISA_M03_SCENARIO_ID,
    KISA_VALIDATION_CONTROL_EXECUTOR_ID,
    KISA_VALIDATION_CONTROL_MATERIALIZER_ID,
    KISA_VALIDATION_CONTROL_MATERIALIZER_VERSION,
    KISAAIChatValidationControlMaterializer,
)
from pajin.replay.compiler import replay_scenario_digest
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
from pajin.workflow.ai_measured_case_authority import (
    AI_M03_CASE_ID,
    AI_M03_TARGET_CONTAINER_PORT,
    AI_M03_TARGET_ROUTE,
    AIBenchmarkMetricFloorRequirement,
    AIImageIdentityProfile,
    AIM03MeasuredTargetProfile,
    AIM03PredecessorContract,
    AIMeasuredCaseAuthority,
    AIMeasuredCaseAuthorityError,
    AIMeasuredCaseRegistry,
    AIMeasurementImageRole,
    AIMeasurementOperationStage,
    AIMeasurementProtocol,
    AIMetricFloorComparison,
    AIPrivateGroundTruthBinding,
    load_ai_measured_case_authority,
    registered_ai_measured_case_mapping,
)
from pajin.workflow.ai_replay_benchmark import AI_ANALYSIS_REPLAY_BENCHMARK_API_VERSION


def test_exact_m03_membership_binds_ai001d_requirement_and_private_ground_truth() -> None:
    mapping = registered_ai_measured_case_mapping()
    authority = mapping.public_authority
    private = mapping.private_binding
    case = authority.public_registry.cases[0]
    scenario = SYSTEM_PROMPT_DISCLOSURE_SCENARIO

    assert tuple(item.case_id for item in authority.public_registry.cases) == (AI_M03_CASE_ID,)
    assert case.scenario_id == KISA_M03_SCENARIO_ID
    assert case.threat_class == "M03"
    assert case.tool_id == AIChatProbeTool.spec.tool_id
    assert case.method == "POST"
    assert private.case.ground_truth_class is RedteamGroundTruthClass.KNOWN_POSITIVE
    assert case.private_ground_truth_case_digest == private.case.case_digest
    assert private.case.scenario_digest == replay_scenario_digest(scenario)
    assert private.predecessor_contract == authority.predecessor_contract.reference()
    assert authority.private_ground_truth_binding_digest == private.binding_digest
    assert (
        authority.predecessor_contract.predecessor_api_version
        == AI_ANALYSIS_REPLAY_BENCHMARK_API_VERSION
    )
    assert authority.predecessor_contract.concrete_binding_required_for_measurement is True
    assert authority.predecessor_contract.concrete_binding_bound is False
    assert authority.predecessor_contract.ground_truth_case_bound is False
    assert authority.predecessor_contract.benchmark_measurement_observed is False
    assert (
        load_ai_measured_case_authority(authority, private_ground_truth_binding=private)
        == authority
    )
    assert (
        AIMeasuredCaseAuthority.model_validate_json(authority.model_dump_json(by_alias=True))
        == authority
    )


def test_public_wire_excludes_private_prompt_check_and_control_derivation() -> None:
    mapping = registered_ai_measured_case_mapping()
    public_wire = json.dumps(
        mapping.public_authority.model_dump(mode="json", by_alias=True),
        sort_keys=True,
    )
    private_wire = json.dumps(
        mapping.private_binding.model_dump(mode="json", by_alias=True),
        sort_keys=True,
    )
    scenario = SYSTEM_PROMPT_DISCLOSURE_SCENARIO
    assert scenario.probe is not None
    prompt = scenario.probe.turns[0].messages[0].content
    check = scenario.probe.checks[0]

    assert '"promptText"' not in public_wire
    assert '"groundTruthClass"' not in json.dumps(
        mapping.public_authority.public_registry.model_dump(mode="json", by_alias=True),
        sort_keys=True,
    )
    assert '"checkId"' not in public_wire
    assert '"checkValue"' not in public_wire
    assert '"expectedVulnerableOutcome"' not in public_wire
    assert '"controlDerivations"' not in public_wire
    assert prompt not in public_wire
    assert check.value not in public_wire
    assert '"promptText"' in private_wire
    assert '"groundTruthClass"' in private_wire
    assert '"checkValue"' in private_wire
    assert prompt in private_wire
    assert check.value in private_wire


def test_private_control_derivation_matches_code_owned_materializer_order() -> None:
    mapping = registered_ai_measured_case_mapping()
    private = mapping.private_binding
    scenario = SYSTEM_PROMPT_DISCLOSURE_SCENARIO
    assert scenario.probe is not None
    source = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class="M03",
        session_id="pajin:ai002a:source",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    controls = KISAAIChatValidationControlMaterializer(scenario).materialize(
        source.model_dump(mode="json"),
        nonce="ai002a",
    )

    assert private.control_materializer_id == KISA_VALIDATION_CONTROL_MATERIALIZER_ID
    assert private.control_materializer_version == KISA_VALIDATION_CONTROL_MATERIALIZER_VERSION
    assert private.control_executor_id == KISA_VALIDATION_CONTROL_EXECUTOR_ID
    assert private.control_mode == CampaignMode.AI_REDTEAM
    assert tuple(item.control_kind for item in private.control_derivations) == (
        ValidationControlKind.BASELINE,
        ValidationControlKind.NEGATIVE_CONTROL,
        ValidationControlKind.COUNTERFACTUAL,
    )
    assert tuple(item.control_kind for item in controls) == tuple(
        item.control_kind for item in private.control_derivations
    )
    assert tuple(item.expected_observed for item in controls) == (True, False, False)
    assert tuple(item.expected_observed for item in private.control_derivations) == (
        True,
        False,
        False,
    )
    assert controls[0].arguments["turns"] == source.model_dump(mode="json")["turns"]
    assert controls[0].arguments["checks"] == source.model_dump(mode="json")["checks"]
    assert controls[1].arguments["turns"] == source.model_dump(mode="json")["turns"]
    assert controls[1].arguments["checks"] != source.model_dump(mode="json")["checks"]
    assert controls[2].arguments["turns"] != source.model_dump(mode="json")["turns"]
    assert (
        controls[2].arguments["checks"][0]["value"]
        == source.model_dump(mode="json")["checks"][0]["value"]
    )


def test_membership_predecessor_and_private_substitution_fail_closed() -> None:
    mapping = registered_ai_measured_case_mapping()

    registry_wire = mapping.public_authority.public_registry.model_dump(
        mode="json",
        by_alias=True,
    )
    registry_wire["registryId"] = ""
    registry_wire["registryDigest"] = ""
    registry_wire["cases"][0]["caseId"] = "ai-fixture:m06-foreign"
    registry_wire["cases"][0]["caseDigest"] = ""
    with pytest.raises(ValidationError):
        AIMeasuredCaseRegistry.model_validate(registry_wire)

    predecessor_wire = mapping.public_authority.predecessor_contract.model_dump(
        mode="json",
        by_alias=True,
    )
    predecessor_wire["contractId"] = ""
    predecessor_wire["contractDigest"] = ""
    predecessor_wire["controlOrder"] = list(reversed(predecessor_wire["controlOrder"]))
    with pytest.raises(ValidationError, match="predecessor contract differs"):
        AIM03PredecessorContract.model_validate(predecessor_wire)

    private_wire = mapping.private_binding.model_dump(mode="json", by_alias=True)
    private_wire["bindingId"] = ""
    private_wire["bindingDigest"] = ""
    private_wire["case"]["caseDigest"] = ""
    private_wire["case"]["promptText"] = "foreign caller prompt"
    with pytest.raises(ValidationError, match="differs from exact KISA M03"):
        AIPrivateGroundTruthBinding.model_validate(private_wire)

    foreign_private = mapping.private_binding.model_copy(update={"binding_digest": "f" * 64})
    with pytest.raises(AIMeasuredCaseAuthorityError, match="failed closed"):
        load_ai_measured_case_authority(
            mapping.public_authority,
            private_ground_truth_binding=foreign_private,
        )


def test_content_addresses_reject_digest_drift_extra_fields_and_boolean_coercion() -> None:
    mapping = registered_ai_measured_case_mapping()
    authority = mapping.public_authority

    drifted = authority.model_dump(mode="json", by_alias=True)
    drifted["authorityDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="authority Digest differs"):
        AIMeasuredCaseAuthority.model_validate(drifted)

    extra = authority.model_dump(mode="json", by_alias=True)
    extra["provider"] = "caller-selected"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AIMeasuredCaseAuthority.model_validate(extra)

    coerced = authority.model_dump(mode="json", by_alias=True)
    coerced["executionAuthorized"] = 0
    with pytest.raises(ValidationError, match="must be boolean false"):
        AIMeasuredCaseAuthority.model_validate(coerced)

    hidden_escalation = authority.model_copy(update={"execution_authorized": True})
    with pytest.raises(AIMeasuredCaseAuthorityError, match="failed closed"):
        load_ai_measured_case_authority(
            hidden_escalation,
            private_ground_truth_binding=mapping.private_binding,
        )


def test_fixed_target_and_image_profiles_reject_route_image_and_caller_configuration() -> None:
    authority = registered_ai_measured_case_mapping().public_authority
    target = authority.target_profile
    images = authority.image_identity_profile

    assert target.internal_container_port == AI_M03_TARGET_CONTAINER_PORT
    assert target.route_path == AI_M03_TARGET_ROUTE
    assert target.method == "POST"
    assert target.target_mode == "vulnerable"
    assert target.run_as_user == "65532:65532"
    assert target.read_only_root_filesystem_required is True
    assert target.capabilities_dropped_all_required is True
    assert target.no_new_privileges_required is True
    assert target.internal_network_required is True
    assert target.no_published_host_port_required is True
    assert tuple(role.role for role in images.roles) == (
        AIMeasurementImageRole.TARGET,
        AIMeasurementImageRole.WORKER,
        AIMeasurementImageRole.PROXY,
    )
    assert all(role.immutable_observed_image_id_required is True for role in images.roles)
    assert all(role.docker_image_built is False for role in images.roles)
    assert all(role.observed_image_id_bound is False for role in images.roles)
    assert all(role.caller_selected_image_authorized is False for role in images.roles)

    target_wire = target.model_dump(mode="json", by_alias=True)
    target_wire["profileId"] = ""
    target_wire["profileDigest"] = ""
    target_wire["routePath"] = "/v1/foreign"
    with pytest.raises(ValidationError):
        AIM03MeasuredTargetProfile.model_validate(target_wire)

    image_wire = images.model_dump(mode="json", by_alias=True)
    image_wire["profileId"] = ""
    image_wire["profileDigest"] = ""
    image_wire["roles"][0]["identityId"] = ""
    image_wire["roles"][0]["identityDigest"] = ""
    image_wire["roles"][0]["contractDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="image role contract differs"):
        AIImageIdentityProfile.model_validate(image_wire)

    image_with_observed_id = images.model_dump(mode="json", by_alias=True)
    image_with_observed_id["roles"][0]["observedImageId"] = "sha256:" + "a" * 64
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AIImageIdentityProfile.model_validate(image_with_observed_id)

    with pytest.raises(TypeError):
        registered_ai_measured_case_mapping(  # type: ignore[call-arg]
            prompt="caller-selected"
        )


def test_protocol_binds_exact_domain_plan_accounting_and_canonical_operation_order() -> None:
    authority = registered_ai_measured_case_mapping().public_authority
    protocol = authority.measurement_protocol
    plan = resolve_registered_domain_benchmark_plan(protocol.domain_benchmark_plan)

    assert plan.domain_classification.domain is SecurityDomain.AI
    assert plan.validation_strategy is DomainValidationStrategy.FRESH_SESSION_INDEPENDENT_REPLAY
    assert protocol.domain_benchmark_plan == authority.domain_benchmark_plan
    assert tuple(item.ordinal for item in protocol.operations) == (1, 2, 3, 4, 5, 6)
    assert tuple(item.stage for item in protocol.operations) == (
        AIMeasurementOperationStage.SOURCE,
        AIMeasurementOperationStage.REPLAY,
        AIMeasurementOperationStage.REPLAY,
        AIMeasurementOperationStage.CONTROL,
        AIMeasurementOperationStage.CONTROL,
        AIMeasurementOperationStage.CONTROL,
    )
    assert tuple(item.repetition for item in protocol.operations) == (None, 1, 2, None, None, None)
    assert tuple(item.control_kind for item in protocol.operations) == (
        None,
        None,
        None,
        ValidationControlKind.BASELINE,
        ValidationControlKind.NEGATIVE_CONTROL,
        ValidationControlKind.COUNTERFACTUAL,
    )
    assert {item.case.case_id for item in protocol.operations} == {AI_M03_CASE_ID}
    assert protocol.registered_request_unit_count == 6
    assert protocol.registered_tool_call_count == 6
    assert protocol.request_unit_semantics == "one-authorized-single-turn-ai-chat-post"
    assert protocol.zero_model_provider_cost_requires_measurement is True
    assert protocol.source_replay_control_identity_disjoint_required is True
    assert protocol.target_cleanup_required is True
    assert protocol.zero_residue_required is True
    assert protocol.application_protocol_write_authorized is False

    reordered = protocol.model_dump(mode="json", by_alias=True)
    reordered["protocolId"] = ""
    reordered["protocolDigest"] = ""
    reordered["operations"] = list(reversed(reordered["operations"]))
    with pytest.raises(ValidationError, match="measurement protocol differs"):
        AIMeasurementProtocol.model_validate(reordered)


def test_floor_preserves_exact_domain006_ai_applicability_cost_and_denominators() -> None:
    floor = registered_ai_measured_case_mapping().public_authority.validation_floor_policy
    requirements = {item.metric.metric_id: item for item in floor.requirements}

    assert len(requirements) == 14
    assert (
        sum(
            item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
            for item in requirements.values()
        )
        == 12
    )
    assert {
        metric_id: item.not_applicable_reason
        for metric_id, item in requirements.items()
        if item.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE
    } == {
        "common.task-success-rate": (
            DomainBenchmarkNotApplicableReason.DETECTION_RECALL_IS_PRIMARY_OUTCOME
        ),
        "common.cleanup-success-rate": (
            DomainBenchmarkNotApplicableReason.READ_ONLY_NO_CLEANUP_REQUIRED
        ),
    }
    assert requirements["common.detection-recall"].minimum_denominator == 1
    assert requirements["common.false-positive-rate"].minimum_denominator == 2
    assert requirements["common.replay-or-reanalysis-success-rate"].minimum_denominator == 2
    assert requirements["common.policy-denial-correctness"].minimum_denominator == 8
    assert requirements["ai.threat-class-coverage"].minimum_denominator == 1
    assert (
        requirements["common.total-request-units"].comparison
        is AIMetricFloorComparison.MEASUREMENT_REQUIRED
    )
    assert requirements["common.total-cost-usd"].applicability is (
        DomainBenchmarkMetricApplicability.REQUIRED
    )
    assert (
        requirements["common.total-cost-usd"].comparison
        is AIMetricFloorComparison.MEASUREMENT_REQUIRED
    )
    assert floor.required_policy_denial_control_count == 8
    assert floor.request_units_must_be_measured is True
    assert floor.model_provider_cost_must_be_measured is True
    assert floor.cleanup_is_mandatory_admission_not_numeric_action_metric is True
    assert floor.zero_residue_required is True
    assert floor.measurement_evaluation_authorized is False
    assert floor.validation_floor_satisfied is False

    cost_wire = requirements["common.total-cost-usd"].model_dump(mode="json", by_alias=True)
    cost_wire["comparison"] = AIMetricFloorComparison.NOT_APPLICABLE.value
    with pytest.raises(ValidationError, match="metric floor differs"):
        AIBenchmarkMetricFloorRequirement.model_validate(cost_wire)


def test_every_runtime_projection_and_scope_expansion_authority_stays_false() -> None:
    authority = registered_ai_measured_case_mapping().public_authority
    false_fields = (
        "docker_image_build_authorized",
        "target_selection_authorized",
        "target_creation_authorized",
        "network_creation_authorized",
        "provider_selection_authorized",
        "prompt_materialization_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "action_permit_issuance_authorized",
        "grant_issuance_authorized",
        "gateway_execution_authorized",
        "tool_execution_authorized",
        "worker_execution_authorized",
        "application_protocol_write_authorized",
        "model_call_authorized",
        "live_measurement_authorized",
        "measurement_observed",
        "validation_floor_satisfied",
        "product_projection_authorized",
        "graph_mutation_authorized",
        "finding_authority",
        "reporting_authorized",
        "external_delivery_authorized",
        "credential_access_authorized",
        "external_provider_authorized",
        "external_target_authorized",
        "production_target_authorized",
        "arbitrary_prompt_authorized",
        "arbitrary_tool_authorized",
        "plugin_authorized",
        "rag_authorized",
        "mcp_authorized",
        "memory_mutation_authorized",
        "m06_authorized",
        "a04_authorized",
        "general_ai_scanner_authorized",
        "caller_configuration_authorized",
        "execution_authorized",
    )

    assert all(getattr(authority, field) is False for field in false_fields)
    protocol = authority.measurement_protocol
    assert all(
        getattr(protocol, field) is False
        for field in (
            "docker_image_build_authorized",
            "target_created",
            "network_created",
            "provider_selected",
            "prompt_materialized",
            "approval_satisfied",
            "action_permit_issuance_authorized",
            "grant_issuance_authorized",
            "gateway_execution_authorized",
            "tool_execution_authorized",
            "worker_execution_authorized",
            "application_protocol_write_authorized",
            "model_call_authorized",
            "live_measurement_authorized",
            "request_units_observed",
            "model_provider_cost_observed",
            "execution_authorized",
        )
    )
