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
from pajin.capabilities.network_service import NetworkServiceProtocolBudget
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow.network_measured_case_authority import (
    NetworkExpectedClassifierOutcome,
    NetworkImageIdentityProfile,
    NetworkMeasuredCaseAuthority,
    NetworkMeasuredCaseAuthorityError,
    NetworkMeasuredCaseRegistry,
    NetworkMeasurementImageRole,
    NetworkMetricFloorComparison,
    NetworkPrivateGroundTruthBinding,
    NetworkTCPBannerEmitterProfile,
    load_network_measured_case_authority,
    registered_network_measured_case_mapping,
)
from pajin.workflow.network_replay_benchmark import (
    NetworkBenchmarkGroundTruthClass,
    registered_network_service_benchmark_fixture_profile,
)

_CASE_IDS = (
    "network-fixture:ftp-known-positive",
    "network-fixture:imap-known-positive",
    "network-fixture:pop3-known-positive",
    "network-fixture:smtp-known-positive",
    "network-fixture:ssh-known-positive",
    "network-fixture:unknown-negative-control",
)


def test_exact_six_case_membership_is_canonical_and_binds_unchanged_net001d() -> None:
    mapping = registered_network_measured_case_mapping()
    authority = mapping.public_authority
    private = mapping.private_binding
    net001d = registered_network_service_benchmark_fixture_profile()

    assert tuple(case.case_id for case in authority.public_registry.cases) == _CASE_IDS
    assert tuple(case.case_id for case in private.cases) == _CASE_IDS
    assert tuple(case.fixture for case in private.cases) == net001d.cases
    assert authority.public_registry.known_positive_count == 5
    assert authority.public_registry.negative_control_count == 1
    assert authority.private_ground_truth_binding_digest == private.binding_digest
    assert private.net001d_profile_id == net001d.profile_id
    assert private.net001d_profile_digest == net001d.profile_digest
    assert (
        load_network_measured_case_authority(
            authority,
            private_ground_truth_binding=private,
        )
        == authority
    )
    assert (
        NetworkMeasuredCaseAuthority.model_validate_json(authority.model_dump_json(by_alias=True))
        == authority
    )


def test_public_wire_excludes_private_banner_and_expected_label_fields() -> None:
    mapping = registered_network_measured_case_mapping()
    public_wire = json.dumps(
        mapping.public_authority.model_dump(mode="json", by_alias=True),
        sort_keys=True,
    )
    private_wire = json.dumps(
        mapping.private_binding.model_dump(mode="json", by_alias=True),
        sort_keys=True,
    )

    assert '"bannerBase64"' not in public_wire
    assert '"bannerSha256"' not in public_wire
    assert '"expectedServiceName"' not in public_wire
    assert '"expectedClassifierOutcome"' not in public_wire
    assert '"fixtureMaterialization"' not in public_wire
    assert '"bannerBase64"' in private_wire
    assert '"expectedServiceName"' in private_wire
    for case in mapping.private_binding.cases:
        assert case.fixture.banner_base64 not in public_wire


def test_unknown_control_means_unresolved_and_never_confirms_a_service() -> None:
    mapping = registered_network_measured_case_mapping()
    public = mapping.public_authority.public_registry.cases[-1]
    private = mapping.private_binding.cases[-1]

    assert public.case_id == "network-fixture:unknown-negative-control"
    assert public.ground_truth_class is NetworkBenchmarkGroundTruthClass.NEGATIVE_CONTROL
    assert public.measurement_role == "classifier-negative-control"
    assert private.fixture.expected_service_name is None
    assert (
        private.expected_classifier_outcome
        is NetworkExpectedClassifierOutcome.PROTOCOL_LABEL_UNRESOLVED
    )
    assert mapping.public_authority.service_confirmation_authorized is False
    assert mapping.public_authority.finding_authority is False
    assert mapping.public_authority.validation_floor_policy.service_confirmation_authorized is False


def test_case_order_substitution_and_private_ground_truth_drift_fail_closed() -> None:
    mapping = registered_network_measured_case_mapping()
    registry_wire = mapping.public_authority.public_registry.model_dump(
        mode="json",
        by_alias=True,
    )
    registry_wire["registryId"] = ""
    registry_wire["registryDigest"] = ""
    registry_wire["cases"] = list(reversed(registry_wire["cases"]))
    with pytest.raises(ValidationError, match="membership or order"):
        NetworkMeasuredCaseRegistry.model_validate(registry_wire)

    private_wire = mapping.private_binding.model_dump(mode="json", by_alias=True)
    private_wire["bindingId"] = ""
    private_wire["bindingDigest"] = ""
    private_wire["cases"][0]["caseDigest"] = ""
    private_wire["cases"][0]["fixture"]["expectedServiceName"] = "ssh"
    with pytest.raises(ValidationError, match="differs from NET-001D"):
        NetworkPrivateGroundTruthBinding.model_validate(private_wire)

    foreign_private = mapping.private_binding.model_copy(
        update={"net001d_profile_digest": "f" * 64}
    )
    with pytest.raises(NetworkMeasuredCaseAuthorityError, match="failed closed"):
        load_network_measured_case_authority(
            mapping.public_authority,
            private_ground_truth_binding=foreign_private,
        )


def test_content_addresses_reject_digest_drift_and_noncanonical_wire() -> None:
    authority = registered_network_measured_case_mapping().public_authority
    drifted = authority.model_dump(mode="json", by_alias=True)
    drifted["authorityDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="authority Digest differs"):
        NetworkMeasuredCaseAuthority.model_validate(drifted)

    extra = authority.model_dump(mode="json", by_alias=True)
    extra["provider"] = "caller-selected"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NetworkMeasuredCaseAuthority.model_validate(extra)

    coerced = authority.model_dump(mode="json", by_alias=True)
    coerced["executionAuthorized"] = 0
    with pytest.raises(ValidationError, match="must be boolean false"):
        NetworkMeasuredCaseAuthority.model_validate(coerced)

    hidden_escalation = authority.model_copy(update={"execution_authorized": True})
    with pytest.raises(NetworkMeasuredCaseAuthorityError, match="failed closed"):
        load_network_measured_case_authority(
            hidden_escalation,
            private_ground_truth_binding=registered_network_measured_case_mapping().private_binding,
        )


def test_emitter_and_image_profiles_reject_caller_or_foreign_configuration() -> None:
    authority = registered_network_measured_case_mapping().public_authority
    emitter = authority.emitter_profile
    images = authority.image_identity_profile

    assert emitter.fixed_container_port == 18_080
    assert emitter.accepted_configuration == "one-code-owned-case-id"
    assert emitter.target_application_read_bytes == 0
    assert emitter.worker_application_write_bytes == 0
    assert emitter.docker_image_built is False
    assert tuple(role.role for role in images.roles) == (
        NetworkMeasurementImageRole.TARGET,
        NetworkMeasurementImageRole.WORKER,
        NetworkMeasurementImageRole.PROXY,
    )
    assert all(role.immutable_observed_image_id_required is True for role in images.roles)
    assert all(role.docker_image_built is False for role in images.roles)
    assert all(role.observed_image_id_bound is False for role in images.roles)
    assert all(role.caller_selected_image_authorized is False for role in images.roles)

    emitter_wire = emitter.model_dump(mode="json", by_alias=True)
    emitter_wire["profileId"] = ""
    emitter_wire["profileDigest"] = ""
    emitter_wire["fixedContainerPort"] = 21
    with pytest.raises(ValidationError):
        NetworkTCPBannerEmitterProfile.model_validate(emitter_wire)

    image_wire = images.model_dump(mode="json", by_alias=True)
    image_wire["profileId"] = ""
    image_wire["profileDigest"] = ""
    image_wire["roles"][0]["identityId"] = ""
    image_wire["roles"][0]["identityDigest"] = ""
    image_wire["roles"][0]["contractDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="image role contract differs"):
        NetworkImageIdentityProfile.model_validate(image_wire)

    image_with_observed_id = images.model_dump(mode="json", by_alias=True)
    image_with_observed_id["roles"][0]["observedImageId"] = "sha256:" + "a" * 64
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NetworkImageIdentityProfile.model_validate(image_with_observed_id)

    with pytest.raises(TypeError):
        registered_network_measured_case_mapping(  # type: ignore[call-arg]
            target_image_id="sha256:" + "a" * 64
        )


def test_protocol_binds_exact_domain_plan_budget_and_source_replay_order() -> None:
    authority = registered_network_measured_case_mapping().public_authority
    protocol = authority.measurement_protocol
    plan = resolve_registered_domain_benchmark_plan(protocol.domain_benchmark_plan)

    assert plan.domain_classification.domain is SecurityDomain.NETWORK
    assert plan.validation_strategy is DomainValidationStrategy.FRESH_WORKER_PROTOCOL_REPLAY
    assert protocol.domain_benchmark_plan == authority.domain_benchmark_plan
    assert protocol.protocol_budget == NetworkServiceProtocolBudget()
    assert tuple(case.case_id for case in protocol.source_case_order) == _CASE_IDS
    assert tuple(case.case_id for case in protocol.replay_case_order) == _CASE_IDS
    assert protocol.minimum_source_executions == 6
    assert protocol.minimum_replay_executions == 6
    assert protocol.fresh_disposable_target_per_case_required is True
    assert protocol.fresh_worker_execution_per_case_required is True
    assert protocol.source_and_replay_authority_disjoint_required is True
    assert protocol.proxy_only_worker_network_required is True
    assert protocol.no_published_target_port_required is True
    assert protocol.application_protocol_write_authorized is False


def test_floor_preserves_exact_domain006_applicability_and_network_denominators() -> None:
    floor = registered_network_measured_case_mapping().public_authority.validation_floor_policy
    requirements = {item.metric.metric_id: item for item in floor.requirements}

    assert len(requirements) == 14
    assert (
        sum(
            item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
            for item in requirements.values()
        )
        == 11
    )
    assert {
        metric_id: item.not_applicable_reason
        for metric_id, item in requirements.items()
        if item.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE
    } == {
        "common.task-success-rate": (
            DomainBenchmarkNotApplicableReason.DETECTION_RECALL_IS_PRIMARY_OUTCOME
        ),
        "common.total-cost-usd": DomainBenchmarkNotApplicableReason.NO_MONETARY_COST_MODEL,
        "common.cleanup-success-rate": (
            DomainBenchmarkNotApplicableReason.READ_ONLY_NO_CLEANUP_REQUIRED
        ),
    }
    network_accuracy = requirements["network.service-identification-accuracy"]
    assert network_accuracy.comparison is NetworkMetricFloorComparison.AT_LEAST
    assert network_accuracy.threshold_numerator == 1
    assert network_accuracy.threshold_denominator == 1
    assert network_accuracy.minimum_denominator == 6
    assert requirements["common.detection-recall"].minimum_denominator == 5
    assert requirements["common.false-positive-rate"].minimum_denominator == 1
    assert requirements["common.policy-denial-correctness"].minimum_denominator == 5
    assert floor.required_policy_denial_control_count == 5
    assert floor.cleanup_is_mandatory_admission_not_numeric_action_metric is True
    assert floor.measurement_evaluation_authorized is False
    assert floor.validation_floor_satisfied is False


def test_every_requested_execution_and_projection_authority_stays_false() -> None:
    authority = registered_network_measured_case_mapping().public_authority
    false_fields = (
        "docker_image_build_authorized",
        "target_selection_authorized",
        "target_creation_authorized",
        "network_creation_authorized",
        "provider_selection_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "gateway_execution_authorized",
        "worker_execution_authorized",
        "live_measurement_authorized",
        "measurement_observed",
        "validation_floor_satisfied",
        "product_projection_authorized",
        "graph_mutation_authorized",
        "finding_authority",
        "reporting_authorized",
        "external_delivery_authorized",
        "dns_authorized",
        "udp_authorized",
        "port_range_authorized",
        "port_enumeration_authorized",
        "raw_socket_authorized",
        "application_protocol_write_authorized",
        "credential_access_authorized",
        "external_target_authorized",
        "production_target_authorized",
        "service_confirmation_authorized",
        "general_scanner_authorized",
        "caller_configuration_authorized",
        "execution_authorized",
    )

    assert all(getattr(authority, field) is False for field in false_fields)
    protocol = authority.measurement_protocol
    assert protocol.target_created is False
    assert protocol.network_created is False
    assert protocol.provider_selected is False
    assert protocol.gateway_execution_authorized is False
    assert protocol.worker_execution_authorized is False
    assert protocol.live_measurement_authorized is False
    assert protocol.execution_authorized is False
