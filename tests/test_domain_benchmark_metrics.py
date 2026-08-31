from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.benchmark import domain_metrics as domain_metrics_module
from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkMetricRequirement,
    DomainBenchmarkRegistry,
    DomainBenchmarkRegistryError,
    RegisteredDomainBenchmarkMetric,
    RegisteredDomainBenchmarkPlan,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_metric,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import (
    BENCHMARK_COMPARISON_API_VERSION,
    BENCHMARK_GROUND_TRUTH_API_VERSION,
    BENCHMARK_MANIFEST_API_VERSION,
    BENCHMARK_METRIC_ORDER,
    BENCHMARK_RESULT_API_VERSION,
)
from pajin.benchmark.redteam import (
    REDTEAM_BENCHMARK_METRIC_ORDER,
    REDTEAM_BENCHMARK_PROFILE_SET_API_VERSION,
    REDTEAM_BENCHMARK_RUN_OBSERVATION_API_VERSION,
    REDTEAM_INITIAL_BENCHMARK_REPORT_API_VERSION,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy

_REGISTRY_FALSE_MARKERS = (
    "benchmarkWireChanged",
    "redteamWireChanged",
    "measurementObserved",
    "detectionQualityEstablished",
    "replayOrValidationSatisfied",
    "profileValidationFloorSatisfied",
    "findingAuthority",
    "targetFactoryAuthority",
    "capabilityActivationAuthorized",
    "permitIssuanceAuthorized",
    "executionAuthorized",
)
_PLAN_FALSE_MARKERS = (
    "runtimeSupportAsserted",
    "measurementObserved",
    "replayOrReanalysisSatisfied",
    "profileValidationFloorSatisfied",
    "findingAuthority",
    "targetFactoryAuthority",
    "executionAuthorized",
)


def test_registry_is_exact_additive_vocabulary_over_existing_wires() -> None:
    registry = registered_domain_benchmark_registry()

    assert registry.benchmark_manifest_api_version == BENCHMARK_MANIFEST_API_VERSION
    assert registry.benchmark_ground_truth_api_version == BENCHMARK_GROUND_TRUTH_API_VERSION
    assert registry.benchmark_result_api_version == BENCHMARK_RESULT_API_VERSION
    assert registry.benchmark_comparison_api_version == BENCHMARK_COMPARISON_API_VERSION
    assert registry.benchmark_metric_order == BENCHMARK_METRIC_ORDER
    assert registry.redteam_profile_set_api_version == REDTEAM_BENCHMARK_PROFILE_SET_API_VERSION
    assert (
        registry.redteam_run_observation_api_version
        == REDTEAM_BENCHMARK_RUN_OBSERVATION_API_VERSION
    )
    assert registry.redteam_report_api_version == REDTEAM_INITIAL_BENCHMARK_REPORT_API_VERSION
    assert registry.redteam_metric_order == REDTEAM_BENCHMARK_METRIC_ORDER
    assert registry.security_domain_taxonomy_digest == (
        registered_security_domain_taxonomy().taxonomy_digest
    )
    assert len(registry.metrics) == 26
    assert len(registry.plans) == 9
    assert len(registry.registry_digest) == 64
    assert (
        DomainBenchmarkRegistry.model_validate(registry.model_dump(mode="json", by_alias=True))
        == registry
    )


def test_metric_registry_separates_common_and_exact_domain_metrics() -> None:
    registry = registered_domain_benchmark_registry()
    common = tuple(metric for metric in registry.metrics if metric.category.value == "common")
    domain_specific = tuple(
        metric for metric in registry.metrics if metric.category.value == "domain-specific"
    )

    assert len(common) == 13
    assert len(domain_specific) == 13
    assert all(metric.domain_classification is None for metric in common)
    assert {metric.domain_classification.domain for metric in domain_specific} == set(
        SecurityDomain
    )
    assert all(metric.registry_only is True for metric in registry.metrics)
    assert all(metric.measurement_observed is False for metric in registry.metrics)
    assert all(metric.detection_quality_established is False for metric in registry.metrics)
    assert all(metric.validation_satisfied is False for metric in registry.metrics)
    assert all(metric.finding_authority is False for metric in registry.metrics)
    assert all(metric.execution_authorized is False for metric in registry.metrics)


def test_every_domain_plan_has_exact_strategy_and_explicit_applicability() -> None:
    registry = registered_domain_benchmark_registry()

    assert tuple(plan.domain_classification.domain for plan in registry.plans) == tuple(
        SecurityDomain
    )
    assert len({plan.validation_strategy for plan in registry.plans}) == 9
    for plan in registry.plans:
        assert plan.registry_only is True
        payload = plan.model_dump(mode="json", by_alias=True)
        assert all(payload[alias] is False for alias in _PLAN_FALSE_MARKERS)
        assert all(
            requirement.not_applicable_reason is None
            if requirement.applicability is DomainBenchmarkMetricApplicability.REQUIRED
            else requirement.not_applicable_reason is not None
            for requirement in plan.metric_requirements
        )


def test_forensics_uses_analysis_metrics_instead_of_exploit_finding_denominators() -> None:
    registry = registered_domain_benchmark_registry()
    plan = next(
        item
        for item in registry.plans
        if item.domain_classification.domain is SecurityDomain.FORENSICS
    )
    requirements = {item.metric.metric_id: item for item in plan.metric_requirements}

    assert requirements["common.task-success-rate"].applicability.value == "required"
    for metric_id in (
        "common.detection-recall",
        "common.false-positive-rate",
        "common.detection-precision",
    ):
        requirement = requirements[metric_id]
        assert requirement.applicability.value == "not-applicable"
        assert requirement.not_applicable_reason is not None
        assert requirement.not_applicable_reason.value == "domain-specific-accuracy-metrics"
    assert {
        "forensics.artifact-coverage",
        "forensics.parsing-accuracy",
        "forensics.provenance-preservation-rate",
        "forensics.corrupted-input-handling-rate",
    }.issubset(requirements)
    assert all(
        requirements[metric_id].applicability.value == "required"
        for metric_id in requirements
        if metric_id.startswith("forensics.")
    )


def test_read_only_first_slice_cleanup_is_not_misreported_as_zero() -> None:
    for plan in registered_domain_benchmark_registry().plans:
        cleanup = next(
            item
            for item in plan.metric_requirements
            if item.metric.metric_id == "common.cleanup-success-rate"
        )
        payload = cleanup.model_dump(mode="json", by_alias=True)

        assert cleanup.applicability.value == "not-applicable"
        assert cleanup.not_applicable_reason is not None
        assert cleanup.not_applicable_reason.value == "read-only-no-cleanup-required"
        assert {"value", "numerator", "denominator"}.isdisjoint(payload)


def test_applicability_rejects_missing_or_invented_na_values() -> None:
    plan = registered_domain_benchmark_registry().plans[0]
    required = next(
        item
        for item in plan.metric_requirements
        if item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
    )
    not_applicable = next(
        item
        for item in plan.metric_requirements
        if item.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE
    )

    missing_reason = not_applicable.model_dump(mode="json", by_alias=True)
    missing_reason["notApplicableReason"] = None
    with pytest.raises(ValidationError, match="require an explicit reason"):
        DomainBenchmarkMetricRequirement.model_validate(missing_reason)

    contradictory = required.model_dump(mode="json", by_alias=True)
    contradictory["notApplicableReason"] = "no-monetary-cost-model"
    with pytest.raises(ValidationError, match="cannot carry an N/A reason"):
        DomainBenchmarkMetricRequirement.model_validate(contradictory)

    invented_zero = not_applicable.model_dump(mode="json", by_alias=True)
    invented_zero["value"] = 0
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DomainBenchmarkMetricRequirement.model_validate(invented_zero)


def test_exact_metric_and_plan_references_resolve_without_activation() -> None:
    registry = registered_domain_benchmark_registry()
    metric = registry.metrics[-1]
    plan = registry.plans[-1]

    resolved_metric = resolve_registered_domain_benchmark_metric(metric.reference())
    resolved_plan = resolve_registered_domain_benchmark_plan(plan.reference())

    assert resolved_metric == metric
    assert resolved_metric is not metric
    assert resolved_plan == plan
    assert resolved_plan is not plan
    assert resolved_plan.runtime_support_asserted is False
    assert resolved_plan.target_factory_authority is False
    assert resolved_plan.execution_authorized is False


def test_registry_and_resolvers_return_defensive_copies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = registered_domain_benchmark_registry()
    second = registered_domain_benchmark_registry()
    metric_reference = first.metrics[-1].reference()
    plan_reference = first.plans[-1].reference()

    assert (
        domain_metrics_module._registered_domain_benchmark_registry_template()
        is domain_metrics_module._registered_domain_benchmark_registry_template()
    )
    assert first == second
    assert first is not second
    assert first.metrics[0] is not second.metrics[0]

    object.__setattr__(first.metrics[0], "metric_digest", "0" * 64)
    third = registered_domain_benchmark_registry()
    assert third.metrics[0] == second.metrics[0]

    def reject_full_registry_rebuild() -> DomainBenchmarkRegistry:
        raise AssertionError("exact resolution must not rebuild the public registry")

    monkeypatch.setattr(
        domain_metrics_module,
        "registered_domain_benchmark_registry",
        reject_full_registry_rebuild,
    )
    assert resolve_registered_domain_benchmark_metric(metric_reference) == second.metrics[-1]
    assert resolve_registered_domain_benchmark_plan(plan_reference) == second.plans[-1]


def test_exact_resolution_rejects_digest_or_domain_substitution() -> None:
    registry = registered_domain_benchmark_registry()
    metric = registry.metrics[0]
    plan = registry.plans[0]

    with pytest.raises(DomainBenchmarkRegistryError, match="metric is not registered exactly"):
        resolve_registered_domain_benchmark_metric(
            metric.reference().model_copy(update={"metric_digest": "0" * 64})
        )
    with pytest.raises(DomainBenchmarkRegistryError, match="plan is not registered exactly"):
        resolve_registered_domain_benchmark_plan(
            plan.reference().model_copy(
                update={
                    "domain_classification": registry.plans[1].domain_classification,
                }
            )
        )


def test_metric_and_plan_identity_mutation_fails_closed() -> None:
    registry = registered_domain_benchmark_registry()

    metric_payload = registry.metrics[0].model_dump(mode="json", by_alias=True)
    metric_payload["definition"] = "A different denominator."
    metric_payload["metricDigest"] = ""
    with pytest.raises(ValidationError, match="definition differs from code authority"):
        RegisteredDomainBenchmarkMetric.model_validate(metric_payload)

    plan_payload = registry.plans[0].model_dump(mode="json", by_alias=True)
    plan_payload["metricRequirements"] = list(reversed(plan_payload["metricRequirements"]))
    plan_payload["planDigest"] = ""
    with pytest.raises(ValidationError, match="plan differs from code authority"):
        RegisteredDomainBenchmarkPlan.model_validate(plan_payload)


def test_registry_rejects_wire_or_membership_drift() -> None:
    payload = registered_domain_benchmark_registry().model_dump(mode="json", by_alias=True)

    reordered = deepcopy(payload)
    reordered["metrics"] = list(reversed(reordered["metrics"]))
    reordered["registryDigest"] = ""
    with pytest.raises(ValidationError, match="registry differs from code authority"):
        DomainBenchmarkRegistry.model_validate(reordered)

    changed_benchmark_order = deepcopy(payload)
    changed_benchmark_order["benchmarkMetricOrder"] = list(
        reversed(changed_benchmark_order["benchmarkMetricOrder"])
    )
    changed_benchmark_order["registryDigest"] = ""
    with pytest.raises(ValidationError, match="registry differs from code authority"):
        DomainBenchmarkRegistry.model_validate(changed_benchmark_order)

    changed_redteam_version = deepcopy(payload)
    changed_redteam_version["redteamReportApiVersion"] = "pajin.dev/report/latest"
    changed_redteam_version["registryDigest"] = ""
    with pytest.raises(ValidationError):
        DomainBenchmarkRegistry.model_validate(changed_redteam_version)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_MARKERS)
@pytest.mark.parametrize("escalated", (True, 1, "false"))
def test_registry_authority_and_quality_claims_fail_closed(
    alias: str,
    escalated: object,
) -> None:
    payload = registered_domain_benchmark_registry().model_dump(mode="json", by_alias=True)
    payload[alias] = escalated
    payload["registryDigest"] = ""

    with pytest.raises(ValidationError):
        DomainBenchmarkRegistry.model_validate(payload)


@pytest.mark.parametrize(
    ("alias", "value"),
    (
        ("profileId", "pajin.profile.pentest"),
        ("capabilityId", "pajin.capability.any"),
        ("toolId", "tool:any"),
        ("workerId", "worker:any"),
        ("scope", {"targets": ["example.test"]}),
        ("permit", {"permitId": "permit:any"}),
        ("measurement", {"value": 1.0}),
    ),
)
def test_registry_rejects_profile_tool_runtime_and_measurement_authority_fields(
    alias: str,
    value: object,
) -> None:
    payload = registered_domain_benchmark_registry().model_dump(mode="json", by_alias=True)
    payload[alias] = value
    payload["registryDigest"] = ""

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DomainBenchmarkRegistry.model_validate(payload)


def test_registry_models_expose_no_numeric_observation_or_authority_identity() -> None:
    forbidden = {
        "value",
        "numerator",
        "denominator",
        "profile_id",
        "capability_id",
        "tool_id",
        "worker_id",
        "scope",
        "permit",
        "target_factory_id",
    }

    assert forbidden.isdisjoint(DomainBenchmarkMetricRequirement.model_fields)
    assert forbidden.isdisjoint(RegisteredDomainBenchmarkMetric.model_fields)
    assert forbidden.isdisjoint(RegisteredDomainBenchmarkPlan.model_fields)
    assert forbidden.isdisjoint(DomainBenchmarkRegistry.model_fields)
