"""DOMAIN-006 domain-aware metric and validation-strategy registry."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.models import (
    BENCHMARK_COMPARISON_API_VERSION,
    BENCHMARK_GROUND_TRUTH_API_VERSION,
    BENCHMARK_MANIFEST_API_VERSION,
    BENCHMARK_METRIC_ORDER,
    BENCHMARK_RESULT_API_VERSION,
    BenchmarkMetric,
    BenchmarkMetricUnit,
    benchmark_digest,
)
from pajin.benchmark.redteam import (
    REDTEAM_BENCHMARK_METRIC_ORDER,
    REDTEAM_BENCHMARK_PROFILE_SET_API_VERSION,
    REDTEAM_BENCHMARK_RUN_OBSERVATION_API_VERSION,
    REDTEAM_INITIAL_BENCHMARK_REPORT_API_VERSION,
    RedteamBenchmarkMetric,
)
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SECURITY_DOMAIN_TAXONOMY_API_VERSION,
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)

DOMAIN_BENCHMARK_METRIC_API_VERSION: Literal["pajin.dev/domain-benchmark-metric/v1alpha1"] = (
    "pajin.dev/domain-benchmark-metric/v1alpha1"
)
DOMAIN_BENCHMARK_PLAN_API_VERSION: Literal["pajin.dev/domain-benchmark-plan/v1alpha1"] = (
    "pajin.dev/domain-benchmark-plan/v1alpha1"
)
DOMAIN_BENCHMARK_REGISTRY_API_VERSION: Literal["pajin.dev/domain-benchmark-registry/v1alpha1"] = (
    "pajin.dev/domain-benchmark-registry/v1alpha1"
)

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_METRIC_BYTES = 64 * 1024
_MAX_PLAN_BYTES = 512 * 1024
_MAX_REGISTRY_BYTES = 4 * 1024 * 1024


class DomainBenchmarkRegistryError(RuntimeError):
    """Raised when an exact DOMAIN-006 reference is not registered."""


class DomainBenchmarkMetricCategory(StrEnum):
    """Separate reusable vocabulary from exact domain-specific measurements."""

    COMMON = "common"
    DOMAIN_SPECIFIC = "domain-specific"


class DomainBenchmarkAggregation(StrEnum):
    """Registered aggregation semantics, not a measured result."""

    RATIO_OF_SUMS = "ratio-of-sums"
    SUM = "sum"
    MINIMUM = "minimum"


class DomainBenchmarkMetricApplicability(StrEnum):
    """Whether a domain plan requires a semantic measurement denominator."""

    REQUIRED = "required"
    NOT_APPLICABLE = "not-applicable"


class DomainBenchmarkNotApplicableReason(StrEnum):
    """Code-owned reasons that distinguish absence from a measured zero."""

    DOMAIN_SPECIFIC_ACCURACY_METRICS = "domain-specific-accuracy-metrics"
    DETECTION_RECALL_IS_PRIMARY_OUTCOME = "detection-recall-is-primary-outcome"
    OFFLINE_NO_REQUEST_UNIT_DENOMINATOR = "offline-no-request-unit-denominator"
    NO_MONETARY_COST_MODEL = "no-monetary-cost-model"
    READ_ONLY_NO_CLEANUP_REQUIRED = "read-only-no-cleanup-required"


class DomainValidationStrategy(StrEnum):
    """Required replay or deterministic re-analysis class for a domain slice."""

    INDEPENDENT_REPLAY = "independent-replay"
    FRESH_WORKER_PROTOCOL_REPLAY = "fresh-worker-protocol-replay"
    IMMUTABLE_SNAPSHOT_REANALYSIS = "immutable-snapshot-reanalysis"
    DETERMINISTIC_ARTIFACT_REANALYSIS = "deterministic-artifact-reanalysis"
    DETERMINISTIC_PACKAGE_REANALYSIS = "deterministic-package-reanalysis"
    FRESH_CREDENTIAL_DETERMINISTIC_REEVALUATION = "fresh-credential-deterministic-reevaluation"
    FRESH_SESSION_INDEPENDENT_REPLAY = "fresh-session-independent-replay"
    INDEPENDENT_RECOMPUTATION = "independent-recomputation"
    INDEPENDENT_PARSER_COMPARISON = "independent-parser-comparison"


class DomainBenchmarkMetricRef(StrictModel):
    """Exact content-addressed reference to one registered metric definition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    metric_id: _Identifier = Field(alias="metricId")
    metric_version: Literal["1.0.0"] = Field(alias="metricVersion")
    metric_digest: _Sha256 = Field(alias="metricDigest")
    category: DomainBenchmarkMetricCategory
    domain_classification: SecurityDomainClassificationRef | None = Field(
        default=None,
        alias="domainClassification",
    )


class RegisteredDomainBenchmarkMetric(StrictModel):
    """One metric definition with no observation or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/domain-benchmark-metric/v1alpha1"] = Field(
        default=DOMAIN_BENCHMARK_METRIC_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredDomainBenchmarkMetric"] = "RegisteredDomainBenchmarkMetric"
    metric_id: _Identifier = Field(alias="metricId")
    metric_version: Literal["1.0.0"] = Field(default="1.0.0", alias="metricVersion")
    metric_digest: str = Field(default="", alias="metricDigest", max_length=64)
    category: DomainBenchmarkMetricCategory
    domain_classification: SecurityDomainClassificationRef | None = Field(
        default=None,
        alias="domainClassification",
    )
    unit: BenchmarkMetricUnit
    aggregation: DomainBenchmarkAggregation
    definition: str = Field(min_length=1, max_length=500)
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    validation_satisfied: Literal[False] = Field(default=False, alias="validationSatisfied")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "registry_only",
        "measurement_observed",
        "detection_quality_established",
        "validation_satisfied",
        "finding_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("DOMAIN-006 metric markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_metric_identity(self) -> Self:
        expected = _metric_spec_by_id(self.metric_id)
        if (
            expected is None
            or (
                self.category,
                _domain_from_reference(self.domain_classification),
                self.unit,
                self.aggregation,
                self.definition,
            )
            != expected[1:]
        ):
            raise ValueError("DOMAIN-006 metric definition differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"metric_digest"})
        digest = benchmark_digest(
            "pajin.benchmark.domain-metric/v1",
            material,
            max_bytes=_MAX_METRIC_BYTES,
        )
        if self.metric_digest and self.metric_digest != digest:
            raise ValueError("DOMAIN-006 metric Digest differs")
        object.__setattr__(self, "metric_digest", digest)
        return self

    def reference(self) -> DomainBenchmarkMetricRef:
        """Return the exact reference used by a domain measurement plan."""

        return DomainBenchmarkMetricRef(
            metricId=self.metric_id,
            metricVersion=self.metric_version,
            metricDigest=self.metric_digest,
            category=self.category,
            domainClassification=self.domain_classification,
        )


class DomainBenchmarkMetricRequirement(StrictModel):
    """Explicit applicability without a numeric observation field."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    metric: DomainBenchmarkMetricRef
    applicability: DomainBenchmarkMetricApplicability
    not_applicable_reason: DomainBenchmarkNotApplicableReason | None = Field(
        default=None,
        alias="notApplicableReason",
    )

    @model_validator(mode="after")
    def require_explicit_applicability(self) -> Self:
        if self.applicability is DomainBenchmarkMetricApplicability.REQUIRED:
            if self.not_applicable_reason is not None:
                raise ValueError("required DOMAIN-006 metrics cannot carry an N/A reason")
        elif self.not_applicable_reason is None:
            raise ValueError("not-applicable DOMAIN-006 metrics require an explicit reason")
        return self


class DomainBenchmarkPlanRef(StrictModel):
    """Exact content-addressed reference to one domain benchmark plan."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    plan_id: _Identifier = Field(alias="planId")
    plan_version: Literal["1.0.0"] = Field(alias="planVersion")
    plan_digest: _Sha256 = Field(alias="planDigest")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")


class RegisteredDomainBenchmarkPlan(StrictModel):
    """Domain measurement applicability and replay strategy, not validation evidence."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/domain-benchmark-plan/v1alpha1"] = Field(
        default=DOMAIN_BENCHMARK_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredDomainBenchmarkPlan"] = "RegisteredDomainBenchmarkPlan"
    plan_id: _Identifier = Field(alias="planId")
    plan_version: Literal["1.0.0"] = Field(default="1.0.0", alias="planVersion")
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    validation_strategy: DomainValidationStrategy = Field(alias="validationStrategy")
    metric_requirements: tuple[DomainBenchmarkMetricRequirement, ...] = Field(
        alias="metricRequirements",
        min_length=14,
        max_length=17,
    )
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    replay_or_reanalysis_satisfied: Literal[False] = Field(
        default=False,
        alias="replayOrReanalysisSatisfied",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "registry_only",
        "runtime_support_asserted",
        "measurement_observed",
        "replay_or_reanalysis_satisfied",
        "profile_validation_floor_satisfied",
        "finding_authority",
        "target_factory_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("DOMAIN-006 plan markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_plan_identity(self) -> Self:
        domain = _domain_from_reference(self.domain_classification)
        if domain is None:
            raise ValueError("DOMAIN-006 plan requires an exact domain classification")
        expected_requirements = _requirements_for_domain(domain)
        if (
            self.plan_id != f"pajin.domain-benchmark-plan.{domain.value}"
            or self.validation_strategy is not _DOMAIN_STRATEGIES[domain]
            or self.metric_requirements != expected_requirements
        ):
            raise ValueError("DOMAIN-006 plan differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"plan_digest"})
        digest = benchmark_digest(
            "pajin.benchmark.domain-plan/v1",
            material,
            max_bytes=_MAX_PLAN_BYTES,
        )
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("DOMAIN-006 plan Digest differs")
        object.__setattr__(self, "plan_digest", digest)
        return self

    def reference(self) -> DomainBenchmarkPlanRef:
        """Return the exact reference without activating a measurement path."""

        return DomainBenchmarkPlanRef(
            planId=self.plan_id,
            planVersion=self.plan_version,
            planDigest=self.plan_digest,
            domainClassification=self.domain_classification,
        )


class DomainBenchmarkRegistry(StrictModel):
    """Exact DOMAIN-006 registry preserving both existing benchmark wires."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/domain-benchmark-registry/v1alpha1"] = Field(
        default=DOMAIN_BENCHMARK_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DomainBenchmarkRegistry"] = "DomainBenchmarkRegistry"
    registry_id: Literal["pajin.domain-benchmark-registry.core"] = Field(
        default="pajin.domain-benchmark-registry.core",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_api_version: Literal["pajin.dev/security-domain-taxonomy/v1alpha1"] = (
        Field(
            default=SECURITY_DOMAIN_TAXONOMY_API_VERSION, alias="securityDomainTaxonomyApiVersion"
        )
    )
    security_domain_taxonomy_digest: _Sha256 = Field(alias="securityDomainTaxonomyDigest")
    benchmark_manifest_api_version: Literal["pajin.dev/benchmark-manifest/v1alpha1"] = Field(
        default=BENCHMARK_MANIFEST_API_VERSION,
        alias="benchmarkManifestApiVersion",
    )
    benchmark_ground_truth_api_version: Literal["pajin.dev/benchmark-ground-truth/v1alpha1"] = (
        Field(default=BENCHMARK_GROUND_TRUTH_API_VERSION, alias="benchmarkGroundTruthApiVersion")
    )
    benchmark_result_api_version: Literal["pajin.dev/benchmark-result/v1alpha1"] = Field(
        default=BENCHMARK_RESULT_API_VERSION,
        alias="benchmarkResultApiVersion",
    )
    benchmark_comparison_api_version: Literal[
        "pajin.dev/benchmark-comparison/v1alpha1"
    ] = Field(
        default=BENCHMARK_COMPARISON_API_VERSION,
        alias="benchmarkComparisonApiVersion",
    )
    benchmark_metric_order: tuple[BenchmarkMetric, ...] = Field(
        default=BENCHMARK_METRIC_ORDER,
        alias="benchmarkMetricOrder",
        min_length=12,
        max_length=12,
    )
    redteam_profile_set_api_version: Literal["pajin.dev/redteam-benchmark-profile-set/v1alpha1"] = (
        Field(
            default=REDTEAM_BENCHMARK_PROFILE_SET_API_VERSION, alias="redteamProfileSetApiVersion"
        )
    )
    redteam_run_observation_api_version: Literal[
        "pajin.dev/redteam-benchmark-run-observation/v1alpha1"
    ] = Field(
        default=REDTEAM_BENCHMARK_RUN_OBSERVATION_API_VERSION,
        alias="redteamRunObservationApiVersion",
    )
    redteam_report_api_version: Literal["pajin.dev/redteam-initial-benchmark-report/v1alpha1"] = (
        Field(default=REDTEAM_INITIAL_BENCHMARK_REPORT_API_VERSION, alias="redteamReportApiVersion")
    )
    redteam_metric_order: tuple[RedteamBenchmarkMetric, ...] = Field(
        default=REDTEAM_BENCHMARK_METRIC_ORDER,
        alias="redteamMetricOrder",
        min_length=12,
        max_length=12,
    )
    metrics: tuple[RegisteredDomainBenchmarkMetric, ...] = Field(
        min_length=26,
        max_length=26,
    )
    plans: tuple[RegisteredDomainBenchmarkPlan, ...] = Field(min_length=9, max_length=9)
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    benchmark_wire_changed: Literal[False] = Field(default=False, alias="benchmarkWireChanged")
    redteam_wire_changed: Literal[False] = Field(default=False, alias="redteamWireChanged")
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    replay_or_validation_satisfied: Literal[False] = Field(
        default=False,
        alias="replayOrValidationSatisfied",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "registry_only",
        "benchmark_wire_changed",
        "redteam_wire_changed",
        "measurement_observed",
        "detection_quality_established",
        "replay_or_validation_satisfied",
        "profile_validation_floor_satisfied",
        "finding_authority",
        "target_factory_authority",
        "capability_activation_authorized",
        "permit_issuance_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("DOMAIN-006 registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.benchmark_metric_order != BENCHMARK_METRIC_ORDER
            or self.redteam_metric_order != REDTEAM_BENCHMARK_METRIC_ORDER
            or self.metrics != _registered_metric_definitions()
            or self.plans != _registered_domain_plans()
        ):
            raise ValueError("DOMAIN-006 registry differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"registry_digest"})
        digest = benchmark_digest(
            "pajin.benchmark.domain-registry/v1",
            material,
            max_bytes=_MAX_REGISTRY_BYTES,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("DOMAIN-006 registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self


_COMMON_METRIC_SPECS: tuple[
    tuple[
        str,
        DomainBenchmarkMetricCategory,
        None,
        BenchmarkMetricUnit,
        DomainBenchmarkAggregation,
        str,
    ],
    ...,
] = (
    (
        "common.ground-truth-coverage",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth cases with an admitted evaluable outcome divided by registered "
        "Ground Truth cases.",
    ),
    (
        "common.detection-recall",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth positive cases detected correctly divided by all Ground Truth "
        "positive cases.",
    ),
    (
        "common.task-success-rate",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth analysis tasks completed correctly divided by all applicable tasks.",
    ),
    (
        "common.false-positive-rate",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth negative cases reported positive divided by all Ground Truth negative cases.",
    ),
    (
        "common.detection-precision",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Correct positive detections divided by all reported positive detections.",
    ),
    (
        "common.replay-or-reanalysis-success-rate",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Successful independent Replay or deterministic re-analysis cases divided by "
        "attempted cases.",
    ),
    (
        "common.time-to-first-valid-result",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.SECONDS,
        DomainBenchmarkAggregation.MINIMUM,
        "Elapsed seconds to the first result satisfying the applicable validation contract.",
    ),
    (
        "common.total-request-units",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.COUNT,
        DomainBenchmarkAggregation.SUM,
        "Total exact request units consumed by applicable provider or protocol operations.",
    ),
    (
        "common.total-tool-calls",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.COUNT,
        DomainBenchmarkAggregation.SUM,
        "Total registered Tool calls observed by the admitted measurement path.",
    ),
    (
        "common.total-cost-usd",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.USD,
        DomainBenchmarkAggregation.SUM,
        "Total admitted monetary cost in US dollars for the measurement coordinate.",
    ),
    (
        "common.evidence-completeness",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Required evidence fields present and verified divided by all required evidence fields.",
    ),
    (
        "common.policy-denial-correctness",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Expected policy denials enforced without execution divided by all expected denial cases.",
    ),
    (
        "common.cleanup-success-rate",
        DomainBenchmarkMetricCategory.COMMON,
        None,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Verified cleanup completions divided by cleanup attempts for actions that "
        "require cleanup.",
    ),
)

_DOMAIN_METRIC_SPECS: tuple[
    tuple[
        str,
        DomainBenchmarkMetricCategory,
        SecurityDomain,
        BenchmarkMetricUnit,
        DomainBenchmarkAggregation,
        str,
    ],
    ...,
] = (
    (
        "web.http-operation-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.WEB,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth HTTP operations analyzed divided by registered HTTP operations.",
    ),
    (
        "network.service-identification-accuracy",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.NETWORK,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Correct protocol and service identifications divided by evaluated service Surfaces.",
    ),
    (
        "system.configuration-control-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.SYSTEM,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth host configuration controls evaluated divided by registered controls.",
    ),
    (
        "application.artifact-analysis-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.APPLICATION,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth application artifacts analyzed divided by registered artifacts.",
    ),
    (
        "mobile.manifest-component-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.MOBILE,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth package manifest components analyzed divided by registered components.",
    ),
    (
        "cloud.resource-policy-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.CLOUD,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth cloud resources and policies evaluated divided by registered "
        "resources and policies.",
    ),
    (
        "ai.threat-class-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.AI,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth AI threat classes exercised divided by registered threat classes.",
    ),
    (
        "cryptography.test-vector-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.CRYPTOGRAPHY,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth cryptographic test vectors evaluated divided by registered vectors.",
    ),
    (
        "cryptography.independent-recomputation-success-rate",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.CRYPTOGRAPHY,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Matching independent cryptographic recomputations divided by attempted recomputations.",
    ),
    (
        "forensics.artifact-coverage",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.FORENSICS,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Ground Truth forensic artifacts parsed divided by registered artifacts.",
    ),
    (
        "forensics.parsing-accuracy",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.FORENSICS,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Correctly parsed Ground Truth fields divided by evaluated fields.",
    ),
    (
        "forensics.provenance-preservation-rate",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.FORENSICS,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Artifacts retaining verified source identity and lineage divided by parsed artifacts.",
    ),
    (
        "forensics.corrupted-input-handling-rate",
        DomainBenchmarkMetricCategory.DOMAIN_SPECIFIC,
        SecurityDomain.FORENSICS,
        BenchmarkMetricUnit.RATIO,
        DomainBenchmarkAggregation.RATIO_OF_SUMS,
        "Corrupted inputs rejected or bounded safely divided by corrupted-input cases.",
    ),
)

_METRIC_SPECS = _COMMON_METRIC_SPECS + _DOMAIN_METRIC_SPECS

_DOMAIN_STRATEGIES: dict[SecurityDomain, DomainValidationStrategy] = {
    SecurityDomain.WEB: DomainValidationStrategy.INDEPENDENT_REPLAY,
    SecurityDomain.NETWORK: DomainValidationStrategy.FRESH_WORKER_PROTOCOL_REPLAY,
    SecurityDomain.SYSTEM: DomainValidationStrategy.IMMUTABLE_SNAPSHOT_REANALYSIS,
    SecurityDomain.APPLICATION: DomainValidationStrategy.DETERMINISTIC_ARTIFACT_REANALYSIS,
    SecurityDomain.MOBILE: DomainValidationStrategy.DETERMINISTIC_PACKAGE_REANALYSIS,
    SecurityDomain.CLOUD: DomainValidationStrategy.FRESH_CREDENTIAL_DETERMINISTIC_REEVALUATION,
    SecurityDomain.AI: DomainValidationStrategy.FRESH_SESSION_INDEPENDENT_REPLAY,
    SecurityDomain.CRYPTOGRAPHY: DomainValidationStrategy.INDEPENDENT_RECOMPUTATION,
    SecurityDomain.FORENSICS: DomainValidationStrategy.INDEPENDENT_PARSER_COMPARISON,
}

_NETWORKED_REQUEST_DOMAINS = frozenset(
    {SecurityDomain.WEB, SecurityDomain.NETWORK, SecurityDomain.CLOUD, SecurityDomain.AI}
)
_MONETARY_COST_DOMAINS = frozenset({SecurityDomain.CLOUD, SecurityDomain.AI})


def registered_domain_benchmark_registry() -> DomainBenchmarkRegistry:
    """Return the exact registry without asserting support or measuring a run."""

    taxonomy = registered_security_domain_taxonomy()
    return DomainBenchmarkRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        metrics=_registered_metric_definitions(),
        plans=_registered_domain_plans(),
    )


def resolve_registered_domain_benchmark_metric(
    reference: DomainBenchmarkMetricRef,
) -> RegisteredDomainBenchmarkMetric:
    """Resolve an exact metric definition without accepting an observation."""

    for metric in registered_domain_benchmark_registry().metrics:
        if metric.reference() == reference:
            return metric.model_copy(deep=True)
    raise DomainBenchmarkRegistryError("DOMAIN-006 metric is not registered exactly")


def resolve_registered_domain_benchmark_plan(
    reference: DomainBenchmarkPlanRef,
) -> RegisteredDomainBenchmarkPlan:
    """Resolve an exact plan without activating Target Factory or Replay authority."""

    for plan in registered_domain_benchmark_registry().plans:
        if plan.reference() == reference:
            return plan.model_copy(deep=True)
    raise DomainBenchmarkRegistryError("DOMAIN-006 plan is not registered exactly")


def _registered_metric_definitions() -> tuple[RegisteredDomainBenchmarkMetric, ...]:
    return tuple(
        RegisteredDomainBenchmarkMetric(
            metricId=metric_id,
            category=category,
            domainClassification=(_domain_reference(domain) if domain is not None else None),
            unit=unit,
            aggregation=aggregation,
            definition=definition,
        )
        for metric_id, category, domain, unit, aggregation, definition in _METRIC_SPECS
    )


def _registered_domain_plans() -> tuple[RegisteredDomainBenchmarkPlan, ...]:
    return tuple(
        RegisteredDomainBenchmarkPlan(
            planId=f"pajin.domain-benchmark-plan.{domain.value}",
            domainClassification=_domain_reference(domain),
            validationStrategy=_DOMAIN_STRATEGIES[domain],
            metricRequirements=_requirements_for_domain(domain),
        )
        for domain in SecurityDomain
    )


def _requirements_for_domain(
    domain: SecurityDomain,
) -> tuple[DomainBenchmarkMetricRequirement, ...]:
    metrics = {metric.metric_id: metric.reference() for metric in _registered_metric_definitions()}
    requirements: list[DomainBenchmarkMetricRequirement] = []
    for metric_id, _, metric_domain, _, _, _ in _METRIC_SPECS:
        if metric_domain is not None and metric_domain is not domain:
            continue
        reason = _not_applicable_reason(domain, metric_id)
        requirements.append(
            DomainBenchmarkMetricRequirement(
                metric=metrics[metric_id],
                applicability=(
                    DomainBenchmarkMetricApplicability.NOT_APPLICABLE
                    if reason is not None
                    else DomainBenchmarkMetricApplicability.REQUIRED
                ),
                notApplicableReason=reason,
            )
        )
    return tuple(requirements)


def _not_applicable_reason(
    domain: SecurityDomain,
    metric_id: str,
) -> DomainBenchmarkNotApplicableReason | None:
    if metric_id == "common.task-success-rate" and domain is not SecurityDomain.FORENSICS:
        return DomainBenchmarkNotApplicableReason.DETECTION_RECALL_IS_PRIMARY_OUTCOME
    if domain is SecurityDomain.FORENSICS and metric_id in {
        "common.detection-recall",
        "common.false-positive-rate",
        "common.detection-precision",
    }:
        return DomainBenchmarkNotApplicableReason.DOMAIN_SPECIFIC_ACCURACY_METRICS
    if metric_id == "common.total-request-units" and domain not in _NETWORKED_REQUEST_DOMAINS:
        return DomainBenchmarkNotApplicableReason.OFFLINE_NO_REQUEST_UNIT_DENOMINATOR
    if metric_id == "common.total-cost-usd" and domain not in _MONETARY_COST_DOMAINS:
        return DomainBenchmarkNotApplicableReason.NO_MONETARY_COST_MODEL
    if metric_id == "common.cleanup-success-rate":
        return DomainBenchmarkNotApplicableReason.READ_ONLY_NO_CLEANUP_REQUIRED
    return None


def _metric_spec_by_id(
    metric_id: str,
) -> (
    tuple[
        str,
        DomainBenchmarkMetricCategory,
        SecurityDomain | None,
        BenchmarkMetricUnit,
        DomainBenchmarkAggregation,
        str,
    ]
    | None
):
    return next((item for item in _METRIC_SPECS if item[0] == metric_id), None)


def _domain_reference(domain: SecurityDomain) -> SecurityDomainClassificationRef:
    return next(
        item.reference()
        for item in registered_security_domain_taxonomy().domains
        if item.domain is domain
    )


def _domain_from_reference(
    reference: SecurityDomainClassificationRef | None,
) -> SecurityDomain | None:
    if reference is None:
        return None
    expected = _domain_reference(reference.domain)
    if reference != expected:
        raise ValueError("DOMAIN-006 requires an exact registered domain classification")
    return reference.domain
