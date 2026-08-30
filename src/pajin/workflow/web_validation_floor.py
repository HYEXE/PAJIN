"""WEB-002A validation-floor vocabulary and private/public Finding mapping."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkMetricRef,
    DomainBenchmarkNotApplicableReason,
    DomainBenchmarkPlanRef,
    RegisteredDomainBenchmarkPlan,
    resolve_registered_domain_benchmark_metric,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import BenchmarkMetricUnit, benchmark_digest
from pajin.benchmark.scanner_baseline import ScannerBaselineMeasurementPlanAuthority
from pajin.benchmark.scanner_sarif import ZAPScannerRegistration
from pajin.benchmark.target_catalog import BenchmarkTargetGroundTruthBinding
from pajin.benchmark.target_factory import RegisteredBenchmarkTargetFactoryAdapter
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.lifecycle import CapabilityLifecycleRegistry, CapabilityReleaseRef
from pajin.capabilities.web_measured_validation import (
    WebMeasuredValidationCapabilityBundle,
    WebMeasuredValidationProfileRef,
)
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow.web_measured_case_authority import (
    WebMeasuredCaseAuthority,
    WebMeasuredCaseAuthorityError,
    WebMeasuredCaseAuthorityRef,
    load_web_measured_case_authority,
)
from pajin.workflow.web_replay_benchmark import (
    WebAPIBenchmarkGroundTruthProfile,
    registered_web_api_benchmark_ground_truth_profile,
)

WEB_BENCHMARK_VALIDATION_FLOOR_POLICY_API_VERSION: Literal[
    "pajin.dev/web-benchmark-validation-floor-policy/v1alpha1"
] = "pajin.dev/web-benchmark-validation-floor-policy/v1alpha1"
WEB_BENCHMARK_FINDING_PROJECTION_POLICY_API_VERSION: Literal[
    "pajin.dev/web-benchmark-finding-projection-policy/v1alpha1"
] = "pajin.dev/web-benchmark-finding-projection-policy/v1alpha1"
WEB_POLICY_DENIAL_CONTROL_REGISTRY_API_VERSION: Literal[
    "pajin.dev/web-policy-denial-control-registry/v1alpha1"
] = "pajin.dev/web-policy-denial-control-registry/v1alpha1"

WEB_BENCHMARK_VALIDATION_FLOOR_POLICY_ID = "web-002a:p0-d1-validation-floor"
WEB_BENCHMARK_VALIDATION_FLOOR_POLICY_VERSION = "1.0.0"
WEB_POLICY_DENIAL_CONTROL_REGISTRY_VERSION: Literal["1.0.0"] = "1.0.0"

_MAX_POLICY_BYTES = 4 * 1024 * 1024
_MAX_MAPPING_BYTES = 4 * 1024 * 1024
_POLICY_FALSE_FIELDS = (
    "measurement_evaluation_authorized",
    "benchmark_validation_floor_satisfied",
    "private_ground_truth_disclosure_authorized",
    "public_expected_finding_reference_exposure_authorized",
    "finding_projection_authorized",
    "product_finding_confirmed",
    "finding_authority",
    "scope_expansion_authorized",
    "graph_mutation_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "permit_issuance_authorized",
    "execution_authorized",
)
_PROJECTION_FALSE_FIELDS = (
    "expected_reference_match_verified",
    "benchmark_validation_floor_satisfied",
    "finding_projection_authorized",
    "product_finding_confirmed",
    "finding_authority",
    "private_ground_truth_disclosure_authorized",
    "public_expected_finding_reference_exposure_authorized",
    "graph_mutation_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "permit_issuance_authorized",
    "execution_authorized",
)


class WebValidationFloorError(RuntimeError):
    """Raised when a WEB-002A floor or private Finding mapping drifts."""


class WebMetricFloorComparison(StrEnum):
    """Exact policy treatment; values are requirements, not observations."""

    AT_LEAST = "at-least"
    AT_MOST = "at-most"
    MEASUREMENT_REQUIRED = "measurement-required-no-quality-threshold"
    NOT_APPLICABLE = "not-applicable"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class WebBenchmarkMetricFloorRequirement(_FrozenStrictModel):
    """One exact DOMAIN-006 Web metric denominator and threshold policy."""

    metric: DomainBenchmarkMetricRef
    unit: BenchmarkMetricUnit
    applicability: DomainBenchmarkMetricApplicability
    not_applicable_reason: DomainBenchmarkNotApplicableReason | None = Field(
        default=None,
        alias="notApplicableReason",
    )
    comparison: WebMetricFloorComparison
    threshold_numerator: int | None = Field(
        default=None,
        alias="thresholdNumerator",
        ge=0,
        le=1_000_000_000,
    )
    threshold_denominator: int | None = Field(
        default=None,
        alias="thresholdDenominator",
        ge=1,
        le=1_000_000_000,
    )
    numerator_semantics: str | None = Field(
        default=None,
        alias="numeratorSemantics",
        max_length=240,
    )
    denominator_semantics: str | None = Field(
        default=None,
        alias="denominatorSemantics",
        max_length=240,
    )
    minimum_denominator: int | None = Field(
        default=None,
        alias="minimumDenominator",
        ge=1,
        le=1_000_000,
    )

    @field_validator(
        "threshold_numerator",
        "threshold_denominator",
        "minimum_denominator",
        mode="before",
    )
    @classmethod
    def require_strict_optional_int(cls, value: object) -> object:
        if value is not None and type(value) is not int:
            raise ValueError("WEB-002A floor numbers must be exact integers")
        return value

    @model_validator(mode="after")
    def bind_requirement(self) -> WebBenchmarkMetricFloorRequirement:
        metric = resolve_registered_domain_benchmark_metric(self.metric)
        spec = _FLOOR_SPECS.get(metric.metric_id)
        if spec is None or (
            self.unit,
            self.applicability,
            self.comparison,
            self.threshold_numerator,
            self.threshold_denominator,
            self.numerator_semantics,
            self.denominator_semantics,
            self.minimum_denominator,
        ) != (
            metric.unit,
            spec.applicability,
            spec.comparison,
            spec.threshold_numerator,
            spec.threshold_denominator,
            spec.numerator_semantics,
            spec.denominator_semantics,
            spec.minimum_denominator,
        ):
            raise ValueError("WEB-002A metric floor differs from code authority")
        if self.applicability is DomainBenchmarkMetricApplicability.REQUIRED:
            if self.not_applicable_reason is not None:
                raise ValueError("required WEB-002A metric cannot carry an N/A reason")
        elif self.not_applicable_reason is None:
            raise ValueError("N/A WEB-002A metric requires the DOMAIN-006 reason")
        return self


class WebPolicyDenialControlCase(_FrozenStrictModel):
    """One code-owned expected denial denominator, not an observed denial."""

    case_id: str = Field(
        default="",
        alias="caseId",
        pattern=r"^web-policy-denial-control_[a-f0-9]{64}$",
    )
    case_digest: str = Field(default="", alias="caseDigest", max_length=64)
    trigger: Literal["target-cleanup-observed-before-controlled-route-verification"] = (
        "target-cleanup-observed-before-controlled-route-verification"
    )
    expected_denial_semantics: Literal[
        "reject-before-route-materialization-without-provider-execution"
    ] = Field(
        default="reject-before-route-materialization-without-provider-execution",
        alias="expectedDenialSemantics",
    )
    expected_route_materialized: Literal[False] = Field(
        default=False,
        alias="expectedRouteMaterialized",
    )
    expected_provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="expectedProviderExecutionAuthorized",
    )
    expected_network_access_authorized: Literal[False] = Field(
        default=False,
        alias="expectedNetworkAccessAuthorized",
    )

    @field_validator(
        "expected_route_materialized",
        "expected_provider_execution_authorized",
        "expected_network_access_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002A denial-control expectations must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_case_identity(self) -> WebPolicyDenialControlCase:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"case_id", "case_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-policy-denial-control-case/v1",
            material,
            max_bytes=512 * 1024,
        )
        case_id = f"web-policy-denial-control_{digest}"
        if self.case_digest and self.case_digest != digest:
            raise ValueError("WEB-002A denial-control case Digest differs")
        if self.case_id and self.case_id != case_id:
            raise ValueError("WEB-002A denial-control case ID differs")
        object.__setattr__(self, "case_digest", digest)
        object.__setattr__(self, "case_id", case_id)
        return self


class WebPolicyDenialControlRegistry(_FrozenStrictModel):
    """Content-addressed exact denominator for policy-denial correctness."""

    api_version: Literal["pajin.dev/web-policy-denial-control-registry/v1alpha1"] = Field(
        default=WEB_POLICY_DENIAL_CONTROL_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebPolicyDenialControlRegistry"] = "WebPolicyDenialControlRegistry"
    registry_id: str = Field(
        default="",
        alias="registryId",
        pattern=r"^web-policy-denial-control-registry_[a-f0-9]{64}$",
    )
    registry_version: Literal["1.0.0"] = Field(
        default=WEB_POLICY_DENIAL_CONTROL_REGISTRY_VERSION,
        alias="registryVersion",
    )
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    cases: tuple[WebPolicyDenialControlCase, ...] = Field(min_length=1, max_length=1)
    state: Literal["registered-not-evaluated"] = "registered-not-evaluated"
    denial_observed: Literal[False] = Field(default=False, alias="denialObserved")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("denial_observed", "execution_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002A denial-control registry markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_registry_identity(self) -> WebPolicyDenialControlRegistry:
        if self.cases != _registered_policy_denial_control_cases():
            raise ValueError("WEB-002A denial-control registry differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_id", "registry_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-policy-denial-control-registry/v1",
            material,
            max_bytes=512 * 1024,
        )
        registry_id = f"web-policy-denial-control-registry_{digest}"
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("WEB-002A denial-control registry Digest differs")
        if self.registry_id and self.registry_id != registry_id:
            raise ValueError("WEB-002A denial-control registry ID differs")
        object.__setattr__(self, "registry_digest", digest)
        object.__setattr__(self, "registry_id", registry_id)
        return self


class WebBenchmarkValidationFloorPolicyRef(_FrozenStrictModel):
    """Exact floor-policy lookup."""

    policy_id: Literal["web-002a:p0-d1-validation-floor"] = Field(alias="policyId")
    policy_version: Literal["1.0.0"] = Field(alias="policyVersion")
    policy_digest: str = Field(alias="policyDigest", pattern=r"^[a-f0-9]{64}$")


class WebBenchmarkValidationFloorPolicy(_FrozenStrictModel):
    """Registered requirements only; no metric has yet been observed or satisfied."""

    api_version: Literal["pajin.dev/web-benchmark-validation-floor-policy/v1alpha1"] = Field(
        default=WEB_BENCHMARK_VALIDATION_FLOOR_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebBenchmarkValidationFloorPolicy"] = "WebBenchmarkValidationFloorPolicy"
    policy_id: Literal["web-002a:p0-d1-validation-floor"] = Field(
        default="web-002a:p0-d1-validation-floor",
        alias="policyId",
    )
    policy_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="policyVersion",
    )
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    profile: WebMeasuredValidationProfileRef
    capability: CodeBackedCapabilityRef
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    private_ground_truth_binding_digest: str = Field(
        alias="privateGroundTruthBindingDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    policy_denial_control_registry: WebPolicyDenialControlRegistry = Field(
        alias="policyDenialControlRegistry"
    )
    requirements: tuple[WebBenchmarkMetricFloorRequirement, ...] = Field(
        min_length=14,
        max_length=14,
    )
    required_source_evidence: tuple[str, ...] = Field(
        alias="requiredSourceEvidence",
        min_length=6,
        max_length=6,
    )
    required_controlled_validation_evidence: tuple[str, ...] = Field(
        alias="requiredControlledValidationEvidence",
        min_length=10,
        max_length=10,
    )
    source_and_validation_identity_separation_required: Literal[True] = Field(
        default=True,
        alias="sourceAndValidationIdentitySeparationRequired",
    )
    state: Literal["registered-policy-not-evaluated"] = "registered-policy-not-evaluated"
    measurement_evaluation_authorized: Literal[False] = Field(
        default=False, alias="measurementEvaluationAuthorized"
    )
    benchmark_validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="benchmarkValidationFloorSatisfied"
    )
    private_ground_truth_disclosure_authorized: Literal[False] = Field(
        default=False, alias="privateGroundTruthDisclosureAuthorized"
    )
    public_expected_finding_reference_exposure_authorized: Literal[False] = Field(
        default=False, alias="publicExpectedFindingReferenceExposureAuthorized"
    )
    finding_projection_authorized: Literal[False] = Field(
        default=False, alias="findingProjectionAuthorized"
    )
    product_finding_confirmed: Literal[False] = Field(
        default=False, alias="productFindingConfirmed"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False, alias="graphMutationAuthorized"
    )
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False, alias="externalDeliveryAuthorized"
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("source_and_validation_identity_separation_required", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002A source/validation separation must be boolean true")
        return value

    @field_validator(*_POLICY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002A floor authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> WebBenchmarkValidationFloorPolicy:
        plan = resolve_registered_domain_benchmark_plan(self.domain_benchmark_plan)
        if (
            plan.domain_classification.domain is not SecurityDomain.WEB
            or self.requirements != _floor_requirements(plan)
            or self.policy_denial_control_registry
            != registered_web_policy_denial_control_registry()
            or self.required_source_evidence != _SOURCE_EVIDENCE
            or self.required_controlled_validation_evidence != _VALIDATION_EVIDENCE
        ):
            raise ValueError("WEB-002A validation-floor policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-benchmark-validation-floor-policy/v1",
            material,
            max_bytes=_MAX_POLICY_BYTES,
        )
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("WEB-002A validation-floor policy Digest differs")
        object.__setattr__(self, "policy_digest", digest)
        return self

    def reference(self) -> WebBenchmarkValidationFloorPolicyRef:
        """Return the exact policy identity without satisfying it."""

        return WebBenchmarkValidationFloorPolicyRef(
            policyId=self.policy_id,
            policyVersion=self.policy_version,
            policyDigest=self.policy_digest,
        )


class WebBenchmarkFindingProjectionPolicyRef(_FrozenStrictModel):
    """Public-safe identity reserved for a future floor-satisfied projection."""

    projection_id: str = Field(
        alias="projectionId",
        pattern=r"^web-benchmark-finding_[a-f0-9]{64}$",
    )
    projection_digest: str = Field(
        alias="projectionDigest",
        pattern=r"^[a-f0-9]{64}$",
    )


class WebBenchmarkFindingProjectionPolicy(_FrozenStrictModel):
    """Public commitment to one private expected reference, not a Finding."""

    api_version: Literal["pajin.dev/web-benchmark-finding-projection-policy/v1alpha1"] = Field(
        default=WEB_BENCHMARK_FINDING_PROJECTION_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebBenchmarkFindingProjectionPolicy"] = "WebBenchmarkFindingProjectionPolicy"
    projection_id: str = Field(default="", alias="projectionId", max_length=90)
    projection_digest: str = Field(default="", alias="projectionDigest", max_length=64)
    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    floor_policy: WebBenchmarkValidationFloorPolicyRef = Field(alias="floorPolicy")
    profile: WebMeasuredValidationProfileRef
    capability: CodeBackedCapabilityRef
    expected_reference_commitment: str = Field(
        alias="expectedReferenceCommitment",
        pattern=r"^[a-f0-9]{64}$",
    )
    claim_ceiling: Literal["benchmark-ground-truth-match"] = Field(
        default="benchmark-ground-truth-match",
        alias="claimCeiling",
    )
    state: Literal["registered-mapping-not-produced"] = "registered-mapping-not-produced"
    expected_reference_match_verified: Literal[False] = Field(
        default=False, alias="expectedReferenceMatchVerified"
    )
    benchmark_validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="benchmarkValidationFloorSatisfied"
    )
    finding_projection_authorized: Literal[False] = Field(
        default=False, alias="findingProjectionAuthorized"
    )
    product_finding_confirmed: Literal[False] = Field(
        default=False, alias="productFindingConfirmed"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    private_ground_truth_disclosure_authorized: Literal[False] = Field(
        default=False, alias="privateGroundTruthDisclosureAuthorized"
    )
    public_expected_finding_reference_exposure_authorized: Literal[False] = Field(
        default=False, alias="publicExpectedFindingReferenceExposureAuthorized"
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False, alias="graphMutationAuthorized"
    )
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False, alias="externalDeliveryAuthorized"
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_PROJECTION_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002A projection authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_projection_identity(self) -> WebBenchmarkFindingProjectionPolicy:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"projection_id", "projection_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-benchmark-finding-projection-policy/v1",
            material,
            max_bytes=_MAX_MAPPING_BYTES,
        )
        projection_id = f"web-benchmark-finding_{digest}"
        if self.projection_digest and self.projection_digest != digest:
            raise ValueError("WEB-002A Finding projection policy Digest differs")
        if self.projection_id and self.projection_id != projection_id:
            raise ValueError("WEB-002A Finding projection policy ID differs")
        object.__setattr__(self, "projection_digest", digest)
        object.__setattr__(self, "projection_id", projection_id)
        return self

    def reference(self) -> WebBenchmarkFindingProjectionPolicyRef:
        """Return the reserved identity without producing a Finding."""

        return WebBenchmarkFindingProjectionPolicyRef(
            projectionId=self.projection_id,
            projectionDigest=self.projection_digest,
        )


class WebPrivateExpectedFindingBinding(_FrozenStrictModel):
    """Deployment-private raw P0-D1 mapping; never a public product artifact."""

    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    floor_policy: WebBenchmarkValidationFloorPolicyRef = Field(alias="floorPolicy")
    public_projection: WebBenchmarkFindingProjectionPolicyRef = Field(alias="publicProjection")
    private_ground_truth: BenchmarkTargetGroundTruthBinding = Field(alias="privateGroundTruth")
    ground_truth_id: str = Field(alias="groundTruthId", min_length=1, max_length=200)
    expected_finding_id: str = Field(alias="expectedFindingId", min_length=1, max_length=200)
    matcher_id: str = Field(alias="matcherId", min_length=1, max_length=200)
    matcher_version: str = Field(alias="matcherVersion", min_length=1, max_length=200)
    matcher_digest: str = Field(alias="matcherDigest", pattern=r"^[a-f0-9]{64}$")
    surface_ids: tuple[str, ...] = Field(alias="surfaceIds", min_length=1, max_length=100)
    expected_reference_commitment: str = Field(
        alias="expectedReferenceCommitment",
        pattern=r"^[a-f0-9]{64}$",
    )
    private_only: Literal[True] = Field(default=True, alias="privateOnly")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("private_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002A private mapping marker must be boolean true")
        return value

    @field_validator("finding_authority", "execution_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002A private mapping authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_private_mapping(self) -> WebPrivateExpectedFindingBinding:
        if len(self.private_ground_truth.ground_truth.cases) != 1:
            raise ValueError("WEB-002A private mapping requires one P0-D1 case")
        case = self.private_ground_truth.ground_truth.cases[0]
        expected_commitment = _expected_reference_commitment(
            self.private_ground_truth,
            ground_truth_id=case.ground_truth_id,
            expected_finding_id=case.expected_finding_id,
            matcher_id=case.matcher_id,
            matcher_version=case.matcher_version,
            matcher_digest=case.matcher_digest,
            surface_ids=tuple(case.surface_ids),
        )
        if (
            self.ground_truth_id,
            self.expected_finding_id,
            self.matcher_id,
            self.matcher_version,
            self.matcher_digest,
            self.surface_ids,
        ) != (
            case.ground_truth_id,
            case.expected_finding_id,
            case.matcher_id,
            case.matcher_version,
            case.matcher_digest,
            tuple(case.surface_ids),
        ) or self.expected_reference_commitment != expected_commitment:
            raise ValueError("WEB-002A private expected Finding mapping differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-private-expected-finding-binding/v1",
            material,
            max_bytes=_MAX_MAPPING_BYTES,
        )
        binding_id = f"web-private-expected-finding:{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("WEB-002A private expected Finding binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("WEB-002A private expected Finding binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


@dataclass(frozen=True, slots=True)
class WebExpectedFindingProjectionMapping:
    """Separated public policy and deployment-private adjudication material."""

    public_policy: WebBenchmarkFindingProjectionPolicy
    private_binding: WebPrivateExpectedFindingBinding


@dataclass(frozen=True, slots=True)
class _FloorSpec:
    applicability: DomainBenchmarkMetricApplicability
    comparison: WebMetricFloorComparison
    threshold_numerator: int | None = None
    threshold_denominator: int | None = None
    numerator_semantics: str | None = None
    denominator_semantics: str | None = None
    minimum_denominator: int | None = None


_RATIO_AT_LEAST = WebMetricFloorComparison.AT_LEAST
_FLOOR_SPECS = {
    "common.ground-truth-coverage": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _RATIO_AT_LEAST,
        1,
        1,
        "admitted-evaluable-ground-truth-cases",
        "registered-ground-truth-cases",
        1,
    ),
    "common.detection-recall": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _RATIO_AT_LEAST,
        1,
        1,
        "matched-expected-positive-findings",
        "registered-expected-positive-findings",
        1,
    ),
    "common.task-success-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        WebMetricFloorComparison.NOT_APPLICABLE,
    ),
    "common.false-positive-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_MOST,
        0,
        1,
        "unexpected-positive-control-signals",
        "registered-negative-control-cases",
        1,
    ),
    "common.detection-precision": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _RATIO_AT_LEAST,
        1,
        1,
        "matched-expected-positive-findings",
        "all-public-safe-projected-candidates",
        1,
    ),
    "common.replay-or-reanalysis-success-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _RATIO_AT_LEAST,
        1,
        1,
        "successful-independent-controlled-validations",
        "attempted-independent-controlled-validations",
        1,
    ),
    "common.time-to-first-valid-result": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.MEASUREMENT_REQUIRED,
        numerator_semantics="elapsed-seconds-to-first-floor-eligible-result",
    ),
    "common.total-request-units": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.MEASUREMENT_REQUIRED,
        numerator_semantics="all-admitted-source-and-validation-request-units",
    ),
    "common.total-tool-calls": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.MEASUREMENT_REQUIRED,
        numerator_semantics="all-admitted-source-and-validation-tool-calls",
    ),
    "common.total-cost-usd": _FloorSpec(
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        WebMetricFloorComparison.NOT_APPLICABLE,
    ),
    "common.evidence-completeness": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _RATIO_AT_LEAST,
        1,
        1,
        "verified-required-evidence-items",
        "registered-required-evidence-items",
        1,
    ),
    "common.policy-denial-correctness": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _RATIO_AT_LEAST,
        1,
        1,
        "expected-escalation-controls-denied-without-execution",
        "registered-code-owned-policy-denial-control-cases",
        1,
    ),
    "common.cleanup-success-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        WebMetricFloorComparison.NOT_APPLICABLE,
    ),
    "web.http-operation-coverage": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _RATIO_AT_LEAST,
        1,
        1,
        "evaluated-ground-truth-http-operations",
        "registered-ground-truth-http-operations",
        1,
    ),
}

_SOURCE_EVIDENCE = (
    "completed-web-002b-target-run-authority",
    "exact-zap-registration-and-scanner-plan",
    "raw-sarif-sha256-and-size",
    "strict-sarif-normalization-digest",
    "signed-measurement-registry-authority",
    "verified-target-cleanup-receipt",
)
_VALIDATION_EVIDENCE = (
    "fresh-target-attempt-operation-and-fence",
    "fresh-capability-activation-approval-and-action-permit",
    "signed-single-use-proxy-route",
    "proxy-attachment-and-detachment-receipts",
    "three-host-observed-request-and-response-receipts",
    "baseline-negative-control-and-boolean-probe-observations",
    "sealed-worker-result-evidence",
    "independent-replay-comparison",
    "expected-policy-denial-control-evidence",
    "verified-target-reconciliation-and-cleanup",
)


def _registered_policy_denial_control_cases() -> tuple[WebPolicyDenialControlCase, ...]:
    return (WebPolicyDenialControlCase(),)


def registered_web_policy_denial_control_registry() -> WebPolicyDenialControlRegistry:
    """Return the exact expected-denial denominator without observing a denial."""

    return WebPolicyDenialControlRegistry(cases=_registered_policy_denial_control_cases())


def registered_web_benchmark_validation_floor_policy(
    measured_case: WebMeasuredCaseAuthority,
    *,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
) -> WebBenchmarkValidationFloorPolicy:
    """Reopen the exact measured case before registering any floor requirement."""

    case = _load_trusted_measured_case(
        measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        release=release,
        target_adapter=target_adapter,
        private_ground_truth_profile=private_ground_truth_profile,
        scanner_plan=scanner_plan,
        scanner_registration=scanner_registration,
    )
    return _floor_policy_for_trusted_case(case)


def _floor_policy_for_trusted_case(
    case: WebMeasuredCaseAuthority,
) -> WebBenchmarkValidationFloorPolicy:
    plan = resolve_registered_domain_benchmark_plan(case.domain_benchmark_plan)
    return WebBenchmarkValidationFloorPolicy(
        measuredCase=case.reference(),
        profile=case.profile.reference(),
        capability=case.profile.capability,
        domainBenchmarkPlan=case.domain_benchmark_plan,
        privateGroundTruthBindingDigest=case.ground_truth_binding_digest,
        policyDenialControlRegistry=registered_web_policy_denial_control_registry(),
        requirements=_floor_requirements(plan),
        requiredSourceEvidence=_SOURCE_EVIDENCE,
        requiredControlledValidationEvidence=_VALIDATION_EVIDENCE,
    )


def resolve_web_benchmark_validation_floor_policy(
    reference: WebBenchmarkValidationFloorPolicyRef,
    *,
    measured_case: WebMeasuredCaseAuthority,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
) -> WebBenchmarkValidationFloorPolicy:
    """Resolve only after reopening the measured case from current trusted context."""

    policy = registered_web_benchmark_validation_floor_policy(
        measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        release=release,
        target_adapter=target_adapter,
        private_ground_truth_profile=private_ground_truth_profile,
        scanner_plan=scanner_plan,
        scanner_registration=scanner_registration,
    )
    if policy.reference() != reference:
        raise WebValidationFloorError("WEB-002A validation-floor policy is not registered")
    return policy.model_copy(deep=True)


def bind_web_expected_finding_projection_policy(
    *,
    measured_case: WebMeasuredCaseAuthority,
    floor_policy: WebBenchmarkValidationFloorPolicy,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
) -> WebExpectedFindingProjectionMapping:
    """Bind one private expected ref to a distinct public, unproduced projection identity."""

    try:
        case_authority = _load_trusted_measured_case(
            measured_case,
            capability_bundle=capability_bundle,
            lifecycle=lifecycle,
            release=release,
            target_adapter=target_adapter,
            private_ground_truth_profile=private_ground_truth_profile,
            scanner_plan=scanner_plan,
            scanner_registration=scanner_registration,
        )
        expected_floor = _floor_policy_for_trusted_case(case_authority)
        if floor_policy != expected_floor:
            raise ValueError("WEB-002A Finding mapping uses another floor policy")
        private_profile = _rebuild_private_profile(private_ground_truth_profile)
        private_binding = private_profile.private_ground_truth
        if (
            private_binding.binding_digest != case_authority.ground_truth_binding_digest
            or private_binding.ground_truth.digest() != case_authority.ground_truth_digest
        ):
            raise ValueError("WEB-002A Finding mapping uses another private Ground Truth")
        if len(private_binding.ground_truth.cases) != 1:
            raise ValueError("WEB-002A Finding mapping requires one exact P0-D1 case")
        ground_truth_case = private_binding.ground_truth.cases[0]
        commitment = _expected_reference_commitment(
            private_binding,
            ground_truth_id=ground_truth_case.ground_truth_id,
            expected_finding_id=ground_truth_case.expected_finding_id,
            matcher_id=ground_truth_case.matcher_id,
            matcher_version=ground_truth_case.matcher_version,
            matcher_digest=ground_truth_case.matcher_digest,
            surface_ids=tuple(ground_truth_case.surface_ids),
        )
        public = WebBenchmarkFindingProjectionPolicy(
            measuredCase=case_authority.reference(),
            floorPolicy=expected_floor.reference(),
            profile=case_authority.profile.reference(),
            capability=case_authority.profile.capability,
            expectedReferenceCommitment=commitment,
        )
        private = WebPrivateExpectedFindingBinding(
            measuredCase=case_authority.reference(),
            floorPolicy=expected_floor.reference(),
            publicProjection=public.reference(),
            privateGroundTruth=private_binding,
            groundTruthId=ground_truth_case.ground_truth_id,
            expectedFindingId=ground_truth_case.expected_finding_id,
            matcherId=ground_truth_case.matcher_id,
            matcherVersion=ground_truth_case.matcher_version,
            matcherDigest=ground_truth_case.matcher_digest,
            surfaceIds=tuple(ground_truth_case.surface_ids),
            expectedReferenceCommitment=commitment,
        )
        return WebExpectedFindingProjectionMapping(
            public_policy=public,
            private_binding=private,
        )
    except WebValidationFloorError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebValidationFloorError(
            "WEB-002A expected Finding projection mapping failed closed"
        ) from exc


def _floor_requirements(
    plan: RegisteredDomainBenchmarkPlan,
) -> tuple[WebBenchmarkMetricFloorRequirement, ...]:
    requirements = []
    for domain_requirement in plan.metric_requirements:
        metric = resolve_registered_domain_benchmark_metric(domain_requirement.metric)
        spec = _FLOOR_SPECS.get(metric.metric_id)
        if spec is None or spec.applicability is not domain_requirement.applicability:
            raise ValueError("WEB-002A floor does not cover the exact DOMAIN-006 Web plan")
        requirements.append(
            WebBenchmarkMetricFloorRequirement(
                metric=domain_requirement.metric,
                unit=metric.unit,
                applicability=domain_requirement.applicability,
                notApplicableReason=domain_requirement.not_applicable_reason,
                comparison=spec.comparison,
                thresholdNumerator=spec.threshold_numerator,
                thresholdDenominator=spec.threshold_denominator,
                numeratorSemantics=spec.numerator_semantics,
                denominatorSemantics=spec.denominator_semantics,
                minimumDenominator=spec.minimum_denominator,
            )
        )
    return tuple(requirements)


def _load_trusted_measured_case(
    measured_case: WebMeasuredCaseAuthority,
    *,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
) -> WebMeasuredCaseAuthority:
    try:
        return load_web_measured_case_authority(
            measured_case,
            capability_bundle=capability_bundle,
            lifecycle=lifecycle,
            release=release,
            target_adapter=target_adapter,
            private_ground_truth_profile=private_ground_truth_profile,
            scanner_plan=scanner_plan,
            scanner_registration=scanner_registration,
        )
    except WebMeasuredCaseAuthorityError as exc:
        raise WebValidationFloorError(
            "WEB-002A measured-case trusted-context reload failed"
        ) from exc


def _expected_reference_commitment(
    private_binding: BenchmarkTargetGroundTruthBinding,
    *,
    ground_truth_id: str,
    expected_finding_id: str,
    matcher_id: str,
    matcher_version: str,
    matcher_digest: str,
    surface_ids: tuple[str, ...],
) -> str:
    return benchmark_digest(
        "pajin.workflow.web-private-expected-finding-commitment/v1",
        {
            "privateGroundTruthBindingDigest": private_binding.binding_digest,
            "groundTruthId": ground_truth_id,
            "expectedFindingId": expected_finding_id,
            "matcherId": matcher_id,
            "matcherVersion": matcher_version,
            "matcherDigest": matcher_digest,
            "surfaceIds": list(surface_ids),
        },
        max_bytes=512 * 1024,
    )


def _rebuild_private_profile(
    supplied: WebAPIBenchmarkGroundTruthProfile,
) -> WebAPIBenchmarkGroundTruthProfile:
    canonical = WebAPIBenchmarkGroundTruthProfile.model_validate(
        supplied.model_dump(mode="json", by_alias=True)
    )
    expected = registered_web_api_benchmark_ground_truth_profile(
        canonical.target_profile,
        benchmark_id=canonical.private_ground_truth.ground_truth.benchmark_id,
    )
    if canonical != expected:
        raise ValueError("WEB-002A private Ground Truth profile differs from code authority")
    return expected


__all__ = [
    "WEB_BENCHMARK_FINDING_PROJECTION_POLICY_API_VERSION",
    "WEB_BENCHMARK_VALIDATION_FLOOR_POLICY_API_VERSION",
    "WEB_BENCHMARK_VALIDATION_FLOOR_POLICY_ID",
    "WEB_BENCHMARK_VALIDATION_FLOOR_POLICY_VERSION",
    "WEB_POLICY_DENIAL_CONTROL_REGISTRY_API_VERSION",
    "WEB_POLICY_DENIAL_CONTROL_REGISTRY_VERSION",
    "WebBenchmarkFindingProjectionPolicy",
    "WebBenchmarkFindingProjectionPolicyRef",
    "WebBenchmarkMetricFloorRequirement",
    "WebBenchmarkValidationFloorPolicy",
    "WebBenchmarkValidationFloorPolicyRef",
    "WebExpectedFindingProjectionMapping",
    "WebMetricFloorComparison",
    "WebPolicyDenialControlCase",
    "WebPolicyDenialControlRegistry",
    "WebPrivateExpectedFindingBinding",
    "WebValidationFloorError",
    "bind_web_expected_finding_projection_policy",
    "registered_web_benchmark_validation_floor_policy",
    "registered_web_policy_denial_control_registry",
    "resolve_web_benchmark_validation_floor_policy",
]
