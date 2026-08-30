"""WEB-002D independent floor evaluation and bounded Finding projection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkMetricRef,
    DomainBenchmarkNotApplicableReason,
    resolve_registered_domain_benchmark_metric,
)
from pajin.benchmark.models import BenchmarkMetricUnit, benchmark_digest
from pajin.benchmark.target_catalog import (
    TRADITIONAL_WEB_API_BOOLEAN_SQLI_MATCHER_DIGEST,
)
from pajin.capabilities.web_measured_validation import (
    WEB_MEASURED_VALIDATION_REQUEST_UNITS,
    WEB_MEASURED_VALIDATION_TARGET,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    BooleanSQLiProbeOutput,
    BooleanSQLiProbeTool,
)
from pajin.workflow.web_controlled_validation_runtime import (
    WebControlledValidationWorkerEvidence,
)
from pajin.workflow.web_measured_case_authority import (
    WebMeasuredCaseAuthority,
    WebMeasuredCaseAuthorityRef,
)
from pajin.workflow.web_replay_benchmark import (
    WebAPIBenchmarkGroundTruthProfile,
    registered_web_api_benchmark_ground_truth_profile,
)
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementAuthority,
    WebZAPSourceMeasurementAuthorityRef,
)
from pajin.workflow.web_validation_floor import (
    WebBenchmarkFindingProjectionPolicy,
    WebBenchmarkFindingProjectionPolicyRef,
    WebBenchmarkMetricFloorRequirement,
    WebBenchmarkValidationFloorPolicy,
    WebBenchmarkValidationFloorPolicyRef,
    WebExpectedFindingProjectionMapping,
    WebMetricFloorComparison,
    WebPrivateExpectedFindingBinding,
)

WEB_VALIDATION_FLOOR_EVALUATION_API_VERSION: Literal[
    "pajin.dev/web-validation-floor-evaluation/v1alpha1"
] = "pajin.dev/web-validation-floor-evaluation/v1alpha1"
WEB_BENCHMARK_FINDING_API_VERSION: Literal["pajin.dev/web-benchmark-finding/v1alpha1"] = (
    "pajin.dev/web-benchmark-finding/v1alpha1"
)
WEB_SOURCE_REQUEST_UNIT_OBSERVATION_API_VERSION: Literal[
    "pajin.dev/web-source-request-unit-observation/v1alpha1"
] = "pajin.dev/web-source-request-unit-observation/v1alpha1"

WEB_VALIDATION_SOURCE_EVIDENCE_NAMES = (
    "completed-web-002b-target-run-authority",
    "exact-zap-registration-and-scanner-plan",
    "raw-sarif-sha256-and-size",
    "strict-sarif-normalization-digest",
    "signed-measurement-registry-authority",
    "verified-target-cleanup-receipt",
)
WEB_VALIDATION_CONTROLLED_EVIDENCE_NAMES = (
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

_MAX_EVALUATION_BYTES = 8 * 1024 * 1024
_MAX_FINDING_BYTES = 2 * 1024 * 1024
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_NonNegativeInt = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
_PositiveInt = Annotated[int, Field(strict=True, ge=1, le=2**63 - 1)]

_METRIC_IDS = (
    "common.ground-truth-coverage",
    "common.detection-recall",
    "common.task-success-rate",
    "common.false-positive-rate",
    "common.detection-precision",
    "common.replay-or-reanalysis-success-rate",
    "common.time-to-first-valid-result",
    "common.total-request-units",
    "common.total-tool-calls",
    "common.total-cost-usd",
    "common.evidence-completeness",
    "common.policy-denial-correctness",
    "common.cleanup-success-rate",
    "web.http-operation-coverage",
)
_FIXED_RATIONALS = {
    "common.ground-truth-coverage": (1, 1),
    "common.detection-recall": (1, 1),
    "common.false-positive-rate": (0, 1),
    "common.detection-precision": (1, 1),
    "common.replay-or-reanalysis-success-rate": (1, 1),
    "common.evidence-completeness": (16, 16),
    "common.policy-denial-correctness": (1, 1),
    "web.http-operation-coverage": (1, 1),
}
_MEASUREMENT_METRICS = frozenset(
    {
        "common.time-to-first-valid-result",
        "common.total-request-units",
        "common.total-tool-calls",
    }
)
_NOT_APPLICABLE_REASONS = {
    "common.task-success-rate": (
        DomainBenchmarkNotApplicableReason.DETECTION_RECALL_IS_PRIMARY_OUTCOME
    ),
    "common.total-cost-usd": DomainBenchmarkNotApplicableReason.NO_MONETARY_COST_MODEL,
    "common.cleanup-success-rate": (
        DomainBenchmarkNotApplicableReason.READ_ONLY_NO_CLEANUP_REQUIRED
    ),
}
_PUBLIC_METRIC_CONTRACTS = {
    "common.ground-truth-coverage": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_LEAST,
    ),
    "common.detection-recall": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_LEAST,
    ),
    "common.task-success-rate": (
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        WebMetricFloorComparison.NOT_APPLICABLE,
    ),
    "common.false-positive-rate": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_MOST,
    ),
    "common.detection-precision": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_LEAST,
    ),
    "common.replay-or-reanalysis-success-rate": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_LEAST,
    ),
    "common.time-to-first-valid-result": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.MEASUREMENT_REQUIRED,
    ),
    "common.total-request-units": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.MEASUREMENT_REQUIRED,
    ),
    "common.total-tool-calls": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.MEASUREMENT_REQUIRED,
    ),
    "common.total-cost-usd": (
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        WebMetricFloorComparison.NOT_APPLICABLE,
    ),
    "common.evidence-completeness": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_LEAST,
    ),
    "common.policy-denial-correctness": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_LEAST,
    ),
    "common.cleanup-success-rate": (
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        WebMetricFloorComparison.NOT_APPLICABLE,
    ),
    "web.http-operation-coverage": (
        DomainBenchmarkMetricApplicability.REQUIRED,
        WebMetricFloorComparison.AT_LEAST,
    ),
}
_TRUE_EVALUATION_FIELDS = (
    "trusted_execution_verified",
    "independent_observation_recomputation_verified",
    "source_validation_identity_disjoint",
    "required_evidence_complete",
    "denial_control_satisfied",
    "target_cleanup_verified",
    "benchmark_validation_floor_satisfied",
)
_FALSE_EVALUATION_FIELDS = (
    "private_ground_truth_disclosure_authorized",
    "raw_sarif_disclosure_authorized",
    "controlled_query_disclosure_authorized",
    "graph_mutation_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "permit_issuance_authorized",
    "additional_execution_authorized",
)
_TRUE_FINDING_FIELDS = (
    "finding_projection_performed",
    "benchmark_ground_truth_match_confirmed",
    "benchmark_validation_floor_satisfied",
    "product_finding_confirmed",
)
_FALSE_FINDING_FIELDS = (
    "private_ground_truth_disclosure_authorized",
    "public_expected_finding_reference_exposure_authorized",
    "raw_sarif_disclosure_authorized",
    "controlled_query_disclosure_authorized",
    "scope_expansion_authorized",
    "graph_mutation_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "permit_issuance_authorized",
    "additional_execution_authorized",
)


class WebValidationEvaluationError(ValueError):
    """Raised when WEB-002D evidence cannot satisfy the registered floor."""


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    """Reject unchecked nested state introduced by ``model_copy(update=...)``."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        if set(value.__dict__) - set(type(value).model_fields):
            raise WebValidationEvaluationError(f"{label} contains unmodeled instance state")
        for field_name in type(value).model_fields:
            _require_known_instance_fields(getattr(value, field_name), label=label, _seen=seen)
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if not isinstance(value, type) and is_dataclass(value):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for item in fields(value):
            _require_known_instance_fields(getattr(value, item.name), label=label, _seen=seen)


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


class WebControlledValidationIdentitySet(_FrozenStrictModel):
    """Fresh WEB-002D identities that must not overlap the WEB-002B source."""

    validation_run_id: _Identifier = Field(alias="validationRunId")
    target_run_id: _Identifier = Field(alias="targetRunId")
    target_attempt_id: _Identifier = Field(alias="targetAttemptId")
    execution_operation_id: _Identifier = Field(alias="executionOperationId")
    cleanup_operation_id: _Identifier = Field(alias="cleanupOperationId")
    route_id: _Identifier = Field(alias="routeId")
    approval_id: _Identifier = Field(alias="approvalId")
    permit_id: _Identifier = Field(alias="permitId")
    worker_execution_id: _Identifier = Field(alias="workerExecutionId")
    dispatch_id: _Identifier = Field(alias="dispatchId")
    tool_request_id: _Identifier = Field(alias="toolRequestId")
    result_evidence_id: _Identifier = Field(alias="resultEvidenceId")
    target_fence: _PositiveInt = Field(alias="targetFence")

    @model_validator(mode="after")
    def require_unique_identities(self) -> Self:
        identities = _validation_identity_strings(self)
        if len(identities) != len(set(identities)):
            raise ValueError("WEB-002D controlled-validation identities must be distinct")
        return self


class WebSourceRequestUnitObservationRef(_FrozenStrictModel):
    observation_id: str = Field(
        alias="observationId",
        pattern=r"^web-source-request-units_[a-f0-9]{64}$",
    )
    observation_digest: _Sha256 = Field(alias="observationDigest")


class WebSourceRequestUnitObservation(_FrozenStrictModel):
    """Content-addressed request-unit count bound to one exact WEB-002B result."""

    api_version: Literal["pajin.dev/web-source-request-unit-observation/v1alpha1"] = Field(
        default=WEB_SOURCE_REQUEST_UNIT_OBSERVATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebSourceRequestUnitObservation"] = "WebSourceRequestUnitObservation"
    observation_id: str = Field(default="", alias="observationId", max_length=110)
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    source_measurement: WebZAPSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    measurement_result_digest: _Sha256 = Field(alias="measurementResultDigest")
    request_units: _PositiveInt = Field(alias="requestUnits")
    source_measurement_bound: Literal[True] = Field(
        default=True,
        alias="sourceMeasurementBound",
    )
    request_units_observed: Literal[True] = Field(
        default=True,
        alias="requestUnitsObserved",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("source_measurement_bound", "request_units_observed", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002D source request-unit markers must be boolean true")
        return value

    @field_validator("execution_authorized", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002D source request-unit authority must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-source-request-unit-observation/v1",
            material,
            max_bytes=512 * 1024,
        )
        observation_id = f"web-source-request-units_{digest}"
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("WEB-002D source request-unit observation Digest differs")
        if self.observation_id and self.observation_id != observation_id:
            raise ValueError("WEB-002D source request-unit observation ID differs")
        object.__setattr__(self, "observation_digest", digest)
        object.__setattr__(self, "observation_id", observation_id)
        return self

    def reference(self) -> WebSourceRequestUnitObservationRef:
        return WebSourceRequestUnitObservationRef(
            observationId=self.observation_id,
            observationDigest=self.observation_digest,
        )


def observe_web_source_request_units(
    source: WebZAPSourceMeasurementAuthority,
) -> WebSourceRequestUnitObservation:
    """Project the exact host-observed WEB-002B request-unit total without authority."""

    canonical = _canonical_exact(
        WebZAPSourceMeasurementAuthority,
        source,
        label="WEB-002D source request-unit authority",
    )
    return WebSourceRequestUnitObservation(
        sourceMeasurement=canonical.reference(),
        measurementResultDigest=canonical.baseline_result_digest,
        requestUnits=canonical.source_request_units,
    )


class WebPrivateMatcherObservation(_FrozenStrictModel):
    """Public-safe proof that the code-owned private matcher ran and matched."""

    observation_id: str = Field(default="", alias="observationId", max_length=110)
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    expected_reference_commitment: _Sha256 = Field(alias="expectedReferenceCommitment")
    private_binding_digest: _Sha256 = Field(alias="privateBindingDigest")
    matcher_execution_commitment: _Sha256 = Field(alias="matcherExecutionCommitment")
    tool_result_digest: _Sha256 = Field(alias="toolResultDigest")
    matched: Literal[True] = True
    private_ground_truth_disclosed: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthDisclosed",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("matched", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002D private matcher must match")
        return value

    @field_validator(
        "private_ground_truth_disclosed",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002D private matcher cannot disclose or authorize")
        return value

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        digest = benchmark_digest(
            "pajin.workflow.web-private-matcher-observation/v1",
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"observation_id", "observation_digest"},
            ),
            max_bytes=512 * 1024,
        )
        observation_id = f"web-private-matcher_{digest}"
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("WEB-002D private matcher observation Digest differs")
        if self.observation_id and self.observation_id != observation_id:
            raise ValueError("WEB-002D private matcher observation ID differs")
        object.__setattr__(self, "observation_digest", digest)
        object.__setattr__(self, "observation_id", observation_id)
        return self


class WebObservedPolicyDenial(_FrozenStrictModel):
    """One observed 1/1 denial with zero route, provider, and network side effects."""

    observation_id: str = Field(default="", alias="observationId", max_length=120)
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    registry_id: _Identifier = Field(alias="registryId")
    registry_digest: _Sha256 = Field(alias="registryDigest")
    case_id: _Identifier = Field(alias="caseId")
    case_digest: _Sha256 = Field(alias="caseDigest")
    numerator: Literal[1] = 1
    denominator: Literal[1] = 1
    denial_observed: Literal[True] = Field(default=True, alias="denialObserved")
    route_materialized: Literal[False] = Field(default=False, alias="routeMaterialized")
    provider_execution_performed: Literal[False] = Field(
        default=False,
        alias="providerExecutionPerformed",
    )
    network_access_performed: Literal[False] = Field(
        default=False,
        alias="networkAccessPerformed",
    )

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-observed-policy-denial/v1",
            material,
            max_bytes=512 * 1024,
        )
        observation_id = f"web-observed-policy-denial:{digest}"
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("WEB-002D denial observation Digest differs")
        if self.observation_id and self.observation_id != observation_id:
            raise ValueError("WEB-002D denial observation ID differs")
        object.__setattr__(self, "observation_digest", digest)
        object.__setattr__(self, "observation_id", observation_id)
        return self


class WebBenchmarkMetricObservation(_FrozenStrictModel):
    """One exact rational metric observation or exact registered N/A decision."""

    metric: DomainBenchmarkMetricRef
    unit: BenchmarkMetricUnit
    applicability: DomainBenchmarkMetricApplicability
    comparison: WebMetricFloorComparison
    numerator: _NonNegativeInt | None = None
    denominator: _PositiveInt | None = None
    not_applicable_reason: DomainBenchmarkNotApplicableReason | None = Field(
        default=None,
        alias="notApplicableReason",
    )
    satisfied: Literal[True] = True

    @model_validator(mode="after")
    def require_complete_rational(self) -> Self:
        if self.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE:
            if (
                self.comparison is not WebMetricFloorComparison.NOT_APPLICABLE
                or self.not_applicable_reason is None
                or self.numerator is not None
                or self.denominator is not None
            ):
                raise ValueError("WEB-002D N/A metric observation differs")
        elif (
            self.comparison is WebMetricFloorComparison.NOT_APPLICABLE
            or self.not_applicable_reason is not None
            or self.numerator is None
            or self.denominator is None
        ):
            raise ValueError("WEB-002D required metric needs one exact rational value")
        return self


class WebValidationFloorEvaluationRef(_FrozenStrictModel):
    evaluation_id: str = Field(
        alias="evaluationId",
        pattern=r"^web-validation-floor-evaluation_[a-f0-9]{64}$",
    )
    evaluation_digest: _Sha256 = Field(alias="evaluationDigest")


class WebValidationFloorEvaluation(_FrozenStrictModel):
    """Content-addressed proof that the exact registered WEB-002 floor is satisfied."""

    api_version: Literal["pajin.dev/web-validation-floor-evaluation/v1alpha1"] = Field(
        default=WEB_VALIDATION_FLOOR_EVALUATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebValidationFloorEvaluation"] = "WebValidationFloorEvaluation"
    evaluation_id: str = Field(default="", alias="evaluationId", max_length=110)
    evaluation_digest: str = Field(default="", alias="evaluationDigest", max_length=64)
    floor_policy: WebBenchmarkValidationFloorPolicyRef = Field(alias="floorPolicy")
    projection_policy: WebBenchmarkFindingProjectionPolicyRef = Field(alias="projectionPolicy")
    source_measurement: WebZAPSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    source_request_units: WebSourceRequestUnitObservationRef = Field(alias="sourceRequestUnits")
    private_matcher_observation: WebPrivateMatcherObservation = Field(
        alias="privateMatcherObservation"
    )
    validation_identity_digest: _Sha256 = Field(alias="validationIdentityDigest")
    denial_control: WebObservedPolicyDenial = Field(alias="denialControl")
    source_evidence_names: tuple[str, ...] = Field(
        alias="sourceEvidenceNames",
        min_length=6,
        max_length=6,
    )
    controlled_validation_evidence_names: tuple[str, ...] = Field(
        alias="controlledValidationEvidenceNames",
        min_length=10,
        max_length=10,
    )
    observations: tuple[WebBenchmarkMetricObservation, ...] = Field(
        min_length=14,
        max_length=14,
    )
    state: Literal["floor-satisfied-independent-controlled-validation"] = (
        "floor-satisfied-independent-controlled-validation"
    )
    trusted_execution_verified: Literal[True] = Field(
        default=True,
        alias="trustedExecutionVerified",
    )
    independent_observation_recomputation_verified: Literal[True] = Field(
        default=True,
        alias="independentObservationRecomputationVerified",
    )
    source_validation_identity_disjoint: Literal[True] = Field(
        default=True,
        alias="sourceValidationIdentityDisjoint",
    )
    required_evidence_complete: Literal[True] = Field(
        default=True,
        alias="requiredEvidenceComplete",
    )
    denial_control_satisfied: Literal[True] = Field(
        default=True,
        alias="denialControlSatisfied",
    )
    target_cleanup_verified: Literal[True] = Field(
        default=True,
        alias="targetCleanupVerified",
    )
    benchmark_validation_floor_satisfied: Literal[True] = Field(
        default=True,
        alias="benchmarkValidationFloorSatisfied",
    )
    private_ground_truth_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthDisclosureAuthorized",
    )
    raw_sarif_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="rawSarifDisclosureAuthorized",
    )
    controlled_query_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="controlledQueryDisclosureAuthorized",
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="graphMutationAuthorized",
    )
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(
        "source_evidence_names",
        "controlled_validation_evidence_names",
        "observations",
        mode="before",
    )
    @classmethod
    def canonicalize_json_tuple(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @field_validator(*_TRUE_EVALUATION_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002D floor completion markers must be boolean true")
        return value

    @field_validator(*_FALSE_EVALUATION_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002D floor authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_evaluation(self) -> Self:
        if (
            self.source_evidence_names != WEB_VALIDATION_SOURCE_EVIDENCE_NAMES
            or self.controlled_validation_evidence_names != WEB_VALIDATION_CONTROLLED_EVIDENCE_NAMES
        ):
            raise ValueError("WEB-002D floor evidence names differ")
        _validate_public_observations(self.observations)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_id", "evaluation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-validation-floor-evaluation/v1",
            material,
            max_bytes=_MAX_EVALUATION_BYTES,
        )
        evaluation_id = f"web-validation-floor-evaluation_{digest}"
        if self.evaluation_digest and self.evaluation_digest != digest:
            raise ValueError("WEB-002D floor evaluation Digest differs")
        if self.evaluation_id and self.evaluation_id != evaluation_id:
            raise ValueError("WEB-002D floor evaluation ID differs")
        object.__setattr__(self, "evaluation_digest", digest)
        object.__setattr__(self, "evaluation_id", evaluation_id)
        return self

    def reference(self) -> WebValidationFloorEvaluationRef:
        return WebValidationFloorEvaluationRef(
            evaluationId=self.evaluation_id,
            evaluationDigest=self.evaluation_digest,
        )


class WebBenchmarkFindingRef(_FrozenStrictModel):
    finding_id: str = Field(
        alias="findingId",
        pattern=r"^web-benchmark-finding_[a-f0-9]{64}$",
    )
    finding_digest: _Sha256 = Field(alias="findingDigest")


class WebBenchmarkFindingProjection(_FrozenStrictModel):
    """Public-safe Finding confirming only one benchmark Ground Truth match."""

    api_version: Literal["pajin.dev/web-benchmark-finding/v1alpha1"] = Field(
        default=WEB_BENCHMARK_FINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebBenchmarkFindingProjection"] = "WebBenchmarkFindingProjection"
    finding_id: str = Field(default="", alias="findingId", max_length=100)
    finding_digest: str = Field(default="", alias="findingDigest", max_length=64)
    evaluation: WebValidationFloorEvaluationRef
    projection_policy: WebBenchmarkFindingProjectionPolicyRef = Field(alias="projectionPolicy")
    source_measurement: WebZAPSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    claim_ceiling: Literal["benchmark-ground-truth-match"] = Field(
        default="benchmark-ground-truth-match",
        alias="claimCeiling",
    )
    finding_state: Literal[
        "confirmed-benchmark-ground-truth-match-only-impact-and-severity-not-evaluated"
    ] = Field(
        default=("confirmed-benchmark-ground-truth-match-only-impact-and-severity-not-evaluated"),
        alias="findingState",
    )
    impact_assurance: Literal["not-evaluated-information-only"] = Field(
        default="not-evaluated-information-only",
        alias="impactAssurance",
    )
    severity_assurance: Literal["not-evaluated-information-only"] = Field(
        default="not-evaluated-information-only",
        alias="severityAssurance",
    )
    finding_projection_performed: Literal[True] = Field(
        default=True,
        alias="findingProjectionPerformed",
    )
    benchmark_ground_truth_match_confirmed: Literal[True] = Field(
        default=True,
        alias="benchmarkGroundTruthMatchConfirmed",
    )
    benchmark_validation_floor_satisfied: Literal[True] = Field(
        default=True,
        alias="benchmarkValidationFloorSatisfied",
    )
    product_finding_confirmed: Literal[True] = Field(
        default=True,
        alias="productFindingConfirmed",
    )
    private_ground_truth_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthDisclosureAuthorized",
    )
    public_expected_finding_reference_exposure_authorized: Literal[False] = Field(
        default=False,
        alias="publicExpectedFindingReferenceExposureAuthorized",
    )
    raw_sarif_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="rawSarifDisclosureAuthorized",
    )
    controlled_query_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="controlledQueryDisclosureAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="graphMutationAuthorized",
    )
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(*_TRUE_FINDING_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002D Finding completion markers must be boolean true")
        return value

    @field_validator(*_FALSE_FINDING_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002D Finding authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_finding(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"finding_id", "finding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-benchmark-finding/v1",
            material,
            max_bytes=_MAX_FINDING_BYTES,
        )
        finding_id = f"web-benchmark-finding_{digest}"
        if self.finding_digest and self.finding_digest != digest:
            raise ValueError("WEB-002D Finding Digest differs")
        if self.finding_id and self.finding_id != finding_id:
            raise ValueError("WEB-002D Finding ID differs")
        object.__setattr__(self, "finding_digest", digest)
        object.__setattr__(self, "finding_id", finding_id)
        return self

    def reference(self) -> WebBenchmarkFindingRef:
        return WebBenchmarkFindingRef(
            findingId=self.finding_id,
            findingDigest=self.finding_digest,
        )


@dataclass(frozen=True, slots=True)
class WebValidationEvaluationOutcome:
    evaluation: WebValidationFloorEvaluation
    finding: WebBenchmarkFindingProjection


class _WebValidationEvaluationGate:
    """Internal Evidence-only evaluator for the sealed WEB-002D authority path."""

    def __init__(self) -> None:
        self._tool = BooleanSQLiProbeTool()

    def evaluate(
        self,
        *,
        floor_policy: WebBenchmarkValidationFloorPolicy,
        mapping: WebExpectedFindingProjectionMapping,
        measured_case_authority: WebMeasuredCaseAuthority,
        private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
        source_authority: WebZAPSourceMeasurementAuthority,
        validation_identities: WebControlledValidationIdentitySet,
        worker_evidence: WebControlledValidationWorkerEvidence,
        denial_control: WebObservedPolicyDenial,
        source_request_units: WebSourceRequestUnitObservation,
    ) -> WebValidationEvaluationOutcome:
        try:
            floor = _canonical_exact(
                WebBenchmarkValidationFloorPolicy,
                floor_policy,
                label="WEB-002D floor policy",
            )
            public_policy, private_binding = _canonical_mapping(mapping)
            measured_case = _canonical_exact(
                WebMeasuredCaseAuthority,
                measured_case_authority,
                label="WEB-002D measured-case authority",
            )
            private_profile = _canonical_exact(
                WebAPIBenchmarkGroundTruthProfile,
                private_ground_truth_profile,
                label="WEB-002D private Ground Truth profile",
            )
            source = _canonical_exact(
                WebZAPSourceMeasurementAuthority,
                source_authority,
                label="WEB-002D source authority",
            )
            identities = _canonical_exact(
                WebControlledValidationIdentitySet,
                validation_identities,
                label="WEB-002D validation identities",
            )
            canonical_worker_evidence = _canonical_exact(
                WebControlledValidationWorkerEvidence,
                worker_evidence,
                label="WEB-002D Worker Evidence",
            )
            canonical_request = canonical_worker_evidence.request
            canonical_worker = canonical_worker_evidence.worker_result
            canonical_result = canonical_worker_evidence.tool_result
            denial = _canonical_exact(
                WebObservedPolicyDenial,
                denial_control,
                label="WEB-002D denial observation",
            )
            request_units = _canonical_exact(
                WebSourceRequestUnitObservation,
                source_request_units,
                label="WEB-002D source request-unit observation",
            )
            _require_policy_mapping_source(floor, public_policy, private_binding, source)
            _require_identity_separation(source, identities, canonical_request, canonical_worker)
            _require_denial_control(floor, denial)
            _require_source_request_units(request_units, source)
            _validate_trusted_probe(
                self._tool,
                canonical_request,
                canonical_worker,
                canonical_result,
            )
            private_matcher = _execute_private_matcher(
                measured_case=measured_case,
                private_profile=private_profile,
                private_binding=private_binding,
                expected_reference_commitment=(public_policy.expected_reference_commitment),
                tool_result=canonical_result,
            )
            source_evidence_names, controlled_validation_evidence_names = (
                _verified_evidence_inventory(
                    floor=floor,
                    source=source,
                    worker_evidence=canonical_worker_evidence,
                    denial=denial,
                    private_matcher=private_matcher,
                )
            )
            observations = _metric_observations(
                floor,
                worker_result=canonical_worker,
                source_request_units=request_units.request_units,
                source_tool_calls=len(source.lineages),
                evidence_count=(
                    len(source_evidence_names) + len(controlled_validation_evidence_names)
                ),
                required_evidence_count=(
                    len(floor.required_source_evidence)
                    + len(floor.required_controlled_validation_evidence)
                ),
                independent_replay_succeeded=private_matcher.matched,
            )
            evaluation = WebValidationFloorEvaluation(
                floorPolicy=floor.reference(),
                projectionPolicy=public_policy.reference(),
                sourceMeasurement=source.reference(),
                sourceRequestUnits=request_units.reference(),
                privateMatcherObservation=private_matcher,
                validationIdentityDigest=web_controlled_validation_identity_digest(identities),
                denialControl=denial,
                sourceEvidenceNames=source_evidence_names,
                controlledValidationEvidenceNames=controlled_validation_evidence_names,
                observations=observations,
            )
            finding = WebBenchmarkFindingProjection(
                evaluation=evaluation.reference(),
                projectionPolicy=public_policy.reference(),
                sourceMeasurement=source.reference(),
            )
            return WebValidationEvaluationOutcome(evaluation=evaluation, finding=finding)
        except WebValidationEvaluationError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise WebValidationEvaluationError(
                "WEB-002D validation evaluation failed closed"
            ) from exc


def _canonical_exact[ModelT: BaseModel](
    cls: type[ModelT],
    value: object,
    *,
    label: str,
) -> ModelT:
    if type(value) is not cls:
        raise WebValidationEvaluationError(f"{label} requires its exact model type")
    _require_known_instance_fields(value, label=label)
    assert isinstance(value, BaseModel)
    return cls.model_validate(value.model_dump(mode="python"))


def _canonical_mapping(
    mapping: WebExpectedFindingProjectionMapping,
) -> tuple[WebBenchmarkFindingProjectionPolicy, WebPrivateExpectedFindingBinding]:
    if type(mapping) is not WebExpectedFindingProjectionMapping:
        raise WebValidationEvaluationError("WEB-002D Finding mapping requires its exact type")
    _require_known_instance_fields(mapping, label="WEB-002D Finding mapping")
    public = _canonical_exact(
        WebBenchmarkFindingProjectionPolicy,
        mapping.public_policy,
        label="WEB-002D public projection policy",
    )
    private = _canonical_exact(
        WebPrivateExpectedFindingBinding,
        mapping.private_binding,
        label="WEB-002D private Finding binding",
    )
    return public, private


def _require_policy_mapping_source(
    floor: WebBenchmarkValidationFloorPolicy,
    public_policy: WebBenchmarkFindingProjectionPolicy,
    private_binding: WebPrivateExpectedFindingBinding,
    source: WebZAPSourceMeasurementAuthority,
) -> None:
    if (
        source.measured_case != floor.measured_case
        or public_policy.measured_case != floor.measured_case
        or private_binding.measured_case != floor.measured_case
        or public_policy.floor_policy != floor.reference()
        or private_binding.floor_policy != floor.reference()
        or private_binding.public_projection != public_policy.reference()
        or public_policy.expected_reference_commitment
        != private_binding.expected_reference_commitment
        or public_policy.profile != floor.profile
        or public_policy.capability != floor.capability
    ):
        raise WebValidationEvaluationError("WEB-002D floor, mapping, and source lineage differ")


def _execute_private_matcher(
    *,
    measured_case: WebMeasuredCaseAuthority,
    private_profile: WebAPIBenchmarkGroundTruthProfile,
    private_binding: WebPrivateExpectedFindingBinding,
    expected_reference_commitment: str,
    tool_result: ToolResult,
) -> WebPrivateMatcherObservation:
    expected_profile = registered_web_api_benchmark_ground_truth_profile(
        private_profile.target_profile,
        benchmark_id=private_profile.private_ground_truth.ground_truth.benchmark_id,
    )
    expected_binding = expected_profile.private_ground_truth
    cases = expected_binding.ground_truth.cases
    if len(cases) != 1:
        raise WebValidationEvaluationError("WEB-002D private matcher requires one registered case")
    case = cases[0]
    output = BooleanSQLiProbeOutput.model_validate(tool_result.data)
    by_name = {item.name: item for item in output.observations}
    if (
        private_profile != expected_profile
        or measured_case.ground_truth_digest != expected_binding.ground_truth.digest()
        or measured_case.ground_truth_binding_digest != expected_binding.binding_digest
        or private_binding.private_ground_truth != expected_binding
        or private_binding.ground_truth_id != case.ground_truth_id
        or private_binding.expected_finding_id != case.expected_finding_id
        or private_binding.matcher_id != case.matcher_id
        or private_binding.matcher_version != case.matcher_version
        or private_binding.matcher_digest != case.matcher_digest
        or private_binding.surface_ids != tuple(case.surface_ids)
        or private_binding.expected_reference_commitment != expected_reference_commitment
        or case.matcher_digest != TRADITIONAL_WEB_API_BOOLEAN_SQLI_MATCHER_DIGEST
        or set(by_name) != {"baseline", "negative-control", "boolean-probe"}
        or (
            by_name["baseline"].status,
            by_name["baseline"].record_count,
            by_name["negative-control"].status,
            by_name["negative-control"].record_count,
            by_name["boolean-probe"].status,
            by_name["boolean-probe"].record_count,
        )
        != (200, 1, 200, 0, 200, 2)
        or not all(item.synthetic for item in by_name.values())
        or output.vulnerable is not True
    ):
        raise WebValidationEvaluationError("WEB-002D code-owned private matcher did not match")
    result_digest = benchmark_digest(
        "pajin.workflow.web-private-matcher-tool-result/v1",
        tool_result.model_dump(mode="json", by_alias=True),
        max_bytes=2 * 1024 * 1024,
    )
    matcher_execution_commitment = benchmark_digest(
        "pajin.workflow.web-private-matcher-execution-commitment/v1",
        {
            "privateBindingDigest": expected_binding.binding_digest,
            "matcherDigest": case.matcher_digest,
            "toolResultDigest": result_digest,
        },
        max_bytes=512 * 1024,
    )
    return WebPrivateMatcherObservation(
        measuredCase=measured_case.reference(),
        expectedReferenceCommitment=expected_reference_commitment,
        privateBindingDigest=expected_binding.binding_digest,
        matcherExecutionCommitment=matcher_execution_commitment,
        toolResultDigest=result_digest,
    )


def _validation_identity_strings(value: WebControlledValidationIdentitySet) -> tuple[str, ...]:
    return (
        value.validation_run_id,
        value.target_run_id,
        value.target_attempt_id,
        value.execution_operation_id,
        value.cleanup_operation_id,
        value.route_id,
        value.approval_id,
        value.permit_id,
        value.worker_execution_id,
        value.dispatch_id,
        value.tool_request_id,
        value.result_evidence_id,
    )


def _collect_strings(value: object) -> set[str]:
    strings: set[str] = set()
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str:
            strings.add(item)
        elif isinstance(item, Mapping):
            pending.extend(item.values())
        elif isinstance(item, (tuple, list, set, frozenset)):
            pending.extend(item)
    return strings


def _require_identity_separation(
    source: WebZAPSourceMeasurementAuthority,
    identities: WebControlledValidationIdentitySet,
    request: ToolRequest,
    worker_result: WorkerResult,
) -> None:
    if (
        identities.tool_request_id != request.request_id
        or identities.worker_execution_id != worker_result.execution_id
    ):
        raise WebValidationEvaluationError("WEB-002D runtime identity binding differs")
    source_strings = _collect_strings(source.model_dump(mode="python"))
    source_fences = {lineage.target_fence for lineage in source.lineages}
    if (
        source_strings.intersection(_validation_identity_strings(identities))
        or identities.target_fence in source_fences
    ):
        raise WebValidationEvaluationError("WEB-002B and WEB-002D identities overlap")


def _verified_evidence_inventory(
    *,
    floor: WebBenchmarkValidationFloorPolicy,
    source: WebZAPSourceMeasurementAuthority,
    worker_evidence: WebControlledValidationWorkerEvidence,
    denial: WebObservedPolicyDenial,
    private_matcher: WebPrivateMatcherObservation,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    source_names = WEB_VALIDATION_SOURCE_EVIDENCE_NAMES
    validation_names = WEB_VALIDATION_CONTROLLED_EVIDENCE_NAMES
    lineages = source.lineages
    output = BooleanSQLiProbeOutput.model_validate(worker_evidence.tool_result.data)
    if (
        source_names != floor.required_source_evidence
        or validation_names != floor.required_controlled_validation_evidence
        or not lineages
        or any(
            not lineage.journal_completed
            or not lineage.cleanup_resources_absent
            or lineage.raw_sarif_size_bytes <= 0
            for lineage in lineages
        )
        or not source.scanner_plan_digest
        or not source.scanner_registration_digest
    ):
        raise WebValidationEvaluationError("WEB-002D source evidence inventory is incomplete")
    if (
        len(worker_evidence.bridge_receipts) != 4
        or len(worker_evidence.host_http_receipt_digests) != 3
        or tuple(item.name for item in output.observations)
        != ("baseline", "negative-control", "boolean-probe")
        or worker_evidence.route_consumed is not True
        or worker_evidence.worker_proxy_only is not True
        or worker_evidence.proxy_bridge_verified is not True
        or worker_evidence.host_receipts_verified is not True
        or worker_evidence.ephemeral_resources_absent is not True
        or private_matcher.matched is not True
        or denial.denial_observed is not True
        or denial.route_materialized is not False
        or denial.provider_execution_performed is not False
        or denial.network_access_performed is not False
    ):
        raise WebValidationEvaluationError(
            "WEB-002D controlled-validation evidence inventory is incomplete"
        )
    return source_names, validation_names


def _require_denial_control(
    floor: WebBenchmarkValidationFloorPolicy,
    denial: WebObservedPolicyDenial,
) -> None:
    registry = floor.policy_denial_control_registry
    case = registry.cases[0]
    if (
        denial.registry_id != registry.registry_id
        or denial.registry_digest != registry.registry_digest
        or denial.case_id != case.case_id
        or denial.case_digest != case.case_digest
    ):
        raise WebValidationEvaluationError("WEB-002D denial observation is not registered")


def _require_exact_true(value: object, *, label: str) -> None:
    if type(value) is not bool or value is not True:
        raise WebValidationEvaluationError(f"WEB-002D {label} must be verified")


def _require_source_request_units(
    value: WebSourceRequestUnitObservation,
    source: WebZAPSourceMeasurementAuthority,
) -> None:
    if (
        value.source_measurement != source.reference()
        or value.measurement_result_digest != source.baseline_result_digest
        or value.request_units != source.source_request_units
        or value.request_units > 2**63 - 1 - WEB_MEASURED_VALIDATION_REQUEST_UNITS
    ):
        raise WebValidationEvaluationError("WEB-002D source request-unit measurement is invalid")


def _validate_trusted_probe(
    tool: BooleanSQLiProbeTool,
    request: ToolRequest,
    worker_result: WorkerResult,
    tool_result: ToolResult,
) -> None:
    if (
        request.tool_id != tool.spec.tool_id
        or request.method != "GET"
        or request.target != WEB_MEASURED_VALIDATION_TARGET
        or request.arguments != {"scenario_id": BOOLEAN_SQLI_SCENARIO}
        or worker_result.backend != "docker"
        or worker_result.status is not WorkerStatus.SUCCEEDED
        or worker_result.exit_code != 0
        or tool_result.request_id != request.request_id
        or tool_result.tool_id != request.tool_id
        or not tool_result.success
        or tool_result.error is not None
        or tool_result.started_at != worker_result.started_at
        or tool_result.finished_at != worker_result.finished_at
    ):
        raise WebValidationEvaluationError("WEB-002D trusted Tool execution identity differs")
    tool.prepare(request)
    interpreted = tool.interpret(request, worker_result)
    if interpreted != tool_result:
        raise WebValidationEvaluationError("WEB-002D Tool result differs from Worker output")
    tool.validate_trusted_execution(
        request,
        tool_result,
        worker_result,
        network_log_trusted=True,
    )
    output = BooleanSQLiProbeOutput.model_validate(tool_result.data)
    by_name = {item.name: item for item in output.observations}
    baseline = by_name["baseline"]
    negative = by_name["negative-control"]
    probe = by_name["boolean-probe"]
    checks = (
        baseline.status == 200 and baseline.record_count == 1,
        negative.status in {200, 400} and negative.record_count == 0,
        probe.status == 200 and probe.record_count > baseline.record_count,
        all(item.synthetic for item in output.observations),
    )
    claimed_checks = (
        output.checks.baseline_single_record,
        output.checks.negative_control_empty,
        output.checks.boolean_probe_expanded,
        output.checks.synthetic_lab_only,
    )
    if (
        output.target != request.target
        or output.scenario_id != BOOLEAN_SQLI_SCENARIO
        or not output.network_performed
        or claimed_checks != checks
        or output.vulnerable is not all(checks)
        or not all(checks)
    ):
        raise WebValidationEvaluationError(
            "WEB-002D Worker claims differ from independently recomputed observations"
        )


def _elapsed_microseconds(started_at: datetime, finished_at: datetime) -> int:
    if (
        started_at.tzinfo is None
        or started_at.utcoffset() is None
        or finished_at.tzinfo is None
        or finished_at.utcoffset() is None
    ):
        raise WebValidationEvaluationError("WEB-002D Worker timestamps require UTC offsets")
    delta = finished_at - started_at
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _metric_values(
    *,
    worker_result: WorkerResult,
    source_request_units: int,
    source_tool_calls: int,
    evidence_count: int,
    required_evidence_count: int,
    independent_replay_succeeded: bool,
) -> dict[str, tuple[int, int]]:
    values = dict(_FIXED_RATIONALS)
    values.update(
        {
            "common.replay-or-reanalysis-success-rate": (
                int(independent_replay_succeeded),
                1,
            ),
            "common.evidence-completeness": (
                evidence_count,
                required_evidence_count,
            ),
            "common.time-to-first-valid-result": (
                _elapsed_microseconds(worker_result.started_at, worker_result.finished_at),
                1_000_000,
            ),
            "common.total-request-units": (
                source_request_units + WEB_MEASURED_VALIDATION_REQUEST_UNITS,
                1,
            ),
            "common.total-tool-calls": (source_tool_calls + 1, 1),
        }
    )
    return values


def _metric_observations(
    floor: WebBenchmarkValidationFloorPolicy,
    *,
    worker_result: WorkerResult,
    source_request_units: int,
    source_tool_calls: int,
    evidence_count: int,
    required_evidence_count: int,
    independent_replay_succeeded: bool,
) -> tuple[WebBenchmarkMetricObservation, ...]:
    if tuple(item.metric.metric_id for item in floor.requirements) != _METRIC_IDS:
        raise WebValidationEvaluationError("WEB-002D floor metric order differs")
    values = _metric_values(
        worker_result=worker_result,
        source_request_units=source_request_units,
        source_tool_calls=source_tool_calls,
        evidence_count=evidence_count,
        required_evidence_count=required_evidence_count,
        independent_replay_succeeded=independent_replay_succeeded,
    )
    observations: list[WebBenchmarkMetricObservation] = []
    for requirement in floor.requirements:
        metric_id = requirement.metric.metric_id
        if requirement.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE:
            observation = WebBenchmarkMetricObservation(
                metric=requirement.metric,
                unit=requirement.unit,
                applicability=requirement.applicability,
                comparison=requirement.comparison,
                notApplicableReason=requirement.not_applicable_reason,
            )
        else:
            numerator, denominator = values[metric_id]
            _require_threshold(requirement, numerator=numerator, denominator=denominator)
            observation = WebBenchmarkMetricObservation(
                metric=requirement.metric,
                unit=requirement.unit,
                applicability=requirement.applicability,
                comparison=requirement.comparison,
                numerator=numerator,
                denominator=denominator,
            )
        observations.append(observation)
    return tuple(observations)


def _require_threshold(
    requirement: WebBenchmarkMetricFloorRequirement,
    *,
    numerator: int,
    denominator: int,
) -> None:
    comparison = requirement.comparison
    threshold_numerator = requirement.threshold_numerator
    threshold_denominator = requirement.threshold_denominator
    minimum_denominator = requirement.minimum_denominator
    if minimum_denominator is not None and denominator < minimum_denominator:
        raise WebValidationEvaluationError("WEB-002D metric denominator is below the floor")
    if comparison is WebMetricFloorComparison.MEASUREMENT_REQUIRED:
        return
    if threshold_numerator is None or threshold_denominator is None:
        raise WebValidationEvaluationError("WEB-002D metric threshold is incomplete")
    left = numerator * threshold_denominator
    right = threshold_numerator * denominator
    if (comparison is WebMetricFloorComparison.AT_LEAST and left < right) or (
        comparison is WebMetricFloorComparison.AT_MOST and left > right
    ):
        raise WebValidationEvaluationError("WEB-002D metric threshold is not satisfied")


def _validate_public_observations(
    observations: tuple[WebBenchmarkMetricObservation, ...],
) -> None:
    if tuple(item.metric.metric_id for item in observations) != _METRIC_IDS:
        raise ValueError("WEB-002D public metric observations differ")
    by_id = {item.metric.metric_id: item for item in observations}
    if len(by_id) != len(_METRIC_IDS):
        raise ValueError("WEB-002D public metric observations are not unique")
    for metric_id, (applicability, comparison) in _PUBLIC_METRIC_CONTRACTS.items():
        item = by_id[metric_id]
        if item.applicability is not applicability or item.comparison is not comparison:
            raise ValueError("WEB-002D public metric contract differs")
    for metric_id, expected in _FIXED_RATIONALS.items():
        item = by_id[metric_id]
        if (item.numerator, item.denominator) != expected:
            raise ValueError("WEB-002D fixed metric observation differs")
    for metric_id, reason in _NOT_APPLICABLE_REASONS.items():
        item = by_id[metric_id]
        if (
            item.applicability is not DomainBenchmarkMetricApplicability.NOT_APPLICABLE
            or item.not_applicable_reason is not reason
        ):
            raise ValueError("WEB-002D N/A metric decision differs")
    for metric_id in _MEASUREMENT_METRICS:
        item = by_id[metric_id]
        if item.numerator is None or item.denominator is None:
            raise ValueError("WEB-002D measurement-only metric is missing")
    if by_id["common.time-to-first-valid-result"].denominator != 1_000_000:
        raise ValueError("WEB-002D elapsed-time rational denominator differs")
    if (
        by_id["common.total-request-units"].denominator != 1
        or by_id["common.total-request-units"].numerator is None
        or by_id["common.total-request-units"].numerator < WEB_MEASURED_VALIDATION_REQUEST_UNITS + 1
        or by_id["common.total-tool-calls"].denominator != 1
        or by_id["common.total-tool-calls"].numerator is None
        or by_id["common.total-tool-calls"].numerator < 2
    ):
        raise ValueError("WEB-002D count metric observation differs")
    for item in observations:
        registered = resolve_registered_domain_benchmark_metric(item.metric)
        if item.unit is not registered.unit:
            raise ValueError("WEB-002D metric unit differs from DOMAIN-006")


def web_controlled_validation_identity_digest(
    identities: WebControlledValidationIdentitySet,
) -> str:
    return benchmark_digest(
        "pajin.workflow.web-controlled-validation-identity-set/v1",
        identities.model_dump(mode="json", by_alias=True),
        max_bytes=512 * 1024,
    )


__all__ = [
    "WEB_BENCHMARK_FINDING_API_VERSION",
    "WEB_SOURCE_REQUEST_UNIT_OBSERVATION_API_VERSION",
    "WEB_VALIDATION_CONTROLLED_EVIDENCE_NAMES",
    "WEB_VALIDATION_FLOOR_EVALUATION_API_VERSION",
    "WEB_VALIDATION_SOURCE_EVIDENCE_NAMES",
    "WebBenchmarkFindingProjection",
    "WebBenchmarkFindingRef",
    "WebBenchmarkMetricObservation",
    "WebControlledValidationIdentitySet",
    "WebObservedPolicyDenial",
    "WebPrivateMatcherObservation",
    "WebSourceRequestUnitObservation",
    "WebSourceRequestUnitObservationRef",
    "WebValidationEvaluationError",
    "WebValidationEvaluationOutcome",
    "WebValidationFloorEvaluation",
    "WebValidationFloorEvaluationRef",
    "observe_web_source_request_units",
    "web_controlled_validation_identity_digest",
]
