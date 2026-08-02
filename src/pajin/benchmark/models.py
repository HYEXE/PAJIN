"""Versioned benchmark contracts for deterministic and adaptive PAJIN runs."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from pajin.domain.models import StrictModel

BENCHMARK_MANIFEST_API_VERSION: Literal["pajin.dev/benchmark-manifest/v1alpha1"] = (
    "pajin.dev/benchmark-manifest/v1alpha1"
)
BENCHMARK_GROUND_TRUTH_API_VERSION: Literal[
    "pajin.dev/benchmark-ground-truth/v1alpha1"
] = "pajin.dev/benchmark-ground-truth/v1alpha1"
BENCHMARK_RESULT_API_VERSION: Literal["pajin.dev/benchmark-result/v1alpha1"] = (
    "pajin.dev/benchmark-result/v1alpha1"
)
BENCHMARK_COMPARISON_API_VERSION: Literal[
    "pajin.dev/benchmark-comparison/v1alpha1"
] = "pajin.dev/benchmark-comparison/v1alpha1"

_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_GROUND_TRUTH_BYTES = 4 * 1024 * 1024
_MAX_RESULT_BYTES = 4 * 1024 * 1024
_MAX_COMPARISON_BYTES = 512 * 1024
_MAX_GROUND_TRUTH_CASES = 10_000
_MAX_RUN_BINDINGS = 2_000
_MAX_EVIDENCE_REFERENCES = 1_000

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_UnitValue = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class BenchmarkMetric(StrEnum):
    ATTACK_SURFACE_RECALL = "attack-surface-recall"
    FINDING_RECALL = "finding-recall"
    FINDING_PRECISION = "finding-precision"
    UNEXPECTED_VALID_FINDING_YIELD = "unexpected-valid-finding-yield"
    CROSS_SURFACE_CHAIN_COMPLETION_RATE = "cross-surface-chain-completion-rate"
    TIME_TO_FIRST_VALID_OR_CONFIRMED_FINDING = (
        "time-to-first-valid-or-confirmed-finding"
    )
    COST_PER_CONFIRMED_FINDING = "cost-per-confirmed-finding"
    REPLAY_SUCCESS_RATE = "replay-success-rate"
    POLICY_REJECTION_OR_VIOLATION_COUNT = "policy-rejection-or-violation-count"
    HUMAN_INTERVENTION_OR_OVERTURN_RATE = "human-intervention-or-overturn-rate"
    RUN_TO_RUN_VARIANCE = "run-to-run-variance"
    CLEANUP_SUCCESS_RATE = "cleanup-success-rate"


BENCHMARK_METRIC_ORDER: tuple[BenchmarkMetric, ...] = tuple(BenchmarkMetric)
REQUIRED_BENCHMARK_METRICS: frozenset[BenchmarkMetric] = frozenset(
    BENCHMARK_METRIC_ORDER
)


class BenchmarkMetricUnit(StrEnum):
    RATIO = "ratio"
    COUNT = "count"
    SECONDS = "seconds"
    USD = "usd"
    COEFFICIENT = "coefficient"


_EXPECTED_METRIC_UNITS: dict[BenchmarkMetric, BenchmarkMetricUnit] = {
    BenchmarkMetric.ATTACK_SURFACE_RECALL: BenchmarkMetricUnit.RATIO,
    BenchmarkMetric.FINDING_RECALL: BenchmarkMetricUnit.RATIO,
    BenchmarkMetric.FINDING_PRECISION: BenchmarkMetricUnit.RATIO,
    BenchmarkMetric.UNEXPECTED_VALID_FINDING_YIELD: BenchmarkMetricUnit.COUNT,
    BenchmarkMetric.CROSS_SURFACE_CHAIN_COMPLETION_RATE: BenchmarkMetricUnit.RATIO,
    BenchmarkMetric.TIME_TO_FIRST_VALID_OR_CONFIRMED_FINDING: (
        BenchmarkMetricUnit.SECONDS
    ),
    BenchmarkMetric.COST_PER_CONFIRMED_FINDING: BenchmarkMetricUnit.USD,
    BenchmarkMetric.REPLAY_SUCCESS_RATE: BenchmarkMetricUnit.RATIO,
    BenchmarkMetric.POLICY_REJECTION_OR_VIOLATION_COUNT: BenchmarkMetricUnit.COUNT,
    BenchmarkMetric.HUMAN_INTERVENTION_OR_OVERTURN_RATE: BenchmarkMetricUnit.RATIO,
    BenchmarkMetric.RUN_TO_RUN_VARIANCE: BenchmarkMetricUnit.COEFFICIENT,
    BenchmarkMetric.CLEANUP_SUCCESS_RATE: BenchmarkMetricUnit.RATIO,
}

_COMPLETED_NOT_APPLICABLE_METRICS = frozenset(
    {
        BenchmarkMetric.FINDING_PRECISION,
        BenchmarkMetric.TIME_TO_FIRST_VALID_OR_CONFIRMED_FINDING,
        BenchmarkMetric.COST_PER_CONFIRMED_FINDING,
        BenchmarkMetric.REPLAY_SUCCESS_RATE,
        BenchmarkMetric.HUMAN_INTERVENTION_OR_OVERTURN_RATE,
    }
)


class BenchmarkArmKind(StrEnum):
    DETERMINISTIC_BASELINE = "deterministic-baseline"
    ADAPTIVE_CANDIDATE = "adaptive-candidate"


class BenchmarkResultStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BenchmarkMetricStatus(StrEnum):
    MEASURED = "measured"
    NOT_APPLICABLE = "not-applicable"


class GroundTruthVisibility(StrEnum):
    SEEDED = "seeded"
    HOLDOUT = "holdout"


def canonical_benchmark_json(value: object, *, label: str, max_bytes: int) -> bytes:
    """Return strict, bounded canonical UTF-8 JSON."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the canonical byte limit")
    return encoded


def benchmark_digest(domain: str, value: object, *, max_bytes: int) -> str:
    """Return one domain-separated digest for a canonical benchmark value."""

    domain_bytes = domain.encode("ascii", errors="strict")
    encoded = canonical_benchmark_json(value, label=domain, max_bytes=max_bytes)
    return sha256(domain_bytes + b"\x00" + encoded).hexdigest()


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _safe_relative_reference(value: str) -> str:
    if value != value.strip():
        raise ValueError("Benchmark evidence reference cannot have surrounding whitespace")
    if "\\" in value:
        raise ValueError("Benchmark evidence reference must use forward slashes")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Benchmark evidence reference must be a normalized relative path")
    if path.as_posix() != value:
        raise ValueError("Benchmark evidence reference must be a normalized relative path")
    return value


class BenchmarkArm(StrictModel):
    """One implementation arm evaluated by the same protocol."""

    arm_id: _Identifier = Field(alias="armId")
    kind: BenchmarkArmKind
    implementation_id: _Identifier = Field(alias="implementationId")
    implementation_version: _Identifier = Field(alias="implementationVersion")
    configuration_digest: _Sha256 = Field(alias="configurationDigest")
    adaptive_supervisor: bool = Field(alias="adaptiveSupervisor")

    @model_validator(mode="after")
    def require_arm_semantics(self) -> Self:
        expected = self.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
        if self.adaptive_supervisor is not expected:
            raise ValueError("Benchmark arm kind and adaptiveSupervisor disagree")
        return self


class BenchmarkRunProtocol(StrictModel):
    """Reset, isolation, budget, and metric rules shared by every arm."""

    protocol_id: _Identifier = Field(alias="protocolId")
    protocol_version: _Identifier = Field(alias="protocolVersion")
    seeds: list[int] = Field(min_length=1, max_length=100)
    repetitions_per_seed: int = Field(
        default=1,
        alias="repetitionsPerSeed",
        ge=1,
        le=20,
    )
    timeout_seconds: int = Field(alias="timeoutSeconds", ge=1, le=86_400)
    max_cost_usd: float = Field(alias="maxCostUsd", ge=0, le=100_000, allow_inf_nan=False)
    max_tool_calls: int = Field(alias="maxToolCalls", ge=1, le=1_000_000)
    max_model_calls: int = Field(alias="maxModelCalls", ge=0, le=1_000_000)
    reset_before_each_run: Literal[True] = Field(
        default=True,
        alias="resetBeforeEachRun",
    )
    isolate_each_run: Literal[True] = Field(default=True, alias="isolateEachRun")
    cleanup_after_each_run: Literal[True] = Field(
        default=True,
        alias="cleanupAfterEachRun",
    )
    open_world_adjudication: Literal[True] = Field(
        default=True,
        alias="openWorldAdjudication",
    )
    metrics: list[BenchmarkMetric] = Field(
        default_factory=lambda: list(BENCHMARK_METRIC_ORDER),
        min_length=len(BENCHMARK_METRIC_ORDER),
        max_length=len(BENCHMARK_METRIC_ORDER),
    )
    @field_validator("seeds")
    @classmethod
    def require_canonical_seeds(cls, value: list[int]) -> list[int]:
        if any(seed < 0 or seed > 2**63 - 1 for seed in value):
            raise ValueError("Benchmark seeds must be non-negative signed 64-bit integers")
        if value != sorted(set(value)):
            raise ValueError("Benchmark seeds must be unique and canonically sorted")
        return value

    @field_validator("metrics")
    @classmethod
    def require_complete_metric_contract(
        cls,
        value: list[BenchmarkMetric],
    ) -> list[BenchmarkMetric]:
        if value != list(BENCHMARK_METRIC_ORDER):
            raise ValueError("Benchmark protocol must contain every required metric in order")
        return value


class BenchmarkManifest(StrictModel):
    """Public benchmark manifest without holdout ground-truth contents."""

    api_version: Literal["pajin.dev/benchmark-manifest/v1alpha1"] = Field(
        default=BENCHMARK_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkManifest"] = "BenchmarkManifest"
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    target_factory_id: _Identifier = Field(alias="targetFactoryId")
    target_factory_version: _Identifier = Field(alias="targetFactoryVersion")
    target_factory_digest: _Sha256 = Field(alias="targetFactoryDigest")
    target_profile_id: _Identifier = Field(alias="targetProfileId")
    target_profile_version: _Identifier = Field(alias="targetProfileVersion")
    mutation_profile_id: _Identifier | None = Field(
        default=None,
        alias="mutationProfileId",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    ground_truth_digest: _Sha256 = Field(alias="groundTruthDigest")
    protocol: BenchmarkRunProtocol
    arms: list[BenchmarkArm] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def require_canonical_arms_and_bounded_manifest(self) -> Self:
        expected_kinds = [
            BenchmarkArmKind.DETERMINISTIC_BASELINE,
            BenchmarkArmKind.ADAPTIVE_CANDIDATE,
        ][: len(self.arms)]
        if [arm.kind for arm in self.arms] != expected_kinds:
            raise ValueError(
                "Benchmark arms must be baseline first and optional adaptive candidate second"
            )
        arm_ids = [arm.arm_id for arm in self.arms]
        if len(arm_ids) != len(set(arm_ids)):
            raise ValueError("Benchmark arm IDs must be unique")
        canonical_benchmark_json(
            self.model_dump(mode="json", by_alias=True),
            label="BenchmarkManifest",
            max_bytes=_MAX_MANIFEST_BYTES,
        )
        return self

    def digest(self) -> str:
        return benchmark_digest(
            "pajin.benchmark.manifest/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_MANIFEST_BYTES,
        )


class BenchmarkGroundTruthCase(StrictModel):
    """One known valid Finding and its deterministic matcher contract."""

    ground_truth_id: _Identifier = Field(alias="groundTruthId")
    expected_finding_id: _Identifier = Field(alias="expectedFindingId")
    surface_ids: list[_Identifier] = Field(alias="surfaceIds", min_length=1, max_length=100)
    chain_id: _Identifier | None = Field(default=None, alias="chainId")
    matcher_id: _Identifier = Field(alias="matcherId")
    matcher_version: _Identifier = Field(alias="matcherVersion")
    matcher_digest: _Sha256 = Field(alias="matcherDigest")
    visibility: GroundTruthVisibility

    @field_validator("surface_ids")
    @classmethod
    def require_canonical_surfaces(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("Ground-truth surface IDs must be unique and sorted")
        return value


class BenchmarkGroundTruth(StrictModel):
    """Private ground truth kept separate from the public manifest."""

    api_version: Literal["pajin.dev/benchmark-ground-truth/v1alpha1"] = Field(
        default=BENCHMARK_GROUND_TRUTH_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkGroundTruth"] = "BenchmarkGroundTruth"
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    target_factory_digest: _Sha256 = Field(alias="targetFactoryDigest")
    cases: list[BenchmarkGroundTruthCase] = Field(
        min_length=1,
        max_length=_MAX_GROUND_TRUTH_CASES,
    )

    @model_validator(mode="after")
    def require_canonical_cases_and_bounded_ground_truth(self) -> Self:
        case_ids = [case.ground_truth_id for case in self.cases]
        if case_ids != sorted(set(case_ids)):
            raise ValueError("Ground-truth cases must have unique, sorted IDs")
        canonical_benchmark_json(
            self.model_dump(mode="json", by_alias=True),
            label="BenchmarkGroundTruth",
            max_bytes=_MAX_GROUND_TRUTH_BYTES,
        )
        return self

    def digest(self) -> str:
        return benchmark_digest(
            "pajin.benchmark.ground-truth/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_GROUND_TRUTH_BYTES,
        )


class BenchmarkMetricObservation(StrictModel):
    """One measured or explicitly unavailable required metric."""

    metric: BenchmarkMetric
    unit: BenchmarkMetricUnit
    status: BenchmarkMetricStatus = BenchmarkMetricStatus.MEASURED
    value: _UnitValue | None = None
    numerator: _UnitValue | None = None
    denominator: _UnitValue | None = None
    reason: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def require_metric_semantics(self) -> Self:
        expected_unit = _EXPECTED_METRIC_UNITS[self.metric]
        if self.unit is not expected_unit:
            raise ValueError(
                f"{self.metric.value} must use the {expected_unit.value} unit"
            )
        if self.status is BenchmarkMetricStatus.NOT_APPLICABLE:
            if any(
                value is not None for value in (self.value, self.numerator, self.denominator)
            ):
                raise ValueError("Not-applicable metric cannot carry numeric values")
            if self.reason is None:
                raise ValueError("Not-applicable metric requires a reason")
            return self
        if self.value is None:
            raise ValueError("Measured metric requires a value")
        if self.reason is not None:
            raise ValueError("Measured metric cannot carry a not-applicable reason")
        if expected_unit is BenchmarkMetricUnit.RATIO and self.value > 1:
            raise ValueError("Ratio metric must be between zero and one")
        if expected_unit is BenchmarkMetricUnit.COUNT and not self.value.is_integer():
            raise ValueError("Count metric must be an integer")
        if (self.numerator is None) is not (self.denominator is None):
            raise ValueError("Metric numerator and denominator must be provided together")
        if self.denominator is not None:
            if self.denominator == 0:
                raise ValueError("Metric denominator must be greater than zero")
            assert self.numerator is not None
            if expected_unit is BenchmarkMetricUnit.RATIO:
                if self.numerator > self.denominator:
                    raise ValueError("Ratio numerator cannot exceed denominator")
                expected_value = self.numerator / self.denominator
                if not math.isclose(self.value, expected_value, rel_tol=1e-12, abs_tol=1e-12):
                    raise ValueError("Ratio metric differs from numerator/denominator")
        return self


class BenchmarkRunBinding(StrictModel):
    """Digest-bound identity of one isolated run contributing to an arm result."""

    run_id: _Identifier = Field(alias="runId")
    seed: int = Field(ge=0, le=2**63 - 1)
    repetition: int = Field(ge=1, le=20)
    run_root_digest: _Sha256 = Field(alias="runRootDigest")
    cleanup_succeeded: bool = Field(alias="cleanupSucceeded")


class BenchmarkEvidenceReference(StrictModel):
    """Digest-bound reference inside a sealed benchmark artifact."""

    reference: str = Field(min_length=1, max_length=2_000)
    sha256: _Sha256
    media_type: str = Field(
        default="application/json",
        alias="mediaType",
        min_length=1,
        max_length=100,
    )

    @field_validator("reference")
    @classmethod
    def require_safe_reference(cls, value: str) -> str:
        return _safe_relative_reference(value)


class BenchmarkResult(StrictModel):
    """Aggregate result for one arm under one exact manifest and protocol."""

    api_version: Literal["pajin.dev/benchmark-result/v1alpha1"] = Field(
        default=BENCHMARK_RESULT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkResult"] = "BenchmarkResult"
    result_id: _Identifier = Field(alias="resultId")
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    arm_id: _Identifier = Field(alias="armId")
    arm_kind: BenchmarkArmKind = Field(alias="armKind")
    target_factory_digest: _Sha256 = Field(alias="targetFactoryDigest")
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    ground_truth_digest: _Sha256 = Field(alias="groundTruthDigest")
    protocol_id: _Identifier = Field(alias="protocolId")
    protocol_version: _Identifier = Field(alias="protocolVersion")
    status: BenchmarkResultStatus
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    runs: list[BenchmarkRunBinding] = Field(
        min_length=1,
        max_length=_MAX_RUN_BINDINGS,
    )
    metrics: list[BenchmarkMetricObservation] = Field(
        min_length=len(BENCHMARK_METRIC_ORDER),
        max_length=len(BENCHMARK_METRIC_ORDER),
    )
    evidence: list[BenchmarkEvidenceReference] = Field(
        min_length=1,
        max_length=_MAX_EVIDENCE_REFERENCES,
    )
    open_world_candidate_ids: list[_Identifier] = Field(
        default_factory=list,
        alias="openWorldCandidateIds",
        max_length=10_000,
    )
    failure_reason: str | None = Field(
        default=None,
        alias="failureReason",
        min_length=1,
        max_length=1_000,
    )

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Benchmark result timestamp")

    @field_validator("open_world_candidate_ids")
    @classmethod
    def require_canonical_open_world_candidates(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("Open-world candidate IDs must be unique and sorted")
        return value

    @model_validator(mode="after")
    def require_complete_result_contract(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("Benchmark result completes before it starts")
        run_keys = [(run.seed, run.repetition, run.run_id) for run in self.runs]
        if run_keys != sorted(set(run_keys)):
            raise ValueError("Benchmark runs must be unique and canonically sorted")
        if [item.metric for item in self.metrics] != list(BENCHMARK_METRIC_ORDER):
            raise ValueError("Benchmark result must contain every required metric in order")
        evidence_keys = [
            (item.reference, item.sha256, item.media_type) for item in self.evidence
        ]
        if evidence_keys != sorted(set(evidence_keys)):
            raise ValueError("Benchmark evidence must be unique and canonically sorted")
        if self.status is BenchmarkResultStatus.COMPLETED:
            if self.failure_reason is not None:
                raise ValueError("Completed benchmark result cannot carry a failure reason")
            if any(
                metric.status is BenchmarkMetricStatus.NOT_APPLICABLE
                and metric.metric not in _COMPLETED_NOT_APPLICABLE_METRICS
                for metric in self.metrics
            ):
                raise ValueError(
                    "Completed benchmark result uses not-applicable without a nullable denominator"
                )
        elif self.failure_reason is None:
            raise ValueError("Failed or cancelled benchmark result requires a reason")

        cleanup = self.metrics[-1]
        if cleanup.metric is not BenchmarkMetric.CLEANUP_SUCCESS_RATE:
            raise ValueError("Cleanup success rate must be the final required metric")
        if cleanup.status is BenchmarkMetricStatus.MEASURED:
            succeeded = sum(run.cleanup_succeeded for run in self.runs)
            total = len(self.runs)
            expected = succeeded / total
            if cleanup.numerator != float(succeeded) or cleanup.denominator != float(total):
                raise ValueError("Cleanup metric must bind exact run cleanup counts")
            if cleanup.value is None or not math.isclose(
                cleanup.value,
                expected,
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                raise ValueError("Cleanup metric differs from run cleanup outcomes")

        canonical_benchmark_json(
            self.model_dump(mode="json", by_alias=True),
            label="BenchmarkResult",
            max_bytes=_MAX_RESULT_BYTES,
        )
        return self

    def digest(self) -> str:
        return benchmark_digest(
            "pajin.benchmark.result/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_RESULT_BYTES,
        )


class BenchmarkMetricDelta(StrictModel):
    metric: BenchmarkMetric
    unit: BenchmarkMetricUnit
    baseline_value: _UnitValue = Field(alias="baselineValue")
    candidate_value: _UnitValue = Field(alias="candidateValue")
    candidate_minus_baseline: float = Field(
        alias="candidateMinusBaseline",
        allow_inf_nan=False,
    )

    @model_validator(mode="after")
    def require_exact_delta(self) -> Self:
        if self.unit is not _EXPECTED_METRIC_UNITS[self.metric]:
            raise ValueError("Benchmark comparison metric uses the wrong unit")
        expected = self.candidate_value - self.baseline_value
        if not math.isclose(
            self.candidate_minus_baseline,
            expected,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise ValueError("Benchmark comparison delta is not exact")
        return self


class BenchmarkComparison(StrictModel):
    """Deterministic baseline versus adaptive candidate on identical run coordinates."""

    api_version: Literal["pajin.dev/benchmark-comparison/v1alpha1"] = Field(
        default=BENCHMARK_COMPARISON_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkComparison"] = "BenchmarkComparison"
    comparison_id: _Identifier = Field(alias="comparisonId")
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    baseline_result_digest: _Sha256 = Field(alias="baselineResultDigest")
    candidate_result_digest: _Sha256 = Field(alias="candidateResultDigest")
    compared_at: datetime = Field(alias="comparedAt")
    deltas: list[BenchmarkMetricDelta] = Field(
        min_length=len(BENCHMARK_METRIC_ORDER),
        max_length=len(BENCHMARK_METRIC_ORDER),
    )

    @field_validator("compared_at")
    @classmethod
    def normalize_compared_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Benchmark comparison timestamp")

    @model_validator(mode="after")
    def require_complete_comparison(self) -> Self:
        if [item.metric for item in self.deltas] != list(BENCHMARK_METRIC_ORDER):
            raise ValueError("Benchmark comparison must contain every required metric in order")
        canonical_benchmark_json(
            self.model_dump(mode="json", by_alias=True),
            label="BenchmarkComparison",
            max_bytes=_MAX_COMPARISON_BYTES,
        )
        return self

    def digest(self) -> str:
        return benchmark_digest(
            "pajin.benchmark.comparison/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_COMPARISON_BYTES,
        )


def compare_benchmark_results(
    baseline: BenchmarkResult,
    candidate: BenchmarkResult,
    *,
    compared_at: datetime,
) -> BenchmarkComparison:
    """Compare completed arms only when every authority and run coordinate matches."""

    if baseline.arm_kind is not BenchmarkArmKind.DETERMINISTIC_BASELINE:
        raise ValueError("Baseline result does not identify the deterministic baseline arm")
    if candidate.arm_kind is not BenchmarkArmKind.ADAPTIVE_CANDIDATE:
        raise ValueError("Candidate result does not identify the adaptive candidate arm")
    if (
        baseline.status is not BenchmarkResultStatus.COMPLETED
        or candidate.status is not BenchmarkResultStatus.COMPLETED
    ):
        raise ValueError("Benchmark comparison requires two completed results")

    bindings = (
        "benchmark_id",
        "manifest_digest",
        "target_factory_digest",
        "campaign_digest",
        "ground_truth_digest",
        "protocol_id",
        "protocol_version",
    )
    for field_name in bindings:
        if getattr(baseline, field_name) != getattr(candidate, field_name):
            raise ValueError(f"Benchmark results disagree on {field_name}")
    baseline_coordinates = [(run.seed, run.repetition) for run in baseline.runs]
    candidate_coordinates = [(run.seed, run.repetition) for run in candidate.runs]
    if baseline_coordinates != candidate_coordinates:
        raise ValueError("Benchmark results use different seed/repetition coordinates")

    deltas: list[BenchmarkMetricDelta] = []
    for baseline_metric, candidate_metric in zip(
        baseline.metrics,
        candidate.metrics,
        strict=True,
    ):
        if baseline_metric.value is None or candidate_metric.value is None:
            raise ValueError("Benchmark comparison requires measured metric values")
        deltas.append(
            BenchmarkMetricDelta(
                metric=baseline_metric.metric,
                unit=baseline_metric.unit,
                baselineValue=baseline_metric.value,
                candidateValue=candidate_metric.value,
                candidateMinusBaseline=candidate_metric.value - baseline_metric.value,
            )
        )

    baseline_digest = baseline.digest()
    candidate_digest = candidate.digest()
    identity = benchmark_digest(
        "pajin.benchmark.comparison-identity/v1",
        {
            "baselineResultDigest": baseline_digest,
            "candidateResultDigest": candidate_digest,
        },
        max_bytes=4 * 1024,
    )
    return BenchmarkComparison(
        comparisonId=f"benchmark-comparison:{identity}",
        benchmarkId=baseline.benchmark_id,
        manifestDigest=baseline.manifest_digest,
        baselineResultDigest=baseline_digest,
        candidateResultDigest=candidate_digest,
        comparedAt=compared_at,
        deltas=deltas,
    )
