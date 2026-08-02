from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.benchmark import (
    BENCHMARK_METRIC_ORDER,
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkEvidenceReference,
    BenchmarkGroundTruth,
    BenchmarkGroundTruthCase,
    BenchmarkManifest,
    BenchmarkMetric,
    BenchmarkMetricObservation,
    BenchmarkMetricStatus,
    BenchmarkMetricUnit,
    BenchmarkResult,
    BenchmarkResultStatus,
    BenchmarkRunBinding,
    BenchmarkRunProtocol,
    GroundTruthVisibility,
    compare_benchmark_results,
)

NOW = datetime(2026, 7, 26, 3, 0, tzinfo=UTC)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64

_UNIT_BY_METRIC = {
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


def _arm(kind: BenchmarkArmKind) -> BenchmarkArm:
    adaptive = kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
    suffix = "candidate" if adaptive else "baseline"
    return BenchmarkArm(
        armId=f"arm:{suffix}",
        kind=kind,
        implementationId=f"pajin:{suffix}",
        implementationVersion="1.0.0",
        configurationDigest=DIGEST_B if adaptive else DIGEST_A,
        adaptiveSupervisor=adaptive,
    )


def _protocol() -> BenchmarkRunProtocol:
    return BenchmarkRunProtocol(
        protocolId="pajin:benchmark-protocol",
        protocolVersion="1.0.0",
        seeds=[7, 11],
        repetitionsPerSeed=2,
        timeoutSeconds=600,
        maxCostUsd=25,
        maxToolCalls=500,
        maxModelCalls=100,
    )


def _manifest() -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId="benchmark:hybrid-v1",
        targetFactoryId="target-factory:hybrid",
        targetFactoryVersion="1.0.0",
        targetFactoryDigest=DIGEST_A,
        targetProfileId="hybrid:file-rag-mcp",
        targetProfileVersion="1.0.0",
        mutationProfileId="mutation:seeded",
        campaignDigest=DIGEST_B,
        groundTruthDigest=DIGEST_C,
        protocol=_protocol(),
        arms=[
            _arm(BenchmarkArmKind.DETERMINISTIC_BASELINE),
            _arm(BenchmarkArmKind.ADAPTIVE_CANDIDATE),
        ],
    )


def _runs(*, cleanup_succeeded: bool = True) -> list[BenchmarkRunBinding]:
    return [
        BenchmarkRunBinding(
            runId="run:7:1",
            seed=7,
            repetition=1,
            runRootDigest=DIGEST_A,
            cleanupSucceeded=cleanup_succeeded,
        ),
        BenchmarkRunBinding(
            runId="run:11:1",
            seed=11,
            repetition=1,
            runRootDigest=DIGEST_B,
            cleanupSucceeded=True,
        ),
    ]


def _metric_observations(
    *,
    delta: float = 0,
    cleanup_succeeded: int = 2,
) -> list[BenchmarkMetricObservation]:
    observations: list[BenchmarkMetricObservation] = []
    for metric in BENCHMARK_METRIC_ORDER:
        unit = _UNIT_BY_METRIC[metric]
        if metric is BenchmarkMetric.CLEANUP_SUCCESS_RATE:
            observations.append(
                BenchmarkMetricObservation(
                    metric=metric,
                    unit=unit,
                    value=cleanup_succeeded / 2,
                    numerator=float(cleanup_succeeded),
                    denominator=2.0,
                )
            )
        elif unit is BenchmarkMetricUnit.RATIO:
            value = 0.5 + delta
            observations.append(
                BenchmarkMetricObservation(
                    metric=metric,
                    unit=unit,
                    value=value,
                    numerator=value * 10,
                    denominator=10.0,
                )
            )
        elif unit is BenchmarkMetricUnit.COUNT:
            observations.append(
                BenchmarkMetricObservation(
                    metric=metric,
                    unit=unit,
                    value=2.0,
                )
            )
        elif unit is BenchmarkMetricUnit.SECONDS:
            observations.append(
                BenchmarkMetricObservation(
                    metric=metric,
                    unit=unit,
                    value=120.0 - delta,
                )
            )
        elif unit is BenchmarkMetricUnit.USD:
            observations.append(
                BenchmarkMetricObservation(
                    metric=metric,
                    unit=unit,
                    value=3.5 + delta,
                )
            )
        else:
            observations.append(
                BenchmarkMetricObservation(
                    metric=metric,
                    unit=unit,
                    value=0.1 + delta,
                )
            )
    return observations


def _result(
    arm_kind: BenchmarkArmKind,
    *,
    manifest_digest: str | None = None,
    delta: float = 0,
) -> BenchmarkResult:
    manifest = _manifest()
    suffix = (
        "candidate"
        if arm_kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
        else "baseline"
    )
    return BenchmarkResult(
        resultId=f"result:{suffix}",
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest_digest or manifest.digest(),
        armId=f"arm:{suffix}",
        armKind=arm_kind,
        targetFactoryDigest=manifest.target_factory_digest,
        campaignDigest=manifest.campaign_digest,
        groundTruthDigest=manifest.ground_truth_digest,
        protocolId=manifest.protocol.protocol_id,
        protocolVersion=manifest.protocol.protocol_version,
        status=BenchmarkResultStatus.COMPLETED,
        startedAt=NOW,
        completedAt=NOW + timedelta(minutes=5),
        runs=_runs(),
        metrics=_metric_observations(delta=delta),
        evidence=[
            BenchmarkEvidenceReference(
                reference=f"benchmark/{suffix}/result.json",
                sha256=DIGEST_D,
            )
        ],
    )


def test_manifest_and_private_ground_truth_have_stable_separate_digests() -> None:
    ground_truth = BenchmarkGroundTruth(
        benchmarkId="benchmark:hybrid-v1",
        targetFactoryDigest=DIGEST_A,
        cases=[
            BenchmarkGroundTruthCase(
                groundTruthId="ground-truth:001",
                expectedFindingId="finding:rag-tool-auth",
                surfaceIds=["surface:file-upload", "surface:mcp-tool"],
                chainId="chain:file-rag-mcp",
                matcherId="matcher:hybrid-chain",
                matcherVersion="1.0.0",
                matcherDigest=DIGEST_B,
                visibility=GroundTruthVisibility.HOLDOUT,
            )
        ],
    )
    manifest = _manifest().model_copy(
        update={"ground_truth_digest": ground_truth.digest()}
    )

    assert manifest.digest() == manifest.digest()
    assert ground_truth.digest() == ground_truth.digest()
    public = manifest.model_dump(mode="json", by_alias=True)
    assert "cases" not in public
    assert public["groundTruthDigest"] == ground_truth.digest()
    assert ground_truth.cases[0].visibility is GroundTruthVisibility.HOLDOUT


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("seeds", [11, 7], "unique and canonically sorted"),
        (
            "metrics",
            list(BENCHMARK_METRIC_ORDER[:-1]),
            "at least 12 items",
        ),
    ],
)
def test_protocol_rejects_noncanonical_or_incomplete_runs(
    field: str,
    value: object,
    message: str,
) -> None:
    raw = _protocol().model_dump(mode="json")
    raw[field] = value

    with pytest.raises(ValidationError, match=message):
        BenchmarkRunProtocol.model_validate(raw)


def test_manifest_rejects_candidate_without_baseline_and_unknown_fields() -> None:
    raw = _manifest().model_dump(mode="json")
    raw["arms"] = [
        _arm(BenchmarkArmKind.ADAPTIVE_CANDIDATE).model_dump(mode="json")
    ]

    with pytest.raises(ValidationError, match="baseline first"):
        BenchmarkManifest.model_validate(raw)

    raw = _manifest().model_dump(mode="json")
    raw["untrustedOverride"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        BenchmarkManifest.model_validate(raw)


def test_metric_contract_rejects_wrong_unit_ratio_and_fraction() -> None:
    with pytest.raises(ValidationError, match="must use the ratio unit"):
        BenchmarkMetricObservation(
            metric=BenchmarkMetric.FINDING_RECALL,
            unit=BenchmarkMetricUnit.COUNT,
            value=1,
        )
    with pytest.raises(ValidationError, match="between zero and one"):
        BenchmarkMetricObservation(
            metric=BenchmarkMetric.FINDING_PRECISION,
            unit=BenchmarkMetricUnit.RATIO,
            value=1.1,
        )
    with pytest.raises(ValidationError, match="differs from numerator/denominator"):
        BenchmarkMetricObservation(
            metric=BenchmarkMetric.REPLAY_SUCCESS_RATE,
            unit=BenchmarkMetricUnit.RATIO,
            value=0.5,
            numerator=9,
            denominator=10,
        )


def test_completed_result_requires_all_metrics_and_exact_cleanup_binding() -> None:
    raw = _result(BenchmarkArmKind.DETERMINISTIC_BASELINE).model_dump(mode="json")
    raw["metrics"] = raw["metrics"][:-1]
    with pytest.raises(ValidationError, match="at least 12 items"):
        BenchmarkResult.model_validate(raw)
    raw = _result(BenchmarkArmKind.DETERMINISTIC_BASELINE).model_dump(mode="json")
    raw["runs"][0]["cleanup_succeeded"] = False
    with pytest.raises(ValidationError, match="exact run cleanup counts"):
        BenchmarkResult.model_validate(raw)

    raw = _result(BenchmarkArmKind.DETERMINISTIC_BASELINE).model_dump(mode="json")
    raw["metrics"][2] = {
        "metric": BenchmarkMetric.FINDING_PRECISION.value,
        "unit": BenchmarkMetricUnit.RATIO.value,
        "status": BenchmarkMetricStatus.NOT_APPLICABLE.value,
        "reason": "no candidate Finding was observed",
    }
    completed = BenchmarkResult.model_validate(raw)
    assert completed.metrics[2].status is BenchmarkMetricStatus.NOT_APPLICABLE

    raw["metrics"][0] = {
        "metric": BenchmarkMetric.ATTACK_SURFACE_RECALL.value,
        "unit": BenchmarkMetricUnit.RATIO.value,
        "status": BenchmarkMetricStatus.NOT_APPLICABLE.value,
        "reason": "invented unavailable denominator",
    }
    with pytest.raises(ValidationError, match="without a nullable denominator"):
        BenchmarkResult.model_validate(raw)


def test_comparison_binds_same_manifest_protocol_and_run_coordinates() -> None:
    baseline = _result(BenchmarkArmKind.DETERMINISTIC_BASELINE)
    candidate = _result(BenchmarkArmKind.ADAPTIVE_CANDIDATE, delta=0.1)

    comparison = compare_benchmark_results(
        baseline,
        candidate,
        compared_at=NOW + timedelta(minutes=6),
    )

    assert comparison.baseline_result_digest == baseline.digest()
    assert comparison.candidate_result_digest == candidate.digest()
    assert [delta.metric for delta in comparison.deltas] == list(
        BENCHMARK_METRIC_ORDER
    )
    assert comparison.deltas[0].candidate_minus_baseline == pytest.approx(0.1)

    foreign = _result(
        BenchmarkArmKind.ADAPTIVE_CANDIDATE,
        manifest_digest=DIGEST_D,
    )
    with pytest.raises(ValueError, match="manifest_digest"):
        compare_benchmark_results(baseline, foreign, compared_at=NOW)


def test_result_rejects_unsafe_evidence_reference_and_naive_timestamp() -> None:
    with pytest.raises(ValidationError, match="forward slashes"):
        BenchmarkEvidenceReference(
            reference=r"benchmark\result.json",
            sha256=DIGEST_A,
        )

    raw = _result(BenchmarkArmKind.DETERMINISTIC_BASELINE).model_dump(mode="json")
    raw["started_at"] = "2026-07-26T03:00:00"
    with pytest.raises(ValidationError, match="explicit UTC offset"):
        BenchmarkResult.model_validate(raw)
