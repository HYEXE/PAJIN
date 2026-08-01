from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkMetric,
    BenchmarkRunProtocol,
    WalkingBenchmarkMeasuredComparisonAuthority,
    WalkingBenchmarkMeasuredComparisonRunner,
    WalkingBenchmarkMeasurementError,
    WalkingBenchmarkRunObservation,
    WalkingBenchmarkRunObservationOutcome,
    WalkingBenchmarkRunObservationRecorder,
    load_walking_benchmark_measured_comparison_authority,
    load_walking_benchmark_run_observation,
)
from pajin.runtime.store import load_verified_run_events, verify_run_integrity

NOW = datetime(2026, 8, 1, 4, 0, tzinfo=UTC)
MEASUREMENT_AUTHORITY_DIGEST = "d" * 64


def _manifest() -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId="benchmark:walking-measured-v1",
        targetFactoryId="target-factory:walking-hybrid",
        targetFactoryVersion="1.0.0",
        targetFactoryDigest="a" * 64,
        targetProfileId="hybrid:file-rag-mcp",
        targetProfileVersion="1.0.0",
        mutationProfileId="mutation:walking-seeded",
        campaignDigest="b" * 64,
        groundTruthDigest="c" * 64,
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:walking-measured-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=2,
            timeoutSeconds=600,
            maxCostUsd=25,
            maxToolCalls=500,
            maxModelCalls=100,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:walking-deterministic-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:walking-deterministic-baseline",
                implementationVersion="1.0.0",
                configurationDigest="e" * 64,
                adaptiveSupervisor=False,
            ),
            BenchmarkArm(
                armId="arm:walking-shadow-candidate",
                kind=BenchmarkArmKind.ADAPTIVE_CANDIDATE,
                implementationId="pajin:walking-shadow-candidate",
                implementationVersion="1.0.0",
                configurationDigest="f" * 64,
                adaptiveSupervisor=True,
            ),
        ],
    )


def _observation(
    manifest: BenchmarkManifest,
    arm_index: int,
    repetition: int,
    *,
    measurement_authority_digest: str = MEASUREMENT_AUTHORITY_DIGEST,
) -> WalkingBenchmarkRunObservation:
    arm = manifest.arms[arm_index]
    candidate = arm.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
    if candidate:
        matched = 3 if repetition == 1 else 4
        unexpected = 1 if repetition == 1 else 0
        valid = matched + unexpected
        confirmed = matched
        surface_found = 9 if repetition == 1 else 10
        completed_chains = 2
        replay_successes = 2
        first_seconds = 60.0 if repetition == 1 else 45.0
        cost = 12.0 if repetition == 1 else 10.0
        policy_count = 1
        human_interventions = 1
    else:
        matched = 2 if repetition == 1 else 3
        unexpected = 0
        valid = matched
        confirmed = matched
        surface_found = 8 if repetition == 1 else 9
        completed_chains = 1
        replay_successes = 1
        first_seconds = 120.0 if repetition == 1 else 90.0
        cost = 10.0 if repetition == 1 else 11.0
        policy_count = 2
        human_interventions = 0
    started_at = NOW + timedelta(hours=arm_index, minutes=repetition)
    return WalkingBenchmarkRunObservation(
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        armId=arm.arm_id,
        armKind=arm.kind,
        configurationDigest=arm.configuration_digest,
        targetFactoryDigest=manifest.target_factory_digest,
        campaignDigest=manifest.campaign_digest,
        groundTruthDigest=manifest.ground_truth_digest,
        protocolId=manifest.protocol.protocol_id,
        protocolVersion=manifest.protocol.protocol_version,
        measurementAuthorityId="measurement-authority:walking-oracle",
        measurementAuthorityVersion="1.0.0",
        measurementAuthorityDigest=measurement_authority_digest,
        seed=7,
        repetition=repetition,
        startedAt=started_at,
        completedAt=started_at + timedelta(minutes=5),
        cleanupSucceeded=True,
        toolCallCount=12,
        modelCallCount=3 if candidate else 0,
        costUsd=cost,
        knownAttackSurfaceCount=10,
        discoveredKnownAttackSurfaceCount=surface_found,
        knownFindingCount=4,
        matchedKnownFindingCount=matched,
        candidateFindingCount=4,
        validCandidateFindingCount=valid,
        unexpectedValidFindingCount=unexpected,
        confirmedFindingCount=confirmed,
        groundTruthChainCount=2,
        completedGroundTruthChainCount=completed_chains,
        firstValidOrConfirmedFindingSeconds=first_seconds,
        replayAttemptCount=2,
        replaySuccessCount=replay_successes,
        policyRejectionOrViolationCount=policy_count,
        humanDecisionCount=2,
        humanInterventionOrOverturnCount=human_interventions,
        openWorldCandidateIds=(
            (f"candidate:open-world:{arm_index}:{repetition}",) if unexpected else ()
        ),
    )


def _record_observations(
    tmp_path: Path,
    manifest: BenchmarkManifest,
) -> tuple[WalkingBenchmarkRunObservationOutcome, ...]:
    recorder = WalkingBenchmarkRunObservationRecorder(output_root=tmp_path / "observations")
    return tuple(
        recorder.run(manifest, _observation(manifest, arm_index, repetition))
        for arm_index in range(2)
        for repetition in range(1, 3)
    )


def test_walking_benchmark_builds_measured_results_from_exact_sealed_coordinates(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    observations = _record_observations(tmp_path, manifest)

    outcome = WalkingBenchmarkMeasuredComparisonRunner(
        output_root=tmp_path / "comparison"
    ).run(manifest, observations)
    authority = outcome.authority
    deltas = {delta.metric: delta for delta in authority.comparison.deltas}

    assert authority.measurement_state == "completed-two-arm-measured"
    assert authority.benchmark_comparison_eligible is True
    assert authority.supervisor_activation_eligible is False
    assert len(authority.observations) == 4
    assert authority.baseline_result.metrics[0].value == pytest.approx(17 / 20)
    assert authority.candidate_result.metrics[0].value == pytest.approx(19 / 20)
    assert deltas[BenchmarkMetric.FINDING_RECALL].candidate_minus_baseline == pytest.approx(
        0.25
    )
    assert deltas[
        BenchmarkMetric.TIME_TO_FIRST_VALID_OR_CONFIRMED_FINDING
    ].candidate_minus_baseline == pytest.approx(-52.5)
    assert authority.baseline_result.metrics[-1].value == 1.0
    assert authority.candidate_result.metrics[-1].value == 1.0
    assert all(verify_run_integrity(item.run_path).valid for item in observations)
    assert verify_run_integrity(outcome.run_path).valid
    assert [event.event_type for event in load_verified_run_events(outcome.run_path)] == [
        "campaign.started",
        "benchmark.walking-measured-comparison.created",
        "campaign.completed",
    ]
    assert (
        load_walking_benchmark_measured_comparison_authority(manifest, outcome)
        == authority
    )
    assert (
        load_walking_benchmark_run_observation(manifest, observations[0])
        == observations[0].observation
    )


def test_walking_benchmark_rejects_missing_foreign_and_mutated_observations(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    observations = _record_observations(tmp_path, manifest)
    runner = WalkingBenchmarkMeasuredComparisonRunner(output_root=tmp_path / "comparison")

    with pytest.raises(WalkingBenchmarkMeasurementError):
        runner.run(manifest, observations[:-1])

    foreign_recorder = WalkingBenchmarkRunObservationRecorder(
        output_root=tmp_path / "foreign"
    )
    foreign = foreign_recorder.run(
        manifest,
        _observation(
            manifest,
            1,
            2,
            measurement_authority_digest="9" * 64,
        ),
    )
    with pytest.raises(WalkingBenchmarkMeasurementError):
        runner.run(manifest, (*observations[:-1], foreign))

    (observations[0].run_path / observations[0].artifact_path).write_text(
        "{}",
        encoding="utf-8",
    )
    with pytest.raises(WalkingBenchmarkMeasurementError):
        runner.run(manifest, observations)


def test_walking_benchmark_rejects_invented_aggregates_and_output_mutation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    with pytest.raises(ValidationError):
        raw = _observation(manifest, 0, 1).model_dump(mode="json", by_alias=True)
        raw["candidateFindingCount"] = 0
        WalkingBenchmarkRunObservation.model_validate(raw)

    observations = _record_observations(tmp_path, manifest)
    outcome = WalkingBenchmarkMeasuredComparisonRunner(
        output_root=tmp_path / "comparison"
    ).run(manifest, observations)
    raw_authority = outcome.authority.model_dump(mode="json", by_alias=True)
    raw_authority["authorityId"] = ""
    raw_authority["authorityDigest"] = ""
    raw_authority["baselineResult"]["metrics"][0]["value"] = 0.0
    with pytest.raises(ValidationError):
        WalkingBenchmarkMeasuredComparisonAuthority.model_validate(raw_authority)

    (outcome.run_path / outcome.comparison_path).write_text("{}", encoding="utf-8")
    with pytest.raises(WalkingBenchmarkMeasurementError):
        load_walking_benchmark_measured_comparison_authority(manifest, outcome)
