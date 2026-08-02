"""Evidence-bound BENCH-003B measurement admission and comparison harness."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from statistics import pvariance
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkComparison,
    BenchmarkEvidenceReference,
    BenchmarkManifest,
    BenchmarkMetric,
    BenchmarkMetricObservation,
    BenchmarkMetricStatus,
    BenchmarkMetricUnit,
    BenchmarkResult,
    BenchmarkResultStatus,
    BenchmarkRunBinding,
    benchmark_digest,
    canonical_benchmark_json,
    compare_benchmark_results,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)

WALKING_BENCHMARK_RUN_OBSERVATION_API_VERSION: Literal[
    "pajin.dev/walking-benchmark-run-observation/v1alpha1"
] = "pajin.dev/walking-benchmark-run-observation/v1alpha1"
WALKING_BENCHMARK_MEASURED_COMPARISON_API_VERSION: Literal[
    "pajin.dev/walking-benchmark-measured-comparison/v1alpha1"
] = "pajin.dev/walking-benchmark-measured-comparison/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Count = Annotated[int, Field(ge=0, le=1_000_000_000)]
_PositiveCount = Annotated[int, Field(ge=1, le=1_000_000_000)]
_FiniteNonNegative = Annotated[float, Field(ge=0, allow_inf_nan=False)]
_MAX_OBSERVATION_BYTES = 256 * 1024
_MAX_AUTHORITY_BYTES = 64 * 1024 * 1024
_OBSERVATION_ARTIFACT = "walking-benchmark-run-observation.json"
_BASELINE_BUNDLE_PATH = "evidence/baseline-observations.json"
_CANDIDATE_BUNDLE_PATH = "evidence/candidate-observations.json"
_AUTHORITY_PATH = "walking-benchmark-measured-comparison-authority.json"
_BASELINE_RESULT_PATH = "baseline-result.json"
_CANDIDATE_RESULT_PATH = "candidate-result.json"
_COMPARISON_PATH = "benchmark-comparison.json"


class WalkingBenchmarkMeasurementError(RuntimeError):
    """Raised when measured benchmark evidence cannot be proven exactly."""


class WalkingBenchmarkRunObservation(StrictModel):
    """Raw measured facts for one arm at one exact seed/repetition coordinate."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-benchmark-run-observation/v1alpha1"] = Field(
        default=WALKING_BENCHMARK_RUN_OBSERVATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingBenchmarkRunObservation"] = "WalkingBenchmarkRunObservation"
    observation_id: str = Field(default="", alias="observationId", max_length=110)
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    arm_id: _Identifier = Field(alias="armId")
    arm_kind: BenchmarkArmKind = Field(alias="armKind")
    configuration_digest: _Sha256 = Field(alias="configurationDigest")
    target_factory_digest: _Sha256 = Field(alias="targetFactoryDigest")
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    ground_truth_digest: _Sha256 = Field(alias="groundTruthDigest")
    protocol_id: _Identifier = Field(alias="protocolId")
    protocol_version: _Identifier = Field(alias="protocolVersion")
    measurement_authority_id: _Identifier = Field(alias="measurementAuthorityId")
    measurement_authority_version: _Identifier = Field(alias="measurementAuthorityVersion")
    measurement_authority_digest: _Sha256 = Field(alias="measurementAuthorityDigest")
    seed: int = Field(ge=0, le=2**63 - 1)
    repetition: int = Field(ge=1, le=20)
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    reset_succeeded: Literal[True] = Field(default=True, alias="resetSucceeded")
    isolation_established: Literal[True] = Field(
        default=True,
        alias="isolationEstablished",
    )
    cleanup_attempted: Literal[True] = Field(default=True, alias="cleanupAttempted")
    cleanup_succeeded: bool = Field(alias="cleanupSucceeded")
    tool_call_count: _Count = Field(alias="toolCallCount")
    model_call_count: _Count = Field(alias="modelCallCount")
    cost_usd: _FiniteNonNegative = Field(alias="costUsd")
    known_attack_surface_count: _PositiveCount = Field(alias="knownAttackSurfaceCount")
    discovered_known_attack_surface_count: _Count = Field(
        alias="discoveredKnownAttackSurfaceCount"
    )
    known_finding_count: _PositiveCount = Field(alias="knownFindingCount")
    matched_known_finding_count: _Count = Field(alias="matchedKnownFindingCount")
    candidate_finding_count: _Count = Field(alias="candidateFindingCount")
    valid_candidate_finding_count: _Count = Field(
        alias="validCandidateFindingCount"
    )
    unexpected_valid_finding_count: _Count = Field(
        alias="unexpectedValidFindingCount"
    )
    confirmed_finding_count: _Count = Field(alias="confirmedFindingCount")
    ground_truth_chain_count: _PositiveCount = Field(alias="groundTruthChainCount")
    completed_ground_truth_chain_count: _Count = Field(
        alias="completedGroundTruthChainCount"
    )
    first_valid_or_confirmed_finding_seconds: _FiniteNonNegative | None = Field(
        alias="firstValidOrConfirmedFindingSeconds"
    )
    replay_attempt_count: _Count = Field(alias="replayAttemptCount")
    replay_success_count: _Count = Field(alias="replaySuccessCount")
    policy_rejection_or_violation_count: _Count = Field(
        alias="policyRejectionOrViolationCount"
    )
    human_decision_count: _Count = Field(alias="humanDecisionCount")
    human_intervention_or_overturn_count: _Count = Field(
        alias="humanInterventionOrOverturnCount"
    )
    open_world_candidate_ids: tuple[_Identifier, ...] = Field(
        default=(),
        alias="openWorldCandidateIds",
        max_length=10_000,
    )

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Walking benchmark timestamps require an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("open_world_candidate_ids")
    @classmethod
    def require_canonical_open_world_candidates(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("Walking benchmark open-world Candidate IDs must be sorted and unique")
        return value

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("Walking benchmark observation completes before it starts")
        if self.discovered_known_attack_surface_count > self.known_attack_surface_count:
            raise ValueError("Discovered known Surface count exceeds Ground Truth")
        if self.matched_known_finding_count > self.known_finding_count:
            raise ValueError("Matched known Finding count exceeds Ground Truth")
        if self.valid_candidate_finding_count > self.candidate_finding_count:
            raise ValueError("Valid Candidate count exceeds all Candidates")
        if (
            self.matched_known_finding_count + self.unexpected_valid_finding_count
            > self.valid_candidate_finding_count
        ):
            raise ValueError("Known and unexpected valid Findings exceed valid Candidates")
        if self.confirmed_finding_count > self.valid_candidate_finding_count:
            raise ValueError("Confirmed Finding count exceeds valid Candidates")
        if self.unexpected_valid_finding_count != len(self.open_world_candidate_ids):
            raise ValueError("Unexpected valid Finding count differs from open-world IDs")
        if self.completed_ground_truth_chain_count > self.ground_truth_chain_count:
            raise ValueError("Completed Chain count exceeds Ground Truth Chains")
        if self.replay_success_count > self.replay_attempt_count:
            raise ValueError("Replay success count exceeds attempts")
        if self.human_intervention_or_overturn_count > self.human_decision_count:
            raise ValueError("Human intervention count exceeds decision opportunities")
        elapsed = (self.completed_at - self.started_at).total_seconds()
        _require_finding_time_semantics(self, elapsed=elapsed)

        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.walking-run-observation/v1",
            material,
            max_bytes=_MAX_OBSERVATION_BYTES,
        )
        observation_id = f"walking-benchmark-observation:{digest}"
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("Walking benchmark Observation Digest differs")
        if self.observation_id and self.observation_id != observation_id:
            raise ValueError("Walking benchmark Observation ID differs")
        object.__setattr__(self, "observation_digest", digest)
        object.__setattr__(self, "observation_id", observation_id)
        return self


def _require_finding_time_semantics(
    observation: WalkingBenchmarkRunObservation,
    *,
    elapsed: float,
) -> None:
    first = observation.first_valid_or_confirmed_finding_seconds
    has_valid_finding = bool(
        observation.valid_candidate_finding_count or observation.confirmed_finding_count
    )
    if first is not None and first > elapsed:
        raise ValueError("First valid Finding time exceeds the observed Run duration")
    if first is None and has_valid_finding:
        raise ValueError("Valid Finding counts require a first-Finding duration")
    if first is not None and not has_valid_finding:
        raise ValueError("First-Finding duration requires a valid or confirmed Finding")


@dataclass(frozen=True, slots=True)
class WalkingBenchmarkRunObservationOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    observation: WalkingBenchmarkRunObservation


class WalkingBenchmarkRunObservationRecorder:
    """Seal one measurement-adapter observation without changing its values."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        manifest: BenchmarkManifest,
        observation: WalkingBenchmarkRunObservation,
    ) -> WalkingBenchmarkRunObservationOutcome:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        authoritative_observation = WalkingBenchmarkRunObservation.model_validate(
            observation.model_dump(mode="json", by_alias=True)
        )
        try:
            _require_observation_matches_manifest(
                authoritative_manifest,
                authoritative_observation,
            )
        except (ValidationError, ValueError) as exc:
            raise WalkingBenchmarkMeasurementError(
                "BENCH-003B Run observation differs from its Manifest"
            ) from exc

        store = RunStore.create(self._output_root, "walking-benchmark-observation")
        store.append_event(
            "campaign.started",
            {
                "benchmarkId": authoritative_manifest.benchmark_id,
                "purpose": "walking-benchmark-run-observation",
            },
        )
        store.write_json(
            "benchmark-manifest.json",
            authoritative_manifest.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            _OBSERVATION_ARTIFACT,
            authoritative_observation.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.walking-run-observation.created",
            _observation_event_payload(artifact_path, authoritative_observation),
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-benchmark-run-observation-sealed",
                "observationId": authoritative_observation.observation_id,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-benchmark-run-observation", "artifact": artifact_path},
        )
        store.seal()
        return WalkingBenchmarkRunObservationOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            observation=authoritative_observation.model_copy(deep=True),
        )


class WalkingBenchmarkObservationBinding(StrictModel):
    """One exact sealed observation and its publication provenance."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: Literal["walking-benchmark-run-observation.json"] = Field(
        default="walking-benchmark-run-observation.json",
        alias="sourceArtifactPath",
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    observation: WalkingBenchmarkRunObservation


class WalkingBenchmarkMeasuredComparisonAuthority(StrictModel):
    """Two measured Results and their canonical comparison from sealed raw observations."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/walking-benchmark-measured-comparison/v1alpha1"
    ] = Field(
        default=WALKING_BENCHMARK_MEASURED_COMPARISON_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingBenchmarkMeasuredComparisonAuthority"] = (
        "WalkingBenchmarkMeasuredComparisonAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest: BenchmarkManifest
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    observations: tuple[WalkingBenchmarkObservationBinding, ...] = Field(
        min_length=2,
        max_length=4_000,
    )
    baseline_result: BenchmarkResult = Field(alias="baselineResult")
    baseline_result_digest: _Sha256 = Field(alias="baselineResultDigest")
    candidate_result: BenchmarkResult = Field(alias="candidateResult")
    candidate_result_digest: _Sha256 = Field(alias="candidateResultDigest")
    comparison: BenchmarkComparison
    comparison_digest: _Sha256 = Field(alias="comparisonDigest")
    measurement_state: Literal["completed-two-arm-measured"] = Field(
        default="completed-two-arm-measured",
        alias="measurementState",
    )
    benchmark_comparison_eligible: Literal[True] = Field(
        default=True,
        alias="benchmarkComparisonEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        expected_observations = _canonical_bindings(self.manifest, self.observations)
        baseline, candidate, comparison = _build_outputs(
            self.manifest,
            expected_observations,
        )
        if (
            self.manifest_digest != self.manifest.digest()
            or self.observations != expected_observations
            or self.baseline_result != baseline
            or self.baseline_result_digest != baseline.digest()
            or self.candidate_result != candidate
            or self.candidate_result_digest != candidate.digest()
            or self.comparison != comparison
            or self.comparison_digest != comparison.digest()
        ):
            raise ValueError("BENCH-003B measured comparison differs from sealed observations")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.walking-measured-comparison-authority/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"walking-benchmark-measured:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking measured Benchmark Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking measured Benchmark Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_benchmark_json(
            self.model_dump(mode="json", by_alias=True),
            label="WalkingBenchmarkMeasuredComparisonAuthority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingBenchmarkMeasuredComparisonOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    baseline_result_path: str
    candidate_result_path: str
    comparison_path: str
    authority: WalkingBenchmarkMeasuredComparisonAuthority


class WalkingBenchmarkMeasuredComparisonRunner:
    """Admit complete sealed observations and publish measured Results plus Comparison."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        manifest: BenchmarkManifest,
        observation_outcomes: tuple[WalkingBenchmarkRunObservationOutcome, ...],
    ) -> WalkingBenchmarkMeasuredComparisonOutcome:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        try:
            bindings = tuple(
                _load_observation_binding(authoritative_manifest, outcome)
                for outcome in observation_outcomes
            )
            canonical_bindings = _canonical_bindings(authoritative_manifest, bindings)
            baseline, candidate, comparison = _build_outputs(
                authoritative_manifest,
                canonical_bindings,
            )
            authority = WalkingBenchmarkMeasuredComparisonAuthority(
                manifest=authoritative_manifest,
                manifestDigest=authoritative_manifest.digest(),
                observations=canonical_bindings,
                baselineResult=baseline,
                baselineResultDigest=baseline.digest(),
                candidateResult=candidate,
                candidateResultDigest=candidate.digest(),
                comparison=comparison,
                comparisonDigest=comparison.digest(),
            )
        except (
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            WalkingBenchmarkMeasurementError,
        ) as exc:
            raise WalkingBenchmarkMeasurementError(
                "BENCH-003B measured comparison could not be proven"
            ) from exc

        store = RunStore.create(self._output_root, "walking-benchmark-comparison")
        store.append_event(
            "campaign.started",
            {
                "benchmarkId": authoritative_manifest.benchmark_id,
                "purpose": "walking-benchmark-measured-comparison",
            },
        )
        store.write_json(
            "benchmark-manifest.json",
            authoritative_manifest.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            _BASELINE_BUNDLE_PATH,
            _observation_bundle(canonical_bindings, BenchmarkArmKind.DETERMINISTIC_BASELINE),
        )
        store.write_json(
            _CANDIDATE_BUNDLE_PATH,
            _observation_bundle(canonical_bindings, BenchmarkArmKind.ADAPTIVE_CANDIDATE),
        )
        baseline_result_path = store.write_json(
            _BASELINE_RESULT_PATH,
            baseline.model_dump(mode="json", by_alias=True),
        )
        candidate_result_path = store.write_json(
            _CANDIDATE_RESULT_PATH,
            candidate.model_dump(mode="json", by_alias=True),
        )
        comparison_path = store.write_json(
            _COMPARISON_PATH,
            comparison.model_dump(mode="json", by_alias=True),
        )
        authority_path = store.write_json(
            _AUTHORITY_PATH,
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.walking-measured-comparison.created",
            _comparison_event_payload(
                authority_path,
                baseline_result_path,
                candidate_result_path,
                comparison_path,
                authority,
            ),
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-benchmark-measured-comparison-sealed",
                "authorityId": authority.authority_id,
                "comparisonId": comparison.comparison_id,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-benchmark-measured-comparison", "artifact": authority_path},
        )
        store.seal()
        return WalkingBenchmarkMeasuredComparisonOutcome(
            run_id=store.run_id,
            run_path=store.path,
            authority_path=authority_path,
            baseline_result_path=baseline_result_path,
            candidate_result_path=candidate_result_path,
            comparison_path=comparison_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_benchmark_run_observation(
    manifest: BenchmarkManifest,
    outcome: WalkingBenchmarkRunObservationOutcome,
) -> WalkingBenchmarkRunObservation:
    """Reload one exact sealed measurement observation and publication event."""

    observation, _, _ = _load_observation_snapshot(manifest, outcome)
    return observation.model_copy(deep=True)


def load_walking_benchmark_measured_comparison_authority(
    manifest: BenchmarkManifest,
    outcome: WalkingBenchmarkMeasuredComparisonOutcome,
) -> WalkingBenchmarkMeasuredComparisonAuthority:
    """Reload BENCH-003B Results, comparison, evidence bundles, and exact event."""

    requests = {
        "benchmark-manifest.json": 256 * 1024,
        _BASELINE_BUNDLE_PATH: _MAX_AUTHORITY_BYTES,
        _CANDIDATE_BUNDLE_PATH: _MAX_AUTHORITY_BYTES,
        outcome.baseline_result_path: 4 * 1024 * 1024,
        outcome.candidate_result_path: 4 * 1024 * 1024,
        outcome.comparison_path: 512 * 1024,
        outcome.authority_path: _MAX_AUTHORITY_BYTES,
    }
    try:
        if (
            outcome.authority_path != _AUTHORITY_PATH
            or outcome.baseline_result_path != _BASELINE_RESULT_PATH
            or outcome.candidate_result_path != _CANDIDATE_RESULT_PATH
            or outcome.comparison_path != _COMPARISON_PATH
        ):
            raise ValueError("BENCH-003B output artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests=requests,
            expected_run_id=outcome.run_id,
        )
        sealed_manifest = BenchmarkManifest.model_validate_json(
            snapshot.artifact_bytes("benchmark-manifest.json")
        )
        authority = WalkingBenchmarkMeasuredComparisonAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.authority_path)
        )
        baseline = BenchmarkResult.model_validate_json(
            snapshot.artifact_bytes(outcome.baseline_result_path)
        )
        candidate = BenchmarkResult.model_validate_json(
            snapshot.artifact_bytes(outcome.candidate_result_path)
        )
        comparison = BenchmarkComparison.model_validate_json(
            snapshot.artifact_bytes(outcome.comparison_path)
        )
        baseline_bundle = _parse_observation_bundle(
            snapshot.artifact_bytes(_BASELINE_BUNDLE_PATH)
        )
        candidate_bundle = _parse_observation_bundle(
            snapshot.artifact_bytes(_CANDIDATE_BUNDLE_PATH)
        )
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise WalkingBenchmarkMeasurementError(
            "BENCH-003B measured comparison is not sealed and valid"
        ) from exc

    expected_baseline_bundle = tuple(
        binding.observation
        for binding in authority.observations
        if binding.observation.arm_kind is BenchmarkArmKind.DETERMINISTIC_BASELINE
    )
    expected_candidate_bundle = tuple(
        binding.observation
        for binding in authority.observations
        if binding.observation.arm_kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
    )
    if (
        sealed_manifest != manifest
        or authority != outcome.authority
        or baseline != authority.baseline_result
        or candidate != authority.candidate_result
        or comparison != authority.comparison
        or baseline_bundle != expected_baseline_bundle
        or candidate_bundle != expected_candidate_bundle
        or sha256(snapshot.artifact_bytes(_BASELINE_BUNDLE_PATH)).hexdigest()
        != authority.baseline_result.evidence[0].sha256
        or sha256(snapshot.artifact_bytes(_CANDIDATE_BUNDLE_PATH)).hexdigest()
        != authority.candidate_result.evidence[0].sha256
    ):
        raise WalkingBenchmarkMeasurementError(
            "BENCH-003B measured output differs from its exact authority"
        )
    created = [
        event
        for event in snapshot.events
        if event.event_type == "benchmark.walking-measured-comparison.created"
    ]
    expected_event = _comparison_event_payload(
        outcome.authority_path,
        outcome.baseline_result_path,
        outcome.candidate_result_path,
        outcome.comparison_path,
        authority,
    )
    if len(created) != 1 or created[0].payload != expected_event:
        raise WalkingBenchmarkMeasurementError("BENCH-003B publication event differs")
    return authority.model_copy(deep=True)


def _load_observation_snapshot(
    manifest: BenchmarkManifest,
    outcome: WalkingBenchmarkRunObservationOutcome,
) -> tuple[WalkingBenchmarkRunObservation, VerifiedRunSnapshot, bytes]:
    try:
        if outcome.artifact_path != _OBSERVATION_ARTIFACT:
            raise ValueError("BENCH-003B observation artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "benchmark-manifest.json": 256 * 1024,
                outcome.artifact_path: _MAX_OBSERVATION_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_manifest = BenchmarkManifest.model_validate_json(
            snapshot.artifact_bytes("benchmark-manifest.json")
        )
        artifact_bytes = snapshot.artifact_bytes(outcome.artifact_path)
        observation = WalkingBenchmarkRunObservation.model_validate_json(artifact_bytes)
        _require_observation_matches_manifest(sealed_manifest, observation)
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise WalkingBenchmarkMeasurementError(
            "BENCH-003B Run observation is not sealed and valid"
        ) from exc
    if (
        sealed_manifest != manifest
        or observation != outcome.observation
    ):
        raise WalkingBenchmarkMeasurementError(
            "BENCH-003B Run observation differs from its sealed publication"
        )
    created = [
        event
        for event in snapshot.events
        if event.event_type == "benchmark.walking-run-observation.created"
    ]
    expected = _observation_event_payload(outcome.artifact_path, observation)
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingBenchmarkMeasurementError("BENCH-003B observation event differs")
    return observation, snapshot, artifact_bytes


def _load_observation_binding(
    manifest: BenchmarkManifest,
    outcome: WalkingBenchmarkRunObservationOutcome,
) -> WalkingBenchmarkObservationBinding:
    observation, snapshot, artifact_bytes = _load_observation_snapshot(manifest, outcome)
    verification = snapshot.verification
    return WalkingBenchmarkObservationBinding(
        sourceRunId=verification.run_id,
        sourceRootDigest=verification.root_digest,
        sourceArtifactSha256=sha256(artifact_bytes).hexdigest(),
        observation=observation,
    )


def _require_observation_matches_manifest(
    manifest: BenchmarkManifest,
    observation: WalkingBenchmarkRunObservation,
) -> None:
    matching_arms = [arm for arm in manifest.arms if arm.arm_id == observation.arm_id]
    if len(matching_arms) != 1:
        raise ValueError("Walking benchmark observation Arm is absent from Manifest")
    arm = matching_arms[0]
    if (
        observation.benchmark_id != manifest.benchmark_id
        or observation.manifest_digest != manifest.digest()
        or observation.arm_kind is not arm.kind
        or observation.configuration_digest != arm.configuration_digest
        or observation.target_factory_digest != manifest.target_factory_digest
        or observation.campaign_digest != manifest.campaign_digest
        or observation.ground_truth_digest != manifest.ground_truth_digest
        or observation.protocol_id != manifest.protocol.protocol_id
        or observation.protocol_version != manifest.protocol.protocol_version
        or observation.seed not in manifest.protocol.seeds
        or observation.repetition > manifest.protocol.repetitions_per_seed
    ):
        raise ValueError("Walking benchmark observation differs from Manifest authority")
    elapsed = (observation.completed_at - observation.started_at).total_seconds()
    if (
        elapsed > manifest.protocol.timeout_seconds
        or observation.cost_usd > manifest.protocol.max_cost_usd
        or observation.tool_call_count > manifest.protocol.max_tool_calls
        or observation.model_call_count > manifest.protocol.max_model_calls
    ):
        raise ValueError("Walking benchmark observation exceeds its Run budget")


def _canonical_bindings(
    manifest: BenchmarkManifest,
    bindings: tuple[WalkingBenchmarkObservationBinding, ...],
) -> tuple[WalkingBenchmarkObservationBinding, ...]:
    if len(manifest.arms) != 2:
        raise ValueError("BENCH-003B requires baseline and adaptive candidate arms")
    baseline_arm, candidate_arm = manifest.arms
    if (
        baseline_arm.kind is not BenchmarkArmKind.DETERMINISTIC_BASELINE
        or baseline_arm.adaptive_supervisor is not False
        or candidate_arm.kind is not BenchmarkArmKind.ADAPTIVE_CANDIDATE
        or candidate_arm.adaptive_supervisor is not True
    ):
        raise ValueError("BENCH-003B Manifest arm semantics differ")
    arm_order = {arm.arm_id: index for index, arm in enumerate(manifest.arms)}
    for binding in bindings:
        _require_observation_matches_manifest(manifest, binding.observation)
    ordered = tuple(
        sorted(
            bindings,
            key=lambda item: (
                arm_order[item.observation.arm_id],
                item.observation.seed,
                item.observation.repetition,
                item.source_run_id,
            ),
        )
    )
    actual_coordinates = [
        (
            binding.observation.arm_id,
            binding.observation.seed,
            binding.observation.repetition,
        )
        for binding in ordered
    ]
    expected_coordinates = [
        (arm.arm_id, seed, repetition)
        for arm in manifest.arms
        for seed in manifest.protocol.seeds
        for repetition in range(1, manifest.protocol.repetitions_per_seed + 1)
    ]
    if actual_coordinates != expected_coordinates:
        raise ValueError("BENCH-003B requires every exact arm/seed/repetition coordinate once")
    run_ids = [binding.source_run_id for binding in ordered]
    roots = [binding.source_root_digest for binding in ordered]
    observation_ids = [binding.observation.observation_id for binding in ordered]
    if (
        len(run_ids) != len(set(run_ids))
        or len(roots) != len(set(roots))
        or len(observation_ids) != len(set(observation_ids))
    ):
        raise ValueError("BENCH-003B observation publications must be fresh and unique")
    authorities = {
        (
            binding.observation.measurement_authority_id,
            binding.observation.measurement_authority_version,
            binding.observation.measurement_authority_digest,
        )
        for binding in ordered
    }
    if len(authorities) != 1:
        raise ValueError("BENCH-003B arms must use one exact measurement authority")
    return ordered


def _build_outputs(
    manifest: BenchmarkManifest,
    bindings: tuple[WalkingBenchmarkObservationBinding, ...],
) -> tuple[BenchmarkResult, BenchmarkResult, BenchmarkComparison]:
    canonical = _canonical_bindings(manifest, bindings)
    baseline = _build_result(manifest, manifest.arms[0], canonical)
    candidate = _build_result(manifest, manifest.arms[1], canonical)
    compared_at = max(baseline.completed_at, candidate.completed_at)
    comparison = compare_benchmark_results(
        baseline,
        candidate,
        compared_at=compared_at,
    )
    return baseline, candidate, comparison


def _build_result(
    manifest: BenchmarkManifest,
    arm: BenchmarkArm,
    bindings: tuple[WalkingBenchmarkObservationBinding, ...],
) -> BenchmarkResult:
    selected = tuple(
        binding for binding in bindings if binding.observation.arm_id == arm.arm_id
    )
    observations = tuple(binding.observation for binding in selected)
    result_identity = benchmark_digest(
        "pajin.benchmark.walking-result-identity/v1",
        {
            "manifestDigest": manifest.digest(),
            "armId": arm.arm_id,
            "observations": [
                {
                    "observationDigest": binding.observation.observation_digest,
                    "sourceRunId": binding.source_run_id,
                    "sourceRootDigest": binding.source_root_digest,
                    "sourceArtifactSha256": binding.source_artifact_sha256,
                }
                for binding in selected
            ],
        },
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    bundle_path = (
        _BASELINE_BUNDLE_PATH
        if arm.kind is BenchmarkArmKind.DETERMINISTIC_BASELINE
        else _CANDIDATE_BUNDLE_PATH
    )
    bundle = [item.model_dump(mode="json", by_alias=True) for item in observations]
    evidence_sha = sha256(_runstore_json_bytes(bundle)).hexdigest()
    return BenchmarkResult(
        resultId=f"benchmark-result:{result_identity}",
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        armId=arm.arm_id,
        armKind=arm.kind,
        targetFactoryDigest=manifest.target_factory_digest,
        campaignDigest=manifest.campaign_digest,
        groundTruthDigest=manifest.ground_truth_digest,
        protocolId=manifest.protocol.protocol_id,
        protocolVersion=manifest.protocol.protocol_version,
        status=BenchmarkResultStatus.COMPLETED,
        startedAt=min(item.started_at for item in observations),
        completedAt=max(item.completed_at for item in observations),
        runs=[
            BenchmarkRunBinding(
                runId=binding.source_run_id,
                seed=binding.observation.seed,
                repetition=binding.observation.repetition,
                runRootDigest=binding.source_root_digest,
                cleanupSucceeded=binding.observation.cleanup_succeeded,
            )
            for binding in selected
        ],
        metrics=aggregate_walking_benchmark_metrics(observations),
        evidence=[BenchmarkEvidenceReference(reference=bundle_path, sha256=evidence_sha)],
        openWorldCandidateIds=sorted(
            {
                candidate_id
                for observation in observations
                for candidate_id in observation.open_world_candidate_ids
            }
        ),
    )


def aggregate_walking_benchmark_metrics(
    observations: tuple[WalkingBenchmarkRunObservation, ...],
) -> list[BenchmarkMetricObservation]:
    """Aggregate the twelve BENCH-001 metrics from exact raw observations."""

    if not observations:
        raise ValueError("Benchmark metric aggregation requires observations")
    surface_found = sum(item.discovered_known_attack_surface_count for item in observations)
    surface_total = sum(item.known_attack_surface_count for item in observations)
    finding_found = sum(item.matched_known_finding_count for item in observations)
    finding_total = sum(item.known_finding_count for item in observations)
    valid_candidates = sum(item.valid_candidate_finding_count for item in observations)
    all_candidates = sum(item.candidate_finding_count for item in observations)
    unexpected_valid = sum(item.unexpected_valid_finding_count for item in observations)
    completed_chains = sum(item.completed_ground_truth_chain_count for item in observations)
    all_chains = sum(item.ground_truth_chain_count for item in observations)
    first_finding_values = [
        item.first_valid_or_confirmed_finding_seconds
        for item in observations
        if item.first_valid_or_confirmed_finding_seconds is not None
    ]
    first_finding_seconds = math.fsum(first_finding_values)
    total_cost = math.fsum(item.cost_usd for item in observations)
    confirmed_findings = sum(item.confirmed_finding_count for item in observations)
    replay_successes = sum(item.replay_success_count for item in observations)
    replay_attempts = sum(item.replay_attempt_count for item in observations)
    policy_count = sum(item.policy_rejection_or_violation_count for item in observations)
    human_interventions = sum(
        item.human_intervention_or_overturn_count for item in observations
    )
    human_decisions = sum(item.human_decision_count for item in observations)
    per_run_finding_recall = [
        item.matched_known_finding_count / item.known_finding_count
        for item in observations
    ]
    cleanup_successes = sum(item.cleanup_succeeded for item in observations)
    run_count = len(observations)

    return [
        _ratio_metric(
            BenchmarkMetric.ATTACK_SURFACE_RECALL,
            surface_found,
            surface_total,
        ),
        _ratio_metric(BenchmarkMetric.FINDING_RECALL, finding_found, finding_total),
        _ratio_metric(BenchmarkMetric.FINDING_PRECISION, valid_candidates, all_candidates),
        BenchmarkMetricObservation(
            metric=BenchmarkMetric.UNEXPECTED_VALID_FINDING_YIELD,
            unit=BenchmarkMetricUnit.COUNT,
            value=float(unexpected_valid),
        ),
        _ratio_metric(
            BenchmarkMetric.CROSS_SURFACE_CHAIN_COMPLETION_RATE,
            completed_chains,
            all_chains,
        ),
        _average_or_not_applicable_metric(
            BenchmarkMetric.TIME_TO_FIRST_VALID_OR_CONFIRMED_FINDING,
            BenchmarkMetricUnit.SECONDS,
            numerator=first_finding_seconds,
            denominator=len(first_finding_values),
            reason="no valid or confirmed Finding was observed",
        ),
        _average_or_not_applicable_metric(
            BenchmarkMetric.COST_PER_CONFIRMED_FINDING,
            BenchmarkMetricUnit.USD,
            numerator=total_cost,
            denominator=confirmed_findings,
            reason="no confirmed Finding was observed",
        ),
        _ratio_metric(BenchmarkMetric.REPLAY_SUCCESS_RATE, replay_successes, replay_attempts),
        BenchmarkMetricObservation(
            metric=BenchmarkMetric.POLICY_REJECTION_OR_VIOLATION_COUNT,
            unit=BenchmarkMetricUnit.COUNT,
            value=float(policy_count),
        ),
        _ratio_metric(
            BenchmarkMetric.HUMAN_INTERVENTION_OR_OVERTURN_RATE,
            human_interventions,
            human_decisions,
        ),
        BenchmarkMetricObservation(
            metric=BenchmarkMetric.RUN_TO_RUN_VARIANCE,
            unit=BenchmarkMetricUnit.COEFFICIENT,
            value=float(pvariance(per_run_finding_recall)),
        ),
        _ratio_metric(
            BenchmarkMetric.CLEANUP_SUCCESS_RATE,
            cleanup_successes,
            run_count,
        ),
    ]


def _ratio_metric(
    metric: BenchmarkMetric,
    numerator: int,
    denominator: int,
) -> BenchmarkMetricObservation:
    if denominator == 0:
        return BenchmarkMetricObservation(
            metric=metric,
            unit=BenchmarkMetricUnit.RATIO,
            status=BenchmarkMetricStatus.NOT_APPLICABLE,
            reason="metric denominator is zero",
        )
    return BenchmarkMetricObservation(
        metric=metric,
        unit=BenchmarkMetricUnit.RATIO,
        value=numerator / denominator,
        numerator=float(numerator),
        denominator=float(denominator),
    )


def _average_or_not_applicable_metric(
    metric: BenchmarkMetric,
    unit: BenchmarkMetricUnit,
    *,
    numerator: float,
    denominator: int,
    reason: str,
) -> BenchmarkMetricObservation:
    if denominator == 0:
        return BenchmarkMetricObservation(
            metric=metric,
            unit=unit,
            status=BenchmarkMetricStatus.NOT_APPLICABLE,
            reason=reason,
        )
    return BenchmarkMetricObservation(
        metric=metric,
        unit=unit,
        value=numerator / denominator,
        numerator=numerator,
        denominator=float(denominator),
    )


def _observation_bundle(
    bindings: tuple[WalkingBenchmarkObservationBinding, ...],
    arm_kind: BenchmarkArmKind,
) -> list[dict[str, object]]:
    return [
        binding.observation.model_dump(mode="json", by_alias=True)
        for binding in bindings
        if binding.observation.arm_kind is arm_kind
    ]


def _parse_observation_bundle(raw: bytes) -> tuple[WalkingBenchmarkRunObservation, ...]:
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError("BENCH-003B observation bundle must be a JSON array")
    return tuple(WalkingBenchmarkRunObservation.model_validate(item) for item in value)


def _runstore_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _observation_event_payload(
    artifact_path: str,
    observation: WalkingBenchmarkRunObservation,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "observationId": observation.observation_id,
        "observationDigest": observation.observation_digest,
        "armId": observation.arm_id,
        "armKind": observation.arm_kind.value,
        "seed": observation.seed,
        "repetition": observation.repetition,
        "measurementAuthorityId": observation.measurement_authority_id,
    }


def _comparison_event_payload(
    authority_path: str,
    baseline_result_path: str,
    candidate_result_path: str,
    comparison_path: str,
    authority: WalkingBenchmarkMeasuredComparisonAuthority,
) -> dict[str, object]:
    return {
        "artifact": authority_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "manifestDigest": authority.manifest_digest,
        "baselineResult": baseline_result_path,
        "baselineResultDigest": authority.baseline_result_digest,
        "candidateResult": candidate_result_path,
        "candidateResultDigest": authority.candidate_result_digest,
        "comparison": comparison_path,
        "comparisonDigest": authority.comparison_digest,
        "measurementState": authority.measurement_state,
        "supervisorActivationEligible": authority.supervisor_activation_eligible,
    }
