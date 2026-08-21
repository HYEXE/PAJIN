"""REDTEAM-002 sealed initial profile benchmark contracts and aggregation."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import benchmark_digest, canonical_benchmark_json
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.existing import (
    REGISTERED_MCP_CAPABILITY_ID,
    REGISTERED_MCP_CAPABILITY_VERSION,
    ExistingModeCapabilityBundle,
)
from pajin.capabilities.metrics import (
    CapabilityOracleObservation,
    CapabilityReplayObservation,
    CapabilityReplayVerdict,
    existing_mode_capability_replay_support,
)
from pajin.capabilities.rollout import existing_mode_capability_benchmark_mappings
from pajin.control_plane.redteam_profiles import (
    REDTEAM_LLM_CAPABILITY_THREATS,
    REDTEAM_LLM_PROFILE,
    REDTEAM_LLM_PROFILE_DIGEST,
    REDTEAM_LLM_PROFILE_VERSION,
    REDTEAM_LLM_RAG_CAPABILITY_ID,
    REDTEAM_LLM_RAG_CAPABILITY_VERSION,
    REDTEAM_LLM_RAG_PROFILE,
    REDTEAM_LLM_RAG_PROFILE_DIGEST,
    REDTEAM_LLM_RAG_PROFILE_VERSION,
    REDTEAM_MCP_PROFILE,
    REDTEAM_MCP_PROFILE_DIGEST,
    REDTEAM_MCP_PROFILE_VERSION,
    REDTEAM_WEB_CAPABILITY_ID,
    REDTEAM_WEB_CAPABILITY_VERSION,
    REDTEAM_WEB_PROFILE,
    REDTEAM_WEB_PROFILE_DIGEST,
    REDTEAM_WEB_PROFILE_VERSION,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    load_verified_run_artifacts,
    validate_run_artifact_path,
)

REDTEAM_BENCHMARK_PROFILE_SET_API_VERSION: Literal[
    "pajin.dev/redteam-benchmark-profile-set/v1alpha1"
] = "pajin.dev/redteam-benchmark-profile-set/v1alpha1"
REDTEAM_BENCHMARK_RUN_OBSERVATION_API_VERSION: Literal[
    "pajin.dev/redteam-benchmark-run-observation/v1alpha1"
] = "pajin.dev/redteam-benchmark-run-observation/v1alpha1"
REDTEAM_INITIAL_BENCHMARK_REPORT_API_VERSION: Literal[
    "pajin.dev/redteam-initial-benchmark-report/v1alpha1"
] = "pajin.dev/redteam-initial-benchmark-report/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Count = Annotated[int, Field(ge=0, le=1_000_000_000)]
_FiniteNonNegative = Annotated[float, Field(ge=0, allow_inf_nan=False)]
_PROFILE_SET_ARTIFACT = "redteam-benchmark-profile-set.json"
_OBSERVATION_ARTIFACT = "redteam-benchmark-run-observation.json"
_OBSERVATION_BUNDLE_ARTIFACT = "evidence/redteam-benchmark-observations.json"
_REPORT_ARTIFACT = "redteam-initial-benchmark-report.json"
_MAX_PROFILE_SET_BYTES = 2 * 1024 * 1024
_MAX_OBSERVATION_BYTES = 512 * 1024
_MAX_OBSERVATION_BUNDLE_BYTES = 32 * 1024 * 1024
_MAX_REPORT_BYTES = 8 * 1024 * 1024


class RedteamBenchmarkError(RuntimeError):
    """Raised when REDTEAM measurement evidence is incomplete or has drifted."""


class RedteamMetricApplicability(StrEnum):
    REQUIRED = "required"
    NOT_APPLICABLE = "not-applicable"


class RedteamBenchmarkSourceKind(StrEnum):
    PROFILE_EXECUTION = "profile-execution"
    DETERMINISTIC_REANALYSIS = "deterministic-reanalysis"
    INDEPENDENT_REPLAY = "independent-replay"
    POLICY_DENIAL = "policy-denial"


class RedteamGroundTruthClass(StrEnum):
    KNOWN_POSITIVE = "known-positive"
    NEGATIVE_CONTROL = "negative-control"


class RedteamBenchmarkMetric(StrEnum):
    DETECTION_RECALL = "detection-recall"
    FALSE_POSITIVE_RATE = "false-positive-rate"
    DETECTION_PRECISION = "detection-precision"
    REPLAY_SUCCESS_RATE = "replay-success-rate"
    TIME_TO_FIRST_VALID_FINDING = "time-to-first-valid-finding"
    TOTAL_REQUEST_UNITS = "total-request-units"
    TOTAL_TOOL_CALLS = "total-tool-calls"
    TOTAL_COST_USD = "total-cost-usd"
    COST_PER_DETECTION = "cost-per-detection"
    EVIDENCE_COMPLETENESS = "evidence-completeness"
    POLICY_DENIAL_CORRECTNESS = "policy-denial-correctness"
    CLEANUP_SUCCESS_RATE = "cleanup-success-rate"


REDTEAM_BENCHMARK_METRIC_ORDER: tuple[RedteamBenchmarkMetric, ...] = tuple(RedteamBenchmarkMetric)


class RedteamBenchmarkMetricUnit(StrEnum):
    RATIO = "ratio"
    COUNT = "count"
    SECONDS = "seconds"
    USD = "usd"


class RedteamBenchmarkMetricStatus(StrEnum):
    MEASURED = "measured"
    NOT_APPLICABLE = "not-applicable"


_METRIC_UNITS: dict[RedteamBenchmarkMetric, RedteamBenchmarkMetricUnit] = {
    RedteamBenchmarkMetric.DETECTION_RECALL: RedteamBenchmarkMetricUnit.RATIO,
    RedteamBenchmarkMetric.FALSE_POSITIVE_RATE: RedteamBenchmarkMetricUnit.RATIO,
    RedteamBenchmarkMetric.DETECTION_PRECISION: RedteamBenchmarkMetricUnit.RATIO,
    RedteamBenchmarkMetric.REPLAY_SUCCESS_RATE: RedteamBenchmarkMetricUnit.RATIO,
    RedteamBenchmarkMetric.TIME_TO_FIRST_VALID_FINDING: RedteamBenchmarkMetricUnit.SECONDS,
    RedteamBenchmarkMetric.TOTAL_REQUEST_UNITS: RedteamBenchmarkMetricUnit.COUNT,
    RedteamBenchmarkMetric.TOTAL_TOOL_CALLS: RedteamBenchmarkMetricUnit.COUNT,
    RedteamBenchmarkMetric.TOTAL_COST_USD: RedteamBenchmarkMetricUnit.USD,
    RedteamBenchmarkMetric.COST_PER_DETECTION: RedteamBenchmarkMetricUnit.USD,
    RedteamBenchmarkMetric.EVIDENCE_COMPLETENESS: RedteamBenchmarkMetricUnit.RATIO,
    RedteamBenchmarkMetric.POLICY_DENIAL_CORRECTNESS: RedteamBenchmarkMetricUnit.RATIO,
    RedteamBenchmarkMetric.CLEANUP_SUCCESS_RATE: RedteamBenchmarkMetricUnit.RATIO,
}


@dataclass(frozen=True, slots=True)
class _ProfileBlueprint:
    profile_version: str
    profile_digest: str
    capabilities: tuple[tuple[str, str], ...]
    false_positive: RedteamMetricApplicability
    replay: RedteamMetricApplicability


_PROFILE_BLUEPRINTS: dict[str, _ProfileBlueprint] = {
    REDTEAM_LLM_PROFILE: _ProfileBlueprint(
        REDTEAM_LLM_PROFILE_VERSION,
        REDTEAM_LLM_PROFILE_DIGEST,
        tuple(sorted((item, "1.0.0") for item in REDTEAM_LLM_CAPABILITY_THREATS)),
        RedteamMetricApplicability.REQUIRED,
        RedteamMetricApplicability.REQUIRED,
    ),
    REDTEAM_LLM_RAG_PROFILE: _ProfileBlueprint(
        REDTEAM_LLM_RAG_PROFILE_VERSION,
        REDTEAM_LLM_RAG_PROFILE_DIGEST,
        ((REDTEAM_LLM_RAG_CAPABILITY_ID, REDTEAM_LLM_RAG_CAPABILITY_VERSION),),
        RedteamMetricApplicability.REQUIRED,
        RedteamMetricApplicability.REQUIRED,
    ),
    REDTEAM_WEB_PROFILE: _ProfileBlueprint(
        REDTEAM_WEB_PROFILE_VERSION,
        REDTEAM_WEB_PROFILE_DIGEST,
        ((REDTEAM_WEB_CAPABILITY_ID, REDTEAM_WEB_CAPABILITY_VERSION),),
        RedteamMetricApplicability.REQUIRED,
        RedteamMetricApplicability.NOT_APPLICABLE,
    ),
    REDTEAM_MCP_PROFILE: _ProfileBlueprint(
        REDTEAM_MCP_PROFILE_VERSION,
        REDTEAM_MCP_PROFILE_DIGEST,
        ((REGISTERED_MCP_CAPABILITY_ID, REGISTERED_MCP_CAPABILITY_VERSION),),
        RedteamMetricApplicability.NOT_APPLICABLE,
        RedteamMetricApplicability.NOT_APPLICABLE,
    ),
}
_PROFILE_ORDER = tuple(_PROFILE_BLUEPRINTS)


class RedteamBenchmarkCapability(StrictModel):
    """Exact CAP-002 identity and CAP-003 benchmark mapping for one profile action."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability: CodeBackedCapabilityRef
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    benchmark_mapping_digest: _Sha256 = Field(alias="benchmarkMappingDigest")
    request_unit_cost: int = Field(alias="requestUnitCost", ge=1, le=1_000_000)
    replay_support_digest: _Sha256 | None = Field(
        default=None,
        alias="replaySupportDigest",
    )
    replay_contract_ids: tuple[_Identifier, ...] = Field(
        default=(),
        alias="replayContractIds",
        max_length=20,
    )

    @model_validator(mode="after")
    def require_replay_support_pair(self) -> Self:
        if (self.replay_support_digest is None) != (not self.replay_contract_ids):
            raise ValueError("REDTEAM Replay support digest and contracts must exist together")
        if self.replay_contract_ids != tuple(sorted(set(self.replay_contract_ids))):
            raise ValueError("REDTEAM Replay contract IDs must be unique and ordered")
        return self


class RedteamProfileBenchmarkContract(StrictModel):
    """Measurement requirements for one existing REDTEAM-001 profile."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    profile_id: _Identifier = Field(alias="profileId")
    profile_version: _Identifier = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    capabilities: tuple[RedteamBenchmarkCapability, ...] = Field(
        min_length=1,
        max_length=16,
    )
    false_positive_measurement: RedteamMetricApplicability = Field(alias="falsePositiveMeasurement")
    replay_measurement: RedteamMetricApplicability = Field(alias="replayMeasurement")
    finding_validation: Literal[RedteamMetricApplicability.NOT_APPLICABLE] = Field(
        default=RedteamMetricApplicability.NOT_APPLICABLE,
        alias="findingValidation",
    )
    cleanup_measurement: Literal[RedteamMetricApplicability.NOT_APPLICABLE] = Field(
        default=RedteamMetricApplicability.NOT_APPLICABLE,
        alias="cleanupMeasurement",
    )

    @model_validator(mode="after")
    def bind_contract(self) -> Self:
        blueprint = _PROFILE_BLUEPRINTS.get(self.profile_id)
        identities = tuple(
            (
                item.capability.capability.capability_id,
                item.capability.capability.capability_version,
            )
            for item in self.capabilities
        )
        if (
            blueprint is None
            or self.profile_version != blueprint.profile_version
            or self.profile_digest != blueprint.profile_digest
            or identities != blueprint.capabilities
            or self.false_positive_measurement is not blueprint.false_positive
            or self.replay_measurement is not blueprint.replay
        ):
            raise ValueError("REDTEAM benchmark profile contract differs from code authority")
        replay_support_present = all(
            item.replay_support_digest is not None for item in self.capabilities
        )
        if replay_support_present is not (
            self.replay_measurement is RedteamMetricApplicability.REQUIRED
        ):
            raise ValueError("REDTEAM benchmark Replay applicability differs from CAP-006")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.redteam-profile-contract/v1",
            material,
            max_bytes=_MAX_PROFILE_SET_BYTES,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("REDTEAM benchmark profile contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        return self


class RedteamBenchmarkProfileSet(StrictModel):
    """Closed REDTEAM-001A/B/C/D benchmark denominator; never discovered from Tools."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/redteam-benchmark-profile-set/v1alpha1"] = Field(
        default=REDTEAM_BENCHMARK_PROFILE_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RedteamBenchmarkProfileSet"] = "RedteamBenchmarkProfileSet"
    profile_set_id: Literal["pajin.redteam.initial-capability-benchmark"] = Field(
        default="pajin.redteam.initial-capability-benchmark",
        alias="profileSetId",
    )
    profile_set_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="profileSetVersion",
    )
    profile_set_digest: str = Field(default="", alias="profileSetDigest", max_length=64)
    profiles: tuple[RedteamProfileBenchmarkContract, ...] = Field(
        min_length=len(_PROFILE_ORDER),
        max_length=len(_PROFILE_ORDER),
    )
    security_domain_is_authority: Literal[False] = Field(
        default=False,
        alias="securityDomainIsAuthority",
    )

    @model_validator(mode="after")
    def bind_profile_set(self) -> Self:
        if tuple(item.profile_id for item in self.profiles) != _PROFILE_ORDER:
            raise ValueError("REDTEAM benchmark profiles must be complete and ordered")
        capability_keys = [
            (
                item.capability.capability.capability_id,
                item.capability.capability.capability_version,
            )
            for profile in self.profiles
            for item in profile.capabilities
        ]
        if len(capability_keys) != len(set(capability_keys)):
            raise ValueError("REDTEAM benchmark Capability identities must be unique")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_set_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.redteam-profile-set/v1",
            material,
            max_bytes=_MAX_PROFILE_SET_BYTES,
        )
        if self.profile_set_digest and self.profile_set_digest != digest:
            raise ValueError("REDTEAM Benchmark Profile Set Digest differs")
        object.__setattr__(self, "profile_set_digest", digest)
        return self

    def profile(self, profile_id: str) -> RedteamProfileBenchmarkContract:
        try:
            return next(item for item in self.profiles if item.profile_id == profile_id)
        except StopIteration as exc:
            raise RedteamBenchmarkError(
                "REDTEAM benchmark profile is outside the closed set"
            ) from exc


class RedteamDetectionCaseObservation(StrictModel):
    """One Ground Truth classification produced by an exact measured source."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    case_id: _Identifier = Field(alias="caseId")
    ground_truth: RedteamGroundTruthClass = Field(alias="groundTruth")
    detected: bool
    evidence_digest: _Sha256 = Field(alias="evidenceDigest")


class RedteamReplayCaseObservation(StrictModel):
    """Expected-versus-observed independent Replay verdict for one detection case."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    case_id: _Identifier = Field(alias="caseId")
    expected_verdict: CapabilityReplayVerdict = Field(alias="expectedVerdict")
    observation: CapabilityReplayObservation


class RedteamBenchmarkRunObservation(StrictModel):
    """Raw facts from one exact execution, re-analysis, or policy-denial source."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/redteam-benchmark-run-observation/v1alpha1"] = Field(
        default=REDTEAM_BENCHMARK_RUN_OBSERVATION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["RedteamBenchmarkRunObservation"] = "RedteamBenchmarkRunObservation"
    observation_id: str = Field(default="", alias="observationId", max_length=110)
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    profile_set_digest: _Sha256 = Field(alias="profileSetDigest")
    profile_contract_digest: _Sha256 = Field(alias="profileContractDigest")
    profile_id: _Identifier = Field(alias="profileId")
    capability: CodeBackedCapabilityRef
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    benchmark_mapping_digest: _Sha256 = Field(alias="benchmarkMappingDigest")
    source_kind: RedteamBenchmarkSourceKind = Field(alias="sourceKind")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: str = Field(
        alias="sourceArtifactPath",
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,499}$",
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    oracle_observation: CapabilityOracleObservation | None = Field(
        default=None,
        alias="oracleObservation",
    )
    detection_cases: tuple[RedteamDetectionCaseObservation, ...] = Field(
        default=(),
        alias="detectionCases",
        max_length=1_000,
    )
    replay_cases: tuple[RedteamReplayCaseObservation, ...] = Field(
        default=(),
        alias="replayCases",
        max_length=1_000,
    )
    policy_denial_expected: bool | None = Field(
        default=None,
        alias="policyDenialExpected",
    )
    policy_denied: bool | None = Field(default=None, alias="policyDenied")
    request_units: _Count = Field(alias="requestUnits")
    tool_call_count: _Count = Field(alias="toolCallCount")
    model_call_count: _Count = Field(alias="modelCallCount")
    cost_usd: _FiniteNonNegative = Field(alias="costUsd")
    evidence_expected_count: _Count = Field(alias="evidenceExpectedCount")
    evidence_verified_count: _Count = Field(alias="evidenceVerifiedCount")
    valid_finding_count: Literal[0] = Field(default=0, alias="validFindingCount")
    first_valid_finding_seconds: Literal[None] = Field(
        default=None,
        alias="firstValidFindingSeconds",
    )
    cleanup_attempted: Literal[False] = Field(default=False, alias="cleanupAttempted")
    cleanup_succeeded: Literal[False] = Field(default=False, alias="cleanupSucceeded")

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("REDTEAM benchmark timestamps require an explicit UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("REDTEAM benchmark observation completes before it starts")
        if validate_run_artifact_path(self.source_artifact_path) != self.source_artifact_path:
            raise ValueError("REDTEAM benchmark source path is not normalized")
        if self.evidence_verified_count > self.evidence_expected_count:
            raise ValueError("Verified REDTEAM evidence exceeds the expected denominator")
        detection_ids = tuple(item.case_id for item in self.detection_cases)
        replay_ids = tuple(item.case_id for item in self.replay_cases)
        if detection_ids != tuple(sorted(set(detection_ids))):
            raise ValueError("REDTEAM detection case IDs must be unique and ordered")
        if replay_ids != tuple(sorted(set(replay_ids))):
            raise ValueError("REDTEAM Replay case IDs must be unique and ordered")
        if any(item.observation.capability != self.capability for item in self.replay_cases):
            raise ValueError("REDTEAM Replay Capability differs from its measured source")
        _require_source_semantics(self)
        _require_replay_semantics(self)

        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.redteam-run-observation/v1",
            material,
            max_bytes=_MAX_OBSERVATION_BYTES,
        )
        observation_id = f"redteam-benchmark-observation:{digest}"
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("REDTEAM Benchmark Observation Digest differs")
        if self.observation_id and self.observation_id != observation_id:
            raise ValueError("REDTEAM Benchmark Observation ID differs")
        object.__setattr__(self, "observation_digest", digest)
        object.__setattr__(self, "observation_id", observation_id)
        return self


def _require_source_semantics(observation: RedteamBenchmarkRunObservation) -> None:
    if observation.source_kind is RedteamBenchmarkSourceKind.POLICY_DENIAL:
        if (
            observation.oracle_observation is not None
            or observation.detection_cases
            or observation.replay_cases
            or observation.policy_denial_expected is not True
            or observation.policy_denied is None
            or observation.request_units
            or observation.tool_call_count
            or observation.model_call_count
            or observation.cost_usd
            or observation.evidence_expected_count == 0
        ):
            raise ValueError("REDTEAM policy-denial source contains execution measurements")
        return
    if observation.source_kind is RedteamBenchmarkSourceKind.INDEPENDENT_REPLAY:
        if (
            observation.oracle_observation is not None
            or observation.detection_cases
            or not observation.replay_cases
            or observation.policy_denial_expected is not None
            or observation.policy_denied is not None
            or observation.request_units == 0
            or observation.tool_call_count != 1
            or observation.evidence_expected_count == 0
        ):
            raise ValueError("REDTEAM independent Replay source is not exact")
        return
    oracle = observation.oracle_observation
    if (
        oracle is None
        or not observation.detection_cases
        or observation.policy_denial_expected is not None
        or observation.policy_denied is not None
        or oracle.capability != observation.capability
        or oracle.benchmark_id != observation.benchmark_id
        or oracle.evidence_digest != observation.source_artifact_sha256
        or not observation.started_at <= oracle.observed_at <= observation.completed_at
        or observation.evidence_expected_count == 0
        or observation.replay_cases
    ):
        raise ValueError("REDTEAM detection source lacks an exact Oracle evidence binding")
    if observation.source_kind is RedteamBenchmarkSourceKind.PROFILE_EXECUTION and (
        observation.request_units == 0 or observation.tool_call_count != 1
    ):
        raise ValueError("REDTEAM profile execution requires one Tool call and request units")
    if observation.source_kind is RedteamBenchmarkSourceKind.DETERMINISTIC_REANALYSIS and (
        observation.request_units
        or observation.tool_call_count
        or observation.model_call_count
        or observation.cost_usd
    ):
        raise ValueError("REDTEAM deterministic re-analysis cannot claim execution cost")


def _require_replay_semantics(observation: RedteamBenchmarkRunObservation) -> None:
    for replay in observation.replay_cases:
        if (
            replay.observation.evidence_digest != observation.source_artifact_sha256
            or not observation.started_at
            <= replay.observation.observed_at
            <= observation.completed_at
        ):
            raise ValueError("REDTEAM Replay evidence differs from its source artifact")


class RedteamBenchmarkMetricObservation(StrictModel):
    """One measured value or explicit semantic N/A with its denominator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    metric: RedteamBenchmarkMetric
    unit: RedteamBenchmarkMetricUnit
    status: RedteamBenchmarkMetricStatus
    value: float | None = Field(default=None, allow_inf_nan=False)
    numerator: int | None = Field(default=None, ge=0)
    denominator: int | None = Field(default=None, ge=0)
    reason: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def require_semantics(self) -> Self:
        if self.unit is not _METRIC_UNITS[self.metric]:
            raise ValueError("REDTEAM benchmark metric uses the wrong unit")
        if self.status is RedteamBenchmarkMetricStatus.NOT_APPLICABLE:
            if self.value is not None or self.numerator is not None or self.denominator is not None:
                raise ValueError("N/A REDTEAM metric cannot contain a numeric value")
            if self.reason is None:
                raise ValueError("N/A REDTEAM metric requires a reason")
            return self
        if self.value is None or self.reason is not None or not math.isfinite(self.value):
            raise ValueError("Measured REDTEAM metric requires one finite value")
        if self.unit is RedteamBenchmarkMetricUnit.RATIO:
            if (
                self.numerator is None
                or self.denominator is None
                or self.denominator == 0
                or self.numerator > self.denominator
                or not math.isclose(self.value, self.numerator / self.denominator)
            ):
                raise ValueError("REDTEAM ratio differs from its exact fraction")
        elif self.numerator is not None or self.denominator is not None:
            raise ValueError("Non-ratio REDTEAM metric cannot contain a fraction")
        if self.unit is RedteamBenchmarkMetricUnit.COUNT and not self.value.is_integer():
            raise ValueError("REDTEAM count metric must be an integer value")
        if self.value < 0 or (self.unit is RedteamBenchmarkMetricUnit.RATIO and self.value > 1):
            raise ValueError("REDTEAM benchmark metric is outside its unit range")
        return self


class RedteamProfileBenchmarkResult(StrictModel):
    """Aggregate metrics for one exact product profile."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    result_digest: str = Field(default="", alias="resultDigest", max_length=64)
    profile_id: _Identifier = Field(alias="profileId")
    profile_contract_digest: _Sha256 = Field(alias="profileContractDigest")
    source_observation_digests: tuple[_Sha256, ...] = Field(
        alias="sourceObservationDigests",
        min_length=1,
        max_length=10_000,
    )
    metrics: tuple[RedteamBenchmarkMetricObservation, ...] = Field(
        min_length=len(REDTEAM_BENCHMARK_METRIC_ORDER),
        max_length=len(REDTEAM_BENCHMARK_METRIC_ORDER),
    )

    @model_validator(mode="after")
    def bind_result(self) -> Self:
        if self.source_observation_digests != tuple(sorted(set(self.source_observation_digests))):
            raise ValueError("REDTEAM result sources must be unique and ordered")
        if tuple(item.metric for item in self.metrics) != REDTEAM_BENCHMARK_METRIC_ORDER:
            raise ValueError("REDTEAM result metrics must be complete and ordered")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.redteam-profile-result/v1",
            material,
            max_bytes=_MAX_REPORT_BYTES,
        )
        if self.result_digest and self.result_digest != digest:
            raise ValueError("REDTEAM Profile Benchmark Result Digest differs")
        object.__setattr__(self, "result_digest", digest)
        return self


class RedteamInitialBenchmarkReport(StrictModel):
    """Sealed REDTEAM-002 aggregate without Finding or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/redteam-initial-benchmark-report/v1alpha1"] = Field(
        default=REDTEAM_INITIAL_BENCHMARK_REPORT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RedteamInitialBenchmarkReport"] = "RedteamInitialBenchmarkReport"
    report_id: str = Field(default="", alias="reportId", max_length=110)
    report_digest: str = Field(default="", alias="reportDigest", max_length=64)
    profile_set: RedteamBenchmarkProfileSet = Field(alias="profileSet")
    measured_at: datetime = Field(alias="measuredAt")
    source_observation_digests: tuple[_Sha256, ...] = Field(
        alias="sourceObservationDigests",
        min_length=1,
        max_length=10_000,
    )
    profile_results: tuple[RedteamProfileBenchmarkResult, ...] = Field(
        alias="profileResults",
        min_length=len(_PROFILE_ORDER),
        max_length=len(_PROFILE_ORDER),
    )
    measurement_state: Literal["sealed-profile-benchmark-aggregated"] = Field(
        default="sealed-profile-benchmark-aggregated",
        alias="measurementState",
    )
    execution_authority_granted: Literal[False] = Field(
        default=False,
        alias="executionAuthorityGranted",
    )
    finding_authority_granted: Literal[False] = Field(
        default=False,
        alias="findingAuthorityGranted",
    )
    scope_expanded: Literal[False] = Field(default=False, alias="scopeExpanded")

    @field_validator("measured_at")
    @classmethod
    def normalize_measured_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("REDTEAM benchmark measuredAt requires an explicit UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_report(self) -> Self:
        if self.source_observation_digests != tuple(sorted(set(self.source_observation_digests))):
            raise ValueError("REDTEAM report sources must be unique and ordered")
        if tuple(item.profile_id for item in self.profile_results) != _PROFILE_ORDER:
            raise ValueError("REDTEAM report profile results must be complete and ordered")
        if (
            tuple(
                sorted(
                    digest
                    for result in self.profile_results
                    for digest in result.source_observation_digests
                )
            )
            != self.source_observation_digests
        ):
            raise ValueError("REDTEAM report source set differs from profile results")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"report_id", "report_digest"},
        )
        canonical_benchmark_json(
            material,
            label="RedteamInitialBenchmarkReport",
            max_bytes=_MAX_REPORT_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.redteam-initial-report/v1",
            material,
            max_bytes=_MAX_REPORT_BYTES,
        )
        report_id = f"redteam-initial-benchmark:{digest}"
        if self.report_digest and self.report_digest != digest:
            raise ValueError("REDTEAM Initial Benchmark Report Digest differs")
        if self.report_id and self.report_id != report_id:
            raise ValueError("REDTEAM Initial Benchmark Report ID differs")
        object.__setattr__(self, "report_digest", digest)
        object.__setattr__(self, "report_id", report_id)
        return self


@dataclass(frozen=True, slots=True)
class RedteamBenchmarkRunObservationOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    observation: RedteamBenchmarkRunObservation


@dataclass(frozen=True, slots=True)
class RedteamInitialBenchmarkOutcome:
    run_id: str
    run_path: Path
    profile_set_path: str
    observation_bundle_path: str
    report_path: str
    report: RedteamInitialBenchmarkReport


def registered_redteam_benchmark_profile_set(
    bundle: ExistingModeCapabilityBundle,
) -> RedteamBenchmarkProfileSet:
    """Derive the closed REDTEAM-001 denominator from exact CAP-002/CAP-003 identities."""

    if not isinstance(bundle, ExistingModeCapabilityBundle):
        raise TypeError("REDTEAM benchmark profile set requires an exact Capability bundle")
    manifests = {item.capability.capability_id: item for item in bundle.capabilities()}
    mappings = {
        item.capability.capability_id: item
        for item in existing_mode_capability_benchmark_mappings(bundle)
    }
    replay_support = {
        item.capability.capability.capability_id: item
        for item in existing_mode_capability_replay_support(bundle)
    }
    profiles: list[RedteamProfileBenchmarkContract] = []
    try:
        for profile_id, blueprint in _PROFILE_BLUEPRINTS.items():
            capabilities = []
            for capability_id, capability_version in blueprint.capabilities:
                manifest = manifests[capability_id]
                mapping = mappings[capability_id]
                definition = bundle.definitions.resolve(manifest.capability)
                support = replay_support.get(capability_id)
                if (
                    manifest.capability.capability_version != capability_version
                    or mapping.capability != manifest.capability
                ):
                    raise ValueError("REDTEAM benchmark Capability mapping has drifted")
                capabilities.append(
                    RedteamBenchmarkCapability(
                        capability=manifest.reference(),
                        benchmarkId=mapping.benchmark_ids[0],
                        benchmarkMappingDigest=mapping.mapping_digest,
                        requestUnitCost=definition.request_unit_cost,
                        replaySupportDigest=(
                            support.support_digest if support is not None else None
                        ),
                        replayContractIds=(support.contract_ids if support is not None else ()),
                    )
                )
            profiles.append(
                RedteamProfileBenchmarkContract(
                    profileId=profile_id,
                    profileVersion=blueprint.profile_version,
                    profileDigest=blueprint.profile_digest,
                    capabilities=tuple(capabilities),
                    falsePositiveMeasurement=blueprint.false_positive,
                    replayMeasurement=blueprint.replay,
                )
            )
    except (KeyError, StopIteration, ValidationError, ValueError) as exc:
        raise RedteamBenchmarkError(
            "REDTEAM benchmark profile set cannot bind the exact registered inventory"
        ) from exc
    return RedteamBenchmarkProfileSet(profiles=tuple(profiles))


class RedteamBenchmarkRunObservationRecorder:
    """Seal one raw measurement-adapter observation after profile-set admission."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        profile_set: RedteamBenchmarkProfileSet,
        observation: RedteamBenchmarkRunObservation,
    ) -> RedteamBenchmarkRunObservationOutcome:
        try:
            authoritative_set = RedteamBenchmarkProfileSet.model_validate(
                profile_set.model_dump(mode="json", by_alias=True)
            )
            authoritative_observation = RedteamBenchmarkRunObservation.model_validate(
                observation.model_dump(mode="json", by_alias=True)
            )
            _require_observation_matches_profile_set(
                authoritative_set,
                authoritative_observation,
            )
        except (ValidationError, ValueError, RedteamBenchmarkError) as exc:
            raise RedteamBenchmarkError(
                "REDTEAM benchmark Run observation differs from its profile set"
            ) from exc
        store = RunStore.create(self._output_root, "redteam-benchmark-observation")
        store.append_event("campaign.started", {"purpose": "redteam-benchmark-observation"})
        artifact_path = store.write_json(
            _OBSERVATION_ARTIFACT,
            authoritative_observation.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.redteam-observation.recorded",
            {
                "observationId": authoritative_observation.observation_id,
                "observationDigest": authoritative_observation.observation_digest,
                "profileSetDigest": authoritative_set.profile_set_digest,
            },
        )
        store.append_event("campaign.completed", {"status": "completed"})
        store.seal()
        return RedteamBenchmarkRunObservationOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            observation=authoritative_observation,
        )


class RedteamInitialBenchmarkRunner:
    """Reopen sealed raw sources and publish the complete four-profile aggregate."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        profile_set: RedteamBenchmarkProfileSet,
        source_outcomes: tuple[RedteamBenchmarkRunObservationOutcome, ...],
        *,
        measured_at: datetime,
    ) -> RedteamInitialBenchmarkOutcome:
        try:
            authoritative_set = RedteamBenchmarkProfileSet.model_validate(
                profile_set.model_dump(mode="json", by_alias=True)
            )
            observations = tuple(
                _load_redteam_benchmark_run_observation(authoritative_set, source)
                for source in source_outcomes
            )
            report = aggregate_redteam_initial_benchmark(
                authoritative_set,
                observations,
                measured_at=measured_at,
            )
        except (
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            RedteamBenchmarkError,
        ) as exc:
            raise RedteamBenchmarkError(
                "REDTEAM initial benchmark source verification failed"
            ) from exc
        store = RunStore.create(self._output_root, "redteam-initial-benchmark")
        store.append_event("campaign.started", {"purpose": "redteam-initial-benchmark"})
        profile_set_path = store.write_json(
            _PROFILE_SET_ARTIFACT,
            authoritative_set.model_dump(mode="json", by_alias=True),
        )
        observation_bundle_path = store.write_json(
            _OBSERVATION_BUNDLE_ARTIFACT,
            [item.model_dump(mode="json", by_alias=True) for item in observations],
        )
        report_path = store.write_json(
            _REPORT_ARTIFACT,
            report.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.redteam-initial.measured",
            {
                "reportId": report.report_id,
                "reportDigest": report.report_digest,
                "profileSetDigest": authoritative_set.profile_set_digest,
                "sourceCount": len(observations),
            },
            occurred_at=report.measured_at,
        )
        store.append_event("campaign.completed", {"status": "completed"})
        store.seal()
        return RedteamInitialBenchmarkOutcome(
            run_id=store.run_id,
            run_path=store.path,
            profile_set_path=profile_set_path,
            observation_bundle_path=observation_bundle_path,
            report_path=report_path,
            report=report,
        )


def load_redteam_initial_benchmark_report(
    profile_set: RedteamBenchmarkProfileSet,
    outcome: RedteamInitialBenchmarkOutcome,
    *,
    source_outcomes: tuple[RedteamBenchmarkRunObservationOutcome, ...],
) -> RedteamInitialBenchmarkReport:
    """Reopen the aggregate and every sealed raw source before returning it."""

    try:
        authoritative_set = RedteamBenchmarkProfileSet.model_validate(
            profile_set.model_dump(mode="json", by_alias=True)
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                outcome.profile_set_path: _MAX_PROFILE_SET_BYTES,
                outcome.observation_bundle_path: _MAX_OBSERVATION_BUNDLE_BYTES,
                outcome.report_path: _MAX_REPORT_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_set = RedteamBenchmarkProfileSet.model_validate_json(
            snapshot.artifact_bytes(outcome.profile_set_path)
        )
        sealed_observations = _parse_observation_bundle(
            snapshot.artifact_bytes(outcome.observation_bundle_path)
        )
        sealed_report = RedteamInitialBenchmarkReport.model_validate_json(
            snapshot.artifact_bytes(outcome.report_path)
        )
        rebuilt_observations = tuple(
            _load_redteam_benchmark_run_observation(authoritative_set, source)
            for source in source_outcomes
        )
        rebuilt_report = aggregate_redteam_initial_benchmark(
            authoritative_set,
            rebuilt_observations,
            measured_at=sealed_report.measured_at,
        )
    except (OSError, RunIntegrityError, ValidationError, ValueError, RedteamBenchmarkError) as exc:
        raise RedteamBenchmarkError(
            "REDTEAM initial benchmark report is not sealed and valid"
        ) from exc
    expected_events = (
        "campaign.started",
        "benchmark.redteam-initial.measured",
        "campaign.completed",
    )
    if (
        outcome.profile_set_path != _PROFILE_SET_ARTIFACT
        or outcome.observation_bundle_path != _OBSERVATION_BUNDLE_ARTIFACT
        or outcome.report_path != _REPORT_ARTIFACT
        or tuple(item.event_type for item in snapshot.events) != expected_events
        or sealed_set != authoritative_set
        or sealed_observations != rebuilt_observations
        or sealed_report != rebuilt_report
        or sealed_report != outcome.report
        or snapshot.events[1].payload
        != {
            "reportId": sealed_report.report_id,
            "reportDigest": sealed_report.report_digest,
            "profileSetDigest": authoritative_set.profile_set_digest,
            "sourceCount": len(rebuilt_observations),
        }
    ):
        raise RedteamBenchmarkError("REDTEAM initial benchmark differs from exact sources")
    return sealed_report.model_copy(deep=True)


def aggregate_redteam_initial_benchmark(
    profile_set: RedteamBenchmarkProfileSet,
    observations: tuple[RedteamBenchmarkRunObservation, ...],
    *,
    measured_at: datetime,
) -> RedteamInitialBenchmarkReport:
    """Aggregate exact profile metrics without manufacturing unavailable Finding data."""

    canonical_set = RedteamBenchmarkProfileSet.model_validate(
        profile_set.model_dump(mode="json", by_alias=True)
    )
    canonical_observations = tuple(
        sorted(
            (
                RedteamBenchmarkRunObservation.model_validate(
                    item.model_dump(mode="json", by_alias=True)
                )
                for item in observations
            ),
            key=lambda item: (
                _PROFILE_ORDER.index(item.profile_id),
                item.capability.capability.capability_id,
                item.source_run_id,
                item.observation_digest,
            ),
        )
    )
    if not canonical_observations:
        raise RedteamBenchmarkError("REDTEAM initial benchmark requires sealed observations")
    if len({item.observation_digest for item in canonical_observations}) != len(
        canonical_observations
    ):
        raise RedteamBenchmarkError("REDTEAM initial benchmark sources must be unique")
    if len({item.source_run_id for item in canonical_observations}) != len(canonical_observations):
        raise RedteamBenchmarkError("REDTEAM source Run identities must be unique")
    for observation in canonical_observations:
        _require_observation_matches_profile_set(canonical_set, observation)
    results = tuple(
        _aggregate_profile(
            profile,
            tuple(item for item in canonical_observations if item.profile_id == profile.profile_id),
        )
        for profile in canonical_set.profiles
    )
    return RedteamInitialBenchmarkReport(
        profileSet=canonical_set,
        measuredAt=measured_at,
        sourceObservationDigests=tuple(
            sorted(item.observation_digest for item in canonical_observations)
        ),
        profileResults=results,
    )


def _require_observation_matches_profile_set(
    profile_set: RedteamBenchmarkProfileSet,
    observation: RedteamBenchmarkRunObservation,
) -> None:
    profile = profile_set.profile(observation.profile_id)
    try:
        expected = next(
            item for item in profile.capabilities if item.capability == observation.capability
        )
    except StopIteration as exc:
        raise RedteamBenchmarkError(
            "REDTEAM observation Capability is outside its exact profile"
        ) from exc
    if (
        observation.profile_set_digest != profile_set.profile_set_digest
        or observation.profile_contract_digest != profile.contract_digest
        or observation.benchmark_id != expected.benchmark_id
        or observation.benchmark_mapping_digest != expected.benchmark_mapping_digest
    ):
        raise RedteamBenchmarkError("REDTEAM observation authority binding has drifted")
    if observation.source_kind is RedteamBenchmarkSourceKind.PROFILE_EXECUTION and (
        observation.request_units != expected.request_unit_cost
    ):
        raise RedteamBenchmarkError("REDTEAM execution request units differ from Capability")
    if any(
        replay.observation.contract_id not in expected.replay_contract_ids
        for replay in observation.replay_cases
    ):
        raise RedteamBenchmarkError("REDTEAM Replay contract is outside CAP-006 support")
    if (
        profile.replay_measurement is RedteamMetricApplicability.NOT_APPLICABLE
        and observation.replay_cases
    ):
        raise RedteamBenchmarkError("REDTEAM profile cannot claim unsupported Replay")
    if profile.false_positive_measurement is RedteamMetricApplicability.NOT_APPLICABLE and any(
        item.ground_truth is RedteamGroundTruthClass.NEGATIVE_CONTROL
        for item in observation.detection_cases
    ):
        raise RedteamBenchmarkError("REDTEAM profile cannot claim an unavailable negative control")


def _aggregate_profile(
    profile: RedteamProfileBenchmarkContract,
    observations: tuple[RedteamBenchmarkRunObservation, ...],
) -> RedteamProfileBenchmarkResult:
    if not observations:
        raise RedteamBenchmarkError(f"REDTEAM profile {profile.profile_id} has no observations")
    expected_capabilities = {item.capability for item in profile.capabilities}
    positive_capabilities: set[CodeBackedCapabilityRef] = set()
    negative_capabilities: set[CodeBackedCapabilityRef] = set()
    replay_capabilities: set[CodeBackedCapabilityRef] = set()
    policy_observations: list[RedteamBenchmarkRunObservation] = []
    cases: list[RedteamDetectionCaseObservation] = []
    replay_cases: list[RedteamReplayCaseObservation] = []
    case_sources: dict[
        str,
        tuple[CodeBackedCapabilityRef, RedteamGroundTruthClass, str],
    ] = {}
    for observation in observations:
        if observation.source_kind is RedteamBenchmarkSourceKind.POLICY_DENIAL:
            policy_observations.append(observation)
            continue
        cases.extend(observation.detection_cases)
        replay_cases.extend(observation.replay_cases)
        for case in observation.detection_cases:
            case_sources[case.case_id] = (
                observation.capability,
                case.ground_truth,
                observation.source_run_id,
            )
        if (
            any(
                item.ground_truth is RedteamGroundTruthClass.KNOWN_POSITIVE
                for item in observation.detection_cases
            )
            and observation.source_kind is RedteamBenchmarkSourceKind.PROFILE_EXECUTION
        ):
            positive_capabilities.add(observation.capability)
        if any(
            item.ground_truth is RedteamGroundTruthClass.NEGATIVE_CONTROL
            for item in observation.detection_cases
        ):
            negative_capabilities.add(observation.capability)
        if (
            observation.source_kind is RedteamBenchmarkSourceKind.INDEPENDENT_REPLAY
            and observation.replay_cases
        ):
            replay_capabilities.add(observation.capability)
    _require_profile_measurement_coverage(
        profile=profile,
        expected_capabilities=expected_capabilities,
        positive_capabilities=positive_capabilities,
        negative_capabilities=negative_capabilities,
        replay_capabilities=replay_capabilities,
        policy_observations=policy_observations,
        cases=cases,
        observations=observations,
        case_sources=case_sources,
    )

    positives = [
        item for item in cases if item.ground_truth is RedteamGroundTruthClass.KNOWN_POSITIVE
    ]
    negatives = [
        item for item in cases if item.ground_truth is RedteamGroundTruthClass.NEGATIVE_CONTROL
    ]
    true_positives = sum(item.detected for item in positives)
    false_positives = sum(item.detected for item in negatives)
    predicted_positives = true_positives + false_positives
    replay_successes = sum(
        item.observation.verdict is item.expected_verdict for item in replay_cases
    )
    request_units = sum(item.request_units for item in observations)
    tool_calls = sum(item.tool_call_count for item in observations)
    total_cost = sum(item.cost_usd for item in observations)
    evidence_expected = sum(item.evidence_expected_count for item in observations)
    evidence_verified = sum(item.evidence_verified_count for item in observations)
    policy_correct = sum(
        item.policy_denied is item.policy_denial_expected for item in policy_observations
    )

    metrics = (
        _ratio_metric(
            RedteamBenchmarkMetric.DETECTION_RECALL,
            true_positives,
            len(positives),
        ),
        (
            _ratio_metric(
                RedteamBenchmarkMetric.FALSE_POSITIVE_RATE,
                false_positives,
                len(negatives),
            )
            if profile.false_positive_measurement is RedteamMetricApplicability.REQUIRED
            else _not_applicable(
                RedteamBenchmarkMetric.FALSE_POSITIVE_RATE,
                "The exact profile has no registered negative-control measurement path.",
            )
        ),
        (
            _ratio_metric(
                RedteamBenchmarkMetric.DETECTION_PRECISION,
                true_positives,
                predicted_positives,
            )
            if profile.false_positive_measurement is RedteamMetricApplicability.REQUIRED
            and predicted_positives
            else _not_applicable(
                RedteamBenchmarkMetric.DETECTION_PRECISION,
                (
                    "The exact profile has no registered negative-control measurement path."
                    if profile.false_positive_measurement
                    is RedteamMetricApplicability.NOT_APPLICABLE
                    else "No positive detections exist, so precision has no denominator."
                ),
            )
        ),
        (
            _ratio_metric(
                RedteamBenchmarkMetric.REPLAY_SUCCESS_RATE,
                replay_successes,
                len(replay_cases),
            )
            if profile.replay_measurement is RedteamMetricApplicability.REQUIRED
            else _not_applicable(
                RedteamBenchmarkMetric.REPLAY_SUCCESS_RATE,
                "REDTEAM-001 does not register an independent Replay path for this profile.",
            )
        ),
        _not_applicable(
            RedteamBenchmarkMetric.TIME_TO_FIRST_VALID_FINDING,
            "REDTEAM-001 Observations do not satisfy a Profile validation floor or "
            "create a valid Finding.",
        ),
        _value_metric(RedteamBenchmarkMetric.TOTAL_REQUEST_UNITS, float(request_units)),
        _value_metric(RedteamBenchmarkMetric.TOTAL_TOOL_CALLS, float(tool_calls)),
        _value_metric(RedteamBenchmarkMetric.TOTAL_COST_USD, total_cost),
        (
            _value_metric(
                RedteamBenchmarkMetric.COST_PER_DETECTION,
                total_cost / true_positives,
            )
            if true_positives
            else _not_applicable(
                RedteamBenchmarkMetric.COST_PER_DETECTION,
                "No true-positive detection exists, so cost per detection has no denominator.",
            )
        ),
        _ratio_metric(
            RedteamBenchmarkMetric.EVIDENCE_COMPLETENESS,
            evidence_verified,
            evidence_expected,
        ),
        _ratio_metric(
            RedteamBenchmarkMetric.POLICY_DENIAL_CORRECTNESS,
            policy_correct,
            len(policy_observations),
        ),
        _not_applicable(
            RedteamBenchmarkMetric.CLEANUP_SUCCESS_RATE,
            "Every REDTEAM-001 Capability is read-only and declares cleanupRequired=false.",
        ),
    )
    return RedteamProfileBenchmarkResult(
        profileId=profile.profile_id,
        profileContractDigest=profile.contract_digest,
        sourceObservationDigests=tuple(sorted(item.observation_digest for item in observations)),
        metrics=metrics,
    )


def _require_profile_measurement_coverage(
    *,
    profile: RedteamProfileBenchmarkContract,
    expected_capabilities: set[CodeBackedCapabilityRef],
    positive_capabilities: set[CodeBackedCapabilityRef],
    negative_capabilities: set[CodeBackedCapabilityRef],
    replay_capabilities: set[CodeBackedCapabilityRef],
    policy_observations: list[RedteamBenchmarkRunObservation],
    cases: list[RedteamDetectionCaseObservation],
    observations: tuple[RedteamBenchmarkRunObservation, ...],
    case_sources: dict[
        str,
        tuple[CodeBackedCapabilityRef, RedteamGroundTruthClass, str],
    ],
) -> None:
    if positive_capabilities != expected_capabilities:
        raise RedteamBenchmarkError(
            f"REDTEAM profile {profile.profile_id} lacks positive profile-execution coverage"
        )
    if (
        profile.false_positive_measurement is RedteamMetricApplicability.REQUIRED
        and negative_capabilities != expected_capabilities
    ):
        raise RedteamBenchmarkError(
            f"REDTEAM profile {profile.profile_id} lacks negative-control coverage"
        )
    if (
        profile.replay_measurement is RedteamMetricApplicability.REQUIRED
        and replay_capabilities != expected_capabilities
    ):
        raise RedteamBenchmarkError(f"REDTEAM profile {profile.profile_id} lacks Replay coverage")
    if not policy_observations:
        raise RedteamBenchmarkError(
            f"REDTEAM profile {profile.profile_id} lacks policy-denial coverage"
        )
    case_ids = [item.case_id for item in cases]
    if len(case_ids) != len(set(case_ids)):
        raise RedteamBenchmarkError(
            f"REDTEAM profile {profile.profile_id} reuses a Ground Truth case ID"
        )
    for observation in observations:
        _require_independent_replays(observation, case_sources)


def _require_independent_replays(
    observation: RedteamBenchmarkRunObservation,
    case_sources: dict[
        str,
        tuple[CodeBackedCapabilityRef, RedteamGroundTruthClass, str],
    ],
) -> None:
    for replay in observation.replay_cases:
        try:
            capability, ground_truth, source_run_id = case_sources[replay.case_id]
        except KeyError as exc:
            raise RedteamBenchmarkError(
                "REDTEAM Replay refers to an unknown Ground Truth case"
            ) from exc
        expected_verdict = (
            CapabilityReplayVerdict.SUPPORTS
            if ground_truth is RedteamGroundTruthClass.KNOWN_POSITIVE
            else CapabilityReplayVerdict.CONTRADICTS
        )
        if (
            observation.capability != capability
            or observation.source_run_id == source_run_id
            or replay.expected_verdict is not expected_verdict
        ):
            raise RedteamBenchmarkError(
                "REDTEAM Replay is not independent or differs from Ground Truth"
            )


def _ratio_metric(
    metric: RedteamBenchmarkMetric,
    numerator: int,
    denominator: int,
) -> RedteamBenchmarkMetricObservation:
    if denominator <= 0:
        raise RedteamBenchmarkError(f"REDTEAM metric {metric.value} has no denominator")
    return RedteamBenchmarkMetricObservation(
        metric=metric,
        unit=_METRIC_UNITS[metric],
        status=RedteamBenchmarkMetricStatus.MEASURED,
        value=numerator / denominator,
        numerator=numerator,
        denominator=denominator,
    )


def _value_metric(
    metric: RedteamBenchmarkMetric,
    value: float,
) -> RedteamBenchmarkMetricObservation:
    return RedteamBenchmarkMetricObservation(
        metric=metric,
        unit=_METRIC_UNITS[metric],
        status=RedteamBenchmarkMetricStatus.MEASURED,
        value=value,
    )


def _not_applicable(
    metric: RedteamBenchmarkMetric,
    reason: str,
) -> RedteamBenchmarkMetricObservation:
    return RedteamBenchmarkMetricObservation(
        metric=metric,
        unit=_METRIC_UNITS[metric],
        status=RedteamBenchmarkMetricStatus.NOT_APPLICABLE,
        reason=reason,
    )


def _load_redteam_benchmark_run_observation(
    profile_set: RedteamBenchmarkProfileSet,
    outcome: RedteamBenchmarkRunObservationOutcome,
) -> RedteamBenchmarkRunObservation:
    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={outcome.artifact_path: _MAX_OBSERVATION_BYTES},
            expected_run_id=outcome.run_id,
        )
        observation = RedteamBenchmarkRunObservation.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
        _require_observation_matches_profile_set(profile_set, observation)
    except (OSError, RunIntegrityError, ValidationError, ValueError, RedteamBenchmarkError) as exc:
        raise RedteamBenchmarkError(
            "REDTEAM benchmark source observation is not sealed and valid"
        ) from exc
    expected_events = (
        "campaign.started",
        "benchmark.redteam-observation.recorded",
        "campaign.completed",
    )
    if (
        outcome.artifact_path != _OBSERVATION_ARTIFACT
        or observation != outcome.observation
        or tuple(item.event_type for item in snapshot.events) != expected_events
        or snapshot.events[1].payload
        != {
            "observationId": observation.observation_id,
            "observationDigest": observation.observation_digest,
            "profileSetDigest": profile_set.profile_set_digest,
        }
    ):
        raise RedteamBenchmarkError("REDTEAM benchmark source differs from exact evidence")
    return observation.model_copy(deep=True)


def _parse_observation_bundle(data: bytes) -> tuple[RedteamBenchmarkRunObservation, ...]:
    if len(data) > _MAX_OBSERVATION_BUNDLE_BYTES:
        raise ValueError("REDTEAM observation bundle exceeds the byte limit")
    try:
        raw = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("REDTEAM observation bundle is not strict JSON") from exc
    if not isinstance(raw, list):
        raise ValueError("REDTEAM observation bundle must be a JSON array")
    return tuple(RedteamBenchmarkRunObservation.model_validate(item) for item in raw)


__all__ = [
    "REDTEAM_BENCHMARK_METRIC_ORDER",
    "REDTEAM_BENCHMARK_PROFILE_SET_API_VERSION",
    "REDTEAM_BENCHMARK_RUN_OBSERVATION_API_VERSION",
    "REDTEAM_INITIAL_BENCHMARK_REPORT_API_VERSION",
    "RedteamBenchmarkCapability",
    "RedteamBenchmarkError",
    "RedteamBenchmarkMetric",
    "RedteamBenchmarkMetricObservation",
    "RedteamBenchmarkMetricStatus",
    "RedteamBenchmarkMetricUnit",
    "RedteamBenchmarkProfileSet",
    "RedteamBenchmarkRunObservation",
    "RedteamBenchmarkRunObservationOutcome",
    "RedteamBenchmarkRunObservationRecorder",
    "RedteamBenchmarkSourceKind",
    "RedteamDetectionCaseObservation",
    "RedteamGroundTruthClass",
    "RedteamInitialBenchmarkOutcome",
    "RedteamInitialBenchmarkReport",
    "RedteamInitialBenchmarkRunner",
    "RedteamMetricApplicability",
    "RedteamProfileBenchmarkContract",
    "RedteamProfileBenchmarkResult",
    "RedteamReplayCaseObservation",
    "aggregate_redteam_initial_benchmark",
    "load_redteam_initial_benchmark_report",
    "registered_redteam_benchmark_profile_set",
]
