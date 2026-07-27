"""Content-addressed CAP-006 registry and execution-quality metrics."""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from enum import StrEnum
from statistics import median
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.capabilities.authorities import (
    CapabilityAuthorityBinding,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapability,
    CodeBackedCapabilityRef,
)
from pajin.capabilities.existing import ExistingModeCapabilityBundle
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecycleRegistry,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
)
from pajin.capabilities.models import (
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    capability_definition_digest,
)
from pajin.capabilities.scaffold import CapabilityBenchmarkMapping
from pajin.domain.models import StrictModel
from pajin.domain.validation import AtomicClaimType
from pajin.modes.ai_redteam.replay import (
    kisa_negative_retest_contract,
    kisa_replay_contract,
)

CAPABILITY_METRIC_SCOPE_API_VERSION: Literal["pajin.dev/capability-metric-scope/v1alpha1"] = (
    "pajin.dev/capability-metric-scope/v1alpha1"
)
CAPABILITY_DELIVERY_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/capability-delivery-evidence/v1alpha1"
] = "pajin.dev/capability-delivery-evidence/v1alpha1"
CAPABILITY_ORACLE_OBSERVATION_API_VERSION: Literal[
    "pajin.dev/capability-oracle-observation/v1alpha1"
] = "pajin.dev/capability-oracle-observation/v1alpha1"
CAPABILITY_REPLAY_SUPPORT_API_VERSION: Literal["pajin.dev/capability-replay-support/v1alpha1"] = (
    "pajin.dev/capability-replay-support/v1alpha1"
)
CAPABILITY_REPLAY_OBSERVATION_API_VERSION: Literal[
    "pajin.dev/capability-replay-observation/v1alpha1"
] = "pajin.dev/capability-replay-observation/v1alpha1"
CAPABILITY_METRICS_REPORT_API_VERSION: Literal["pajin.dev/capability-metrics-report/v1alpha1"] = (
    "pajin.dev/capability-metrics-report/v1alpha1"
)

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Ratio = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
_Duration = Annotated[float, Field(ge=0, allow_inf_nan=False)]

_EXISTING_REPLAY_SCENARIOS = {
    "pajin.ai.kisa.system-prompt-disclosure": ("kisa.model.system-prompt-disclosure"),
    "pajin.ai.kisa.jailbreak-policy-bypass": ("kisa.model.jailbreak-policy-bypass"),
    "pajin.ai.kisa.memory-poisoning-persistence": ("kisa.agent.memory-poisoning-persistence"),
}


class CapabilityMetricDimension(StrEnum):
    """A measured CAP-006 dimension that can produce an explicit gap."""

    AUTHORITY = "authority"
    BENCHMARK = "benchmark"
    DEFINITION = "definition"
    DELIVERY = "delivery"
    LIFECYCLE = "lifecycle"
    ORACLE_OBSERVATION = "oracle-observation"
    REPLAY_OBSERVATION = "replay-observation"
    REPLAY_SUPPORT = "replay-support"


class CapabilityMetricsReportStatus(StrEnum):
    """Whether every requirement in the exact metric scope has evidence."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class CapabilityReplayVerdict(StrEnum):
    """Bounded replay sample outcome used by CAP-006 aggregation."""

    CONTRADICTS = "contradicts"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    SUPPORTS = "supports"


class CapabilityMetricRequirement(StrictModel):
    """One exact code-backed Capability and its required measurement dimensions."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability: CodeBackedCapabilityRef
    benchmark_required: bool = Field(default=True, alias="benchmarkRequired")
    delivery_evidence_required: bool = Field(
        default=True,
        alias="deliveryEvidenceRequired",
    )
    oracle_observation_required: bool = Field(
        default=True,
        alias="oracleObservationRequired",
    )
    replay_required: bool = Field(default=False, alias="replayRequired")
    lifecycle_required: bool = Field(default=True, alias="lifecycleRequired")

    @model_validator(mode="after")
    def require_oracle_benchmark_mapping(self) -> Self:
        if self.oracle_observation_required and not self.benchmark_required:
            raise ValueError("Capability Oracle observations require a benchmark mapping")
        return self


class CapabilityMetricScope(StrictModel):
    """Closed external denominator for registry metrics; never inferred from the registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-metric-scope/v1alpha1"] = Field(
        default=CAPABILITY_METRIC_SCOPE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityMetricScope"] = "CapabilityMetricScope"
    scope_id: _Identifier = Field(alias="scopeId")
    scope_version: _Identifier = Field(alias="scopeVersion")
    scope_digest: str = Field(default="", alias="scopeDigest", max_length=64)
    requirements: tuple[CapabilityMetricRequirement, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def bind_scope_identity(self) -> Self:
        keys = [_capability_key(item.capability) for item in self.requirements]
        if keys != sorted(set(keys)):
            raise ValueError("Capability metric requirements must be unique and canonically sorted")
        capability_ids = [item.capability.capability.capability_id for item in self.requirements]
        if len(capability_ids) != len(set(capability_ids)):
            raise ValueError(
                "Capability metric scope cannot contain multiple versions of one Capability"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"scope_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.metric-scope/v1",
            material,
        )
        if self.scope_digest and self.scope_digest != digest:
            raise ValueError("Capability metric scope digest differs from canonical identity")
        object.__setattr__(self, "scope_digest", digest)
        return self


class CapabilityDeliveryEvidence(StrictModel):
    """Auditable timestamps for authoring-to-code and authoring-to-release lead time."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-delivery-evidence/v1alpha1"] = Field(
        default=CAPABILITY_DELIVERY_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityDeliveryEvidence"] = "CapabilityDeliveryEvidence"
    evidence_id: str = Field(default="", alias="evidenceId", max_length=93)
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    capability: CodeBackedCapabilityRef
    authored_at: datetime = Field(alias="authoredAt")
    code_backed_at: datetime = Field(alias="codeBackedAt")
    released_at: datetime | None = Field(default=None, alias="releasedAt")
    release: CapabilityReleaseRef | None = None
    source_digest: _Sha256 = Field(alias="sourceDigest")

    @field_validator("authored_at", "code_backed_at", "released_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _aware_utc(value, label="Capability delivery timestamp")

    @model_validator(mode="after")
    def bind_delivery_identity(self) -> Self:
        if self.code_backed_at < self.authored_at:
            raise ValueError("Capability code-backed timestamp predates authoring")
        if self.released_at is not None and self.released_at < self.code_backed_at:
            raise ValueError("Capability release timestamp predates code-backed completion")
        if (self.released_at is None) != (self.release is None):
            raise ValueError(
                "Capability delivery release timestamp and reference must exist together"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_id", "evidence_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.delivery-evidence/v1",
            material,
        )
        evidence_id = f"capability-delivery_{digest}"
        _bind_content_identity(
            current_id=self.evidence_id,
            current_digest=self.evidence_digest,
            expected_id=evidence_id,
            expected_digest=digest,
            label="Capability delivery evidence",
        )
        object.__setattr__(self, "evidence_id", evidence_id)
        object.__setattr__(self, "evidence_digest", digest)
        return self


class CapabilityOracleObservation(StrictModel):
    """One benchmark-bound CAP-002 Success Oracle decision."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-oracle-observation/v1alpha1"] = Field(
        default=CAPABILITY_ORACLE_OBSERVATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityOracleObservation"] = "CapabilityOracleObservation"
    observation_id: str = Field(default="", alias="observationId", max_length=103)
    observation_digest: str = Field(
        default="",
        alias="observationDigest",
        max_length=64,
    )
    capability: CodeBackedCapabilityRef
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    decision: CapabilityOracleDecision
    observed_at: datetime = Field(alias="observedAt")
    evidence_digest: _Sha256 = Field(alias="evidenceDigest")

    @field_validator("observed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Capability Oracle observation timestamp")

    @model_validator(mode="after")
    def bind_observation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.oracle-observation/v1",
            material,
        )
        observation_id = f"capability-oracle-observation_{digest}"
        _bind_content_identity(
            current_id=self.observation_id,
            current_digest=self.observation_digest,
            expected_id=observation_id,
            expected_digest=digest,
            label="Capability Oracle observation",
        )
        object.__setattr__(self, "observation_id", observation_id)
        object.__setattr__(self, "observation_digest", digest)
        return self


class CapabilityReplaySupport(StrictModel):
    """Exact Replay Strategy authority and contracts supported by one Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-replay-support/v1alpha1"] = Field(
        default=CAPABILITY_REPLAY_SUPPORT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityReplaySupport"] = "CapabilityReplaySupport"
    support_digest: str = Field(default="", alias="supportDigest", max_length=64)
    capability: CodeBackedCapabilityRef
    replay_authority_digest: _Sha256 = Field(alias="replayAuthorityDigest")
    contract_ids: tuple[_Identifier, ...] = Field(
        alias="contractIds",
        min_length=1,
        max_length=20,
    )

    @model_validator(mode="after")
    def bind_support_identity(self) -> Self:
        if self.contract_ids != tuple(sorted(set(self.contract_ids))):
            raise ValueError("Capability Replay contract IDs must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"support_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.replay-support/v1",
            material,
        )
        if self.support_digest and self.support_digest != digest:
            raise ValueError("Capability Replay support digest differs from canonical identity")
        object.__setattr__(self, "support_digest", digest)
        return self


class CapabilityReplayObservation(StrictModel):
    """One exact executed Replay contract verdict."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-replay-observation/v1alpha1"] = Field(
        default=CAPABILITY_REPLAY_OBSERVATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityReplayObservation"] = "CapabilityReplayObservation"
    observation_id: str = Field(default="", alias="observationId", max_length=103)
    observation_digest: str = Field(
        default="",
        alias="observationDigest",
        max_length=64,
    )
    capability: CodeBackedCapabilityRef
    contract_id: _Identifier = Field(alias="contractId")
    verdict: CapabilityReplayVerdict
    observed_at: datetime = Field(alias="observedAt")
    evidence_digest: _Sha256 = Field(alias="evidenceDigest")

    @field_validator("observed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Capability Replay observation timestamp")

    @model_validator(mode="after")
    def bind_observation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.replay-observation/v1",
            material,
        )
        observation_id = f"capability-replay-observation_{digest}"
        _bind_content_identity(
            current_id=self.observation_id,
            current_digest=self.observation_digest,
            expected_id=observation_id,
            expected_digest=digest,
            label="Capability Replay observation",
        )
        object.__setattr__(self, "observation_id", observation_id)
        object.__setattr__(self, "observation_digest", digest)
        return self


class CapabilityRatioMetric(StrictModel):
    """Exact count-backed ratio; empty denominators remain unavailable, never zero."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    numerator: int = Field(strict=True, ge=0)
    denominator: int = Field(strict=True, ge=0)
    value: _Ratio | None = None

    @model_validator(mode="after")
    def require_exact_ratio(self) -> Self:
        if self.numerator > self.denominator:
            raise ValueError("Capability metric numerator cannot exceed denominator")
        if self.denominator == 0:
            if self.numerator or self.value is not None:
                raise ValueError("empty Capability metric ratio cannot carry a value")
            return self
        expected = self.numerator / self.denominator
        if self.value is None or not math.isclose(
            self.value,
            expected,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise ValueError("Capability metric ratio differs from exact counts")
        return self


class CapabilityRegistryCoverageMetrics(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    expected_capabilities: int = Field(alias="expectedCapabilities", strict=True, ge=1)
    benchmark_required_capabilities: int = Field(
        alias="benchmarkRequiredCapabilities",
        strict=True,
        ge=0,
    )
    definition_coverage: CapabilityRatioMetric = Field(alias="definitionCoverage")
    authority_coverage: CapabilityRatioMetric = Field(alias="authorityCoverage")
    benchmark_mapping_coverage: CapabilityRatioMetric = Field(alias="benchmarkMappingCoverage")

    @model_validator(mode="after")
    def require_common_denominator(self) -> Self:
        if any(
            metric.denominator != self.expected_capabilities
            for metric in (
                self.definition_coverage,
                self.authority_coverage,
            )
        ):
            raise ValueError("Registry coverage metrics must use the scope denominator")
        if self.benchmark_mapping_coverage.denominator != self.benchmark_required_capabilities:
            raise ValueError("Benchmark coverage must use the benchmark-required denominator")
        return self


class CapabilityDurationSummary(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    sample_count: int = Field(alias="sampleCount", strict=True, ge=1)
    median_seconds: _Duration = Field(alias="medianSeconds")
    p95_seconds: _Duration = Field(alias="p95Seconds")
    minimum_seconds: _Duration = Field(alias="minimumSeconds")
    maximum_seconds: _Duration = Field(alias="maximumSeconds")

    @model_validator(mode="after")
    def require_ordered_summary(self) -> Self:
        if not (
            self.minimum_seconds <= self.median_seconds <= self.maximum_seconds
            and self.minimum_seconds <= self.p95_seconds <= self.maximum_seconds
        ):
            raise ValueError("Capability duration summary is not ordered")
        return self


class CapabilityLeadTimeMetrics(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    delivery_coverage: CapabilityRatioMetric = Field(alias="deliveryCoverage")
    release_lead_time_coverage: CapabilityRatioMetric = Field(alias="releaseLeadTimeCoverage")
    authored_to_code_backed: CapabilityDurationSummary | None = Field(
        default=None,
        alias="authoredToCodeBacked",
    )
    authored_to_release: CapabilityDurationSummary | None = Field(
        default=None,
        alias="authoredToRelease",
    )

    @model_validator(mode="after")
    def require_summary_presence(self) -> Self:
        if (self.delivery_coverage.numerator > 0) != (self.authored_to_code_backed is not None):
            raise ValueError("Delivery coverage and code-backed duration summary disagree")
        if (self.release_lead_time_coverage.numerator > 0) != (
            self.authored_to_release is not None
        ):
            raise ValueError("Release coverage and release duration summary disagree")
        return self


class CapabilityOracleMetrics(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    authority_coverage: CapabilityRatioMetric = Field(alias="authorityCoverage")
    observation_coverage: CapabilityRatioMetric = Field(alias="observationCoverage")
    observation_count: int = Field(alias="observationCount", strict=True, ge=0)
    succeeded_count: int = Field(alias="succeededCount", strict=True, ge=0)
    failed_count: int = Field(alias="failedCount", strict=True, ge=0)
    inconclusive_count: int = Field(alias="inconclusiveCount", strict=True, ge=0)
    determinate_rate: CapabilityRatioMetric = Field(alias="determinateRate")

    @model_validator(mode="after")
    def require_exact_counts(self) -> Self:
        if (
            self.succeeded_count + self.failed_count + self.inconclusive_count
            != self.observation_count
        ):
            raise ValueError("Capability Oracle decision counts are incomplete")
        if (
            self.determinate_rate.numerator != self.succeeded_count + self.failed_count
            or self.determinate_rate.denominator != self.observation_count
        ):
            raise ValueError("Capability Oracle determinate rate differs from decisions")
        return self


class CapabilityReplayMetrics(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    support_coverage: CapabilityRatioMetric = Field(alias="supportCoverage")
    observation_coverage: CapabilityRatioMetric = Field(alias="observationCoverage")
    observation_count: int = Field(alias="observationCount", strict=True, ge=0)
    supports_count: int = Field(alias="supportsCount", strict=True, ge=0)
    contradicts_count: int = Field(alias="contradictsCount", strict=True, ge=0)
    inconclusive_count: int = Field(alias="inconclusiveCount", strict=True, ge=0)
    failed_count: int = Field(alias="failedCount", strict=True, ge=0)
    support_rate: CapabilityRatioMetric = Field(alias="supportRate")

    @model_validator(mode="after")
    def require_exact_counts(self) -> Self:
        if (
            self.supports_count
            + self.contradicts_count
            + self.inconclusive_count
            + self.failed_count
            != self.observation_count
        ):
            raise ValueError("Capability Replay verdict counts are incomplete")
        if (
            self.support_rate.numerator != self.supports_count
            or self.support_rate.denominator != self.observation_count
        ):
            raise ValueError("Capability Replay support rate differs from verdicts")
        return self


class CapabilityLifecycleMetrics(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release_coverage: CapabilityRatioMetric = Field(alias="releaseCoverage")
    experimental_count: int = Field(alias="experimentalCount", strict=True, ge=0)
    canary_count: int = Field(alias="canaryCount", strict=True, ge=0)
    stable_count: int = Field(alias="stableCount", strict=True, ge=0)
    deprecated_count: int = Field(alias="deprecatedCount", strict=True, ge=0)
    retired_count: int = Field(alias="retiredCount", strict=True, ge=0)

    @model_validator(mode="after")
    def require_exact_counts(self) -> Self:
        observed = (
            self.experimental_count
            + self.canary_count
            + self.stable_count
            + self.deprecated_count
            + self.retired_count
        )
        if observed != self.release_coverage.numerator:
            raise ValueError("Capability lifecycle maturity counts differ from coverage")
        return self


class CapabilityMetricsInputBinding(StrictModel):
    """Sorted exact source identities included in one report digest."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    definition_digests: tuple[_Sha256, ...] = Field(alias="definitionDigests")
    authority_set_digests: tuple[_Sha256, ...] = Field(alias="authoritySetDigests")
    benchmark_mapping_digests: tuple[_Sha256, ...] = Field(alias="benchmarkMappingDigests")
    delivery_evidence_digests: tuple[_Sha256, ...] = Field(alias="deliveryEvidenceDigests")
    oracle_observation_digests: tuple[_Sha256, ...] = Field(alias="oracleObservationDigests")
    replay_support_digests: tuple[_Sha256, ...] = Field(alias="replaySupportDigests")
    replay_observation_digests: tuple[_Sha256, ...] = Field(alias="replayObservationDigests")
    lifecycle_release_digests: tuple[_Sha256, ...] = Field(alias="lifecycleReleaseDigests")

    @model_validator(mode="after")
    def require_canonical_digests(self) -> Self:
        for value in (
            self.definition_digests,
            self.authority_set_digests,
            self.benchmark_mapping_digests,
            self.delivery_evidence_digests,
            self.oracle_observation_digests,
            self.replay_support_digests,
            self.replay_observation_digests,
            self.lifecycle_release_digests,
        ):
            if value != tuple(sorted(set(value))):
                raise ValueError("Capability metric input digests must be unique and sorted")
        return self


class CapabilityMetricGap(StrictModel):
    """One exact missing dimension; no zero value is invented."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability: CodeBackedCapabilityRef
    dimension: CapabilityMetricDimension
    reason: _Identifier


class CapabilityRegistryMetricsReport(StrictModel):
    """Content-addressed CAP-006 report over one exact external denominator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-metrics-report/v1alpha1"] = Field(
        default=CAPABILITY_METRICS_REPORT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityRegistryMetricsReport"] = "CapabilityRegistryMetricsReport"
    report_id: str = Field(default="", alias="reportId", max_length=91)
    report_digest: str = Field(default="", alias="reportDigest", max_length=64)
    scope_id: _Identifier = Field(alias="scopeId")
    scope_version: _Identifier = Field(alias="scopeVersion")
    scope_digest: _Sha256 = Field(alias="scopeDigest")
    measured_at: datetime = Field(alias="measuredAt")
    status: CapabilityMetricsReportStatus
    inputs: CapabilityMetricsInputBinding
    registry: CapabilityRegistryCoverageMetrics
    lead_time: CapabilityLeadTimeMetrics = Field(alias="leadTime")
    oracle: CapabilityOracleMetrics
    replay: CapabilityReplayMetrics
    lifecycle: CapabilityLifecycleMetrics
    gaps: tuple[CapabilityMetricGap, ...]

    @field_validator("measured_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Capability metrics measurement timestamp")

    @model_validator(mode="after")
    def bind_report_identity(self) -> Self:
        gap_keys = [
            (*_capability_key(item.capability), item.dimension.value, item.reason)
            for item in self.gaps
        ]
        if gap_keys != sorted(set(gap_keys)):
            raise ValueError("Capability metric gaps must be unique and sorted")
        expected_status = (
            CapabilityMetricsReportStatus.COMPLETE
            if not self.gaps
            else CapabilityMetricsReportStatus.INCOMPLETE
        )
        if self.status is not expected_status:
            raise ValueError("Capability metrics status differs from its explicit gaps")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"report_id", "report_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.metrics-report/v1",
            material,
        )
        report_id = f"capability-metrics_{digest}"
        _bind_content_identity(
            current_id=self.report_id,
            current_digest=self.report_digest,
            expected_id=report_id,
            expected_digest=digest,
            label="Capability metrics report",
        )
        object.__setattr__(self, "report_id", report_id)
        object.__setattr__(self, "report_digest", digest)
        return self


_DefinitionKey = tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class _MetricSources:
    mappings: dict[_DefinitionKey, CapabilityBenchmarkMapping]
    deliveries: dict[_DefinitionKey, CapabilityDeliveryEvidence]
    oracle_samples: dict[
        _DefinitionKey,
        tuple[CapabilityOracleObservation, ...],
    ]
    supports: dict[_DefinitionKey, CapabilityReplaySupport]
    replay_samples: dict[
        _DefinitionKey,
        tuple[CapabilityReplayObservation, ...],
    ]
    lifecycle: CapabilityLifecycleRegistry | None


@dataclass(slots=True)
class _MetricState:
    gaps: list[CapabilityMetricGap] = dataclass_field(default_factory=list)
    definition_digests: list[str] = dataclass_field(default_factory=list)
    authority_digests: list[str] = dataclass_field(default_factory=list)
    mapping_digests: list[str] = dataclass_field(default_factory=list)
    delivery_digests: list[str] = dataclass_field(default_factory=list)
    oracle_digests: list[str] = dataclass_field(default_factory=list)
    support_digests: list[str] = dataclass_field(default_factory=list)
    replay_digests: list[str] = dataclass_field(default_factory=list)
    release_digests: list[str] = dataclass_field(default_factory=list)
    delivery_seconds: list[float] = dataclass_field(default_factory=list)
    release_seconds: list[float] = dataclass_field(default_factory=list)
    lifecycle_maturities: list[CapabilityMaturity] = dataclass_field(default_factory=list)
    oracle_authority_count: int = 0
    oracle_observed_capabilities: int = 0
    replay_supported_capabilities: int = 0
    replay_observed_capabilities: int = 0


def build_capability_registry_metrics(
    *,
    scope: CapabilityMetricScope,
    definitions: CapabilityDefinitionRegistry,
    authorities: CapabilityAuthorityRegistry,
    measured_at: datetime,
    benchmark_mappings: Iterable[CapabilityBenchmarkMapping] = (),
    delivery_evidence: Iterable[CapabilityDeliveryEvidence] = (),
    oracle_observations: Iterable[CapabilityOracleObservation] = (),
    replay_support: Iterable[CapabilityReplaySupport] = (),
    replay_observations: Iterable[CapabilityReplayObservation] = (),
    lifecycle: CapabilityLifecycleRegistry | None = None,
) -> CapabilityRegistryMetricsReport:
    """Measure only exact scope requirements and bind all contributing source digests."""

    canonical_scope = _canonical_metric_scope(scope)
    _require_metric_registries(definitions, authorities, lifecycle)
    sources = _metric_sources(
        benchmark_mappings=benchmark_mappings,
        delivery_evidence=delivery_evidence,
        oracle_observations=oracle_observations,
        replay_support=replay_support,
        replay_observations=replay_observations,
        lifecycle=lifecycle,
    )
    _reject_foreign_inputs(canonical_scope, sources)

    state = _MetricState()
    for requirement in canonical_scope.requirements:
        _measure_requirement(
            requirement,
            definitions=definitions,
            authorities=authorities,
            sources=sources,
            state=state,
        )
    return _build_metrics_report(
        scope=canonical_scope,
        measured_at=measured_at,
        sources=sources,
        state=state,
    )


def _canonical_metric_scope(scope: CapabilityMetricScope) -> CapabilityMetricScope:
    try:
        return CapabilityMetricScope.model_validate(scope.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValueError) as exc:
        raise ValueError("Capability metric scope is not canonical") from exc


def _require_metric_registries(
    definitions: CapabilityDefinitionRegistry,
    authorities: CapabilityAuthorityRegistry,
    lifecycle: CapabilityLifecycleRegistry | None,
) -> None:
    if not isinstance(definitions, CapabilityDefinitionRegistry):
        raise TypeError("Capability metrics require a CapabilityDefinitionRegistry")
    if not isinstance(authorities, CapabilityAuthorityRegistry):
        raise TypeError("Capability metrics require a CapabilityAuthorityRegistry")
    if lifecycle is not None and not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Capability metrics lifecycle must be a verified registry")


def _metric_sources(
    *,
    benchmark_mappings: Iterable[CapabilityBenchmarkMapping],
    delivery_evidence: Iterable[CapabilityDeliveryEvidence],
    oracle_observations: Iterable[CapabilityOracleObservation],
    replay_support: Iterable[CapabilityReplaySupport],
    replay_observations: Iterable[CapabilityReplayObservation],
    lifecycle: CapabilityLifecycleRegistry | None,
) -> _MetricSources:
    return _MetricSources(
        mappings=_unique_by_capability(
            benchmark_mappings,
            model_type=CapabilityBenchmarkMapping,
            label="benchmark mapping",
            reference=lambda item: item.capability,
        ),
        deliveries=_unique_by_capability(
            delivery_evidence,
            model_type=CapabilityDeliveryEvidence,
            label="delivery evidence",
            reference=lambda item: item.capability.capability,
        ),
        oracle_samples=_observations_by_capability(
            oracle_observations,
            model_type=CapabilityOracleObservation,
            label="Oracle observation",
            reference=lambda item: item.capability.capability,
            identity=lambda item: item.observation_digest,
        ),
        supports=_unique_by_capability(
            replay_support,
            model_type=CapabilityReplaySupport,
            label="Replay support",
            reference=lambda item: item.capability.capability,
        ),
        replay_samples=_observations_by_capability(
            replay_observations,
            model_type=CapabilityReplayObservation,
            label="Replay observation",
            reference=lambda item: item.capability.capability,
            identity=lambda item: item.observation_digest,
        ),
        lifecycle=lifecycle,
    )


def _measure_requirement(
    requirement: CapabilityMetricRequirement,
    *,
    definitions: CapabilityDefinitionRegistry,
    authorities: CapabilityAuthorityRegistry,
    sources: _MetricSources,
    state: _MetricState,
) -> None:
    key = _definition_key(requirement.capability.capability)
    manifest = _measure_registry(requirement, definitions, authorities, state)
    mapping = _measure_benchmark(requirement, sources.mappings.get(key), state)
    delivery = _measure_delivery(requirement, sources.deliveries.get(key), state)
    _measure_oracle(
        requirement,
        mapping=mapping,
        samples=sources.oracle_samples.get(key, ()),
        state=state,
    )
    _measure_replay(
        requirement,
        manifest=manifest,
        support=sources.supports.get(key),
        samples=sources.replay_samples.get(key, ()),
        state=state,
    )
    _measure_lifecycle(
        requirement,
        delivery=delivery,
        lifecycle=sources.lifecycle,
        state=state,
    )


def _measure_registry(
    requirement: CapabilityMetricRequirement,
    definitions: CapabilityDefinitionRegistry,
    authorities: CapabilityAuthorityRegistry,
    state: _MetricState,
) -> CodeBackedCapability | None:
    try:
        definition = definitions.resolve(requirement.capability.capability)
        state.definition_digests.append(definition.capability_digest)
    except CapabilityDefinitionError:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.DEFINITION,
            "definition-missing",
        )

    try:
        manifest = authorities.resolve(requirement.capability)
        state.authority_digests.append(manifest.authority_set_digest)
    except CapabilityAuthorityError:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.AUTHORITY,
            "authority-missing",
        )
        return None
    if _authority_binding(manifest, CapabilityAuthorityRole.SUCCESS_ORACLE) is None:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.AUTHORITY,
            "success-oracle-authority-missing",
        )
    else:
        state.oracle_authority_count += 1
    return manifest


def _measure_benchmark(
    requirement: CapabilityMetricRequirement,
    mapping: CapabilityBenchmarkMapping | None,
    state: _MetricState,
) -> CapabilityBenchmarkMapping | None:
    if not requirement.benchmark_required:
        if mapping is not None:
            raise ValueError("non-benchmark Capability cannot contribute benchmark metrics")
        return None
    if mapping is None:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.BENCHMARK,
            "benchmark-mapping-missing",
        )
        return None
    state.mapping_digests.append(mapping.mapping_digest)
    return mapping


def _measure_delivery(
    requirement: CapabilityMetricRequirement,
    delivery: CapabilityDeliveryEvidence | None,
    state: _MetricState,
) -> CapabilityDeliveryEvidence | None:
    if not requirement.delivery_evidence_required:
        if delivery is not None:
            raise ValueError(
                "Capability without delivery requirement cannot contribute delivery metrics"
            )
        return None
    if delivery is None:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.DELIVERY,
            "delivery-evidence-missing",
        )
        return None
    if delivery.capability != requirement.capability:
        raise ValueError("delivery evidence differs from the metric scope authority")
    state.delivery_digests.append(delivery.evidence_digest)
    state.delivery_seconds.append((delivery.code_backed_at - delivery.authored_at).total_seconds())
    return delivery


def _measure_oracle(
    requirement: CapabilityMetricRequirement,
    *,
    mapping: CapabilityBenchmarkMapping | None,
    samples: tuple[CapabilityOracleObservation, ...],
    state: _MetricState,
) -> None:
    if not requirement.oracle_observation_required:
        if samples:
            raise ValueError(
                "Capability without Oracle requirement cannot contribute Oracle metrics"
            )
        return
    if not samples:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.ORACLE_OBSERVATION,
            "oracle-observation-missing",
        )
        return
    if mapping is None:
        raise ValueError("Oracle observations require an exact benchmark mapping")
    for sample in samples:
        if sample.capability != requirement.capability:
            raise ValueError("Oracle observation differs from metric scope authority")
        if sample.benchmark_id not in mapping.benchmark_ids:
            raise ValueError("Oracle observation uses a benchmark outside the exact mapping")
    state.oracle_observed_capabilities += 1
    state.oracle_digests.extend(item.observation_digest for item in samples)


def _measure_replay(
    requirement: CapabilityMetricRequirement,
    *,
    manifest: CodeBackedCapability | None,
    support: CapabilityReplaySupport | None,
    samples: tuple[CapabilityReplayObservation, ...],
    state: _MetricState,
) -> None:
    if not requirement.replay_required:
        if support is not None or samples:
            raise ValueError("non-Replay Capability cannot contribute Replay metrics")
        return
    if support is None:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.REPLAY_SUPPORT,
            "replay-support-missing",
        )
    else:
        _measure_replay_support(requirement, manifest, support, state)
    if not samples:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.REPLAY_OBSERVATION,
            "replay-observation-missing",
        )
        return
    if support is None:
        raise ValueError("Replay observations require exact Replay support")
    for sample in samples:
        if sample.capability != requirement.capability:
            raise ValueError("Replay observation differs from metric scope authority")
        if sample.contract_id not in support.contract_ids:
            raise ValueError("Replay observation uses a contract outside exact Replay support")
    state.replay_observed_capabilities += 1
    state.replay_digests.extend(item.observation_digest for item in samples)


def _measure_replay_support(
    requirement: CapabilityMetricRequirement,
    manifest: CodeBackedCapability | None,
    support: CapabilityReplaySupport,
    state: _MetricState,
) -> None:
    if support.capability != requirement.capability:
        raise ValueError("Replay support differs from metric scope authority")
    if manifest is None:
        raise ValueError("Replay support cannot resolve its exact authority set")
    binding = _authority_binding(manifest, CapabilityAuthorityRole.REPLAY_STRATEGY)
    if binding is None or support.replay_authority_digest != binding.authority_digest:
        raise ValueError("Replay support differs from the registered Replay authority")
    state.replay_supported_capabilities += 1
    state.support_digests.append(support.support_digest)


def _measure_lifecycle(
    requirement: CapabilityMetricRequirement,
    *,
    delivery: CapabilityDeliveryEvidence | None,
    lifecycle: CapabilityLifecycleRegistry | None,
    state: _MetricState,
) -> None:
    if not requirement.lifecycle_required:
        if delivery is not None and delivery.release is not None:
            raise ValueError("Capability without lifecycle requirement cannot bind a release")
        return
    release = _lifecycle_release(lifecycle, requirement)
    if release is None:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.LIFECYCLE,
            "signed-release-missing",
        )
        return
    state.release_digests.append(release.release_digest)
    state.lifecycle_maturities.append(release.maturity)
    if delivery is None:
        return
    if delivery.release is None:
        _gap(
            state.gaps,
            requirement,
            CapabilityMetricDimension.DELIVERY,
            "release-lead-evidence-missing",
        )
        return
    if delivery.release != release.reference() or delivery.released_at != release.issued_at:
        raise ValueError("delivery evidence differs from the verified lifecycle release")
    assert delivery.released_at is not None
    state.release_seconds.append((delivery.released_at - delivery.authored_at).total_seconds())


def _build_metrics_report(
    *,
    scope: CapabilityMetricScope,
    measured_at: datetime,
    sources: _MetricSources,
    state: _MetricState,
) -> CapabilityRegistryMetricsReport:
    requirements = scope.requirements
    expected = len(requirements)
    benchmark_required = sum(item.benchmark_required for item in requirements)
    delivery_required = sum(item.delivery_evidence_required for item in requirements)
    release_lead_required = sum(
        item.delivery_evidence_required and item.lifecycle_required for item in requirements
    )
    oracle_required = sum(item.oracle_observation_required for item in requirements)
    replay_required = sum(item.replay_required for item in requirements)
    lifecycle_required = sum(item.lifecycle_required for item in requirements)
    oracle_items = _flatten_observations(sources.oracle_samples)
    replay_items = _flatten_observations(sources.replay_samples)
    report_gaps = tuple(
        sorted(
            state.gaps,
            key=lambda item: (
                *_capability_key(item.capability),
                item.dimension.value,
                item.reason,
            ),
        )
    )
    return CapabilityRegistryMetricsReport(
        scopeId=scope.scope_id,
        scopeVersion=scope.scope_version,
        scopeDigest=scope.scope_digest,
        measuredAt=measured_at,
        status=(
            CapabilityMetricsReportStatus.COMPLETE
            if not report_gaps
            else CapabilityMetricsReportStatus.INCOMPLETE
        ),
        inputs=_metric_input_binding(state),
        registry=CapabilityRegistryCoverageMetrics(
            expectedCapabilities=expected,
            benchmarkRequiredCapabilities=benchmark_required,
            definitionCoverage=_ratio(len(state.definition_digests), expected),
            authorityCoverage=_ratio(len(state.authority_digests), expected),
            benchmarkMappingCoverage=_ratio(
                len(state.mapping_digests),
                benchmark_required,
            ),
        ),
        leadTime=CapabilityLeadTimeMetrics(
            deliveryCoverage=_ratio(len(state.delivery_seconds), delivery_required),
            releaseLeadTimeCoverage=_ratio(
                len(state.release_seconds),
                release_lead_required,
            ),
            authoredToCodeBacked=_duration_summary(state.delivery_seconds),
            authoredToRelease=_duration_summary(state.release_seconds),
        ),
        oracle=_oracle_metrics(
            expected=expected,
            required=oracle_required,
            items=oracle_items,
            state=state,
        ),
        replay=_replay_metrics(
            required=replay_required,
            items=replay_items,
            state=state,
        ),
        lifecycle=_lifecycle_metrics(
            required=lifecycle_required,
            maturities=state.lifecycle_maturities,
        ),
        gaps=report_gaps,
    )


def _metric_input_binding(state: _MetricState) -> CapabilityMetricsInputBinding:
    return CapabilityMetricsInputBinding(
        definitionDigests=tuple(sorted(set(state.definition_digests))),
        authoritySetDigests=tuple(sorted(set(state.authority_digests))),
        benchmarkMappingDigests=tuple(sorted(set(state.mapping_digests))),
        deliveryEvidenceDigests=tuple(sorted(set(state.delivery_digests))),
        oracleObservationDigests=tuple(sorted(set(state.oracle_digests))),
        replaySupportDigests=tuple(sorted(set(state.support_digests))),
        replayObservationDigests=tuple(sorted(set(state.replay_digests))),
        lifecycleReleaseDigests=tuple(sorted(set(state.release_digests))),
    )


def _oracle_metrics(
    *,
    expected: int,
    required: int,
    items: tuple[CapabilityOracleObservation, ...],
    state: _MetricState,
) -> CapabilityOracleMetrics:
    succeeded = sum(item.decision is CapabilityOracleDecision.SUCCEEDED for item in items)
    failed = sum(item.decision is CapabilityOracleDecision.FAILED for item in items)
    inconclusive = sum(item.decision is CapabilityOracleDecision.INCONCLUSIVE for item in items)
    return CapabilityOracleMetrics(
        authorityCoverage=_ratio(state.oracle_authority_count, expected),
        observationCoverage=_ratio(
            state.oracle_observed_capabilities,
            required,
        ),
        observationCount=len(items),
        succeededCount=succeeded,
        failedCount=failed,
        inconclusiveCount=inconclusive,
        determinateRate=_ratio(succeeded + failed, len(items)),
    )


def _replay_metrics(
    *,
    required: int,
    items: tuple[CapabilityReplayObservation, ...],
    state: _MetricState,
) -> CapabilityReplayMetrics:
    supports = sum(item.verdict is CapabilityReplayVerdict.SUPPORTS for item in items)
    contradicts = sum(item.verdict is CapabilityReplayVerdict.CONTRADICTS for item in items)
    inconclusive = sum(item.verdict is CapabilityReplayVerdict.INCONCLUSIVE for item in items)
    failed = sum(item.verdict is CapabilityReplayVerdict.FAILED for item in items)
    return CapabilityReplayMetrics(
        supportCoverage=_ratio(state.replay_supported_capabilities, required),
        observationCoverage=_ratio(
            state.replay_observed_capabilities,
            required,
        ),
        observationCount=len(items),
        supportsCount=supports,
        contradictsCount=contradicts,
        inconclusiveCount=inconclusive,
        failedCount=failed,
        supportRate=_ratio(supports, len(items)),
    )


def _lifecycle_metrics(
    *,
    required: int,
    maturities: list[CapabilityMaturity],
) -> CapabilityLifecycleMetrics:
    return CapabilityLifecycleMetrics(
        releaseCoverage=_ratio(len(maturities), required),
        experimentalCount=maturities.count(CapabilityMaturity.EXPERIMENTAL),
        canaryCount=maturities.count(CapabilityMaturity.CANARY),
        stableCount=maturities.count(CapabilityMaturity.STABLE),
        deprecatedCount=maturities.count(CapabilityMaturity.DEPRECATED),
        retiredCount=maturities.count(CapabilityMaturity.RETIRED),
    )


def existing_mode_capability_metric_scope(
    bundle: ExistingModeCapabilityBundle,
) -> CapabilityMetricScope:
    """Build CAP-006's closed denominator from the exact CAP-005 authority bundle."""

    if not isinstance(bundle, ExistingModeCapabilityBundle):
        raise TypeError("existing Mode metric scope requires its exact Capability bundle")
    requirements = tuple(
        CapabilityMetricRequirement(
            capability=manifest.reference(),
            replayRequired=(manifest.capability.capability_id in _EXISTING_REPLAY_SCENARIOS),
        )
        for manifest in bundle.capabilities()
    )
    return CapabilityMetricScope(
        scopeId="pajin.existing-mode.capability-metrics",
        scopeVersion="1.0.0",
        requirements=requirements,
    )


def existing_mode_capability_replay_support(
    bundle: ExistingModeCapabilityBundle,
) -> tuple[CapabilityReplaySupport, ...]:
    """Bind the three CAP-005 Replay Strategies to existing exact KISA contracts."""

    supports = []
    for manifest in bundle.capabilities():
        scenario_id = _EXISTING_REPLAY_SCENARIOS.get(manifest.capability.capability_id)
        if scenario_id is None:
            continue
        binding = _authority_binding(
            manifest,
            CapabilityAuthorityRole.REPLAY_STRATEGY,
        )
        if binding is None:
            raise ValueError("existing Replay Capability lacks its Replay authority")
        contracts = (
            kisa_replay_contract(scenario_id).contract_id,
            kisa_replay_contract(
                scenario_id,
                claim_type=AtomicClaimType.IMPACT,
            ).contract_id,
            kisa_replay_contract(
                scenario_id,
                claim_type=AtomicClaimType.SEVERITY,
            ).contract_id,
            kisa_negative_retest_contract(scenario_id).contract_id,
        )
        supports.append(
            CapabilityReplaySupport(
                capability=manifest.reference(),
                replayAuthorityDigest=binding.authority_digest,
                contractIds=tuple(sorted(contracts)),
            )
        )
    return tuple(sorted(supports, key=lambda item: _capability_key(item.capability)))


def existing_mode_capability_metrics_baseline(
    bundle: ExistingModeCapabilityBundle,
    *,
    measured_at: datetime,
) -> CapabilityRegistryMetricsReport:
    """Report implemented CAP-005 structure and every still-unmeasured CAP-006 gap."""

    return build_capability_registry_metrics(
        scope=existing_mode_capability_metric_scope(bundle),
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        measured_at=measured_at,
        replay_support=existing_mode_capability_replay_support(bundle),
    )


def _ratio(numerator: int, denominator: int) -> CapabilityRatioMetric:
    return CapabilityRatioMetric(
        numerator=numerator,
        denominator=denominator,
        value=None if denominator == 0 else numerator / denominator,
    )


def _duration_summary(values: list[float]) -> CapabilityDurationSummary | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(0.95 * len(ordered)))
    return CapabilityDurationSummary(
        sampleCount=len(ordered),
        medianSeconds=float(median(ordered)),
        p95Seconds=ordered[rank - 1],
        minimumSeconds=ordered[0],
        maximumSeconds=ordered[-1],
    )


def _lifecycle_release(
    lifecycle: CapabilityLifecycleRegistry | None,
    requirement: CapabilityMetricRequirement,
) -> CapabilityReleaseStatement | None:
    if lifecycle is None:
        return None
    capability_id = requirement.capability.capability.capability_id
    try:
        head = lifecycle.head(capability_id)
        bundle = lifecycle.resolve_release(head)
    except CapabilityLifecycleError:
        return None
    release = bundle.release.statement
    if release.capability != requirement.capability:
        raise ValueError("Capability lifecycle head differs from the metric scope authority")
    return release


def _gap(
    gaps: list[CapabilityMetricGap],
    requirement: CapabilityMetricRequirement,
    dimension: CapabilityMetricDimension,
    reason: str,
) -> None:
    gaps.append(
        CapabilityMetricGap(
            capability=requirement.capability,
            dimension=dimension,
            reason=reason,
        )
    )


def _authority_binding(
    manifest: CodeBackedCapability,
    role: CapabilityAuthorityRole,
) -> CapabilityAuthorityBinding | None:
    return next((item for item in manifest.authorities if item.role is role), None)


def _unique_by_capability[ModelT: StrictModel](
    values: Iterable[ModelT],
    *,
    model_type: type[ModelT],
    label: str,
    reference: Callable[[ModelT], CapabilityDefinitionRef],
) -> dict[_DefinitionKey, ModelT]:
    records: dict[_DefinitionKey, ModelT] = {}
    for value in values:
        try:
            canonical = model_type.model_validate(value.model_dump(mode="json", by_alias=True))
        except (AttributeError, ValueError) as exc:
            raise ValueError(f"Capability {label} is not canonical") from exc
        key = _definition_key(reference(canonical))
        if key in records:
            raise ValueError(f"Capability {label} is duplicated")
        records[key] = canonical
    return records


def _observations_by_capability[ObservationT: StrictModel](
    values: Iterable[ObservationT],
    *,
    model_type: type[ObservationT],
    label: str,
    reference: Callable[[ObservationT], CapabilityDefinitionRef],
    identity: Callable[[ObservationT], str],
) -> dict[_DefinitionKey, tuple[ObservationT, ...]]:
    grouped: dict[_DefinitionKey, list[ObservationT]] = {}
    identities: set[str] = set()
    for value in values:
        try:
            canonical = model_type.model_validate(value.model_dump(mode="json", by_alias=True))
        except (AttributeError, ValueError) as exc:
            raise ValueError(f"Capability {label} is not canonical") from exc
        canonical_identity = identity(canonical)
        key = _definition_key(reference(canonical))
        if canonical_identity in identities:
            raise ValueError(f"Capability {label} is duplicated")
        identities.add(canonical_identity)
        grouped.setdefault(key, []).append(canonical)
    return {key: tuple(sorted(items, key=identity)) for key, items in grouped.items()}


def _reject_foreign_inputs(
    scope: CapabilityMetricScope,
    sources: _MetricSources,
) -> None:
    expected_keys = {_definition_key(item.capability.capability) for item in scope.requirements}
    groups: tuple[tuple[str, Mapping[_DefinitionKey, object]], ...] = (
        ("mappings", sources.mappings),
        ("deliveries", sources.deliveries),
        ("supports", sources.supports),
        ("oracle samples", sources.oracle_samples),
        ("replay samples", sources.replay_samples),
    )
    for label, group in groups:
        foreign = set(group) - expected_keys
        if foreign:
            raise ValueError(f"Capability metrics {label} contains out-of-scope evidence")


def _bind_content_identity(
    *,
    current_id: str,
    current_digest: str,
    expected_id: str,
    expected_digest: str,
    label: str,
) -> None:
    if current_digest and current_digest != expected_digest:
        raise ValueError(f"{label} digest differs from canonical identity")
    if current_id and current_id != expected_id:
        raise ValueError(f"{label} ID differs from canonical identity")


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _flatten_observations[ObservationT](
    observations: dict[_DefinitionKey, tuple[ObservationT, ...]],
) -> tuple[ObservationT, ...]:
    return tuple(item for key in sorted(observations) for item in observations[key])


def _definition_key(reference: CapabilityDefinitionRef) -> _DefinitionKey:
    return (
        reference.capability_id,
        reference.capability_version,
        reference.capability_digest,
    )


def _capability_key(reference: CodeBackedCapabilityRef) -> tuple[str, str, str, str]:
    return (
        reference.capability.capability_id,
        reference.capability.capability_version,
        reference.capability.capability_digest,
        reference.authority_set_digest,
    )
