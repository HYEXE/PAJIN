"""Structural-only BENCH-003A comparison for one Walking Shadow decision."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.benchmark.models import (
    BENCHMARK_METRIC_ORDER,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkMetric,
    BenchmarkMetricDelta,
    benchmark_digest,
    canonical_benchmark_json,
)
from pajin.discovery.walking_shadow import (
    WalkingShadowSupervisorAuthority,
    WalkingShadowSupervisorError,
    WalkingShadowSupervisorOutcome,
    load_walking_shadow_supervisor_authority,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

WALKING_SHADOW_BENCHMARK_COMPARISON_API_VERSION: Literal[
    "pajin.dev/walking-shadow-benchmark-comparison/v1alpha1"
] = "pajin.dev/walking-shadow-benchmark-comparison/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_AUTHORITY_BYTES = 16 * 1024 * 1024


class WalkingShadowBenchmarkComparisonError(RuntimeError):
    """Raised when BENCH-003A structural comparison cannot be proven."""


class WalkingDeterministicBaselineDecision(StrictModel):
    """Code-owned projection of the deterministic lifecycle's terminal choice."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    decision_id: str = Field(default="", alias="decisionId", max_length=110)
    decision_digest: str = Field(default="", alias="decisionDigest", max_length=64)
    source_retest_authority_id: str = Field(
        alias="sourceRetestAuthorityId", min_length=1, max_length=110
    )
    source_retest_authority_digest: _Sha256 = Field(alias="sourceRetestAuthorityDigest")
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    finding_id: str = Field(alias="findingId", min_length=1, max_length=200)
    retest_assessment_id: str = Field(
        alias="retestAssessmentId", min_length=1, max_length=110
    )
    task_selection: Literal["none-after-completed-retest"] = Field(alias="taskSelection")
    stop_action: Literal["stop-after-completed-retest"] = Field(
        default="stop-after-completed-retest",
        alias="stopAction",
    )
    execution_allowed: Literal[False] = Field(default=False, alias="executionAllowed")

    @model_validator(mode="after")
    def bind_decision(self) -> Self:
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"decision_id", "decision_digest"}
        )
        digest = benchmark_digest(
            "pajin.benchmark.walking-deterministic-decision/v1",
            material,
            max_bytes=64 * 1024,
        )
        decision_id = f"benchmark-baseline-decision:{digest}"
        if self.decision_digest and self.decision_digest != digest:
            raise ValueError("Walking deterministic baseline Decision Digest differs")
        if self.decision_id and self.decision_id != decision_id:
            raise ValueError("Walking deterministic baseline Decision ID differs")
        object.__setattr__(self, "decision_digest", digest)
        object.__setattr__(self, "decision_id", decision_id)
        return self


class WalkingShadowDecisionDelta(StrictModel):
    """Exact non-metric difference between baseline and Shadow decisions."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    delta_id: str = Field(default="", alias="deltaId", max_length=110)
    delta_digest: str = Field(default="", alias="deltaDigest", max_length=64)
    baseline_decision_id: str = Field(alias="baselineDecisionId", min_length=1, max_length=110)
    baseline_decision_digest: _Sha256 = Field(alias="baselineDecisionDigest")
    shadow_authority_id: str = Field(alias="shadowAuthorityId", min_length=1, max_length=110)
    shadow_authority_digest: _Sha256 = Field(alias="shadowAuthorityDigest")
    shadow_task_proposal_id: str = Field(
        alias="shadowTaskProposalId", min_length=1, max_length=110
    )
    shadow_task_proposal_digest: _Sha256 = Field(alias="shadowTaskProposalDigest")
    shadow_stop_decision_id: str = Field(
        alias="shadowStopDecisionId", min_length=1, max_length=110
    )
    shadow_stop_decision_digest: _Sha256 = Field(alias="shadowStopDecisionDigest")
    human_review_task_added: Literal[True] = Field(
        default=True,
        alias="humanReviewTaskAdded",
    )
    autonomous_execution_changed: Literal[False] = Field(
        default=False,
        alias="autonomousExecutionChanged",
    )
    capability_set_changed: Literal[False] = Field(
        default=False,
        alias="capabilitySetChanged",
    )
    source_baseline_mutated: Literal[False] = Field(
        default=False,
        alias="sourceBaselineMutated",
    )
    metric_impact_measured: Literal[False] = Field(
        default=False,
        alias="metricImpactMeasured",
    )

    @model_validator(mode="after")
    def bind_delta(self) -> Self:
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"delta_id", "delta_digest"}
        )
        digest = benchmark_digest(
            "pajin.benchmark.walking-shadow-decision-delta/v1",
            material,
            max_bytes=64 * 1024,
        )
        delta_id = f"benchmark-shadow-decision-delta:{digest}"
        if self.delta_digest and self.delta_digest != digest:
            raise ValueError("Walking Shadow Decision Delta Digest differs")
        if self.delta_id and self.delta_id != delta_id:
            raise ValueError("Walking Shadow Decision Delta ID differs")
        object.__setattr__(self, "delta_digest", digest)
        object.__setattr__(self, "delta_id", delta_id)
        return self


class WalkingShadowBenchmarkComparisonAuthority(StrictModel):
    """BENCH-003A structural comparison that contains no invented metric values."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/walking-shadow-benchmark-comparison/v1alpha1"
    ] = Field(
        default=WALKING_SHADOW_BENCHMARK_COMPARISON_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingShadowBenchmarkComparisonAuthority"] = (
        "WalkingShadowBenchmarkComparisonAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest: BenchmarkManifest
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    baseline_arm_id: str = Field(alias="baselineArmId", min_length=1, max_length=200)
    baseline_configuration_digest: _Sha256 = Field(alias="baselineConfigurationDigest")
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source: WalkingShadowSupervisorAuthority
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: Literal["walking-shadow-supervisor-authority.json"] = Field(
        default="walking-shadow-supervisor-authority.json",
        alias="sourceArtifactPath",
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    baseline_decision: WalkingDeterministicBaselineDecision = Field(alias="baselineDecision")
    decision_delta: WalkingShadowDecisionDelta = Field(alias="decisionDelta")
    required_metrics: tuple[BenchmarkMetric, ...] = Field(
        alias="requiredMetrics",
        min_length=len(BENCHMARK_METRIC_ORDER),
        max_length=len(BENCHMARK_METRIC_ORDER),
    )
    metric_deltas: tuple[BenchmarkMetricDelta, ...] = Field(
        default=(),
        alias="metricDeltas",
        max_length=0,
    )
    measurement_state: Literal["not-measured-no-benchmark-results"] = Field(
        default="not-measured-no-benchmark-results",
        alias="measurementState",
    )
    benchmark_comparison_eligible: Literal[False] = Field(
        default=False,
        alias="benchmarkComparisonEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )
    comparison_state: Literal["structural-decision-only"] = Field(
        default="structural-decision-only",
        alias="comparisonState",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        if len(self.manifest.arms) != 1:
            raise ValueError("BENCH-003A requires one deterministic baseline-only Manifest")
        baseline_arm = self.manifest.arms[0]
        expected_baseline = _baseline_decision(self.source)
        expected_delta = _decision_delta(expected_baseline, self.source)
        if (
            self.manifest_digest != self.manifest.digest()
            or baseline_arm.kind is not BenchmarkArmKind.DETERMINISTIC_BASELINE
            or baseline_arm.adaptive_supervisor is not False
            or self.baseline_arm_id != baseline_arm.arm_id
            or self.baseline_configuration_digest != baseline_arm.configuration_digest
            or self.campaign_digest != self.manifest.campaign_digest
            or self.campaign_digest != self.source.campaign_digest
            or self.source.shadow_mode is not True
            or self.source.baseline_mutated is not False
            or self.source.decision_state != "recorded-not-applied"
            or self.baseline_decision != expected_baseline
            or self.decision_delta != expected_delta
            or self.required_metrics != tuple(BENCHMARK_METRIC_ORDER)
            or self.metric_deltas
        ):
            raise ValueError("BENCH-003A structural comparison differs from its exact sources")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"authority_id", "authority_digest"}
        )
        digest = benchmark_digest(
            "pajin.benchmark.walking-shadow-comparison-authority/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"walking-shadow-benchmark:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking Shadow Benchmark Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking Shadow Benchmark Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_benchmark_json(
            self.model_dump(mode="json", by_alias=True),
            label="WalkingShadowBenchmarkComparisonAuthority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingShadowBenchmarkComparisonOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: WalkingShadowBenchmarkComparisonAuthority


class WalkingShadowBenchmarkComparisonRunner:
    """Seal structural decision comparison without creating BenchmarkResult values."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        manifest: BenchmarkManifest,
        source_outcome: WalkingShadowSupervisorOutcome,
    ) -> WalkingShadowBenchmarkComparisonOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        try:
            source = load_walking_shadow_supervisor_authority(
                authoritative_campaign,
                source_outcome,
            )
            source_snapshot = load_verified_run_artifacts(
                source_outcome.run_path,
                requests={source_outcome.artifact_path: _MAX_AUTHORITY_BYTES},
                expected_run_id=source_outcome.run_id,
            )
            source_artifact = source_snapshot.artifact_bytes(source_outcome.artifact_path)
            if source_outcome.artifact_path != "walking-shadow-supervisor-authority.json":
                raise ValueError("BENCH-003A source artifact path differs")
            if len(authoritative_manifest.arms) != 1:
                raise ValueError("BENCH-003A cannot claim an unmeasured candidate arm")
            baseline = _baseline_decision(source)
            delta = _decision_delta(baseline, source)
            authority = WalkingShadowBenchmarkComparisonAuthority(
                manifest=authoritative_manifest,
                manifestDigest=authoritative_manifest.digest(),
                baselineArmId=authoritative_manifest.arms[0].arm_id,
                baselineConfigurationDigest=(
                    authoritative_manifest.arms[0].configuration_digest
                ),
                campaignDigest=source.campaign_digest,
                source=source,
                sourceRunId=source_snapshot.verification.run_id,
                sourceRootDigest=source_snapshot.verification.root_digest,
                sourceArtifactPath="walking-shadow-supervisor-authority.json",
                sourceArtifactSha256=sha256(source_artifact).hexdigest(),
                baselineDecision=baseline,
                decisionDelta=delta,
                requiredMetrics=tuple(BENCHMARK_METRIC_ORDER),
            )
        except (
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            WalkingShadowSupervisorError,
        ) as exc:
            raise WalkingShadowBenchmarkComparisonError(
                "BENCH-003A Shadow Decision comparison could not be verified"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-shadow-benchmark-comparison",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            "benchmark-manifest.json",
            authoritative_manifest.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            "walking-shadow-benchmark-comparison-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.walking-shadow-comparison.created",
            {
                "artifact": artifact_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "manifestDigest": authority.manifest_digest,
                "baselineDecisionId": authority.baseline_decision.decision_id,
                "decisionDeltaId": authority.decision_delta.delta_id,
                "measurementState": authority.measurement_state,
                "comparisonState": authority.comparison_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-shadow-benchmark-comparison-sealed",
                "authorityId": authority.authority_id,
                "comparisonState": authority.comparison_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-shadow-benchmark-comparison", "artifact": artifact_path},
        )
        store.seal()
        return WalkingShadowBenchmarkComparisonOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_shadow_benchmark_comparison_authority(
    campaign: CampaignManifest,
    outcome: WalkingShadowBenchmarkComparisonOutcome,
) -> WalkingShadowBenchmarkComparisonAuthority:
    """Rebuild BENCH-003A from its sealed Manifest, authority, and event."""

    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_AUTHORITY_BYTES,
                "benchmark-manifest.json": _MAX_AUTHORITY_BYTES,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        manifest = BenchmarkManifest.model_validate_json(
            snapshot.artifact_bytes("benchmark-manifest.json")
        )
        authority = WalkingShadowBenchmarkComparisonAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise WalkingShadowBenchmarkComparisonError(
            "BENCH-003A Shadow Decision comparison is not sealed and valid"
        ) from exc
    if (
        sealed_campaign != campaign
        or authority != outcome.authority
        or manifest != authority.manifest
    ):
        raise WalkingShadowBenchmarkComparisonError(
            "BENCH-003A Shadow Decision comparison differs from sealed authority"
        )
    created = [
        event
        for event in snapshot.events
        if event.event_type == "benchmark.walking-shadow-comparison.created"
    ]
    expected = {
        "artifact": outcome.artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "manifestDigest": authority.manifest_digest,
        "baselineDecisionId": authority.baseline_decision.decision_id,
        "decisionDeltaId": authority.decision_delta.delta_id,
        "measurementState": authority.measurement_state,
        "comparisonState": authority.comparison_state,
    }
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingShadowBenchmarkComparisonError("BENCH-003A publication event differs")
    return authority.model_copy(deep=True)


def _baseline_decision(
    source: WalkingShadowSupervisorAuthority,
) -> WalkingDeterministicBaselineDecision:
    retest = source.source
    return WalkingDeterministicBaselineDecision(
        sourceRetestAuthorityId=retest.authority_id,
        sourceRetestAuthorityDigest=retest.authority_digest,
        candidateId=retest.assessment.candidate_id,
        findingId=retest.assessment.finding_id,
        retestAssessmentId=retest.assessment.assessment_id,
        taskSelection="none-after-completed-retest",
    )


def _decision_delta(
    baseline: WalkingDeterministicBaselineDecision,
    source: WalkingShadowSupervisorAuthority,
) -> WalkingShadowDecisionDelta:
    return WalkingShadowDecisionDelta(
        baselineDecisionId=baseline.decision_id,
        baselineDecisionDigest=baseline.decision_digest,
        shadowAuthorityId=source.authority_id,
        shadowAuthorityDigest=source.authority_digest,
        shadowTaskProposalId=source.selected_task.proposal_id,
        shadowTaskProposalDigest=source.selected_task.proposal_digest,
        shadowStopDecisionId=source.stop_decision.decision_id,
        shadowStopDecisionDigest=source.stop_decision.decision_digest,
    )
