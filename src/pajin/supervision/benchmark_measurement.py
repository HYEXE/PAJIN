"""SUP-005B2 source-bound measured Supervisor benchmark admission."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.measurement import (
    WalkingBenchmarkMeasuredComparisonAuthority,
    WalkingBenchmarkMeasuredComparisonOutcome,
    WalkingBenchmarkMeasuredComparisonRunner,
    WalkingBenchmarkMeasurementError,
    WalkingBenchmarkObservationBinding,
    WalkingBenchmarkRunObservationOutcome,
    load_walking_benchmark_measured_comparison_authority,
)
from pajin.benchmark.measurement_harness import (
    BenchmarkRegistryGovernedHarnessError,
    BenchmarkRegistryGovernedHarnessOutcome,
    load_registry_governed_benchmark_observation,
)
from pajin.benchmark.measurement_registry_distribution import (
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
)
from pajin.benchmark.models import BenchmarkArmKind, benchmark_digest
from pajin.benchmark.shadow_measurement import (
    WalkingShadowMeasuredBenchmarkError,
    WalkingShadowMeasuredBenchmarkOutcome,
)
from pajin.benchmark.target_factory import (
    BenchmarkTargetCoordinate,
    BenchmarkTargetFactoryError,
    BenchmarkTargetRunAuthority,
    load_benchmark_target_run_authority,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)
from pajin.supervision.benchmark_campaign import (
    SupervisorBenchmarkCampaignPlan,
    SupervisorBenchmarkCampaignPlanError,
    SupervisorBenchmarkCampaignPlanOutcome,
    SupervisorBenchmarkCandidateInvocation,
    SupervisorBenchmarkScheduleSource,
    load_supervisor_benchmark_campaign_plan,
    verify_supervisor_benchmark_candidate_invocation,
)
from pajin.supervision.invocation_journal import SupervisorInvocationJournal

SUPERVISOR_BENCHMARK_CANDIDATE_EXECUTION_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/supervisor-benchmark-candidate-execution-evidence/v1alpha1"
] = "pajin.dev/supervisor-benchmark-candidate-execution-evidence/v1alpha1"
SUPERVISOR_BENCHMARK_MEASURED_COMPARISON_API_VERSION: Literal[
    "pajin.dev/supervisor-benchmark-measured-comparison/v1alpha1"
] = "pajin.dev/supervisor-benchmark-measured-comparison/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_StableRequestId = Annotated[str, Field(pattern=r"^supervisor_[a-f0-9]{64}$")]
_AUTHORITY_ARTIFACT: Literal["supervision/supervisor-benchmark-measured-comparison.json"] = (
    "supervision/supervisor-benchmark-measured-comparison.json"
)
_PLAN_ARTIFACT: Literal["supervision/supervisor-benchmark-campaign-plan.json"] = (
    "supervision/supervisor-benchmark-campaign-plan.json"
)
_MEASURED_AUTHORITY_ARTIFACT: Literal["walking-benchmark-measured-comparison-authority.json"] = (
    "walking-benchmark-measured-comparison-authority.json"
)
_HARNESS_AUTHORITY_ARTIFACT: Literal["benchmark-registry-governed-harness-authority.json"] = (
    "benchmark-registry-governed-harness-authority.json"
)
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 64 * 1024 * 1024
_MAX_RUN_BYTES = 256 * 1024


class SupervisorBenchmarkMeasurementError(RuntimeError):
    """Raised when SUP-005B2 cannot prove exact externally measured lineage."""


class SupervisorBenchmarkCandidateInvocationBinding(StrictModel):
    """Digest-only B3 identity admitted into one candidate execution relation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    plan_id: str = Field(alias="planId", min_length=1, max_length=110)
    plan_digest: _Sha256 = Field(alias="planDigest")
    coordinate_id: str = Field(alias="coordinateId", min_length=1, max_length=110)
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    request_context_id: str = Field(alias="requestContextId", min_length=1, max_length=110)
    request_context_digest: _Sha256 = Field(alias="requestContextDigest")
    stable_request_id: _StableRequestId = Field(alias="stableRequestId")
    invocation_intent_id: str = Field(alias="invocationIntentId", min_length=1, max_length=110)
    invocation_intent_digest: _Sha256 = Field(alias="invocationIntentDigest")
    dispatch_event_digest: _Sha256 = Field(alias="dispatchEventDigest")
    dispatch_started_at: datetime = Field(alias="dispatchStartedAt")
    terminal_at: datetime = Field(alias="terminalAt")
    provider_run_id: _Identifier = Field(alias="providerRunId")
    provider_final_root_digest: _Sha256 = Field(alias="providerFinalRootDigest")
    receipt_sha256: _Sha256 = Field(alias="receiptSha256")
    receipt_id: str = Field(alias="receiptId", min_length=1, max_length=110)
    receipt_digest: _Sha256 = Field(alias="receiptDigest")
    provider_outcome_digest: _Sha256 = Field(alias="providerOutcomeDigest")
    proposal_id: str = Field(alias="proposalId", min_length=1, max_length=110)
    proposal_digest: _Sha256 = Field(alias="proposalDigest")
    model_call_count: Literal[1] = Field(default=1, alias="modelCallCount")

    @field_validator("dispatch_started_at", "terminal_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Supervisor benchmark invocation time requires a UTC offset")
        return value.astimezone(UTC)

    @field_validator("model_call_count", mode="before")
    @classmethod
    def require_one_model_call(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("Supervisor benchmark candidate requires exactly one model call")
        return value

    @model_validator(mode="after")
    def bind_invocation(self) -> Self:
        if self.terminal_at < self.dispatch_started_at:
            raise ValueError("Supervisor benchmark invocation terminates before dispatch")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.supervision.benchmark-candidate-invocation-binding/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        binding_id = f"supervisor-benchmark-invocation:{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Supervisor Benchmark Invocation Binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Supervisor Benchmark Invocation Binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


class SupervisorBenchmarkCandidateExecutionEvidence(StrictModel):
    """Typed preimage whose digest must be signed by the Target execution receipt."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-benchmark-candidate-execution-evidence/v1alpha1"] = (
        Field(
            default=SUPERVISOR_BENCHMARK_CANDIDATE_EXECUTION_EVIDENCE_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["SupervisorBenchmarkCandidateExecutionEvidence"] = (
        "SupervisorBenchmarkCandidateExecutionEvidence"
    )
    evidence_id: str = Field(default="", alias="evidenceId", max_length=110)
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    coordinate_id: str = Field(alias="coordinateId", min_length=1, max_length=110)
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    target_provider_evidence_digest: _Sha256 = Field(alias="targetProviderEvidenceDigest")
    invocation: SupervisorBenchmarkCandidateInvocationBinding
    relation_state: Literal["target-execution-receipt-attested-b3-relation"] = Field(
        default="target-execution-receipt-attested-b3-relation",
        alias="relationState",
    )
    proposal_content_used_as_measurement: Literal[False] = Field(
        default=False,
        alias="proposalContentUsedAsMeasurement",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator(
        "proposal_content_used_as_measurement",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Supervisor benchmark execution evidence authority must remain false")
        return value

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        if (
            self.coordinate_id != self.invocation.coordinate_id
            or self.coordinate_digest != self.invocation.coordinate_digest
        ):
            raise ValueError("Supervisor benchmark execution evidence changes coordinate")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_id", "evidence_digest"},
        )
        digest = benchmark_digest(
            "pajin.supervision.benchmark-candidate-execution-evidence/v1",
            material,
            max_bytes=4 * 1024 * 1024,
        )
        evidence_id = f"supervisor-benchmark-execution-evidence:{digest}"
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("Supervisor Benchmark Execution Evidence Digest differs")
        if self.evidence_id and self.evidence_id != evidence_id:
            raise ValueError("Supervisor Benchmark Execution Evidence ID differs")
        object.__setattr__(self, "evidence_digest", digest)
        object.__setattr__(self, "evidence_id", evidence_id)
        return self


class SupervisorBenchmarkCoordinateMeasurementBinding(StrictModel):
    """Digest-only registry, Target, Observation, and optional B3 provenance."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    coordinate: BenchmarkTargetCoordinate
    harness_run_id: _Identifier = Field(alias="harnessRunId")
    harness_root_digest: _Sha256 = Field(alias="harnessRootDigest")
    harness_authority_path: Literal["benchmark-registry-governed-harness-authority.json"] = Field(
        alias="harnessAuthorityPath"
    )
    harness_authority_sha256: _Sha256 = Field(alias="harnessAuthoritySha256")
    harness_authority_id: str = Field(alias="harnessAuthorityId", min_length=1, max_length=110)
    harness_authority_digest: _Sha256 = Field(alias="harnessAuthorityDigest")
    activation_digest: _Sha256 = Field(alias="activationDigest")
    registry_digest: _Sha256 = Field(alias="registryDigest")
    registry_revision: int = Field(alias="registryRevision", ge=1, le=2**31 - 1)
    admission_run_id: _Identifier = Field(alias="admissionRunId")
    admission_root_digest: _Sha256 = Field(alias="admissionRootDigest")
    admission_authority_digest: _Sha256 = Field(alias="admissionAuthorityDigest")
    target_run_id: _Identifier = Field(alias="targetRunId")
    target_root_digest: _Sha256 = Field(alias="targetRootDigest")
    target_authority_sha256: _Sha256 = Field(alias="targetAuthoritySha256")
    target_authority_digest: _Sha256 = Field(alias="targetAuthorityDigest")
    target_attestation_digest: _Sha256 = Field(alias="targetAttestationDigest")
    execution_receipt_digest: _Sha256 = Field(alias="executionReceiptDigest")
    execution_provider_evidence_digest: _Sha256 = Field(alias="executionProviderEvidenceDigest")
    observation_id: str = Field(alias="observationId", min_length=1, max_length=110)
    observation_digest: _Sha256 = Field(alias="observationDigest")
    candidate_execution_evidence: SupervisorBenchmarkCandidateExecutionEvidence | None = Field(
        default=None,
        alias="candidateExecutionEvidence",
    )
    cost_attribution_mode: Literal["external-coordinate-total-separate-from-b3-upper-bound"] = (
        Field(
            default="external-coordinate-total-separate-from-b3-upper-bound",
            alias="costAttributionMode",
        )
    )

    @field_validator("registry_revision", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Supervisor benchmark registry revision must be an integer")
        return value

    @model_validator(mode="after")
    def bind_coordinate_source(self) -> Self:
        candidate = self.coordinate.arm.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
        if candidate != (self.candidate_execution_evidence is not None):
            raise ValueError("Supervisor benchmark candidate evidence arm differs")
        if self.candidate_execution_evidence is not None and (
            self.candidate_execution_evidence.coordinate_id != self.coordinate.coordinate_id
            or self.candidate_execution_evidence.coordinate_digest
            != self.coordinate.coordinate_digest
            or self.execution_provider_evidence_digest
            != self.candidate_execution_evidence.evidence_digest
        ):
            raise ValueError("Supervisor benchmark execution receipt relation differs")
        return self


class SupervisorBenchmarkMeasuredComparisonAuthority(StrictModel):
    """Complete SUP-005B2 lineage without duplicating observations or numeric outputs."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-benchmark-measured-comparison/v1alpha1"] = Field(
        default=SUPERVISOR_BENCHMARK_MEASURED_COMPARISON_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorBenchmarkMeasuredComparisonAuthority"] = (
        "SupervisorBenchmarkMeasuredComparisonAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign_manifest_digest: _Sha256 = Field(alias="campaignManifestDigest")
    plan_id: str = Field(alias="planId", min_length=1, max_length=110)
    plan_digest: _Sha256 = Field(alias="planDigest")
    plan_run_id: _Identifier = Field(alias="planRunId")
    plan_root_digest: _Sha256 = Field(alias="planRootDigest")
    plan_artifact_path: Literal["supervision/supervisor-benchmark-campaign-plan.json"] = Field(
        alias="planArtifactPath"
    )
    plan_artifact_sha256: _Sha256 = Field(alias="planArtifactSha256")
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    coordinate_set_digest: _Sha256 = Field(alias="coordinateSetDigest")
    candidate_implementation_digest: _Sha256 = Field(alias="candidateImplementationDigest")
    measurements: tuple[SupervisorBenchmarkCoordinateMeasurementBinding, ...] = Field(
        min_length=2,
        max_length=4_000,
    )
    measured_run_id: _Identifier = Field(alias="measuredRunId")
    measured_root_digest: _Sha256 = Field(alias="measuredRootDigest")
    measured_authority_path: Literal["walking-benchmark-measured-comparison-authority.json"] = (
        Field(alias="measuredAuthorityPath")
    )
    measured_authority_sha256: _Sha256 = Field(alias="measuredAuthoritySha256")
    measured_authority_id: str = Field(
        alias="measuredAuthorityId",
        min_length=1,
        max_length=110,
    )
    measured_authority_digest: _Sha256 = Field(alias="measuredAuthorityDigest")
    baseline_result_digest: _Sha256 = Field(alias="baselineResultDigest")
    candidate_result_digest: _Sha256 = Field(alias="candidateResultDigest")
    comparison_id: str = Field(alias="comparisonId", min_length=1, max_length=200)
    comparison_digest: _Sha256 = Field(alias="comparisonDigest")
    candidate_coordinate_count: int = Field(alias="candidateCoordinateCount", ge=1)
    candidate_model_call_count: int = Field(alias="candidateModelCallCount", ge=1)
    measurement_state: Literal["complete-registry-governed-model-backed-shadow"] = Field(
        default="complete-registry-governed-model-backed-shadow",
        alias="measurementState",
    )
    benchmark_coordinate_bound_to_invocation: Literal[True] = Field(
        default=True,
        alias="benchmarkCoordinateBoundToInvocation",
    )
    externally_attested_observation_set: Literal[True] = Field(
        default=True,
        alias="externallyAttestedObservationSet",
    )
    benchmark_comparison_eligible: Literal[True] = Field(
        default=True,
        alias="benchmarkComparisonEligible",
    )
    proposal_causal_effect_attributed: Literal[False] = Field(
        default=False,
        alias="proposalCausalEffectAttributed",
    )
    threshold_evaluation_eligible: Literal[False] = Field(
        default=False,
        alias="thresholdEvaluationEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("candidate_coordinate_count", "candidate_model_call_count", mode="before")
    @classmethod
    def require_literal_count(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Supervisor benchmark measurement counts must be integers")
        return value

    @field_validator(
        "benchmark_coordinate_bound_to_invocation",
        "externally_attested_observation_set",
        "benchmark_comparison_eligible",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Supervisor benchmark completed measurement marker must be true")
        return value

    @field_validator(
        "proposal_causal_effect_attributed",
        "threshold_evaluation_eligible",
        "supervisor_activation_eligible",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Supervisor benchmark activation authority must remain false")
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        coordinates = [item.coordinate.coordinate_id for item in self.measurements]
        roots = [item.harness_root_digest for item in self.measurements]
        target_roots = [item.target_root_digest for item in self.measurements]
        observations = [item.observation_id for item in self.measurements]
        candidate_evidence = [
            item.candidate_execution_evidence
            for item in self.measurements
            if item.candidate_execution_evidence is not None
        ]
        invocations = [item.invocation for item in candidate_evidence]
        if (
            len(coordinates) != len(set(coordinates))
            or len(roots) != len(set(roots))
            or len(target_roots) != len(set(target_roots))
            or len(observations) != len(set(observations))
            or len(candidate_evidence) != self.candidate_coordinate_count
            or len(candidate_evidence) != self.candidate_model_call_count
            or len({item.stable_request_id for item in invocations}) != len(invocations)
            or len({item.invocation_intent_id for item in invocations}) != len(invocations)
            or len({item.provider_run_id for item in invocations}) != len(invocations)
            or len({item.receipt_id for item in invocations}) != len(invocations)
            or len({item.proposal_id for item in invocations}) != len(invocations)
            or len({item.activation_digest for item in self.measurements}) != 1
            or len({item.registry_digest for item in self.measurements}) != 1
            or len({item.registry_revision for item in self.measurements}) != 1
        ):
            raise ValueError("Supervisor benchmark measured source set is incomplete or reused")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.supervision.benchmark-measured-comparison-authority/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"supervisor-benchmark-measured:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Supervisor Benchmark Measured Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Supervisor Benchmark Measured Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class SupervisorBenchmarkMeasuredComparisonOutcome:
    authority: SupervisorBenchmarkMeasuredComparisonAuthority
    measured: WalkingBenchmarkMeasuredComparisonOutcome
    run_id: str
    run_path: Path
    artifact_path: Literal["supervision/supervisor-benchmark-measured-comparison.json"]
    artifact_sha256: str
    root_digest: str


@dataclass(frozen=True, slots=True)
class _LoadedMeasurementSource:
    coordinate: BenchmarkTargetCoordinate
    harness_outcome: BenchmarkRegistryGovernedHarnessOutcome
    harness_snapshot: VerifiedRunSnapshot
    target_authority: BenchmarkTargetRunAuthority
    observation_outcome: WalkingBenchmarkRunObservationOutcome
    candidate: SupervisorBenchmarkCandidateInvocation | None
    candidate_evidence: SupervisorBenchmarkCandidateExecutionEvidence | None


class SupervisorBenchmarkMeasuredComparisonRunner:
    """Admit a complete externally measured set and reuse BENCH-003B1 exactly once."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = Path(output_root)

    def run(
        self,
        campaign: CampaignManifest,
        plan_outcome: SupervisorBenchmarkCampaignPlanOutcome,
        baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
        schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
        harness_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
        candidate_invocations: tuple[SupervisorBenchmarkCandidateInvocation, ...],
        candidate_execution_evidence: tuple[SupervisorBenchmarkCandidateExecutionEvidence, ...],
        *,
        journal: SupervisorInvocationJournal,
        activation_store: BenchmarkMeasurementRegistryActivationStore,
        distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
    ) -> SupervisorBenchmarkMeasuredComparisonOutcome:
        try:
            authoritative_campaign = CampaignManifest.model_validate(
                campaign.model_dump(mode="json", by_alias=True)
            )
            plan = load_supervisor_benchmark_campaign_plan(
                authoritative_campaign,
                plan_outcome,
                baseline_source,
                schedule_sources,
            )
            sources = _load_measurement_sources(
                authoritative_campaign,
                plan,
                baseline_source,
                schedule_sources,
                harness_outcomes,
                candidate_invocations,
                candidate_execution_evidence,
                journal=journal,
                activation_store=activation_store,
                distribution_trust_anchor=distribution_trust_anchor,
            )
            measured = WalkingBenchmarkMeasuredComparisonRunner(output_root=self._output_root).run(
                plan.manifest,
                tuple(item.observation_outcome for item in sources),
            )
            measured_authority = load_walking_benchmark_measured_comparison_authority(
                plan.manifest,
                measured,
            )
            authority = _expected_authority(
                plan_outcome,
                plan,
                sources,
                measured,
                measured_authority,
            )
            outcome = _seal_authority(
                self._output_root, authoritative_campaign, measured, authority
            )
            load_supervisor_benchmark_measured_comparison_authority(
                authoritative_campaign,
                outcome,
                plan_outcome,
                baseline_source,
                schedule_sources,
                harness_outcomes,
                candidate_invocations,
                candidate_execution_evidence,
                journal=journal,
                activation_store=activation_store,
                distribution_trust_anchor=distribution_trust_anchor,
            )
            return outcome
        except SupervisorBenchmarkMeasurementError:
            raise
        except (
            AttributeError,
            BenchmarkRegistryGovernedHarnessError,
            BenchmarkTargetFactoryError,
            OSError,
            RunIntegrityError,
            SupervisorBenchmarkCampaignPlanError,
            TypeError,
            ValidationError,
            ValueError,
            WalkingBenchmarkMeasurementError,
            WalkingShadowMeasuredBenchmarkError,
        ) as exc:
            raise SupervisorBenchmarkMeasurementError(
                "SUP-005B2 measured comparison failed closed"
            ) from exc


def build_supervisor_benchmark_candidate_execution_evidence(
    candidate: SupervisorBenchmarkCandidateInvocation,
    *,
    target_provider_evidence_digest: str,
) -> SupervisorBenchmarkCandidateExecutionEvidence:
    """Build the typed relation digest an external Target execution must sign."""

    try:
        binding = _candidate_invocation_binding(candidate)
        return SupervisorBenchmarkCandidateExecutionEvidence(
            coordinateId=binding.coordinate_id,
            coordinateDigest=binding.coordinate_digest,
            targetProviderEvidenceDigest=target_provider_evidence_digest,
            invocation=binding,
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise SupervisorBenchmarkMeasurementError(
            "Supervisor benchmark candidate execution evidence is invalid"
        ) from exc


def load_supervisor_benchmark_measured_comparison_authority(
    campaign: CampaignManifest,
    outcome: SupervisorBenchmarkMeasuredComparisonOutcome,
    plan_outcome: SupervisorBenchmarkCampaignPlanOutcome,
    baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
    schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
    harness_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
    candidate_invocations: tuple[SupervisorBenchmarkCandidateInvocation, ...],
    candidate_execution_evidence: tuple[SupervisorBenchmarkCandidateExecutionEvidence, ...],
    *,
    journal: SupervisorInvocationJournal,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> SupervisorBenchmarkMeasuredComparisonAuthority:
    """Reload SUP-005B2 only after every live Plan, B3, Harness, and B1 source verifies."""

    try:
        if outcome.artifact_path != _AUTHORITY_ARTIFACT:
            raise ValueError("Supervisor benchmark measured artifact path differs")
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        plan = load_supervisor_benchmark_campaign_plan(
            authoritative_campaign,
            plan_outcome,
            baseline_source,
            schedule_sources,
        )
        sources = _load_measurement_sources(
            authoritative_campaign,
            plan,
            baseline_source,
            schedule_sources,
            harness_outcomes,
            candidate_invocations,
            candidate_execution_evidence,
            journal=journal,
            activation_store=activation_store,
            distribution_trust_anchor=distribution_trust_anchor,
        )
        measured_authority = load_walking_benchmark_measured_comparison_authority(
            plan.manifest,
            outcome.measured,
        )
        expected = _expected_authority(
            plan_outcome,
            plan,
            sources,
            outcome.measured,
            measured_authority,
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": 256 * 1024,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
                "run.json": _MAX_RUN_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        artifact_bytes = snapshot.artifact_bytes(outcome.artifact_path)
        authority = SupervisorBenchmarkMeasuredComparisonAuthority.model_validate(
            parse_strict_json_bytes(
                artifact_bytes,
                label="SUP-005B2 measured comparison authority",
                max_bytes=_MAX_AUTHORITY_BYTES,
            )
        )
        run_record = parse_strict_json_bytes(
            snapshot.artifact_bytes("run.json"),
            label="SUP-005B2 Run record",
            max_bytes=_MAX_RUN_BYTES,
        )
        final_paths = {artifact.path for artifact in snapshot.seals[-1].artifacts}
        if (
            sealed_campaign != authoritative_campaign
            or authority != outcome.authority
            or authority != expected
            or snapshot.verification.root_digest != outcome.root_digest
            or sha256(artifact_bytes).hexdigest() != outcome.artifact_sha256
            or snapshot.verification.seal_count != 1
            or snapshot.verification.artifact_count != 3
            or final_paths != {"campaign.json", outcome.artifact_path, "run.json"}
            or tuple(event.event_type for event in snapshot.events)
            != (
                "campaign.started",
                "benchmark.supervisor-measured-comparison.created",
                "campaign.completed",
            )
            or snapshot.events[0].payload
            != {
                "campaign": authoritative_campaign.metadata.name,
                "purpose": "supervisor-benchmark-measured-comparison",
            }
            or snapshot.events[1].payload
            != _authority_event_payload(outcome.artifact_path, authority)
            or snapshot.events[2].payload
            != {
                "purpose": "supervisor-benchmark-measured-comparison",
                "artifact": outcome.artifact_path,
            }
            or run_record
            != {
                "runId": outcome.run_id,
                "status": "completed",
                "stage": "supervisor-benchmark-measured-comparison-sealed",
                "authorityId": authority.authority_id,
                "comparisonId": authority.comparison_id,
            }
        ):
            raise ValueError("Supervisor benchmark measured authority differs from sources")
        return authority.model_copy(deep=True)
    except SupervisorBenchmarkMeasurementError:
        raise
    except (
        AttributeError,
        BenchmarkRegistryGovernedHarnessError,
        BenchmarkTargetFactoryError,
        OSError,
        RunIntegrityError,
        SupervisorBenchmarkCampaignPlanError,
        TypeError,
        ValidationError,
        ValueError,
        WalkingBenchmarkMeasurementError,
        WalkingShadowMeasuredBenchmarkError,
    ) as exc:
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 measured comparison is not exact and sealed"
        ) from exc


def _load_measurement_sources(
    campaign: CampaignManifest,
    plan: SupervisorBenchmarkCampaignPlan,
    baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
    schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
    harness_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
    candidate_invocations: tuple[SupervisorBenchmarkCandidateInvocation, ...],
    candidate_execution_evidence: tuple[SupervisorBenchmarkCandidateExecutionEvidence, ...],
    *,
    journal: SupervisorInvocationJournal,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> tuple[_LoadedMeasurementSource, ...]:
    if len(harness_outcomes) != len(plan.coordinates):
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 requires one registry-governed Harness per Plan coordinate"
        )
    candidate_coordinates = tuple(
        item for item in plan.coordinates if item.arm.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
    )
    if len(candidate_invocations) != len(candidate_coordinates) or len(
        candidate_execution_evidence
    ) != len(candidate_coordinates):
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 requires one B3 invocation relation per candidate coordinate"
        )

    verified_candidates: dict[str, SupervisorBenchmarkCandidateInvocation] = {}
    for candidate in candidate_invocations:
        verified = verify_supervisor_benchmark_candidate_invocation(
            campaign,
            candidate,
            baseline_source,
            schedule_sources,
            journal=journal,
        )
        coordinate_id = verified.coordinate.coordinate_id
        if coordinate_id in verified_candidates:
            raise SupervisorBenchmarkMeasurementError(
                "SUP-005B2 candidate invocation coordinate is duplicated"
            )
        verified_candidates[coordinate_id] = verified

    evidence_by_coordinate: dict[str, SupervisorBenchmarkCandidateExecutionEvidence] = {}
    for raw_evidence in candidate_execution_evidence:
        evidence = SupervisorBenchmarkCandidateExecutionEvidence.model_validate(
            raw_evidence.model_dump(mode="json", by_alias=True)
        )
        if evidence.coordinate_id in evidence_by_coordinate:
            raise SupervisorBenchmarkMeasurementError(
                "SUP-005B2 candidate execution evidence coordinate is duplicated"
            )
        evidence_by_coordinate[evidence.coordinate_id] = evidence

    loaded_by_coordinate: dict[str, _LoadedMeasurementSource] = {}
    for harness in harness_outcomes:
        observation = load_registry_governed_benchmark_observation(
            plan.manifest,
            harness,
            activation_store=activation_store,
            distribution_trust_anchor=distribution_trust_anchor,
        )
        target = load_benchmark_target_run_authority(plan.manifest, harness.target)
        coordinate = target.coordinate
        if coordinate.coordinate_id in loaded_by_coordinate:
            raise SupervisorBenchmarkMeasurementError("SUP-005B2 Harness coordinate is duplicated")
        harness_snapshot = load_verified_run_artifacts(
            harness.run_path,
            requests={harness.authority_path: _MAX_SOURCE_BYTES},
            expected_run_id=harness.run_id,
        )
        candidate_for_coordinate = verified_candidates.get(coordinate.coordinate_id)
        evidence_for_coordinate = evidence_by_coordinate.get(coordinate.coordinate_id)
        _require_coordinate_measurement(
            plan,
            coordinate,
            target,
            observation,
            candidate_for_coordinate,
            evidence_for_coordinate,
        )
        loaded_by_coordinate[coordinate.coordinate_id] = _LoadedMeasurementSource(
            coordinate=coordinate.model_copy(deep=True),
            harness_outcome=harness,
            harness_snapshot=harness_snapshot,
            target_authority=target,
            observation_outcome=observation,
            candidate=candidate_for_coordinate,
            candidate_evidence=evidence_for_coordinate,
        )

    expected_ids = tuple(item.coordinate_id for item in plan.coordinates)
    if (
        set(loaded_by_coordinate) != set(expected_ids)
        or set(verified_candidates) != {item.coordinate_id for item in candidate_coordinates}
        or set(evidence_by_coordinate) != set(verified_candidates)
    ):
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 measured source set differs from complete Plan coordinates"
        )
    ordered = tuple(loaded_by_coordinate[item] for item in expected_ids)
    _require_complete_source_uniqueness(ordered)
    return ordered


def _require_coordinate_measurement(
    plan: SupervisorBenchmarkCampaignPlan,
    coordinate: BenchmarkTargetCoordinate,
    target: BenchmarkTargetRunAuthority,
    observation: WalkingBenchmarkRunObservationOutcome,
    candidate: SupervisorBenchmarkCandidateInvocation | None,
    evidence: SupervisorBenchmarkCandidateExecutionEvidence | None,
) -> None:
    if observation.observation != target.observation:
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 Harness Observation differs from Target authority"
        )
    candidate_arm = coordinate.arm.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
    if not candidate_arm:
        if (
            candidate is not None
            or evidence is not None
            or target.observation.model_call_count != 0
        ):
            raise SupervisorBenchmarkMeasurementError(
                "SUP-005B2 baseline must have no B3 invocation or model call"
            )
        return
    if candidate is None or evidence is None:
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 candidate is missing its B3 execution relation"
        )
    expected_evidence = build_supervisor_benchmark_candidate_execution_evidence(
        candidate,
        target_provider_evidence_digest=evidence.target_provider_evidence_digest,
    )
    entry = candidate.completion.publication.journal_entry
    receipt = candidate.completion.publication.receipt
    schedule = next(
        item for item in plan.candidate_schedules if item.coordinate == coordinate
    ).schedule
    usage_bound = schedule.request_binding.usage_bound
    execution = target.execution_receipt
    if (
        candidate.coordinate != coordinate
        or evidence != expected_evidence
        or execution.provider_evidence_digest != evidence.evidence_digest
        or entry.dispatch_started_at is None
        or entry.terminal_at is None
        or execution.started_at > entry.dispatch_started_at
        or entry.terminal_at > execution.completed_at
        or target.observation.model_call_count != 1
        or receipt.provider_outcome.charged_usage.model_calls != 1
        or usage_bound.cost_usd > plan.manifest.protocol.max_cost_usd
        or usage_bound.timeout_seconds > plan.manifest.protocol.timeout_seconds
    ):
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 candidate execution is not exact, in-window, and one-call"
        )


def _require_complete_source_uniqueness(
    sources: tuple[_LoadedMeasurementSource, ...],
) -> None:
    harness_runs = [item.harness_outcome.run_id for item in sources]
    harness_roots = [item.harness_snapshot.verification.root_digest for item in sources]
    target_runs = [item.harness_outcome.target.run_id for item in sources]
    target_roots = [item.harness_outcome.authority.target_root_digest for item in sources]
    admission_runs = [item.harness_outcome.admission.run_id for item in sources]
    observations = [item.target_authority.observation.observation_id for item in sources]
    execution_receipts = [item.target_authority.execution_receipt.receipt_id for item in sources]
    candidate_bindings = [
        _candidate_invocation_binding(item.candidate)
        for item in sources
        if item.candidate is not None
    ]
    values = (
        harness_runs,
        harness_roots,
        target_runs,
        target_roots,
        admission_runs,
        observations,
        execution_receipts,
    )
    if any(len(items) != len(set(items)) for items in values) or any(
        len(items) != len(set(items))
        for items in (
            [item.stable_request_id for item in candidate_bindings],
            [item.invocation_intent_id for item in candidate_bindings],
            [item.provider_run_id for item in candidate_bindings],
            [item.receipt_id for item in candidate_bindings],
            [item.proposal_id for item in candidate_bindings],
        )
    ):
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 measured sources reuse a sealed publication or B3 invocation"
        )
    activations = {item.harness_outcome.authority.activation for item in sources}
    registries = {
        item.harness_outcome.authority.registry_admission_authority.registry for item in sources
    }
    if len(activations) != 1 or len(registries) != 1:
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 coordinates use different registry activation authority"
        )


def _candidate_invocation_binding(
    candidate: SupervisorBenchmarkCandidateInvocation,
) -> SupervisorBenchmarkCandidateInvocationBinding:
    if type(candidate) is not SupervisorBenchmarkCandidateInvocation:
        raise TypeError("Supervisor benchmark candidate invocation type differs")
    publication = candidate.completion.publication
    entry = publication.journal_entry
    receipt = publication.receipt
    proposal = candidate.completion.proposal
    if (
        entry.dispatch_started_at is None
        or entry.terminal_at is None
        or entry.dispatch_event_digest is None
        or entry.final_root_digest is None
        or entry.receipt_sha256 is None
        or entry.final_root_digest != publication.final_root_digest
        or entry.receipt_sha256 != publication.receipt_sha256
        or receipt.provider_outcome.charged_usage.model_calls != 1
    ):
        raise ValueError("Supervisor benchmark candidate B3 publication is not terminal")
    return SupervisorBenchmarkCandidateInvocationBinding(
        planId=candidate.plan.plan_id,
        planDigest=candidate.plan.plan_digest,
        coordinateId=candidate.coordinate.coordinate_id,
        coordinateDigest=candidate.coordinate.coordinate_digest,
        requestContextId=candidate.request_context.context_id,
        requestContextDigest=candidate.request_context.context_digest,
        stableRequestId=candidate.stable_request_id,
        invocationIntentId=entry.intent.intent_id,
        invocationIntentDigest=entry.intent.intent_digest,
        dispatchEventDigest=entry.dispatch_event_digest,
        dispatchStartedAt=entry.dispatch_started_at,
        terminalAt=entry.terminal_at,
        providerRunId=receipt.provider_run_id,
        providerFinalRootDigest=publication.final_root_digest,
        receiptSha256=publication.receipt_sha256,
        receiptId=receipt.receipt_id,
        receiptDigest=receipt.receipt_digest,
        providerOutcomeDigest=receipt.provider_outcome_digest,
        proposalId=proposal.proposal_id,
        proposalDigest=proposal.proposal_digest,
        modelCallCount=1,
    )


def _expected_authority(
    plan_outcome: SupervisorBenchmarkCampaignPlanOutcome,
    plan: SupervisorBenchmarkCampaignPlan,
    sources: tuple[_LoadedMeasurementSource, ...],
    measured: WalkingBenchmarkMeasuredComparisonOutcome,
    measured_authority: WalkingBenchmarkMeasuredComparisonAuthority,
) -> SupervisorBenchmarkMeasuredComparisonAuthority:
    _require_measured_observations_match_sources(sources, measured_authority)
    plan_snapshot = load_verified_run_artifacts(
        plan_outcome.run_path,
        requests={plan_outcome.artifact_path: _MAX_SOURCE_BYTES},
        expected_run_id=plan_outcome.run_id,
    )
    measured_snapshot = load_verified_run_artifacts(
        measured.run_path,
        requests={measured.authority_path: _MAX_SOURCE_BYTES},
        expected_run_id=measured.run_id,
    )
    measurements = tuple(_coordinate_binding(item) for item in sources)
    candidate_count = sum(
        item.coordinate.arm.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE for item in sources
    )
    return SupervisorBenchmarkMeasuredComparisonAuthority(
        campaignManifestDigest=plan.campaign_manifest_digest,
        planId=plan.plan_id,
        planDigest=plan.plan_digest,
        planRunId=plan_outcome.run_id,
        planRootDigest=plan_snapshot.verification.root_digest,
        planArtifactPath=_PLAN_ARTIFACT,
        planArtifactSha256=sha256(
            plan_snapshot.artifact_bytes(plan_outcome.artifact_path)
        ).hexdigest(),
        manifestDigest=plan.manifest_digest,
        coordinateSetDigest=plan.coordinate_set_digest,
        candidateImplementationDigest=plan.candidate_implementation.implementation_digest,
        measurements=measurements,
        measuredRunId=measured.run_id,
        measuredRootDigest=measured_snapshot.verification.root_digest,
        measuredAuthorityPath=_MEASURED_AUTHORITY_ARTIFACT,
        measuredAuthoritySha256=sha256(
            measured_snapshot.artifact_bytes(measured.authority_path)
        ).hexdigest(),
        measuredAuthorityId=measured_authority.authority_id,
        measuredAuthorityDigest=measured_authority.authority_digest,
        baselineResultDigest=measured_authority.baseline_result_digest,
        candidateResultDigest=measured_authority.candidate_result_digest,
        comparisonId=measured_authority.comparison.comparison_id,
        comparisonDigest=measured_authority.comparison_digest,
        candidateCoordinateCount=candidate_count,
        candidateModelCallCount=candidate_count,
    )


def _require_measured_observations_match_sources(
    sources: tuple[_LoadedMeasurementSource, ...],
    measured_authority: WalkingBenchmarkMeasuredComparisonAuthority,
) -> None:
    expected: list[WalkingBenchmarkObservationBinding] = []
    for source in sources:
        target = source.harness_outcome.target
        snapshot = load_verified_run_artifacts(
            target.run_path,
            requests={target.observation_path: _MAX_SOURCE_BYTES},
            expected_run_id=target.run_id,
        )
        observation_bytes = snapshot.artifact_bytes(target.observation_path)
        expected.append(
            WalkingBenchmarkObservationBinding(
                sourceRunId=target.run_id,
                sourceRootDigest=snapshot.verification.root_digest,
                sourceArtifactPath="walking-benchmark-run-observation.json",
                sourceArtifactSha256=sha256(observation_bytes).hexdigest(),
                observation=source.target_authority.observation,
            )
        )
    if measured_authority.observations != tuple(expected):
        raise SupervisorBenchmarkMeasurementError(
            "SUP-005B2 numeric Comparison differs from registry-governed Observations"
        )


def _coordinate_binding(
    source: _LoadedMeasurementSource,
) -> SupervisorBenchmarkCoordinateMeasurementBinding:
    harness = source.harness_outcome
    authority_bytes = source.harness_snapshot.artifact_bytes(harness.authority_path)
    authority = harness.authority
    admission = authority.registry_admission_authority
    target = source.target_authority
    return SupervisorBenchmarkCoordinateMeasurementBinding(
        coordinate=source.coordinate,
        harnessRunId=harness.run_id,
        harnessRootDigest=source.harness_snapshot.verification.root_digest,
        harnessAuthorityPath=_HARNESS_AUTHORITY_ARTIFACT,
        harnessAuthoritySha256=sha256(authority_bytes).hexdigest(),
        harnessAuthorityId=authority.authority_id,
        harnessAuthorityDigest=authority.authority_digest,
        activationDigest=authority.activation.activation_digest,
        registryDigest=admission.registry_digest,
        registryRevision=admission.registry.registry_revision,
        admissionRunId=authority.admission_run_id,
        admissionRootDigest=authority.admission_root_digest,
        admissionAuthorityDigest=admission.authority_digest,
        targetRunId=authority.target_run_id,
        targetRootDigest=authority.target_root_digest,
        targetAuthoritySha256=authority.target_authority_sha256,
        targetAuthorityDigest=authority.target_authority_digest,
        targetAttestationDigest=authority.target_attestation_digest,
        executionReceiptDigest=target.execution_receipt.receipt_digest,
        executionProviderEvidenceDigest=target.execution_receipt.provider_evidence_digest,
        observationId=target.observation.observation_id,
        observationDigest=target.observation.observation_digest,
        candidateExecutionEvidence=source.candidate_evidence,
    )


def _seal_authority(
    output_root: Path,
    campaign: CampaignManifest,
    measured: WalkingBenchmarkMeasuredComparisonOutcome,
    authority: SupervisorBenchmarkMeasuredComparisonAuthority,
) -> SupervisorBenchmarkMeasuredComparisonOutcome:
    store = RunStore.create(output_root, campaign.metadata.name)
    store.append_event(
        "campaign.started",
        {
            "campaign": campaign.metadata.name,
            "purpose": "supervisor-benchmark-measured-comparison",
        },
    )
    store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
    artifact_path = store.write_json(
        _AUTHORITY_ARTIFACT,
        authority.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "benchmark.supervisor-measured-comparison.created",
        _authority_event_payload(artifact_path, authority),
    )
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "completed",
            "stage": "supervisor-benchmark-measured-comparison-sealed",
            "authorityId": authority.authority_id,
            "comparisonId": authority.comparison_id,
        },
    )
    store.append_event(
        "campaign.completed",
        {"purpose": "supervisor-benchmark-measured-comparison", "artifact": artifact_path},
    )
    seal = store.seal()
    artifact = next(item for item in seal.artifacts if item.path == artifact_path)
    return SupervisorBenchmarkMeasuredComparisonOutcome(
        authority=authority.model_copy(deep=True),
        measured=measured,
        run_id=store.run_id,
        run_path=store.path.resolve(),
        artifact_path=_AUTHORITY_ARTIFACT,
        artifact_sha256=artifact.sha256,
        root_digest=seal.root_digest,
    )


def _authority_event_payload(
    artifact_path: str,
    authority: SupervisorBenchmarkMeasuredComparisonAuthority,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "planId": authority.plan_id,
        "planDigest": authority.plan_digest,
        "coordinateSetDigest": authority.coordinate_set_digest,
        "measuredAuthorityDigest": authority.measured_authority_digest,
        "comparisonDigest": authority.comparison_digest,
        "benchmarkComparisonEligible": True,
        "supervisorActivationEligible": False,
    }
