"""SUP-005B1 planning and typed pre-dispatch binding for benchmark coordinates."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkRunProtocol,
)
from pajin.benchmark.shadow_measurement import (
    WalkingShadowMeasuredBenchmarkError,
    WalkingShadowMeasuredBenchmarkOutcome,
    load_walking_shadow_measured_benchmark_authority,
)
from pajin.benchmark.target_factory import (
    BenchmarkTargetCoordinate,
    benchmark_target_coordinate,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.walking import walking_campaign_digest
from pajin.domain.models import CampaignManifest, StrictModel, campaign_manifest_digest
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.supervision.checkpoint_scheduler import (
    SupervisorCheckpointSchedule,
    SupervisorCheckpointScheduleError,
    SupervisorCheckpointSchedulePublication,
    verify_supervisor_checkpoint_schedule_publication,
)
from pajin.supervision.invocation import SupervisorDedicatedBudgetPolicy
from pajin.supervision.invocation_journal import (
    SupervisorBenchmarkRequestContext,
    SupervisorInvocationJournal,
    SupervisorInvocationJournalState,
    supervisor_stable_request_id,
)
from pajin.supervision.invocation_runtime import (
    SupervisorCheckpointInvoker,
    SupervisorInvocationAuthorities,
    SupervisorInvocationCompletion,
    SupervisorInvocationRuntimeError,
    consume_supervisor_invocation,
)
from pajin.supervision.model_binding import SupervisorModelBinding
from pajin.supervision.proposal_compiler import (
    SupervisorProposalCompilationPolicy,
    registered_supervisor_proposal_compilation_policy,
)

SUPERVISOR_BENCHMARK_CAMPAIGN_PLAN_API_VERSION: Literal[
    "pajin.dev/supervisor-benchmark-campaign-plan/v1alpha1"
] = "pajin.dev/supervisor-benchmark-campaign-plan/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_PLAN_ARTIFACT: Literal["supervision/supervisor-benchmark-campaign-plan.json"] = (
    "supervision/supervisor-benchmark-campaign-plan.json"
)
_SOURCE_ARTIFACT: Literal["walking-shadow-measured-benchmark-authority.json"] = (
    "walking-shadow-measured-benchmark-authority.json"
)
_SCHEDULE_ARTIFACT: Literal["supervision/supervisor-checkpoint-schedule.json"] = (
    "supervision/supervisor-checkpoint-schedule.json"
)
_MAX_PLAN_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_RUN_BYTES = 256 * 1024


class SupervisorBenchmarkCampaignPlanError(RuntimeError):
    """Raised when a model-backed benchmark campaign is not exact before dispatch."""


class SupervisorBenchmarkCandidateImplementation(StrictModel):
    """Static candidate identity shared by every coordinate in one Manifest."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    implementation_id: Literal["pajin:supervisor-model-shadow-candidate"] = Field(
        default="pajin:supervisor-model-shadow-candidate",
        alias="implementationId",
    )
    implementation_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="implementationVersion",
    )
    implementation_digest: str = Field(
        default="",
        alias="implementationDigest",
        max_length=64,
    )
    model_binding: SupervisorModelBinding = Field(alias="modelBinding")
    model_binding_digest: _Sha256 = Field(alias="modelBindingDigest")
    proposal_compilation_policy: SupervisorProposalCompilationPolicy = Field(
        alias="proposalCompilationPolicy"
    )
    proposal_compilation_policy_digest: _Sha256 = Field(alias="proposalCompilationPolicyDigest")
    dedicated_budget_policy: SupervisorDedicatedBudgetPolicy = Field(alias="dedicatedBudgetPolicy")
    dedicated_budget_policy_digest: _Sha256 = Field(alias="dedicatedBudgetPolicyDigest")
    request_schema_digest: _Sha256 = Field(alias="requestSchemaDigest")
    response_schema_id: Literal["pajin.dev/supervisor-shadow-proposal-draft/v1alpha1"] = Field(
        alias="responseSchemaId"
    )
    response_schema_digest: _Sha256 = Field(alias="responseSchemaDigest")
    implementation_state: Literal["model-bound-shadow-not-activated"] = Field(
        default="model-bound-shadow-not-activated",
        alias="implementationState",
    )
    proposal_causal_effect_attributed: Literal[False] = Field(
        default=False,
        alias="proposalCausalEffectAttributed",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "proposal_causal_effect_attributed",
        "supervisor_activation_eligible",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_implementation(self) -> Self:
        policy = registered_supervisor_proposal_compilation_policy()
        if (
            self.model_binding_digest != self.model_binding.binding_digest
            or self.proposal_compilation_policy != policy
            or self.proposal_compilation_policy_digest != policy.policy_digest
            or self.dedicated_budget_policy_digest != self.dedicated_budget_policy.policy_digest
        ):
            raise ValueError("Supervisor benchmark implementation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"implementation_digest"},
        )
        digest = _digest("pajin.supervision.benchmark-candidate-implementation/v1", material)
        if self.implementation_digest and self.implementation_digest != digest:
            raise ValueError("Supervisor benchmark implementation Digest differs")
        object.__setattr__(self, "implementation_digest", digest)
        return self


class SupervisorBenchmarkBaselineSource(StrictModel):
    """Exact BENCH-003B2 source identity used only to derive a fresh Manifest."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    authority_id: str = Field(alias="authorityId", min_length=1, max_length=110)
    authority_digest: _Sha256 = Field(alias="authorityDigest")
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=100)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: Literal["walking-shadow-measured-benchmark-authority.json"] = Field(
        default=_SOURCE_ARTIFACT, alias="sourceArtifactPath"
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    structural_authority_id: str = Field(
        alias="structuralAuthorityId",
        min_length=1,
        max_length=110,
    )
    structural_authority_digest: _Sha256 = Field(alias="structuralAuthorityDigest")
    baseline_manifest: BenchmarkManifest = Field(alias="baselineManifest")
    baseline_manifest_digest: _Sha256 = Field(alias="baselineManifestDigest")
    walking_campaign_digest: _Sha256 = Field(alias="walkingCampaignDigest")
    source_state: Literal["policy-measured-not-model-backed"] = Field(
        default="policy-measured-not-model-backed",
        alias="sourceState",
    )
    numeric_results_reused: Literal[False] = Field(
        default=False,
        alias="numericResultsReused",
    )

    @field_validator("numeric_results_reused", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_source(self) -> Self:
        if (
            len(self.baseline_manifest.arms) != 1
            or self.baseline_manifest.arms[0].kind is not BenchmarkArmKind.DETERMINISTIC_BASELINE
            or self.baseline_manifest.protocol.max_model_calls != 0
            or self.baseline_manifest_digest != self.baseline_manifest.digest()
        ):
            raise ValueError("Supervisor benchmark source is not the exact baseline Manifest")
        return self


class SupervisorBenchmarkCoordinateScheduleBinding(StrictModel):
    """One candidate coordinate and its exact pre-existing SUP-004A schedule."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    coordinate: BenchmarkTargetCoordinate
    schedule: SupervisorCheckpointSchedule
    schedule_run_id: str = Field(alias="scheduleRunId", min_length=1, max_length=100)
    schedule_root_digest: _Sha256 = Field(alias="scheduleRootDigest")
    schedule_artifact_path: Literal["supervision/supervisor-checkpoint-schedule.json"] = Field(
        default=_SCHEDULE_ARTIFACT, alias="scheduleArtifactPath"
    )
    schedule_artifact_sha256: _Sha256 = Field(alias="scheduleArtifactSha256")
    binding_state: Literal["schedule-bound-plan-not-dispatch-authority"] = Field(
        default="schedule-bound-plan-not-dispatch-authority",
        alias="bindingState",
    )
    model_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="modelInvocationAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("model_invocation_authorized", "execution_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_schedule_publication(self) -> Self:
        expected_sha = sha256(
            _runstore_json_bytes(self.schedule.model_dump(mode="json", by_alias=True))
        ).hexdigest()
        if (
            self.coordinate.arm.kind is not BenchmarkArmKind.ADAPTIVE_CANDIDATE
            or self.schedule_artifact_sha256 != expected_sha
            or self.schedule.schedule_state != "scheduled-not-invoked"
            or self.schedule.model_invocation_authorized is not False
            or self.schedule.execution_authorized is not False
            or self.schedule.activation_eligible is not False
        ):
            raise ValueError("Supervisor benchmark coordinate schedule differs")
        return self


class SupervisorBenchmarkCampaignPlan(StrictModel):
    """Complete two-arm schedule mapping that grants no dispatch or timing authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-benchmark-campaign-plan/v1alpha1"] = Field(
        default=SUPERVISOR_BENCHMARK_CAMPAIGN_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorBenchmarkCampaignPlan"] = "SupervisorBenchmarkCampaignPlan"
    plan_id: str = Field(default="", alias="planId", max_length=110)
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    campaign_manifest_digest: _Sha256 = Field(alias="campaignManifestDigest")
    campaign_manifest: CampaignManifest = Field(alias="campaignManifest")
    baseline_source: SupervisorBenchmarkBaselineSource = Field(alias="baselineSource")
    candidate_implementation: SupervisorBenchmarkCandidateImplementation = Field(
        alias="candidateImplementation"
    )
    manifest: BenchmarkManifest
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    coordinate_set_digest: _Sha256 = Field(alias="coordinateSetDigest")
    coordinates: tuple[BenchmarkTargetCoordinate, ...] = Field(
        min_length=2,
        max_length=64,
    )
    candidate_schedules: tuple[SupervisorBenchmarkCoordinateScheduleBinding, ...] = Field(
        alias="candidateSchedules",
        min_length=1,
        max_length=32,
    )
    plan_state: Literal["sealed-complete-set-not-dispatch-authority"] = Field(
        default="sealed-complete-set-not-dispatch-authority",
        alias="planState",
    )
    pre_dispatch_binding_proven: Literal[False] = Field(
        default=False,
        alias="preDispatchBindingProven",
    )
    numeric_results_reused: Literal[False] = Field(
        default=False,
        alias="numericResultsReused",
    )
    proposal_causal_effect_attributed: Literal[False] = Field(
        default=False,
        alias="proposalCausalEffectAttributed",
    )
    benchmark_comparison_eligible: Literal[False] = Field(
        default=False,
        alias="benchmarkComparisonEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "numeric_results_reused",
        "pre_dispatch_binding_proven",
        "proposal_causal_effect_attributed",
        "benchmark_comparison_eligible",
        "supervisor_activation_eligible",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        expected_manifest = _candidate_manifest(
            self.baseline_source.baseline_manifest,
            self.candidate_implementation,
        )
        expected_coordinates = _manifest_coordinates(expected_manifest)
        expected_candidate_coordinates = tuple(
            coordinate
            for coordinate in expected_coordinates
            if coordinate.arm.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
        )
        schedule_coordinates = tuple(binding.coordinate for binding in self.candidate_schedules)
        schedules = tuple(binding.schedule for binding in self.candidate_schedules)
        if (
            self.campaign_manifest_digest != campaign_manifest_digest(self.campaign_manifest)
            or self.candidate_implementation.model_binding.profile_compilation.source_campaign
            != self.campaign_manifest
            or self.baseline_source.walking_campaign_digest
            != walking_campaign_digest(self.campaign_manifest)
            or self.baseline_source.baseline_manifest.campaign_digest
            != walking_campaign_digest(self.campaign_manifest)
            or self.manifest != expected_manifest
            or self.manifest_digest != expected_manifest.digest()
            or self.coordinates != expected_coordinates
            or schedule_coordinates != expected_candidate_coordinates
            or self.coordinate_set_digest
            != _coordinate_set_digest(expected_manifest, expected_coordinates)
            or len(schedules)
            > self.candidate_implementation.dedicated_budget_policy.max_model_calls
        ):
            raise ValueError("Supervisor benchmark Plan coordinate set differs")
        if len({binding.schedule_run_id for binding in self.candidate_schedules}) != len(
            self.candidate_schedules
        ):
            raise ValueError("Supervisor benchmark schedule Runs are duplicated")
        unique_fields = (
            "checkpoint_key",
            "schedule_digest",
            "request_binding_digest",
            "source_snapshot_digest",
        )
        for field_name in unique_fields:
            if len({getattr(schedule, field_name) for schedule in schedules}) != len(schedules):
                raise ValueError(f"Supervisor benchmark schedules duplicate {field_name}")
        for binding in self.candidate_schedules:
            schedule = binding.schedule
            request = schedule.request_binding
            implementation = self.candidate_implementation
            if (
                binding.coordinate.arm.configuration_digest != implementation.implementation_digest
                or schedule.campaign_digest != implementation.model_binding.campaign_digest
                or request.model_binding_id != implementation.model_binding.binding_id
                or request.model_binding_digest != implementation.model_binding.binding_digest
                or request.provider_model_digest
                != implementation.model_binding.provider_model_digest
                or request.configuration_digest != implementation.model_binding.configuration_digest
                or request.request_schema_digest != implementation.request_schema_digest
                or request.response_schema_id != implementation.response_schema_id
                or request.response_schema_digest != implementation.response_schema_digest
                or schedule.dedicated_budget_policy != implementation.dedicated_budget_policy
            ):
                raise ValueError("Supervisor benchmark schedule changed candidate implementation")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_id", "plan_digest"},
        )
        digest = _digest("pajin.supervision.benchmark-campaign-plan/v1", material)
        plan_id = f"supervisor-benchmark-plan:{digest}"
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("Supervisor Benchmark Campaign Plan Digest differs")
        if self.plan_id and self.plan_id != plan_id:
            raise ValueError("Supervisor Benchmark Campaign Plan ID differs")
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "plan_id", plan_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Supervisor benchmark campaign Plan",
            max_bytes=_MAX_PLAN_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class SupervisorBenchmarkScheduleSource:
    """Current authorities for one candidate coordinate schedule, in coordinate order."""

    publication: SupervisorCheckpointSchedulePublication
    authorities: SupervisorInvocationAuthorities


@dataclass(frozen=True, slots=True)
class SupervisorBenchmarkCampaignPlanOutcome:
    plan: SupervisorBenchmarkCampaignPlan
    run_id: str
    run_path: Path
    artifact_path: Literal["supervision/supervisor-benchmark-campaign-plan.json"]
    artifact_sha256: str
    root_digest: str


@dataclass(frozen=True, slots=True)
class SupervisorBenchmarkCandidateInvocation:
    """One B3 completion proven to use a Plan- and coordinate-bound ToolRequest ID."""

    plan_outcome: SupervisorBenchmarkCampaignPlanOutcome
    plan: SupervisorBenchmarkCampaignPlan
    coordinate: BenchmarkTargetCoordinate
    request_context: SupervisorBenchmarkRequestContext
    stable_request_id: str
    completion: SupervisorInvocationCompletion


class SupervisorBenchmarkCampaignPlanner:
    """Seal the complete candidate coordinate set without dispatching a Provider."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = Path(output_root)

    def run(
        self,
        campaign: CampaignManifest,
        baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
        schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
    ) -> SupervisorBenchmarkCampaignPlanOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            plan = _expected_plan(
                authoritative_campaign,
                baseline_source,
                schedule_sources,
            )
        except (
            AttributeError,
            OSError,
            RunIntegrityError,
            SupervisorCheckpointScheduleError,
            TypeError,
            ValidationError,
            ValueError,
            WalkingShadowMeasuredBenchmarkError,
        ) as exc:
            raise SupervisorBenchmarkCampaignPlanError(
                "SUP-005B1 benchmark campaign planning failed closed"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "supervisor-benchmark-campaign-plan",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            _PLAN_ARTIFACT,
            plan.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.supervisor-campaign-plan.created",
            _publication_event_payload(artifact_path, plan),
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "supervisor-benchmark-campaign-plan-sealed",
                "planId": plan.plan_id,
                "planState": plan.plan_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "supervisor-benchmark-campaign-plan", "artifact": artifact_path},
        )
        seal = store.seal()
        artifact = next(item for item in seal.artifacts if item.path == artifact_path)
        return SupervisorBenchmarkCampaignPlanOutcome(
            plan=plan.model_copy(deep=True),
            run_id=store.run_id,
            run_path=store.path.resolve(),
            artifact_path=_PLAN_ARTIFACT,
            artifact_sha256=artifact.sha256,
            root_digest=seal.root_digest,
        )


def load_supervisor_benchmark_campaign_plan(
    campaign: CampaignManifest,
    outcome: SupervisorBenchmarkCampaignPlanOutcome,
    baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
    schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
) -> SupervisorBenchmarkCampaignPlan:
    """Reload a Plan only after its complete envelope and every live source reverify."""

    try:
        if outcome.artifact_path != _PLAN_ARTIFACT:
            raise ValueError("Supervisor benchmark Plan artifact path differs")
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": 256 * 1024,
                outcome.artifact_path: _MAX_PLAN_BYTES,
                "run.json": _MAX_RUN_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        artifact_bytes = snapshot.artifact_bytes(outcome.artifact_path)
        plan = SupervisorBenchmarkCampaignPlan.model_validate(
            parse_strict_json_bytes(
                artifact_bytes,
                label="SUP-005B1 benchmark campaign Plan",
                max_bytes=_MAX_PLAN_BYTES,
            )
        )
        run_record = parse_strict_json_bytes(
            snapshot.artifact_bytes("run.json"),
            label="SUP-005B1 Run record",
            max_bytes=_MAX_RUN_BYTES,
        )
        expected = _expected_plan(
            authoritative_campaign,
            baseline_source,
            schedule_sources,
        )
        final_artifacts = {artifact.path for artifact in snapshot.seals[-1].artifacts}
        expected_run_record = {
            "runId": outcome.run_id,
            "status": "completed",
            "stage": "supervisor-benchmark-campaign-plan-sealed",
            "planId": plan.plan_id,
            "planState": plan.plan_state,
        }
        if (
            sealed_campaign != authoritative_campaign
            or plan != outcome.plan
            or plan != expected
            or snapshot.verification.root_digest != outcome.root_digest
            or sha256(artifact_bytes).hexdigest() != outcome.artifact_sha256
            or snapshot.verification.seal_count != 1
            or snapshot.verification.artifact_count != 3
            or final_artifacts != {"campaign.json", outcome.artifact_path, "run.json"}
            or tuple(event.event_type for event in snapshot.events)
            != (
                "campaign.started",
                "benchmark.supervisor-campaign-plan.created",
                "campaign.completed",
            )
            or snapshot.events[0].payload
            != {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "supervisor-benchmark-campaign-plan",
            }
            or snapshot.events[1].payload != _publication_event_payload(outcome.artifact_path, plan)
            or snapshot.events[2].payload
            != {
                "purpose": "supervisor-benchmark-campaign-plan",
                "artifact": outcome.artifact_path,
            }
            or run_record != expected_run_record
        ):
            raise ValueError("Supervisor benchmark Plan differs from exact sealed sources")
        return plan.model_copy(deep=True)
    except SupervisorBenchmarkCampaignPlanError:
        raise
    except (
        AttributeError,
        OSError,
        RunIntegrityError,
        SupervisorCheckpointScheduleError,
        TypeError,
        ValidationError,
        ValueError,
        WalkingShadowMeasuredBenchmarkError,
    ) as exc:
        raise SupervisorBenchmarkCampaignPlanError(
            "SUP-005B1 benchmark campaign Plan is not exact and sealed"
        ) from exc


async def invoke_supervisor_benchmark_candidate(
    campaign: CampaignManifest,
    plan_outcome: SupervisorBenchmarkCampaignPlanOutcome,
    baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
    schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
    *,
    coordinate_id: str,
    invoker: SupervisorCheckpointInvoker,
) -> SupervisorBenchmarkCandidateInvocation:
    """Invoke one candidate only after binding the sealed Plan and coordinate into B3."""

    try:
        if type(invoker) is not SupervisorCheckpointInvoker:
            raise TypeError("Supervisor benchmark invocation requires the exact B3 invoker")
        plan = load_supervisor_benchmark_campaign_plan(
            campaign,
            plan_outcome,
            baseline_source,
            schedule_sources,
        )
        matches = [
            (index, binding)
            for index, binding in enumerate(plan.candidate_schedules)
            if binding.coordinate.coordinate_id == coordinate_id
        ]
        if len(matches) != 1:
            raise ValueError("Supervisor benchmark candidate coordinate is not unique")
        index, binding = matches[0]
        source = schedule_sources[index]
        context = _request_context(plan_outcome, plan, binding)
        expected_request_id = supervisor_stable_request_id(
            source.publication,
            request_context=context,
        )
        completion = await invoker.invoke(
            source.publication,
            source.authorities,
            request_context=context,
        )
        if type(completion) is not SupervisorInvocationCompletion:
            raise TypeError("Supervisor benchmark B3 completion type differs")
        candidate = SupervisorBenchmarkCandidateInvocation(
            plan_outcome=plan_outcome,
            plan=plan,
            coordinate=binding.coordinate.model_copy(deep=True),
            request_context=context,
            stable_request_id=expected_request_id,
            completion=completion,
        )
        return verify_supervisor_benchmark_candidate_invocation(
            campaign,
            candidate,
            baseline_source,
            schedule_sources,
            journal=invoker.journal,
        )
    except SupervisorBenchmarkCampaignPlanError:
        raise
    except (
        AttributeError,
        OSError,
        RunIntegrityError,
        SupervisorInvocationRuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorBenchmarkCampaignPlanError(
            "SUP-005B1 candidate invocation failed closed"
        ) from exc


def verify_supervisor_benchmark_candidate_invocation(
    campaign: CampaignManifest,
    candidate: SupervisorBenchmarkCandidateInvocation,
    baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
    schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
    *,
    journal: SupervisorInvocationJournal,
) -> SupervisorBenchmarkCandidateInvocation:
    """Reconsume B3 and exact-match one typed Plan/coordinate request context."""

    try:
        if (
            type(candidate) is not SupervisorBenchmarkCandidateInvocation
            or type(journal) is not SupervisorInvocationJournal
            or type(candidate.completion) is not SupervisorInvocationCompletion
        ):
            raise TypeError("Supervisor benchmark candidate authority type differs")
        plan = load_supervisor_benchmark_campaign_plan(
            campaign,
            candidate.plan_outcome,
            baseline_source,
            schedule_sources,
        )
        matches = [
            (index, binding)
            for index, binding in enumerate(plan.candidate_schedules)
            if binding.coordinate.coordinate_id == candidate.coordinate.coordinate_id
        ]
        if len(matches) != 1:
            raise ValueError("Supervisor benchmark candidate coordinate is not unique")
        index, binding = matches[0]
        source = schedule_sources[index]
        context = _request_context(candidate.plan_outcome, plan, binding)
        expected_request_id = supervisor_stable_request_id(
            source.publication,
            request_context=context,
        )
        proposal = consume_supervisor_invocation(
            candidate.completion.publication,
            journal=journal,
            schedule_publication=source.publication,
            authorities=source.authorities,
        )
        entry = candidate.completion.publication.journal_entry
        receipt = candidate.completion.publication.receipt
        plan_snapshot = load_verified_run_artifacts(
            candidate.plan_outcome.run_path,
            requests={candidate.plan_outcome.artifact_path: _MAX_PLAN_BYTES},
            expected_run_id=candidate.plan_outcome.run_id,
        )
        if (
            candidate.plan != plan
            or candidate.coordinate != binding.coordinate
            or candidate.request_context != context
            or candidate.stable_request_id != expected_request_id
            or candidate.completion.proposal != proposal
            or entry.state is not SupervisorInvocationJournalState.TERMINAL_SUCCESS
            or entry.intent.request_context != context
            or entry.intent.stable_request_id != expected_request_id
            or receipt.request_context != context
            or receipt.stable_request_id != expected_request_id
            or receipt.provider_outcome.request_id != expected_request_id
            or entry.dispatch_started_at is None
            or plan_snapshot.seals[-1].sealed_at > entry.dispatch_started_at
        ):
            raise ValueError("Supervisor benchmark Provider request was not pre-bound")
        return candidate
    except SupervisorBenchmarkCampaignPlanError:
        raise
    except (
        AttributeError,
        OSError,
        RunIntegrityError,
        SupervisorInvocationRuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorBenchmarkCampaignPlanError(
            "SUP-005B1 candidate invocation is not exact and sealed"
        ) from exc


def _expected_plan(
    campaign: CampaignManifest,
    baseline_source: WalkingShadowMeasuredBenchmarkOutcome,
    schedule_sources: tuple[SupervisorBenchmarkScheduleSource, ...],
) -> SupervisorBenchmarkCampaignPlan:
    if not schedule_sources or len(schedule_sources) > 32:
        raise ValueError("Supervisor benchmark candidate schedule set is empty or unbounded")
    source = load_walking_shadow_measured_benchmark_authority(campaign, baseline_source)
    source_snapshot = load_verified_run_artifacts(
        baseline_source.run_path,
        requests={baseline_source.artifact_path: _MAX_SOURCE_BYTES},
        expected_run_id=baseline_source.run_id,
    )
    if (
        baseline_source.artifact_path != _SOURCE_ARTIFACT
        or source.supervisor_activation_eligible is not False
        or source.measured_source.supervisor_activation_eligible is not False
        or source.structural_source.supervisor_activation_eligible is not False
    ):
        raise ValueError("Supervisor benchmark baseline source authority differs")
    baseline_manifest = source.structural_source.manifest.model_copy(deep=True)
    baseline_lineage = SupervisorBenchmarkBaselineSource(
        authorityId=source.authority_id,
        authorityDigest=source.authority_digest,
        sourceRunId=source_snapshot.verification.run_id,
        sourceRootDigest=source_snapshot.verification.root_digest,
        sourceArtifactSha256=sha256(
            source_snapshot.artifact_bytes(baseline_source.artifact_path)
        ).hexdigest(),
        structuralAuthorityId=source.structural_source.authority_id,
        structuralAuthorityDigest=source.structural_source.authority_digest,
        baselineManifest=baseline_manifest,
        baselineManifestDigest=baseline_manifest.digest(),
        walkingCampaignDigest=source.structural_source.source.campaign_digest,
    )

    verified_schedules: list[SupervisorCheckpointSchedule] = []
    canonical_sources: list[SupervisorBenchmarkScheduleSource] = []
    for item in schedule_sources:
        authorities = item.authorities
        if (
            CampaignManifest.model_validate(
                authorities.campaign.model_dump(mode="json", by_alias=True)
            )
            != campaign
        ):
            raise ValueError("Supervisor benchmark schedule crossed Campaign authority")
        schedule = verify_supervisor_checkpoint_schedule_publication(
            item.publication,
            authorities.snapshot_input,
            authorities.binding,
            authorities.campaign,
            authorities.provider_registration,
            model_revision=authorities.model_revision,
            configuration=authorities.configuration,
            budget_policy=authorities.budget_policy,
            collaboration_snapshot=authorities.collaboration_snapshot,
            graph_snapshot_store=authorities.graph_snapshot_store,
            shared_artifact_sources=authorities.shared_artifact_sources,
        )
        verified_schedules.append(schedule)
        canonical_sources.append(item)

    first_schedule = verified_schedules[0]
    first_authorities = canonical_sources[0].authorities
    implementation = SupervisorBenchmarkCandidateImplementation(
        modelBinding=first_authorities.binding,
        modelBindingDigest=first_authorities.binding.binding_digest,
        proposalCompilationPolicy=registered_supervisor_proposal_compilation_policy(),
        proposalCompilationPolicyDigest=(
            registered_supervisor_proposal_compilation_policy().policy_digest
        ),
        dedicatedBudgetPolicy=first_schedule.dedicated_budget_policy,
        dedicatedBudgetPolicyDigest=first_schedule.dedicated_budget_policy_digest,
        requestSchemaDigest=first_schedule.request_binding.request_schema_digest,
        responseSchemaId=first_schedule.request_binding.response_schema_id,
        responseSchemaDigest=first_schedule.request_binding.response_schema_digest,
    )
    manifest = _candidate_manifest(baseline_manifest, implementation)
    coordinates = _manifest_coordinates(manifest)
    candidate_coordinates = tuple(
        coordinate
        for coordinate in coordinates
        if coordinate.arm.kind is BenchmarkArmKind.ADAPTIVE_CANDIDATE
    )
    if len(candidate_coordinates) != len(schedule_sources):
        raise ValueError("Supervisor benchmark candidate schedule set is incomplete")

    bindings: list[SupervisorBenchmarkCoordinateScheduleBinding] = []
    for coordinate, item, schedule in zip(
        candidate_coordinates,
        canonical_sources,
        verified_schedules,
        strict=True,
    ):
        if (
            item.authorities.binding != first_authorities.binding
            or item.authorities.budget_policy != first_authorities.budget_policy
        ):
            raise ValueError("Supervisor benchmark candidate implementation equivocated")
        bindings.append(
            SupervisorBenchmarkCoordinateScheduleBinding(
                coordinate=coordinate,
                schedule=schedule,
                scheduleRunId=item.publication.run_id,
                scheduleRootDigest=item.publication.root_digest,
                scheduleArtifactSha256=item.publication.artifact_sha256,
            )
        )
    return SupervisorBenchmarkCampaignPlan(
        campaignManifestDigest=campaign_manifest_digest(campaign),
        campaignManifest=campaign,
        baselineSource=baseline_lineage,
        candidateImplementation=implementation,
        manifest=manifest,
        manifestDigest=manifest.digest(),
        coordinateSetDigest=_coordinate_set_digest(manifest, coordinates),
        coordinates=coordinates,
        candidateSchedules=tuple(bindings),
    )


def _candidate_manifest(
    baseline_manifest: BenchmarkManifest,
    implementation: SupervisorBenchmarkCandidateImplementation,
) -> BenchmarkManifest:
    protocol = BenchmarkRunProtocol.model_validate(
        baseline_manifest.protocol.model_dump(mode="json", by_alias=True) | {"maxModelCalls": 1}
    )
    candidate = BenchmarkArm(
        armId="arm:walking-model-backed-shadow-candidate",
        kind=BenchmarkArmKind.ADAPTIVE_CANDIDATE,
        implementationId=implementation.implementation_id,
        implementationVersion=implementation.implementation_version,
        configurationDigest=implementation.implementation_digest,
        adaptiveSupervisor=True,
    )
    raw = baseline_manifest.model_dump(mode="json", by_alias=True)
    raw["protocol"] = protocol.model_dump(mode="json", by_alias=True)
    raw["arms"] = [
        baseline_manifest.arms[0].model_dump(mode="json", by_alias=True),
        candidate.model_dump(mode="json", by_alias=True),
    ]
    return BenchmarkManifest.model_validate(raw)


def _manifest_coordinates(
    manifest: BenchmarkManifest,
) -> tuple[BenchmarkTargetCoordinate, ...]:
    return tuple(
        benchmark_target_coordinate(
            manifest,
            arm_id=arm.arm_id,
            seed=seed,
            repetition=repetition,
        )
        for arm in manifest.arms
        for seed in manifest.protocol.seeds
        for repetition in range(1, manifest.protocol.repetitions_per_seed + 1)
    )


def _coordinate_set_digest(
    manifest: BenchmarkManifest,
    coordinates: tuple[BenchmarkTargetCoordinate, ...],
) -> str:
    return _digest(
        "pajin.supervision.benchmark-coordinate-set/v1",
        {
            "manifestDigest": manifest.digest(),
            "coordinateDigests": [coordinate.coordinate_digest for coordinate in coordinates],
        },
    )


def _request_context(
    outcome: SupervisorBenchmarkCampaignPlanOutcome,
    plan: SupervisorBenchmarkCampaignPlan,
    binding: SupervisorBenchmarkCoordinateScheduleBinding,
) -> SupervisorBenchmarkRequestContext:
    return SupervisorBenchmarkRequestContext(
        planApiVersion=plan.api_version,
        planKind=plan.kind,
        planId=plan.plan_id,
        planDigest=plan.plan_digest,
        planRunId=outcome.run_id,
        planRootDigest=outcome.root_digest,
        planArtifactPath=outcome.artifact_path,
        planArtifactSha256=outcome.artifact_sha256,
        manifestDigest=plan.manifest_digest,
        coordinateSetDigest=plan.coordinate_set_digest,
        coordinateId=binding.coordinate.coordinate_id,
        coordinateDigest=binding.coordinate.coordinate_digest,
        scheduleId=binding.schedule.schedule_id,
        scheduleDigest=binding.schedule.schedule_digest,
        scheduleRunId=binding.schedule_run_id,
        scheduleRootDigest=binding.schedule_root_digest,
    )


def _publication_event_payload(
    artifact_path: str,
    plan: SupervisorBenchmarkCampaignPlan,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "planId": plan.plan_id,
        "planDigest": plan.plan_digest,
        "manifestDigest": plan.manifest_digest,
        "coordinateSetDigest": plan.coordinate_set_digest,
        "candidateImplementationDigest": (plan.candidate_implementation.implementation_digest),
        "candidateCoordinateCount": len(plan.candidate_schedules),
        "planState": plan.plan_state,
        "supervisorActivationEligible": plan.supervisor_activation_eligible,
    }


def _digest(domain: str, value: object) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Supervisor benchmark authority",
        max_bytes=_MAX_PLAN_BYTES,
    )
    return sha256(domain.encode("ascii") + b"\x00" + encoded).hexdigest()


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


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("Supervisor benchmark authority markers must be literal booleans")
    return expected
