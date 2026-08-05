"""Source-bound SUP-005A lineage between one B3 proposal and BENCH-003B2."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import BENCHMARK_METRIC_ORDER, BenchmarkMetric
from pajin.benchmark.shadow_measurement import (
    WalkingShadowMeasuredBenchmarkError,
    WalkingShadowMeasuredBenchmarkOutcome,
    load_walking_shadow_measured_benchmark_authority,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.walking_shadow import walking_shadow_supervisor_policy
from pajin.domain.models import CampaignManifest, StrictModel, campaign_manifest_digest
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.supervision.checkpoint_scheduler import SupervisorCheckpointSchedulePublication
from pajin.supervision.invocation_journal import (
    SupervisorInvocationJournal,
    SupervisorInvocationJournalState,
)
from pajin.supervision.invocation_runtime import (
    SupervisorInvocationAuthorities,
    SupervisorInvocationCompletion,
    SupervisorInvocationRuntimeError,
    consume_supervisor_invocation,
)
from pajin.supervision.proposal_compiler import SupervisorTypedProposal

SUPERVISOR_DETERMINISTIC_BASELINE_LINEAGE_API_VERSION: Literal[
    "pajin.dev/supervisor-deterministic-baseline-lineage/v1alpha1"
] = "pajin.dev/supervisor-deterministic-baseline-lineage/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_AUTHORITY_ARTIFACT = "supervision/supervisor-deterministic-baseline-lineage.json"
_SCHEDULE_ARTIFACT: Literal["supervision/supervisor-checkpoint-schedule.json"] = (
    "supervision/supervisor-checkpoint-schedule.json"
)
_B3_RECEIPT_ARTIFACT: Literal["supervision/supervisor-invocation-receipt.json"] = (
    "supervision/supervisor-invocation-receipt.json"
)
_B2_AUTHORITY_ARTIFACT: Literal[
    "walking-shadow-measured-benchmark-authority.json"
] = "walking-shadow-measured-benchmark-authority.json"
_MAX_CAMPAIGN_BYTES = 256 * 1024
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 8 * 1024 * 1024
_MAX_RUN_BYTES = 256 * 1024


class SupervisorDeterministicBaselineLineageError(RuntimeError):
    """Raised when SUP-005A cannot prove exact non-causal source lineage."""


class SupervisorBenchmarkInvocationLineage(StrictModel):
    """Digest-only B3 provenance plus the content-free SUP-003 proposal identity."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    journal_intent_id: str = Field(alias="journalIntentId", min_length=1, max_length=110)
    journal_intent_digest: _Sha256 = Field(alias="journalIntentDigest")
    journal_state_digest: _Sha256 = Field(alias="journalStateDigest")
    journal_event_digests: tuple[_Sha256, ...] = Field(
        alias="journalEventDigests",
        min_length=3,
        max_length=3,
    )
    dispatch_event_digest: _Sha256 = Field(alias="dispatchEventDigest")
    schedule_id: str = Field(alias="scheduleId", min_length=1, max_length=110)
    schedule_digest: _Sha256 = Field(alias="scheduleDigest")
    checkpoint_key: _Sha256 = Field(alias="checkpointKey")
    planned_call_index: int = Field(alias="plannedCallIndex", ge=1, le=32)
    schedule_run_id: str = Field(alias="scheduleRunId", min_length=1, max_length=100)
    schedule_root_digest: _Sha256 = Field(alias="scheduleRootDigest")
    schedule_artifact_path: Literal[
        "supervision/supervisor-checkpoint-schedule.json"
    ] = Field(alias="scheduleArtifactPath")
    schedule_artifact_sha256: _Sha256 = Field(alias="scheduleArtifactSha256")
    request_binding_id: str = Field(alias="requestBindingId", min_length=1, max_length=110)
    request_binding_digest: _Sha256 = Field(alias="requestBindingDigest")
    provider_chat_request_digest: _Sha256 = Field(alias="providerChatRequestDigest")
    response_schema_id: str = Field(alias="responseSchemaId", min_length=1, max_length=110)
    response_schema_digest: _Sha256 = Field(alias="responseSchemaDigest")
    dedicated_budget_policy_id: str = Field(
        alias="dedicatedBudgetPolicyId", min_length=1, max_length=110
    )
    dedicated_budget_policy_digest: _Sha256 = Field(alias="dedicatedBudgetPolicyDigest")
    stable_request_id: str = Field(
        alias="stableRequestId",
        pattern=r"^supervisor_[a-f0-9]{64}$",
    )
    provider_run_id: str = Field(alias="providerRunId", min_length=1, max_length=100)
    provider_run_root_digest: _Sha256 = Field(alias="providerRunRootDigest")
    receipt_artifact_path: Literal[
        "supervision/supervisor-invocation-receipt.json"
    ] = Field(alias="receiptArtifactPath")
    receipt_artifact_sha256: _Sha256 = Field(alias="receiptArtifactSha256")
    receipt_id: str = Field(alias="receiptId", min_length=1, max_length=110)
    receipt_digest: _Sha256 = Field(alias="receiptDigest")
    provider_outcome_id: str = Field(alias="providerOutcomeId", min_length=1, max_length=110)
    provider_outcome_digest: _Sha256 = Field(alias="providerOutcomeDigest")
    provider_id: str = Field(alias="providerId", min_length=1, max_length=200)
    provider_model: str = Field(alias="providerModel", min_length=1, max_length=200)
    source_snapshot_id: str = Field(alias="sourceSnapshotId", min_length=1, max_length=110)
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    model_binding_id: str = Field(alias="modelBindingId", min_length=1, max_length=110)
    model_binding_digest: _Sha256 = Field(alias="modelBindingDigest")
    proposal_id: str = Field(alias="proposalId", min_length=1, max_length=110)
    proposal_digest: _Sha256 = Field(alias="proposalDigest")
    proposal_kind: Literal["task", "replan", "stop", "escalate"] = Field(
        alias="proposalKind"
    )
    proposal_compilation_policy_digest: _Sha256 = Field(
        alias="proposalCompilationPolicyDigest"
    )
    shadow_policy_digest: _Sha256 = Field(alias="shadowPolicyDigest")
    budget_scope: Literal["campaign-and-dedicated"] = Field(alias="budgetScope")

    @field_validator("planned_call_index", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("SUP-005 invocation ordinal must be a JSON integer")
        return value


class SupervisorBenchmarkMeasurementLineage(StrictModel):
    """Exact BENCH-003B2 identity without copying metric values into the B3 claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    authority_id: str = Field(alias="authorityId", min_length=1, max_length=110)
    authority_digest: _Sha256 = Field(alias="authorityDigest")
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=100)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: Literal[
        "walking-shadow-measured-benchmark-authority.json"
    ] = Field(alias="sourceArtifactPath")
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    structural_authority_id: str = Field(
        alias="structuralAuthorityId", min_length=1, max_length=110
    )
    structural_authority_digest: _Sha256 = Field(alias="structuralAuthorityDigest")
    measured_authority_id: str = Field(
        alias="measuredAuthorityId", min_length=1, max_length=110
    )
    measured_authority_digest: _Sha256 = Field(alias="measuredAuthorityDigest")
    benchmark_id: str = Field(alias="benchmarkId", min_length=1, max_length=200)
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    baseline_arm_id: str = Field(alias="baselineArmId", min_length=1, max_length=200)
    candidate_arm_id: str = Field(alias="candidateArmId", min_length=1, max_length=200)
    candidate_policy_id: str = Field(
        alias="candidatePolicyId", min_length=1, max_length=200
    )
    candidate_policy_version: str = Field(
        alias="candidatePolicyVersion", min_length=1, max_length=200
    )
    candidate_policy_digest: _Sha256 = Field(alias="candidatePolicyDigest")
    baseline_result_digest: _Sha256 = Field(alias="baselineResultDigest")
    candidate_result_digest: _Sha256 = Field(alias="candidateResultDigest")
    comparison_id: str = Field(alias="comparisonId", min_length=1, max_length=200)
    comparison_digest: _Sha256 = Field(alias="comparisonDigest")
    candidate_coordinate_count: int = Field(alias="candidateCoordinateCount", ge=1)
    candidate_observed_model_calls: int = Field(
        alias="candidateObservedModelCalls", ge=0
    )

    @field_validator(
        "candidate_coordinate_count",
        "candidate_observed_model_calls",
        mode="before",
    )
    @classmethod
    def require_literal_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("SUP-005 measurement counts must be JSON integers")
        return value


class SupervisorDeterministicBaselineLineageAuthority(StrictModel):
    """Bind B3 and B2 sources while refusing model-effect attribution."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/supervisor-deterministic-baseline-lineage/v1alpha1"
    ] = Field(
        default=SUPERVISOR_DETERMINISTIC_BASELINE_LINEAGE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorDeterministicBaselineLineageAuthority"] = (
        "SupervisorDeterministicBaselineLineageAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign_manifest_digest: _Sha256 = Field(alias="campaignManifestDigest")
    supervisor_campaign_digest: _Sha256 = Field(alias="supervisorCampaignDigest")
    walking_campaign_digest: _Sha256 = Field(alias="walkingCampaignDigest")
    invocation: SupervisorBenchmarkInvocationLineage
    measurement: SupervisorBenchmarkMeasurementLineage
    proposal: SupervisorTypedProposal
    required_metrics: tuple[BenchmarkMetric, ...] = Field(
        alias="requiredMetrics",
        min_length=len(BENCHMARK_METRIC_ORDER),
        max_length=len(BENCHMARK_METRIC_ORDER),
    )
    same_policy_lineage_verified: Literal[True] = Field(
        default=True,
        alias="samePolicyLineageVerified",
    )
    policy_benchmark_comparison_available: Literal[True] = Field(
        default=True,
        alias="policyBenchmarkComparisonAvailable",
    )
    comparison_state: Literal["structural-source-bound-not-model-measured"] = Field(
        default="structural-source-bound-not-model-measured",
        alias="comparisonState",
    )
    model_proposal_measurement_attributed: Literal[False] = Field(
        default=False,
        alias="modelProposalMeasurementAttributed",
    )
    benchmark_coordinate_bound_to_invocation: Literal[False] = Field(
        default=False,
        alias="benchmarkCoordinateBoundToInvocation",
    )
    model_backed_benchmark_eligible: Literal[False] = Field(
        default=False,
        alias="modelBackedBenchmarkEligible",
    )
    threshold_evaluation_eligible: Literal[False] = Field(
        default=False,
        alias="thresholdEvaluationEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )
    baseline_mutated: Literal[False] = Field(default=False, alias="baselineMutated")
    task_created: Literal[False] = Field(default=False, alias="taskCreated")
    plan_mutated: Literal[False] = Field(default=False, alias="planMutated")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    next_required_binding: Literal[
        "pre-invocation-benchmark-coordinate-and-observation-binding"
    ] = Field(
        default="pre-invocation-benchmark-coordinate-and-observation-binding",
        alias="nextRequiredBinding",
    )

    @field_validator(
        "same_policy_lineage_verified",
        "policy_benchmark_comparison_available",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("SUP-005 positive markers must be literal true")
        return value

    @field_validator(
        "model_proposal_measurement_attributed",
        "benchmark_coordinate_bound_to_invocation",
        "model_backed_benchmark_eligible",
        "threshold_evaluation_eligible",
        "supervisor_activation_eligible",
        "baseline_mutated",
        "task_created",
        "plan_mutated",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("SUP-005 authority markers must be literal false")
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        proposal = self.proposal
        invocation = self.invocation
        measurement = self.measurement
        if (
            self.supervisor_campaign_digest != proposal.campaign_digest
            or invocation.proposal_id != proposal.proposal_id
            or invocation.proposal_digest != proposal.proposal_digest
            or invocation.proposal_kind != proposal.source_proposal_kind.value
            or invocation.model_binding_id != proposal.model_binding_id
            or invocation.model_binding_digest != proposal.model_binding_digest
            or invocation.proposal_compilation_policy_digest
            != proposal.compilation_policy_digest
            or invocation.shadow_policy_digest != proposal.shadow_policy_digest
            or invocation.dispatch_event_digest != invocation.journal_event_digests[1]
            or invocation.source_snapshot_id != proposal.source_snapshot_id
            or invocation.source_snapshot_digest != proposal.source_snapshot_digest
            or measurement.candidate_policy_digest != proposal.shadow_policy_digest
            or self.required_metrics != tuple(BENCHMARK_METRIC_ORDER)
        ):
            raise ValueError("SUP-005A lineage differs from its exact source identities")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = _lineage_digest(
            "pajin.supervision.deterministic-baseline-lineage/v1",
            material,
        )
        authority_id = f"supervisor-baseline-lineage:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Supervisor baseline Lineage Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Supervisor baseline Lineage Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Supervisor deterministic baseline lineage authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class SupervisorDeterministicBaselineLineageOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: SupervisorDeterministicBaselineLineageAuthority


class SupervisorDeterministicBaselineLineageRunner:
    """Seal exact B3/B2 lineage without attributing policy metrics to one model call."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = Path(output_root)

    def run(
        self,
        campaign: CampaignManifest,
        invocation_completion: SupervisorInvocationCompletion,
        measured_outcome: WalkingShadowMeasuredBenchmarkOutcome,
        *,
        journal: SupervisorInvocationJournal,
        schedule_publication: SupervisorCheckpointSchedulePublication,
        invocation_authorities: SupervisorInvocationAuthorities,
    ) -> SupervisorDeterministicBaselineLineageOutcome:
        """Reverify both sealed sources and publish one non-causal comparison lineage."""

        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            authority = _expected_authority(
                authoritative_campaign,
                invocation_completion,
                measured_outcome,
                journal=journal,
                schedule_publication=schedule_publication,
                invocation_authorities=invocation_authorities,
            )
        except (
            OSError,
            RunIntegrityError,
            SupervisorInvocationRuntimeError,
            WalkingShadowMeasuredBenchmarkError,
            ValidationError,
            ValueError,
        ) as exc:
            raise SupervisorDeterministicBaselineLineageError(
                "SUP-005A source lineage could not be verified"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "supervisor-deterministic-baseline-lineage",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            _AUTHORITY_ARTIFACT,
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.supervisor-baseline-lineage.created",
            _publication_event_payload(artifact_path, authority),
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "supervisor-deterministic-baseline-lineage-sealed",
                "authorityId": authority.authority_id,
                "comparisonState": authority.comparison_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {
                "purpose": "supervisor-deterministic-baseline-lineage",
                "artifact": artifact_path,
            },
        )
        store.seal()
        return SupervisorDeterministicBaselineLineageOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
        )


def load_supervisor_deterministic_baseline_lineage_authority(
    campaign: CampaignManifest,
    outcome: SupervisorDeterministicBaselineLineageOutcome,
    invocation_completion: SupervisorInvocationCompletion,
    measured_outcome: WalkingShadowMeasuredBenchmarkOutcome,
    *,
    journal: SupervisorInvocationJournal,
    schedule_publication: SupervisorCheckpointSchedulePublication,
    invocation_authorities: SupervisorInvocationAuthorities,
) -> SupervisorDeterministicBaselineLineageAuthority:
    """Reload SUP-005A and rebuild both current sealed predecessor authorities."""

    authoritative_campaign = CampaignManifest.model_validate(
        campaign.model_dump(mode="json", by_alias=True)
    )
    try:
        if outcome.artifact_path != _AUTHORITY_ARTIFACT:
            raise ValueError("SUP-005A output artifact path differs")
        expected = _expected_authority(
            authoritative_campaign,
            invocation_completion,
            measured_outcome,
            journal=journal,
            schedule_publication=schedule_publication,
            invocation_authorities=invocation_authorities,
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_CAMPAIGN_BYTES,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
                "run.json": _MAX_RUN_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = SupervisorDeterministicBaselineLineageAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
        run_record = parse_strict_json_bytes(
            snapshot.artifact_bytes("run.json"),
            label="SUP-005A Run record",
            max_bytes=_MAX_RUN_BYTES,
        )
        final_artifacts = {artifact.path for artifact in snapshot.seals[-1].artifacts}
    except (
        OSError,
        RunIntegrityError,
        SupervisorInvocationRuntimeError,
        WalkingShadowMeasuredBenchmarkError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorDeterministicBaselineLineageError(
            "SUP-005A authority is not sealed and current"
        ) from exc
    expected_event_types = (
        "campaign.started",
        "benchmark.supervisor-baseline-lineage.created",
        "campaign.completed",
    )
    expected_run_record = {
        "runId": outcome.run_id,
        "status": "completed",
        "stage": "supervisor-deterministic-baseline-lineage-sealed",
        "authorityId": authority.authority_id,
        "comparisonState": authority.comparison_state,
    }
    if (
        sealed_campaign != authoritative_campaign
        or authority != outcome.authority
        or authority != expected
        or snapshot.verification.seal_count != 1
        or snapshot.verification.artifact_count != 3
        or final_artifacts != {"campaign.json", outcome.artifact_path, "run.json"}
        or tuple(event.event_type for event in snapshot.events) != expected_event_types
        or snapshot.events[0].payload
        != {
            "campaign": authoritative_campaign.metadata.name,
            "mode": authoritative_campaign.spec.mode.value,
            "purpose": "supervisor-deterministic-baseline-lineage",
        }
        or snapshot.events[2].payload
        != {
            "purpose": "supervisor-deterministic-baseline-lineage",
            "artifact": outcome.artifact_path,
        }
        or run_record != expected_run_record
    ):
        raise SupervisorDeterministicBaselineLineageError(
            "SUP-005A output differs from exact sealed sources"
        )
    expected_event = _publication_event_payload(outcome.artifact_path, authority)
    if snapshot.events[1].payload != expected_event:
        raise SupervisorDeterministicBaselineLineageError(
            "SUP-005A publication event differs"
        )
    return authority.model_copy(deep=True)


def _expected_authority(
    campaign: CampaignManifest,
    invocation_completion: SupervisorInvocationCompletion,
    measured_outcome: WalkingShadowMeasuredBenchmarkOutcome,
    *,
    journal: SupervisorInvocationJournal,
    schedule_publication: SupervisorCheckpointSchedulePublication,
    invocation_authorities: SupervisorInvocationAuthorities,
) -> SupervisorDeterministicBaselineLineageAuthority:
    if CampaignManifest.model_validate(
        invocation_authorities.campaign.model_dump(mode="json", by_alias=True)
    ) != campaign:
        raise ValueError("SUP-005A invocation and benchmark Campaigns differ")
    proposal = consume_supervisor_invocation(
        invocation_completion.publication,
        journal=journal,
        schedule_publication=schedule_publication,
        authorities=invocation_authorities,
    )
    if proposal != invocation_completion.proposal:
        raise ValueError("SUP-005A completion proposal differs from current B3 consumer")
    measured = load_walking_shadow_measured_benchmark_authority(
        campaign,
        measured_outcome,
    )
    policy = walking_shadow_supervisor_policy()
    if (
        proposal.compilation_policy.shadow_policy_id != policy.policy_id
        or proposal.shadow_policy_digest != policy.policy_digest
        or measured.candidate_policy_id != policy.policy_id
        or measured.candidate_policy_version != policy.policy_version
        or measured.candidate_policy_digest != policy.policy_digest
        or measured.supervisor_activation_eligible is not False
        or measured.measured_source.supervisor_activation_eligible is not False
    ):
        raise ValueError("SUP-005A sources do not share the exact WALK-006 policy")

    publication = invocation_completion.publication
    entry = publication.journal_entry
    receipt = publication.receipt
    if (
        entry.state is not SupervisorInvocationJournalState.TERMINAL_SUCCESS
        or entry.intent.receipt_path != _B3_RECEIPT_ARTIFACT
        or receipt.schedule_artifact_path != _SCHEDULE_ARTIFACT
        or receipt.provider_run_id == measured_outcome.run_id
    ):
        raise ValueError("SUP-005A source Run identities are not independent and terminal")
    invocation_snapshot = load_verified_run_artifacts(
        publication.run_path,
        requests={_B3_RECEIPT_ARTIFACT: _MAX_SOURCE_BYTES},
        expected_run_id=receipt.provider_run_id,
    )
    measurement_snapshot = load_verified_run_artifacts(
        measured_outcome.run_path,
        requests={_B2_AUTHORITY_ARTIFACT: _MAX_SOURCE_BYTES},
        expected_run_id=measured_outcome.run_id,
    )
    if (
        measured_outcome.artifact_path != _B2_AUTHORITY_ARTIFACT
        or invocation_snapshot.verification.root_digest != publication.final_root_digest
        or invocation_snapshot.verification.root_digest
        == measurement_snapshot.verification.root_digest
    ):
        raise ValueError("SUP-005A sealed source roots differ")
    receipt_bytes = invocation_snapshot.artifact_bytes(_B3_RECEIPT_ARTIFACT)
    measured_bytes = measurement_snapshot.artifact_bytes(_B2_AUTHORITY_ARTIFACT)
    if (
        sha256(receipt_bytes).hexdigest() != publication.receipt_sha256
    ):
        raise ValueError("SUP-005A sealed source bytes differ")

    candidate_observations = tuple(
        binding.observation
        for binding in measured.measured_source.observations
        if binding.observation.arm_id == measured.candidate_arm_id
    )
    if not candidate_observations:
        raise ValueError("SUP-005A measured source has no candidate coordinates")
    invocation_lineage = SupervisorBenchmarkInvocationLineage(
        journalIntentId=entry.intent.intent_id,
        journalIntentDigest=entry.intent.intent_digest,
        journalStateDigest=entry.state_digest,
        journalEventDigests=entry.event_digests,
        dispatchEventDigest=receipt.dispatch_event_digest,
        scheduleId=receipt.schedule_id,
        scheduleDigest=receipt.schedule_digest,
        checkpointKey=receipt.checkpoint_key,
        plannedCallIndex=receipt.planned_call_index,
        scheduleRunId=receipt.schedule_run_id,
        scheduleRootDigest=receipt.schedule_root_digest,
        scheduleArtifactPath=_SCHEDULE_ARTIFACT,
        scheduleArtifactSha256=receipt.schedule_artifact_sha256,
        requestBindingId=receipt.request_binding_id,
        requestBindingDigest=receipt.request_binding_digest,
        providerChatRequestDigest=receipt.provider_chat_request_digest,
        responseSchemaId=receipt.response_schema_id,
        responseSchemaDigest=receipt.response_schema_digest,
        dedicatedBudgetPolicyId=entry.intent.dedicated_budget_policy_id,
        dedicatedBudgetPolicyDigest=entry.intent.dedicated_budget_policy_digest,
        stableRequestId=receipt.stable_request_id,
        providerRunId=receipt.provider_run_id,
        providerRunRootDigest=publication.final_root_digest,
        receiptArtifactPath=_B3_RECEIPT_ARTIFACT,
        receiptArtifactSha256=publication.receipt_sha256,
        receiptId=receipt.receipt_id,
        receiptDigest=receipt.receipt_digest,
        providerOutcomeId=receipt.provider_outcome.outcome_id,
        providerOutcomeDigest=receipt.provider_outcome_digest,
        providerId=receipt.provider_outcome.provider_id,
        providerModel=receipt.provider_outcome.model,
        sourceSnapshotId=receipt.source_snapshot_id,
        sourceSnapshotDigest=receipt.source_snapshot_digest,
        modelBindingId=proposal.model_binding_id,
        modelBindingDigest=proposal.model_binding_digest,
        proposalId=proposal.proposal_id,
        proposalDigest=proposal.proposal_digest,
        proposalKind=proposal.source_proposal_kind.value,
        proposalCompilationPolicyDigest=proposal.compilation_policy_digest,
        shadowPolicyDigest=proposal.shadow_policy_digest,
        budgetScope=receipt.budget_scope,
    )
    measurement_lineage = SupervisorBenchmarkMeasurementLineage(
        authorityId=measured.authority_id,
        authorityDigest=measured.authority_digest,
        sourceRunId=measurement_snapshot.verification.run_id,
        sourceRootDigest=measurement_snapshot.verification.root_digest,
        sourceArtifactPath=_B2_AUTHORITY_ARTIFACT,
        sourceArtifactSha256=sha256(measured_bytes).hexdigest(),
        structuralAuthorityId=measured.structural_source.authority_id,
        structuralAuthorityDigest=measured.structural_source.authority_digest,
        measuredAuthorityId=measured.measured_source.authority_id,
        measuredAuthorityDigest=measured.measured_source.authority_digest,
        benchmarkId=measured.measured_source.manifest.benchmark_id,
        manifestDigest=measured.measured_source.manifest_digest,
        baselineArmId=measured.baseline_arm_id,
        candidateArmId=measured.candidate_arm_id,
        candidatePolicyId=measured.candidate_policy_id,
        candidatePolicyVersion=measured.candidate_policy_version,
        candidatePolicyDigest=measured.candidate_policy_digest,
        baselineResultDigest=measured.measured_source.baseline_result_digest,
        candidateResultDigest=measured.measured_source.candidate_result_digest,
        comparisonId=measured.measured_source.comparison.comparison_id,
        comparisonDigest=measured.measured_source.comparison_digest,
        candidateCoordinateCount=len(candidate_observations),
        candidateObservedModelCalls=sum(
            observation.model_call_count for observation in candidate_observations
        ),
    )
    return SupervisorDeterministicBaselineLineageAuthority(
        campaignManifestDigest=campaign_manifest_digest(campaign),
        supervisorCampaignDigest=proposal.campaign_digest,
        walkingCampaignDigest=measured.structural_source.source.campaign_digest,
        invocation=invocation_lineage,
        measurement=measurement_lineage,
        proposal=proposal,
        requiredMetrics=tuple(BENCHMARK_METRIC_ORDER),
    )


def _publication_event_payload(
    artifact_path: str,
    authority: SupervisorDeterministicBaselineLineageAuthority,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "invocationReceiptDigest": authority.invocation.receipt_digest,
        "proposalDigest": authority.proposal.proposal_digest,
        "benchmarkAuthorityDigest": authority.measurement.authority_digest,
        "benchmarkComparisonDigest": authority.measurement.comparison_digest,
        "comparisonState": authority.comparison_state,
        "modelProposalMeasurementAttributed": (
            authority.model_proposal_measurement_attributed
        ),
        "supervisorActivationEligible": authority.supervisor_activation_eligible,
    }


def _lineage_digest(domain: str, value: object) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Supervisor deterministic baseline lineage",
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + encoded).hexdigest()


__all__ = [
    "SUPERVISOR_DETERMINISTIC_BASELINE_LINEAGE_API_VERSION",
    "SupervisorBenchmarkInvocationLineage",
    "SupervisorBenchmarkMeasurementLineage",
    "SupervisorDeterministicBaselineLineageAuthority",
    "SupervisorDeterministicBaselineLineageError",
    "SupervisorDeterministicBaselineLineageOutcome",
    "SupervisorDeterministicBaselineLineageRunner",
    "load_supervisor_deterministic_baseline_lineage_authority",
]
