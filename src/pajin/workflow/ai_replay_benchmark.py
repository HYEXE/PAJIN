"""AI-001D fresh-session Replay, Control, and benchmark-contract binding."""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.redteam import (
    RedteamBenchmarkCapability,
    RedteamBenchmarkProfileSet,
    RedteamGroundTruthClass,
    RedteamMetricApplicability,
    RedteamProfileBenchmarkContract,
    registered_redteam_benchmark_profile_set,
)
from pajin.capabilities.existing import existing_mode_capability_bundle
from pajin.discovery.validation_depth import ValidationDepth
from pajin.domain.models import StrictModel, ToolRequest
from pajin.domain.replay import ReplaySessionPolicy
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.modes.ai_redteam.replay import KISAReplayBatchOutcome
from pajin.modes.ai_redteam.validation_controls import KISAValidationControlBatchOutcome
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.ai_analysis_admission import (
    AIAnalysisObservationAdmission,
    AIAnalysisObservationSourceInputs,
    load_verified_ai_analysis_observation_source,
)
from pajin.workflow.profile_evidence import (
    ProfileValidationEvidenceAssessment,
    evaluate_kisa_profile_validation_evidence,
)

AI_ANALYSIS_REPLAY_BENCHMARK_API_VERSION: Literal[
    "pajin.dev/ai-analysis-replay-benchmark-binding/v1alpha1"
] = "pajin.dev/ai-analysis-replay-benchmark-binding/v1alpha1"

_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_TRUE_FIELDS = (
    "sealed_ai_source_reverified",
    "fresh_session_replay_verified",
    "independent_controls_verified",
    "independent_profile_floor_satisfied",
    "benchmark_contract_registered",
    "ground_truth_vocabulary_bound",
    "negative_control_required",
    "replay_measurement_required",
)
_FALSE_FIELDS = (
    "ground_truth_case_bound",
    "benchmark_measurement_observed",
    "ai_observation_confirmed",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "tool_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "execution_authorized",
    "replay_authorized",
)


class AIReplayBenchmarkError(RuntimeError):
    """Raised when AI-001D predecessors or semantic coordinates differ."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class AIAnalysisReplayBenchmarkBinding(_FrozenStrictModel):
    """Content-addressed binding over independently sealed AI validation evidence."""

    api_version: Literal[
        "pajin.dev/ai-analysis-replay-benchmark-binding/v1alpha1"
    ] = Field(
        default=AI_ANALYSIS_REPLAY_BENCHMARK_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIAnalysisReplayBenchmarkBinding"] = (
        "AIAnalysisReplayBenchmarkBinding"
    )
    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    ai_admission: AIAnalysisObservationAdmission = Field(alias="aiAdmission")
    profile_validation: ProfileValidationEvidenceAssessment = Field(
        alias="profileValidation"
    )
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    redteam_profile_set: RedteamBenchmarkProfileSet = Field(alias="redteamProfileSet")
    redteam_profile: RedteamProfileBenchmarkContract = Field(alias="redteamProfile")
    redteam_capability: RedteamBenchmarkCapability = Field(alias="redteamCapability")
    ground_truth_classes: tuple[RedteamGroundTruthClass, ...] = Field(
        alias="groundTruthClasses",
        min_length=2,
        max_length=2,
    )
    scenario_id: str = Field(alias="scenarioId", min_length=1, max_length=200)
    threat_class: str = Field(alias="threatClass", min_length=1, max_length=200)
    state: Literal["fresh-session-replay-controls-benchmark-contract-bound"] = (
        "fresh-session-replay-controls-benchmark-contract-bound"
    )
    sealed_ai_source_reverified: Literal[True] = Field(
        default=True,
        alias="sealedAISourceReverified",
    )
    fresh_session_replay_verified: Literal[True] = Field(
        default=True,
        alias="freshSessionReplayVerified",
    )
    independent_controls_verified: Literal[True] = Field(
        default=True,
        alias="independentControlsVerified",
    )
    independent_profile_floor_satisfied: Literal[True] = Field(
        default=True,
        alias="independentProfileFloorSatisfied",
    )
    benchmark_contract_registered: Literal[True] = Field(
        default=True,
        alias="benchmarkContractRegistered",
    )
    ground_truth_vocabulary_bound: Literal[True] = Field(
        default=True,
        alias="groundTruthVocabularyBound",
    )
    negative_control_required: Literal[True] = Field(
        default=True,
        alias="negativeControlRequired",
    )
    replay_measurement_required: Literal[True] = Field(
        default=True,
        alias="replayMeasurementRequired",
    )
    ground_truth_case_bound: Literal[False] = Field(
        default=False,
        alias="groundTruthCaseBound",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    ai_observation_confirmed: Literal[False] = Field(
        default=False,
        alias="aiObservationConfirmed",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")

    @field_validator(*_TRUE_FIELDS, mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI-001D verified markers must be boolean true")
        return value

    @field_validator(*_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI-001D authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_replay_controls_and_benchmark(self) -> Self:
        try:
            domain_plan = resolve_registered_domain_benchmark_plan(
                self.domain_benchmark_plan
            )
            expected_profile_set = _registered_redteam_profile_set()
            expected_profile = expected_profile_set.profile(
                self.ai_admission.candidate.preparation.binding.capability_binding.profile.profile_id
            )
        except Exception as exc:
            raise ValueError("AI-001D benchmark authorities are not registered exactly") from exc

        static = self.ai_admission.candidate.preparation.binding.capability_binding
        matching_capabilities = tuple(
            item
            for item in expected_profile.capabilities
            if item.capability == static.capability
        )
        if len(matching_capabilities) != 1:
            raise ValueError("AI-001D Capability is outside the registered benchmark profile")
        expected_capability = matching_capabilities[0]
        replay = self.profile_validation.replay_evidence
        controls = self.profile_validation.control_evidence
        packet = replay.artifact_set.validation_packet
        spec = replay.artifact_set.spec
        contract = replay.artifact_set.contract
        request = self.ai_admission.candidate.preparation.prepared_action.request

        if (
            domain_plan.domain_classification.domain is not SecurityDomain.AI
            or domain_plan.validation_strategy
            is not DomainValidationStrategy.FRESH_SESSION_INDEPENDENT_REPLAY
            or self.redteam_profile_set != expected_profile_set
            or self.redteam_profile != expected_profile
            or self.redteam_capability != expected_capability
            or self.ground_truth_classes
            != (
                RedteamGroundTruthClass.KNOWN_POSITIVE,
                RedteamGroundTruthClass.NEGATIVE_CONTROL,
            )
            or expected_profile.false_positive_measurement
            is not RedteamMetricApplicability.REQUIRED
            or expected_profile.replay_measurement is not RedteamMetricApplicability.REQUIRED
            or expected_capability.replay_support_digest is None
            or contract.contract_id not in expected_capability.replay_contract_ids
            or controls is None
            or self.profile_validation.profile_floor.profile_id
            != "pajin.profile.ai-assessment"
            or self.profile_validation.achieved_depth
            is not ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY
            or spec.session_policy is not ReplaySessionPolicy.FRESH_SESSION
            or self.scenario_id != static.scenario_id
            or self.scenario_id != packet.scenario_id
            or self.scenario_id != spec.binding.scenario_id
            or self.scenario_id != controls.plan.scenario_id
            or self.threat_class != static.threat_class
            or self.threat_class != packet.threat_class
            or self.threat_class != spec.binding.threat_class
            or request.tool_id != spec.binding.tool_id
            or request.target != spec.binding.target
            or request.method != spec.method
        ):
            raise ValueError("AI-001D source, Replay, Control, or benchmark coordinates differ")

        _require_equivalent_fresh_session_semantics(
            ai_request=request,
            validation=self.profile_validation,
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-analysis-replay-benchmark-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"ai-analysis-replay-benchmark_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI-001D binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("AI-001D binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


def bind_ai_analysis_replay_controls_and_benchmark(
    inputs: AIAnalysisObservationSourceInputs,
    admission: AIAnalysisObservationAdmission,
    *,
    graph_store: SQLiteGraphStore,
    kisa_source_run_path: Path,
    candidate_id: str,
    replay_outcome: KISAReplayBatchOutcome,
    control_outcome: KISAValidationControlBatchOutcome,
) -> AIAnalysisReplayBenchmarkBinding:
    """Reopen every sealed predecessor and emit one non-authorizing AI-001D binding."""

    try:
        canonical_admission = AIAnalysisObservationAdmission.model_validate(
            admission.model_dump(mode="json", by_alias=True)
        )
        source = load_verified_ai_analysis_observation_source(
            inputs,
            graph_store=graph_store,
        )
        proposal = canonical_admission.candidate.proposal
        stored_event = graph_store.event_log.event_for_attempt(
            proposal.proposal_id,
            proposal.digest(),
        )
        candidate = canonical_admission.candidate
        if (
            stored_event != canonical_admission.graph_event
            or candidate.preparation != source.preparation
            or candidate.source_run_id != source.snapshot.verification.run_id
            or candidate.source_root_digest != source.snapshot.verification.root_digest
            or candidate.request_reservation_path != source.reservation_path
            or candidate.request_reservation_sha256 != source.reservation_sha256
            or candidate.execution_evidence_path != source.evidence_path
            or candidate.execution_evidence_sha256 != source.evidence_sha256
            or candidate.terminal_event_digest != source.terminal.event_digest
            or candidate.reconciliation_digest != source.reconciliation.reconciliation_digest
        ):
            raise ValueError("AI-001D admission differs from its sealed AI source")

        profile_validation = evaluate_kisa_profile_validation_evidence(
            "pajin.profile.ai-assessment",
            "1.0.0",
            candidate_id,
            kisa_source_run_path,
            replay_outcome,
            control_outcome,
        )
        profile_set = _registered_redteam_profile_set()
        static = candidate.preparation.binding.capability_binding
        profile = profile_set.profile(static.profile.profile_id)
        capability = next(
            item for item in profile.capabilities if item.capability == static.capability
        )
        return AIAnalysisReplayBenchmarkBinding(
            aiAdmission=canonical_admission,
            profileValidation=profile_validation,
            domainBenchmarkPlan=_ai_domain_benchmark_plan_ref(),
            redteamProfileSet=profile_set,
            redteamProfile=profile,
            redteamCapability=capability,
            groundTruthClasses=(
                RedteamGroundTruthClass.KNOWN_POSITIVE,
                RedteamGroundTruthClass.NEGATIVE_CONTROL,
            ),
            scenarioId=static.scenario_id,
            threatClass=static.threat_class,
        )
    except AIReplayBenchmarkError:
        raise
    except (
        AttributeError,
        KeyError,
        OSError,
        RuntimeError,
        StopIteration,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise AIReplayBenchmarkError(
            "AI-001D Replay, Control, and benchmark binding failed closed"
        ) from exc


def _require_equivalent_fresh_session_semantics(
    *,
    ai_request: ToolRequest,
    validation: ProfileValidationEvidenceAssessment,
) -> None:
    request = validation.replay_evidence.artifact_set.spec
    source_probe = AIChatProbeInput.model_validate(request.arguments)
    ai_probe = AIChatProbeInput.model_validate(ai_request.arguments)
    ai_semantics = ai_probe.model_dump(mode="json", exclude={"session_id"})
    source_semantics = source_probe.model_dump(mode="json", exclude={"session_id"})
    if ai_semantics != source_semantics:
        raise ValueError("AI-001D KISA source differs from the admitted AI probe semantics")

    replay = validation.replay_evidence
    controls = validation.control_evidence
    if controls is None:
        raise ValueError("AI-001D requires the independent three-Control set")
    replay_sessions = tuple(
        AIChatProbeInput.model_validate(attempt.materialization.arguments).session_id
        for attempt in replay.artifact_set.outcome.attempts
        if attempt.materialization is not None
    )
    control_sessions = tuple(item.session_id for item in controls.plan.controls)
    sessions = (
        ai_probe.session_id,
        source_probe.session_id,
        *replay_sessions,
        *control_sessions,
    )
    if len(replay_sessions) != replay.repetition_count or len(sessions) != len(set(sessions)):
        raise ValueError("AI-001D source, Replay, and Control sessions are not independent")

    ai_request_id = ai_request.request_id
    request_ids = (
        ai_request_id,
        request.binding.original_request_id,
        *replay.replay_request_ids,
        *(item.request_id for item in controls.requests),
    )
    if len(request_ids) != len(set(request_ids)):
        raise ValueError("AI-001D source, Replay, and Control request identities overlap")


def _ai_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.AI:
            return plan.reference()
    raise AIReplayBenchmarkError("DOMAIN-006 AI benchmark plan is missing")


@cache
def _registered_redteam_profile_set() -> RedteamBenchmarkProfileSet:
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
        demo_mcp_tool(),
    ):
        tools.register(tool)
    return registered_redteam_benchmark_profile_set(
        existing_mode_capability_bundle(tools, include_registered_mcp=True)
    )


__all__ = [
    "AI_ANALYSIS_REPLAY_BENCHMARK_API_VERSION",
    "AIAnalysisReplayBenchmarkBinding",
    "AIReplayBenchmarkError",
    "bind_ai_analysis_replay_controls_and_benchmark",
]
