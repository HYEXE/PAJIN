"""Server-owned derivation of non-executable KISA replay compilations."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Self, cast
from uuid import uuid4

from pydantic import Field, model_validator

from pajin.agents.base import CandidateAuthority
from pajin.control_plane.models import ArtifactRef
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CampaignMode,
    StrictModel,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.domain.orchestration import AgentNode, AgentRole, AgentStatus, TaskGraph, TaskStatus
from pajin.domain.replay import (
    ModeReplayContract,
    ReplayCompilation,
    ReplayPurpose,
    ReplayRetestContext,
    replay_evidence_digest,
    replay_request_digest,
)
from pajin.domain.validation import (
    CandidateFinding,
    ValidationDecision,
    ValidatorOutputArtifact,
    candidate_claim_digest,
    validator_finding_matches_candidate_claim,
)
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import KISAScenarioDefinition
from pajin.modes.ai_redteam.replay import (
    build_kisa_replay_compilation_inputs,
    derive_kisa_source_replay_context,
    eligible_for_kisa_replay,
    kisa_negative_retest_contract,
    kisa_replay_contract,
)
from pajin.modes.ai_redteam.replay_source import (
    SealedRunReader,
    confirmed_baseline_candidates,
    load_remediation_bindings,
    read_array,
    read_object,
    validate_completed_run,
    validate_parent_retest_plan_and_evidence,
    validate_retest_context,
)
from pajin.policy.capability import CapabilityRecord
from pajin.replay.compiler import ReplayCompiler
from pajin.replay.tickets import (
    canonical_replay_compilation_bytes,
    replay_context_digest,
)
from pajin.runtime.store import (
    AuditEvent,
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.tools.ai import AIChatProbeTool
from pajin.workflow.validation import validate_findings
from pajin.workflow.validation_artifacts import (
    VALIDATOR_OUTPUT_PATH,
    VERSIONED_VALIDATION_ROOT,
    load_source_validation_artifacts_from_snapshot,
    load_validation_snapshot,
)

KISA_CONFIRMATION_POLICY_VERSION = "pajin.kisa-confirmation:v1"
KISA_RETEST_POLICY_VERSION = "pajin.kisa-negative-retest:v1"
KISA_CONFIRMATION_REPETITIONS = 2
KISA_CONFIRMATION_REQUIRED_SUCCESSES = 2
KISA_CONFIRMATION_REQUIRED_ATTEMPTS = 1
KISA_CONFIRMATION_MAX_ATTEMPTS = 3

_SOURCE_ARTIFACT_MEDIA_TYPE = "application/vnd.pajin.run+directory"
_SOURCE_ARTIFACT_SCHEMA_KIND = "pajin.run.sealed.v1"
_REPLAY_RUN_ID = re.compile(r"^run_[0-9a-f]{32}$")
_MAX_KISA_SOURCE_JSON_BYTES = 64 * 1024 * 1024
_MAX_KISA_SOURCE_EVIDENCE_BYTES = 16 * 1024 * 1024
_KISA_SOURCE_FIXED_ARTIFACTS = (
    "run.json",
    "campaign.json",
    "plan.json",
    "capabilities.json",
    "budget.json",
    "rate-limits.json",
    "agents.json",
    "task-graph.json",
    "candidate-findings.json",
    VALIDATOR_OUTPUT_PATH,
    "validation-decisions.json",
    "findings.json",
)


class _BudgetSnapshot(StrictModel):
    agent_count: int = Field(alias="agentCount", strict=True, ge=0)
    max_agents: int = Field(alias="maxAgents", strict=True, ge=1)
    tool_calls: int = Field(alias="toolCalls", strict=True, ge=0)
    max_tool_calls: int = Field(alias="maxToolCalls", strict=True, ge=1)
    model_calls: int = Field(alias="modelCalls", strict=True, ge=0)
    max_model_calls: int = Field(alias="maxModelCalls", strict=True, ge=0)
    model_prompt_tokens: int = Field(alias="modelPromptTokens", strict=True, ge=0)
    model_completion_tokens: int = Field(alias="modelCompletionTokens", strict=True, ge=0)
    model_tokens: int = Field(alias="modelTokens", strict=True, ge=0)
    max_model_tokens: int = Field(alias="maxModelTokens", strict=True, ge=0)
    cost_usd: float = Field(alias="costUsd", strict=True, ge=0)
    max_cost_usd: float = Field(alias="maxCostUsd", strict=True, ge=0)
    elapsed_seconds: float = Field(alias="elapsedSeconds", strict=True, ge=0)
    duration_seconds: int = Field(alias="durationSeconds", strict=True, ge=1)

    @model_validator(mode="after")
    def require_consistent_totals(self) -> Self:
        if self.agent_count > self.max_agents:
            raise ValueError("sealed KISA budget agent usage exceeds its maximum")
        if self.tool_calls > self.max_tool_calls:
            raise ValueError("sealed KISA budget tool usage exceeds its maximum")
        if self.model_calls > self.max_model_calls:
            raise ValueError("sealed KISA budget model-call usage exceeds its maximum")
        if self.model_tokens != self.model_prompt_tokens + self.model_completion_tokens:
            raise ValueError("sealed KISA budget token total is inconsistent")
        if self.model_tokens > self.max_model_tokens:
            raise ValueError("sealed KISA budget model-token usage exceeds its maximum")
        if self.cost_usd > self.max_cost_usd:
            raise ValueError("sealed KISA budget cost exceeds its maximum")
        if self.elapsed_seconds > self.duration_seconds:
            raise ValueError("sealed KISA budget duration exceeds its maximum")
        return self


class _RateLimitSnapshot(StrictModel):
    ledger_id: str = Field(
        alias="ledgerId",
        pattern=r"^rate-ledger_[0-9a-f]{32}$",
    )
    reservation_counts: dict[str, int] = Field(alias="reservationCounts", max_length=1_000)

    @model_validator(mode="after")
    def require_bounded_counts(self) -> Self:
        if any(
            not campaign
            or len(campaign) > 128
            or type(count) is not int
            or count < 0
            or count > 1_000_000
            for campaign, count in self.reservation_counts.items()
        ):
            raise ValueError("sealed KISA rate-limit reservations are invalid")
        return self


@dataclass(frozen=True, slots=True)
class DerivedKISAReplayItem:
    """One canonical compiler output derived only from the sealed source."""

    candidate_id: str
    decision_id: str
    replay_run_id: str
    candidate: CandidateFinding
    decision: ValidationDecision
    scenario: KISAScenarioDefinition
    contract: ModeReplayContract
    compilation: ReplayCompilation
    canonical_compilation: bytes
    candidate_digest: str
    contract_digest: str
    compilation_digest: str
    grant_digest: str
    required_request_units: int
    required_attempts: int = KISA_CONFIRMATION_REQUIRED_ATTEMPTS
    max_attempts: int = KISA_CONFIRMATION_MAX_ATTEMPTS


@dataclass(frozen=True, slots=True)
class DerivedKISAReplayBatch:
    """Canonical planned batch; it carries no ticket or execution permission."""

    artifact_ref: ArtifactRef
    retest_artifact_ref: ArtifactRef | None
    campaign: CampaignManifest
    campaign_name: str
    candidate_run_id: str
    source_root_digest: str
    mode: CampaignMode
    purpose: ReplayPurpose
    policy_version: str
    compiled_at: datetime
    used_tool_calls: int
    max_tool_calls: int
    required_tool_calls: int
    budget_digest: str
    rate_limits_digest: str
    rate_ledger_id: str
    observed_campaign_request_units: int
    max_requests_per_minute: int | None
    required_request_units: int
    items: tuple[DerivedKISAReplayItem, ...]

    @property
    def capacity_artifact_ref(self) -> ArtifactRef:
        """Return the sealed Run whose budget and rate ledger fund execution."""

        return self.retest_artifact_ref or self.artifact_ref


@dataclass(frozen=True, slots=True)
class _CanonicalCandidateDerivation:
    candidates: list[CandidateFinding]
    results: list[ToolResult]
    authoritative_request_claims: set[CandidateAuthority]


@dataclass(frozen=True, slots=True)
class _ValidatorExecutionIdentity:
    validator_id: str
    validation_task_id: str
    running_sequence: int
    task_succeeded_sequence: int


@dataclass(frozen=True, slots=True)
class _ReadOnlyValidationStore:
    """Minimal validation Store facade that cannot mutate the managed source."""

    path: Path

    @property
    def evidence_path(self) -> Path:
        return self.path / "evidence"

    def append_event(self, _event_type: str, _payload: object = None) -> None:
        return None


def derive_kisa_confirmation_batch(
    *,
    source_root: Path,
    artifact_ref: ArtifactRef,
    replay_run_id_factory: Callable[[], str] = lambda: f"run_{uuid4().hex}",
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> DerivedKISAReplayBatch:
    """Compile all exact eligible KISA Candidates without issuing execution tickets."""

    root = source_root.resolve()
    snapshot = _load_kisa_source_snapshot(root)
    verification = snapshot.verification
    _require_artifact_binding(
        artifact_ref,
        run_id=verification.run_id,
        root_digest=verification.root_digest,
    )

    run_summary = _read_object(snapshot, "run.json")
    if run_summary.get("runId") != verification.run_id or run_summary.get("status") != "completed":
        raise ValueError("KISA replay derivation requires a sealed completed source Run")

    campaign = CampaignManifest.model_validate(_read_object(snapshot, "campaign.json"))
    if campaign.spec.mode is not CampaignMode.AI_REDTEAM:
        raise ValueError("KISA replay derivation requires an AI Red Team Campaign")
    plan = AgentPlan.model_validate(_read_object(snapshot, "plan.json"))
    validation = load_source_validation_artifacts_from_snapshot(snapshot)
    capability_records = [
        CapabilityRecord.model_validate(item) for item in _read_array(snapshot, "capabilities.json")
    ]
    budget = _BudgetSnapshot.model_validate(_read_object(snapshot, "budget.json"))
    rate_limits = _RateLimitSnapshot.model_validate(_read_object(snapshot, "rate-limits.json"))
    events = list(snapshot.events)
    _require_campaign_budget(campaign, budget, events=events)

    canonical_derivation = _derive_canonical_candidates(
        snapshot=snapshot,
        campaign=campaign,
        plan=plan,
        stored_candidates=validation.candidates,
    )
    validator = _derive_validator_identity(
        snapshot=snapshot,
        campaign=campaign,
        capability_records=capability_records,
    )
    validator_output = _load_validator_output(
        snapshot=snapshot,
        validator=validator,
        candidates=canonical_derivation.candidates,
    )
    canonical_decisions = _derive_canonical_decisions(
        snapshot=snapshot,
        campaign=campaign,
        candidates=canonical_derivation.candidates,
        results=canonical_derivation.results,
        authoritative_request_claims=canonical_derivation.authoritative_request_claims,
        validator=validator,
        validator_output=validator_output,
        stored_decisions=validation.decisions,
    )
    decisions_by_candidate = {decision.candidate_id: decision for decision in canonical_decisions}
    eligible = sorted(
        (
            (candidate, decisions_by_candidate[candidate.candidate_id])
            for candidate in canonical_derivation.candidates
            if eligible_for_kisa_replay(
                candidate,
                decisions_by_candidate[candidate.candidate_id],
            )
        ),
        key=lambda pair: pair[0].candidate_id,
    )
    if not eligible:
        raise ValueError("sealed KISA source contains no eligible confirmation Candidate")

    required_calls = len(eligible) * KISA_CONFIRMATION_REPETITIONS
    if budget.tool_calls + required_calls > budget.max_tool_calls:
        raise ValueError(
            "KISA replay derivation requires aggregate Campaign tool-call budget for every "
            "eligible Candidate"
        )

    compiled_at = _utc(clock())
    replay_run_ids: set[str] = set()
    items: list[DerivedKISAReplayItem] = []
    probe_tool = AIChatProbeTool()
    for candidate, decision in eligible:
        source = derive_kisa_source_replay_context(
            source_root=root,
            plan=plan,
            candidate=candidate,
            capability_records=capability_records,
            verified_source=snapshot,
            expected_run_id=artifact_ref.run_id,
            expected_root_digest=artifact_ref.integrity_root_digest,
        )
        contract = kisa_replay_contract(
            source.scenario.scenario_id,
            repetitions=KISA_CONFIRMATION_REPETITIONS,
            required_successes=KISA_CONFIRMATION_REQUIRED_SUCCESSES,
        )
        replay_run_id = replay_run_id_factory()
        if (
            not _REPLAY_RUN_ID.fullmatch(replay_run_id)
            or replay_run_id == verification.run_id
            or replay_run_id in replay_run_ids
        ):
            raise ValueError("KISA replay Run identity factory returned an invalid identity")
        replay_run_ids.add(replay_run_id)

        inputs = build_kisa_replay_compilation_inputs(
            source_root=root,
            candidate_run_id=verification.run_id,
            candidate=candidate,
            source=source,
            contract=contract,
            created_at=compiled_at,
            verified_source=snapshot,
            expected_run_id=artifact_ref.run_id,
            expected_root_digest=artifact_ref.integrity_root_digest,
        )
        compilation = ReplayCompiler.compile(
            campaign=campaign,
            plan=plan,
            original_request=source.original_request,
            source_capability=source.source_capability,
            validation_packet=inputs.validation_packet,
            intent=inputs.intent,
            contract=contract,
            scenario=source.scenario,
            registered_tools={AIChatProbeTool.spec.tool_id: AIChatProbeTool.spec},
            evidence_by_request=source.evidence_by_request,
            trusted_original_request_digest=replay_request_digest(source.original_request),
            trusted_original_evidence_digest=replay_evidence_digest(
                source.evidence_by_request[source.original_request.request_id]
            ),
            replay_run_id=replay_run_id,
            used_campaign_calls=budget.tool_calls,
            compiled_at=compiled_at,
        )
        canonical_compilation = canonical_replay_compilation_bytes(compilation)
        required_request_units = (
            probe_tool.network_request_cost(compilation.original_request) * contract.repetitions
        )
        items.append(
            DerivedKISAReplayItem(
                candidate_id=candidate.candidate_id,
                decision_id=decision.decision_id,
                replay_run_id=replay_run_id,
                candidate=candidate,
                decision=decision,
                scenario=source.scenario,
                contract=contract,
                compilation=compilation,
                canonical_compilation=canonical_compilation,
                candidate_digest=replay_context_digest(candidate),
                contract_digest=replay_context_digest(contract),
                compilation_digest=sha256(canonical_compilation).hexdigest(),
                grant_digest=replay_context_digest(compilation.grant),
                required_request_units=required_request_units,
            )
        )

    final_snapshot = load_verified_run_snapshot(root, expected_run_id=verification.run_id)
    require_same_authority(
        snapshot,
        final_snapshot,
        message="sealed KISA source changed during replay derivation",
    )
    return DerivedKISAReplayBatch(
        artifact_ref=artifact_ref,
        retest_artifact_ref=None,
        campaign=campaign,
        campaign_name=campaign.metadata.name,
        candidate_run_id=verification.run_id,
        source_root_digest=verification.root_digest,
        mode=CampaignMode.AI_REDTEAM,
        purpose=ReplayPurpose.CONFIRMATION,
        policy_version=KISA_CONFIRMATION_POLICY_VERSION,
        compiled_at=compiled_at,
        used_tool_calls=budget.tool_calls,
        max_tool_calls=budget.max_tool_calls,
        required_tool_calls=required_calls,
        budget_digest=replay_context_digest(budget),
        rate_limits_digest=replay_context_digest(rate_limits),
        rate_ledger_id=rate_limits.ledger_id,
        observed_campaign_request_units=rate_limits.reservation_counts.get(
            campaign.metadata.name,
            0,
        ),
        max_requests_per_minute=campaign.spec.rules_of_engagement.max_requests_per_minute,
        required_request_units=sum(item.required_request_units for item in items),
        items=tuple(items),
    )


def derive_kisa_retest_batch(
    *,
    source_root: Path,
    artifact_ref: ArtifactRef,
    retest_root: Path,
    retest_artifact_ref: ArtifactRef,
    replay_run_id_factory: Callable[[], str] = lambda: f"run_{uuid4().hex}",
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> DerivedKISAReplayBatch:
    """Compile a baseline-bound negative batch from two immutable managed Runs."""

    baseline_path = source_root.resolve()
    parent_path = retest_root.resolve()
    baseline_reader = SealedRunReader.open(baseline_path)
    parent_reader = SealedRunReader.open(parent_path)
    baseline_verification = baseline_reader.verification
    parent_verification = parent_reader.verification
    _require_artifact_binding(
        artifact_ref,
        run_id=baseline_verification.run_id,
        root_digest=baseline_verification.root_digest,
    )
    _require_artifact_binding(
        retest_artifact_ref,
        run_id=parent_verification.run_id,
        root_digest=parent_verification.root_digest,
    )
    validate_completed_run(baseline_reader, label="baseline")
    validate_completed_run(parent_reader, label="Retest")
    if baseline_verification.run_id == parent_verification.run_id:
        raise ValueError("KISA retest requires distinct baseline and parent Retest Runs")

    campaign = CampaignManifest.model_validate(read_object(baseline_reader, "campaign.json"))
    parent_campaign = CampaignManifest.model_validate(read_object(parent_reader, "campaign.json"))
    if campaign != parent_campaign or campaign.spec.mode is not CampaignMode.AI_REDTEAM:
        raise ValueError("KISA baseline and parent Retest Campaigns must match exactly")
    plan = AgentPlan.model_validate(read_object(baseline_reader, "plan.json"))
    capability_records = [
        CapabilityRecord.model_validate(item)
        for item in read_array(baseline_reader, "capabilities.json")
    ]
    validation = load_validation_snapshot(
        baseline_path,
        verified_snapshot=baseline_reader.snapshot,
    )
    confirmed = confirmed_baseline_candidates(validation.validation)
    if not confirmed:
        raise ValueError("KISA retest requires at least one confirmed baseline Candidate")
    remediation = load_remediation_bindings(baseline_reader)
    expected_ids = {candidate.candidate_id for candidate, _decision in confirmed}
    if set(remediation) != expected_ids:
        raise ValueError("KISA remediation plan must exactly cover confirmed baseline Candidates")

    validate_parent_retest_plan_and_evidence(
        parent_reader,
        campaign=campaign,
        repetitions=KISA_CONFIRMATION_REPETITIONS,
    )
    budget = _BudgetSnapshot.model_validate(read_object(parent_reader, "budget.json"))
    rate_limits = _RateLimitSnapshot.model_validate(read_object(parent_reader, "rate-limits.json"))
    _require_campaign_budget(campaign, budget, events=list(parent_reader.events))
    required_calls = len(confirmed) * KISA_CONFIRMATION_REPETITIONS
    if budget.tool_calls + required_calls > budget.max_tool_calls:
        raise ValueError(
            "KISA retest requires shared parent Retest tool-call budget for every Candidate"
        )

    compiled_at = _utc(clock())
    probe_tool = AIChatProbeTool()
    replay_run_ids: set[str] = set()
    items: list[DerivedKISAReplayItem] = []
    for candidate, decision in confirmed:
        binding = remediation[candidate.candidate_id]
        context = ReplayRetestContext(
            baselineDecisionId=decision.decision_id,
            baselineFindingId=candidate.claim.finding_id,
            remediationId=binding.remediation_id,
            retestRunId=parent_verification.run_id,
            retestSourceRootDigest=parent_verification.root_digest,
        )
        validate_retest_context(
            candidate=candidate,
            decision=decision,
            context=context,
            remediation=binding,
            retest_verification=parent_verification,
        )
        source = derive_kisa_source_replay_context(
            source_root=baseline_path,
            plan=plan,
            candidate=candidate,
            capability_records=capability_records,
            verified_source=baseline_reader.snapshot,
            expected_run_id=artifact_ref.run_id,
            expected_root_digest=artifact_ref.integrity_root_digest,
        )
        contract = kisa_negative_retest_contract(
            source.scenario.scenario_id,
            repetitions=KISA_CONFIRMATION_REPETITIONS,
        )
        replay_run_id = replay_run_id_factory()
        if (
            not _REPLAY_RUN_ID.fullmatch(replay_run_id)
            or replay_run_id in {
                baseline_verification.run_id,
                parent_verification.run_id,
            }
            or replay_run_id in replay_run_ids
        ):
            raise ValueError("KISA replay Run identity factory returned an invalid identity")
        replay_run_ids.add(replay_run_id)
        inputs = build_kisa_replay_compilation_inputs(
            source_root=baseline_path,
            candidate_run_id=baseline_verification.run_id,
            candidate=candidate,
            source=source,
            contract=contract,
            created_at=compiled_at,
            retest_context=context,
            verified_source=baseline_reader.snapshot,
            expected_run_id=artifact_ref.run_id,
            expected_root_digest=artifact_ref.integrity_root_digest,
        )
        compilation = ReplayCompiler.compile(
            campaign=campaign,
            plan=plan,
            original_request=source.original_request,
            source_capability=source.source_capability,
            validation_packet=inputs.validation_packet,
            intent=inputs.intent,
            contract=contract,
            scenario=source.scenario,
            registered_tools={AIChatProbeTool.spec.tool_id: AIChatProbeTool.spec},
            evidence_by_request=source.evidence_by_request,
            trusted_original_request_digest=replay_request_digest(source.original_request),
            trusted_original_evidence_digest=replay_evidence_digest(
                source.evidence_by_request[source.original_request.request_id]
            ),
            replay_run_id=replay_run_id,
            used_campaign_calls=budget.tool_calls,
            compiled_at=compiled_at,
        )
        canonical_compilation = canonical_replay_compilation_bytes(compilation)
        required_request_units = (
            probe_tool.network_request_cost(compilation.original_request) * contract.repetitions
        )
        items.append(
            DerivedKISAReplayItem(
                candidate_id=candidate.candidate_id,
                decision_id=decision.decision_id,
                replay_run_id=replay_run_id,
                candidate=candidate,
                decision=decision,
                scenario=source.scenario,
                contract=contract,
                compilation=compilation,
                canonical_compilation=canonical_compilation,
                candidate_digest=replay_context_digest(candidate),
                contract_digest=replay_context_digest(contract),
                compilation_digest=sha256(canonical_compilation).hexdigest(),
                grant_digest=replay_context_digest(compilation.grant),
                required_request_units=required_request_units,
            )
        )

    baseline_reader.require_current()
    parent_reader.require_current()
    return DerivedKISAReplayBatch(
        artifact_ref=artifact_ref,
        retest_artifact_ref=retest_artifact_ref,
        campaign=campaign,
        campaign_name=campaign.metadata.name,
        candidate_run_id=baseline_verification.run_id,
        source_root_digest=baseline_verification.root_digest,
        mode=CampaignMode.AI_REDTEAM,
        purpose=ReplayPurpose.REMEDIATION_RETEST,
        policy_version=KISA_RETEST_POLICY_VERSION,
        compiled_at=compiled_at,
        used_tool_calls=budget.tool_calls,
        max_tool_calls=budget.max_tool_calls,
        required_tool_calls=required_calls,
        budget_digest=replay_context_digest(budget),
        rate_limits_digest=replay_context_digest(rate_limits),
        rate_ledger_id=rate_limits.ledger_id,
        observed_campaign_request_units=rate_limits.reservation_counts.get(
            campaign.metadata.name,
            0,
        ),
        max_requests_per_minute=campaign.spec.rules_of_engagement.max_requests_per_minute,
        required_request_units=sum(item.required_request_units for item in items),
        items=tuple(items),
    )


def _derive_canonical_candidates(
    *,
    snapshot: VerifiedRunSnapshot,
    campaign: CampaignManifest,
    plan: AgentPlan,
    stored_candidates: list[CandidateFinding],
) -> _CanonicalCandidateDerivation:
    """Re-run the trusted producer and reject any stored Candidate substitution."""

    results = _load_planned_tool_results(snapshot, plan)
    producer = KISACandidateProducer()
    production = producer.produce(campaign, plan, results)
    derived = list(production.candidates)
    stored_marked_trusted = [
        candidate
        for candidate in stored_candidates
        if candidate.source == producer.candidate_source
        and candidate.source_agent_id == producer.producer_id
    ]
    derived_ids = {candidate.candidate_id for candidate in derived}
    stored_by_id = {candidate.candidate_id: candidate for candidate in stored_marked_trusted}
    if (
        derived_ids != set(stored_by_id)
        or len(stored_marked_trusted) != len(stored_candidates)
        or len(stored_candidates) != len(derived)
    ):
        raise ValueError("sealed KISA Candidates differ from trusted producer derivation")

    canonical: list[CandidateFinding] = []
    for candidate in derived:
        stored = stored_by_id[candidate.candidate_id]
        normalized = candidate.model_copy(update={"created_at": stored.created_at})
        if normalized != stored:
            raise ValueError("sealed KISA Candidate differs from trusted producer output")
        canonical.append(normalized)
    if canonical != stored_candidates:
        raise ValueError("sealed KISA Candidate order differs from trusted producer output")
    return _CanonicalCandidateDerivation(
        candidates=canonical,
        results=results,
        authoritative_request_claims=set(production.authoritative_request_claims),
    )


def _derive_validator_identity(
    *,
    snapshot: VerifiedRunSnapshot,
    campaign: CampaignManifest,
    capability_records: list[CapabilityRecord],
) -> _ValidatorExecutionIdentity:
    """Bind the semantic Validator to its completed Agent, Task, and grant lineage."""

    agents = [AgentNode.model_validate(item) for item in _read_array(snapshot, "agents.json")]
    if len({agent.agent_id for agent in agents}) != len(agents):
        raise ValueError("sealed KISA Agent graph contains duplicate identities")
    supervisors = [agent for agent in agents if agent.role is AgentRole.SUPERVISOR]
    validators = [agent for agent in agents if agent.role is AgentRole.VALIDATOR]
    if len(supervisors) != 1 or len(validators) != 1:
        raise ValueError("sealed KISA source must contain one Supervisor and one Validator")
    supervisor = supervisors[0]
    validator = validators[0]
    if (
        supervisor.status is not AgentStatus.COMPLETED
        or supervisor.error is not None
        or supervisor.parent_agent_id is not None
        or supervisor.depth != 0
        or validator.status is not AgentStatus.COMPLETED
        or validator.error is not None
        or validator.parent_agent_id != supervisor.agent_id
        or validator.depth != 1
    ):
        raise ValueError("sealed KISA Validator Agent role lineage is not completed and exact")

    graph = TaskGraph.model_validate(_read_object(snapshot, "task-graph.json"))
    validation_tasks = [
        task
        for task in graph.tasks.values()
        if task.title == "Independently validate candidate findings"
    ]
    if len(validation_tasks) != 1:
        raise ValueError("sealed KISA source must contain one semantic validation Task")
    validation_task = validation_tasks[0]
    agents_by_id = {agent.agent_id: agent for agent in agents}
    if (
        validation_task.assigned_agent_id != validator.agent_id
        or validation_task.status is not TaskStatus.SUCCEEDED
        or validation_task.error is not None
        or validation_task.request is not None
        or validation_task.attempts != 0
        or validation_task.max_attempts != 1
        or not validation_task.depends_on
    ):
        raise ValueError("sealed KISA validation Task is not bound to the completed Validator")
    for dependency_id in validation_task.depends_on:
        dependency = graph.tasks[dependency_id]
        assigned = agents_by_id.get(dependency.assigned_agent_id or "")
        if (
            dependency.status is not TaskStatus.SUCCEEDED
            or dependency.request is None
            or assigned is None
            or assigned.role is not AgentRole.SPECIALIST
            or assigned.status is not AgentStatus.COMPLETED
        ):
            raise ValueError("sealed KISA validation Task does not follow completed Specialists")

    records_by_id = {record.grant.grant_id: record for record in capability_records}
    if len(records_by_id) != len(capability_records):
        raise ValueError("sealed KISA capability ledger contains duplicate grants")
    supervisor_record = records_by_id.get(supervisor.capability_grant_id)
    validator_record = records_by_id.get(validator.capability_grant_id)
    if supervisor_record is None or validator_record is None:
        raise ValueError("sealed KISA Validator Agent has no exact capability lineage")
    supervisor_grant = supervisor_record.grant
    validator_grant = validator_record.grant
    if (
        supervisor_grant.subject != supervisor.agent_id
        or supervisor_grant.campaign != campaign.metadata.name
        or supervisor_grant.parent_grant_id is not None
        or supervisor_grant.depth != 0
        or not supervisor_grant.delegable
        or validator_grant.subject != validator.agent_id
        or validator_grant.campaign != campaign.metadata.name
        or validator_grant.parent_grant_id != supervisor_grant.grant_id
        or validator_grant.depth != 1
        or validator_grant.tools
        or validator_grant.targets
        or validator_grant.max_risk_tier is not ToolRiskTier.T0
        or validator_grant.max_calls != 0
        or validator_record.remaining_calls != 0
        or validator_grant.delegable
        or not validator_grant.attenuates(supervisor_grant)
    ):
        raise ValueError("sealed KISA Validator capability lineage is not least privilege")

    events = list(snapshot.events)
    expected_spawn = {
        "agentId": validator.agent_id,
        "role": AgentRole.VALIDATOR.value,
        "parentAgentId": supervisor.agent_id,
        "depth": 1,
        "grantId": validator_grant.grant_id,
    }
    expected_completed = {
        "agentId": validator.agent_id,
        "role": AgentRole.VALIDATOR.value,
        "error": None,
    }
    expected_running = {
        "agentId": validator.agent_id,
        "role": AgentRole.VALIDATOR.value,
        "error": None,
    }
    expected_task = {"taskId": validation_task.task_id, "error": None}
    spawned = _matching_events(events, "agent.spawned", expected_spawn)
    running = _matching_events(events, "agent.running", expected_running)
    task_succeeded = _matching_events(events, "task.succeeded", expected_task)
    completed = _matching_events(events, "agent.completed", expected_completed)
    validated = [event for event in events if event.event_type == "findings.validated"]
    if (
        len(spawned) != 1
        or len(running) != 1
        or len(task_succeeded) != 1
        or len(completed) != 1
        or len(validated) != 1
    ):
        raise ValueError("sealed KISA Validator identity differs from its audit lineage")
    if not (
        spawned[0].sequence
        < running[0].sequence
        < task_succeeded[0].sequence
        < completed[0].sequence
    ):
        raise ValueError("sealed KISA Validator lifecycle event sequence is not exact")
    _require_post_execution_revocation(
        events,
        (
            (supervisor_record, completed[0].sequence),
            (validator_record, validated[0].sequence),
        ),
    )
    return _ValidatorExecutionIdentity(
        validator_id=validator.agent_id,
        validation_task_id=validation_task.task_id,
        running_sequence=running[0].sequence,
        task_succeeded_sequence=task_succeeded[0].sequence,
    )


def _require_post_execution_revocation(
    events: list[AuditEvent],
    records: tuple[tuple[CapabilityRecord, int], ...],
) -> None:
    """Treat snapshot revocation as live state while preserving historical authority."""

    for record, after_sequence in records:
        grant_id = record.grant.grant_id
        revocations = [
            event
            for event in events
            if event.event_type == "capability.revoked"
            and isinstance(event.payload.get("revokedGrantIds"), list)
            and grant_id in event.payload["revokedGrantIds"]
        ]
        if record.revoked != bool(revocations):
            raise ValueError("sealed KISA capability live revocation state is inconsistent")
        if any(event.sequence <= after_sequence for event in revocations):
            raise ValueError("sealed KISA capability was revoked before execution completed")


def _load_validator_output(
    *,
    snapshot: VerifiedRunSnapshot,
    validator: _ValidatorExecutionIdentity,
    candidates: list[CandidateFinding],
) -> ValidatorOutputArtifact:
    """Load one exact Candidate-aware Validator output from the pinned source snapshot."""

    output = ValidatorOutputArtifact.model_validate(_read_object(snapshot, VALIDATOR_OUTPUT_PATH))
    if (
        output.source_run_id != snapshot.verification.run_id
        or output.validator_id != validator.validator_id
        or output.validation_task_id != validator.validation_task_id
    ):
        raise ValueError("sealed KISA Validator output belongs to another Run, Agent, or Task")

    candidates_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    assessments_by_id = {assessment.candidate_id: assessment for assessment in output.assessments}
    if set(assessments_by_id) != set(candidates_by_id):
        raise ValueError("sealed KISA Validator output must assess every exact Candidate once")
    claimed_finding_indices: set[int] = set()
    for candidate_id, assessment in assessments_by_id.items():
        candidate = candidates_by_id[candidate_id]
        if assessment.claim_digest != candidate_claim_digest(candidate):
            raise ValueError("sealed KISA Validator assessment differs from its Candidate claim")
        if assessment.supports_claim:
            if assessment.supporting_evidence != candidate.claim.evidence:
                raise ValueError(
                    "sealed KISA supporting assessment differs from exact Candidate evidence"
                )
            matching_finding_indices = [
                finding_index
                for finding_index, finding in enumerate(output.findings)
                if finding.validated
                and validator_finding_matches_candidate_claim(candidate.claim, finding)
            ]
            if (
                len(matching_finding_indices) != 1
                or matching_finding_indices[0] in claimed_finding_indices
            ):
                raise ValueError(
                    "sealed KISA supporting assessment has no unique exact Validator Finding"
                )
            claimed_finding_indices.add(matching_finding_indices[0])
    return output


def _derive_canonical_decisions(
    *,
    snapshot: VerifiedRunSnapshot,
    campaign: CampaignManifest,
    candidates: list[CandidateFinding],
    results: list[ToolResult],
    authoritative_request_claims: set[CandidateAuthority],
    validator: _ValidatorExecutionIdentity,
    validator_output: ValidatorOutputArtifact,
    stored_decisions: list[ValidationDecision],
) -> list[ValidationDecision]:
    """Replay the gate from the exact sealed Validator output and compare Decisions."""

    replay_store = cast(RunStore, _ReadOnlyValidationStore(path=snapshot.run_path))
    replayed = validate_findings(
        campaign,
        results,
        [finding.model_copy(deep=True) for finding in validator_output.findings],
        replay_store,
        validator_id=validator.validator_id,
        validator_assessments=[
            assessment.model_copy(deep=True) for assessment in validator_output.assessments
        ],
        admitted_candidates=candidates,
        producer_authoritative_request_claims=authoritative_request_claims,
        pinned_evidence=snapshot.artifacts,
    )
    if replayed.candidates != candidates or replayed.confirmed_findings:
        raise ValueError("trusted KISA validation replay changed the canonical Candidate set")
    stored_by_candidate = {decision.candidate_id: decision for decision in stored_decisions}
    if (
        len(stored_by_candidate) != len(stored_decisions)
        or set(stored_by_candidate) != {candidate.candidate_id for candidate in candidates}
        or len(replayed.decisions) != len(stored_decisions)
    ):
        raise ValueError("sealed KISA Decisions differ from trusted validation replay")

    events = list(snapshot.events)
    canonical: list[ValidationDecision] = []
    previous_terminal_sequence = validator.running_sequence
    for decision in replayed.decisions:
        stored = stored_by_candidate[decision.candidate_id]
        first_sequence, terminal_sequence = _validate_decision_event_lineage(
            events,
            candidate=next(
                candidate
                for candidate in candidates
                if candidate.candidate_id == decision.candidate_id
            ),
            decision=stored,
        )
        if first_sequence <= previous_terminal_sequence:
            raise ValueError("sealed KISA Decision event sequence is not canonical")
        previous_terminal_sequence = terminal_sequence
        normalized = decision.model_copy(update={"decided_at": stored.decided_at})
        if normalized != stored:
            raise ValueError("sealed KISA Decision differs from trusted validation output")
        canonical.append(normalized)
    if canonical != stored_decisions:
        raise ValueError("sealed KISA Decision order differs from trusted validation output")
    if previous_terminal_sequence >= validator.task_succeeded_sequence:
        raise ValueError("sealed KISA Decisions do not precede Validator completion")
    return canonical


def _validate_decision_event_lineage(
    events: list[AuditEvent],
    *,
    candidate: CandidateFinding,
    decision: ValidationDecision,
) -> tuple[int, int]:
    pending_payload = {
        "candidateId": candidate.candidate_id,
        "findingId": candidate.claim.finding_id,
        "decisionId": decision.decision_id,
        "validatorId": decision.validator_id,
        "reasonCodes": [],
    }
    decided_payload = {
        **pending_payload,
        "reasonCodes": [reason.value for reason in decision.reason_codes],
    }
    validator_running = _matching_events(
        events,
        "agent.running",
        {
            "agentId": decision.validator_id,
            "role": AgentRole.VALIDATOR.value,
            "error": None,
        },
    )
    created = _matching_events(events, "candidate.finding.created", pending_payload)
    started = _matching_events(events, "validation.started", pending_payload)
    decided = _matching_events(
        events,
        f"validation.{decision.disposition.value}",
        decided_payload,
    )
    rejected = _matching_events(events, "finding.rejected", decided_payload)
    event_matches = (validator_running, created, started, decided, rejected)
    if not all(len(matches) == 1 for matches in event_matches):
        raise ValueError("sealed KISA Decision has no unique audit event lineage")
    if not (
        validator_running[0].occurred_at
        <= decision.decided_at
        <= created[0].occurred_at
        <= started[0].occurred_at
        <= decided[0].occurred_at
        <= rejected[0].occurred_at
    ):
        raise ValueError("sealed KISA Decision timestamp is outside its audit event lineage")
    if not (
        validator_running[0].sequence
        < created[0].sequence
        < started[0].sequence
        < decided[0].sequence
        < rejected[0].sequence
    ):
        raise ValueError("sealed KISA Decision audit event sequence is not exact")
    return created[0].sequence, rejected[0].sequence


def _matching_events(
    events: list[AuditEvent],
    event_type: str,
    payload: Mapping[str, object],
) -> list[AuditEvent]:
    return [
        event for event in events if event.event_type == event_type and event.payload == payload
    ]


def _load_planned_tool_results(
    snapshot: VerifiedRunSnapshot,
    plan: AgentPlan,
) -> list[ToolResult]:
    """Reconstruct producer inputs from exact Gateway evidence, never Candidate files."""

    results: list[ToolResult] = []
    for step in plan.steps:
        reference = f"evidence/{step.request.request_id}.json"
        if reference not in snapshot.artifacts:
            continue
        payload = _read_object(snapshot, reference)
        try:
            executed_request = ToolRequest.model_validate(payload.get("request"))
            result_value = payload.get("result")
            if not isinstance(result_value, dict):
                raise ValueError("Gateway result must be an object")
            serialized_result = dict(result_value)
            serialized_result["evidence"] = [reference]
            result = ToolResult.model_validate(serialized_result)
        except ValueError as exc:
            raise ValueError("sealed KISA Gateway evidence is not canonical") from exc
        if (
            executed_request.model_dump(mode="json", exclude={"agent_id"})
            != step.request.model_dump(mode="json", exclude={"agent_id"})
            or result.request_id != executed_request.request_id
            or result.tool_id != executed_request.tool_id
        ):
            raise ValueError("sealed KISA Gateway evidence differs from its Plan step")
        results.append(result)
    return results


def _require_artifact_binding(
    artifact_ref: ArtifactRef,
    *,
    run_id: str,
    root_digest: str,
) -> None:
    if (
        artifact_ref.media_type != _SOURCE_ARTIFACT_MEDIA_TYPE
        or artifact_ref.schema_kind != _SOURCE_ARTIFACT_SCHEMA_KIND
        or artifact_ref.run_id != run_id
        or artifact_ref.integrity_root_digest != root_digest
    ):
        raise ValueError("managed ArtifactRef does not bind the sealed KISA source Run")


def _require_campaign_budget(
    campaign: CampaignManifest,
    snapshot: _BudgetSnapshot,
    *,
    events: list[AuditEvent],
) -> None:
    budgets = campaign.spec.budgets
    if (
        snapshot.max_agents != budgets.max_agents
        or snapshot.max_tool_calls != budgets.max_tool_calls
        or snapshot.max_model_calls != budgets.max_model_calls
        or snapshot.max_model_tokens != budgets.max_model_tokens
        or snapshot.max_cost_usd != budgets.max_cost_usd
        or snapshot.duration_seconds != budgets.duration_seconds
    ):
        raise ValueError("sealed KISA budget maxima differ from the Campaign contract")
    if snapshot.tool_calls != _executed_tool_call_count(events):
        raise ValueError("sealed KISA budget tool-call usage differs from execution lineage")


def _executed_tool_call_count(events: list[AuditEvent]) -> int:
    """Count exact completed Gateway dispatches that consume the Tool-call budget."""

    def execution_key(event: AuditEvent) -> tuple[str, str]:
        request_id = event.payload.get("requestId")
        execution_id = event.payload.get("executionId")
        if not isinstance(request_id, str) or not isinstance(execution_id, str):
            raise ValueError("sealed KISA Worker event has no exact execution identity")
        return request_id, execution_id

    dispatched = [
        execution_key(event) for event in events if event.event_type == "worker.dispatched"
    ]
    completed = [execution_key(event) for event in events if event.event_type == "worker.completed"]
    if (
        len(dispatched) != len(set(dispatched))
        or len(completed) != len(set(completed))
        or set(completed) != set(dispatched)
    ):
        raise ValueError("sealed KISA Worker dispatch/completion lineage is not exact")
    return len(dispatched)


def _load_kisa_source_snapshot(root: Path) -> VerifiedRunSnapshot:
    initial = load_verified_run_snapshot(root)
    sealed_paths = frozenset(artifact.path for seal in initial.seals for artifact in seal.artifacts)
    if any(path.startswith(f"{VERSIONED_VALIDATION_ROOT}/") for path in sealed_paths):
        raise ValueError(
            "KISA replay derivation rejects an already-versioned validation projection"
        )

    fixed_requests = {path: _MAX_KISA_SOURCE_JSON_BYTES for path in _KISA_SOURCE_FIXED_ARTIFACTS}
    preliminary = load_verified_run_artifacts(
        root,
        requests=fixed_requests,
        expected_run_id=initial.verification.run_id,
    )
    require_same_authority(
        initial,
        preliminary,
        message="sealed KISA source changed during replay derivation",
    )
    plan = AgentPlan.model_validate(_read_object(preliminary, "plan.json"))
    evidence_paths = {
        f"evidence/{step.request.request_id}.json"
        for step in plan.steps
        if f"evidence/{step.request.request_id}.json" in sealed_paths
    }
    requests = dict(fixed_requests)
    requests.update({path: _MAX_KISA_SOURCE_EVIDENCE_BYTES for path in evidence_paths})
    snapshot = load_verified_run_artifacts(
        root,
        requests=requests,
        expected_run_id=initial.verification.run_id,
    )
    require_same_authority(
        preliminary,
        snapshot,
        message="sealed KISA source changed during replay derivation",
    )
    return snapshot


def _read_object(
    snapshot: VerifiedRunSnapshot,
    relative_path: str,
) -> dict[str, object]:
    max_bytes = (
        _MAX_KISA_SOURCE_EVIDENCE_BYTES
        if relative_path.startswith("evidence/")
        else _MAX_KISA_SOURCE_JSON_BYTES
    )
    return strict_json(
        snapshot,
        relative_path,
        label=f"sealed KISA source artifact {relative_path}",
        max_bytes=max_bytes,
        expected_type=dict,
        missing_or_invalid_message=(
            f"sealed KISA source artifact could not be read: {relative_path}"
        ),
        type_message=f"sealed KISA source artifact must be an object: {relative_path}",
    )


def _read_array(
    snapshot: VerifiedRunSnapshot,
    relative_path: str,
) -> list[object]:
    return strict_json(
        snapshot,
        relative_path,
        label=f"sealed KISA source artifact {relative_path}",
        max_bytes=_MAX_KISA_SOURCE_JSON_BYTES,
        expected_type=list,
        missing_or_invalid_message=(
            f"sealed KISA source artifact could not be read: {relative_path}"
        ),
        type_message=f"sealed KISA source artifact must be an array: {relative_path}",
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("KISA replay compilation time must include a UTC offset or Z")
    return value.astimezone(UTC)
