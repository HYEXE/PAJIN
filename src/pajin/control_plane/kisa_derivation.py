"""Server-owned derivation of non-executable KISA replay compilations."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Self, cast
from uuid import uuid4

from pydantic import Field, model_validator

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
    replay_evidence_digest,
    replay_request_digest,
)
from pajin.domain.validation import CandidateFinding, ValidationDecision
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import KISAScenarioDefinition
from pajin.modes.ai_redteam.replay import (
    build_kisa_replay_compilation_inputs,
    derive_kisa_source_replay_context,
    eligible_for_kisa_replay,
    kisa_replay_contract,
)
from pajin.policy.capability import CapabilityRecord
from pajin.replay.compiler import ReplayCompiler
from pajin.replay.tickets import (
    canonical_replay_compilation_bytes,
    replay_context_digest,
)
from pajin.runtime.store import AuditEvent, RunStore, verify_run_integrity
from pajin.tools.ai import AIChatProbeTool
from pajin.workflow.validation import validate_findings
from pajin.workflow.validation_artifacts import load_source_validation_artifacts

KISA_CONFIRMATION_POLICY_VERSION = "pajin.kisa-confirmation:v1"
KISA_CONFIRMATION_REPETITIONS = 2
KISA_CONFIRMATION_REQUIRED_SUCCESSES = 2
KISA_CONFIRMATION_REQUIRED_ATTEMPTS = 1
KISA_CONFIRMATION_MAX_ATTEMPTS = 3

_SOURCE_ARTIFACT_MEDIA_TYPE = "application/vnd.pajin.run+directory"
_SOURCE_ARTIFACT_SCHEMA_KIND = "pajin.run.sealed.v1"
_REPLAY_RUN_ID = re.compile(r"^run_[0-9a-f]{32}$")


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


@dataclass(frozen=True, slots=True)
class _CanonicalCandidateDerivation:
    candidates: list[CandidateFinding]
    results: list[ToolResult]
    authoritative_request_ids: set[str]
    authoritative_claim_keys: set[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class _ValidatorExecutionIdentity:
    validator_id: str
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
    verification = verify_run_integrity(root)
    _require_artifact_binding(
        artifact_ref,
        run_id=verification.run_id,
        root_digest=verification.root_digest,
    )

    run_summary = _read_object(root / "run.json")
    if run_summary.get("runId") != verification.run_id or run_summary.get("status") != "completed":
        raise ValueError("KISA replay derivation requires a sealed completed source Run")

    campaign = CampaignManifest.model_validate(_read_object(root / "campaign.json"))
    if campaign.spec.mode is not CampaignMode.AI_REDTEAM:
        raise ValueError("KISA replay derivation requires an AI Red Team Campaign")
    plan = AgentPlan.model_validate(_read_object(root / "plan.json"))
    if (root / "validation" / "v1alpha1").exists():
        raise ValueError(
            "KISA replay derivation rejects an already-versioned validation projection"
        )
    validation = load_source_validation_artifacts(root)
    capability_records = [
        CapabilityRecord.model_validate(item) for item in _read_array(root / "capabilities.json")
    ]
    budget = _BudgetSnapshot.model_validate(_read_object(root / "budget.json"))
    rate_limits = _RateLimitSnapshot.model_validate(_read_object(root / "rate-limits.json"))
    _require_campaign_budget(campaign, budget, events=_load_events(root))

    canonical_derivation = _derive_canonical_candidates(
        root=root,
        campaign=campaign,
        plan=plan,
        stored_candidates=validation.candidates,
    )
    validator = _derive_validator_identity(
        root=root,
        campaign=campaign,
        capability_records=capability_records,
    )
    canonical_decisions = _derive_canonical_decisions(
        root=root,
        campaign=campaign,
        candidates=canonical_derivation.candidates,
        results=canonical_derivation.results,
        authoritative_request_ids=canonical_derivation.authoritative_request_ids,
        authoritative_claim_keys=canonical_derivation.authoritative_claim_keys,
        validator=validator,
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
        )
        compilation = ReplayCompiler.compile(
            campaign=campaign,
            plan=plan,
            original_request=source.original_request,
            specialist_grant=source.specialist_grant,
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

    final_verification = verify_run_integrity(root)
    if final_verification != verification:
        raise ValueError("sealed KISA source changed during replay derivation")
    return DerivedKISAReplayBatch(
        artifact_ref=artifact_ref,
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


def _derive_canonical_candidates(
    *,
    root: Path,
    campaign: CampaignManifest,
    plan: AgentPlan,
    stored_candidates: list[CandidateFinding],
) -> _CanonicalCandidateDerivation:
    """Re-run the trusted producer and reject any stored Candidate substitution."""

    results = _load_planned_tool_results(root, plan)
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
        authoritative_request_ids=set(production.authoritative_request_ids),
        authoritative_claim_keys=set(production.authoritative_claim_keys),
    )


def _derive_validator_identity(
    *,
    root: Path,
    campaign: CampaignManifest,
    capability_records: list[CapabilityRecord],
) -> _ValidatorExecutionIdentity:
    """Bind the semantic Validator to its completed Agent, Task, and grant lineage."""

    agents = [AgentNode.model_validate(item) for item in _read_array(root / "agents.json")]
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

    graph = TaskGraph.model_validate(_read_object(root / "task-graph.json"))
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
        supervisor_record.revoked
        or validator_record.revoked
        or supervisor_grant.subject != supervisor.agent_id
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

    events = _load_events(root)
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
    if len(spawned) != 1 or len(running) != 1 or len(task_succeeded) != 1 or len(completed) != 1:
        raise ValueError("sealed KISA Validator identity differs from its audit lineage")
    if not (
        spawned[0].sequence
        < running[0].sequence
        < task_succeeded[0].sequence
        < completed[0].sequence
    ):
        raise ValueError("sealed KISA Validator lifecycle event sequence is not exact")
    return _ValidatorExecutionIdentity(
        validator_id=validator.agent_id,
        running_sequence=running[0].sequence,
        task_succeeded_sequence=task_succeeded[0].sequence,
    )


def _derive_canonical_decisions(
    *,
    root: Path,
    campaign: CampaignManifest,
    candidates: list[CandidateFinding],
    results: list[ToolResult],
    authoritative_request_ids: set[str],
    authoritative_claim_keys: set[tuple[str, str]],
    validator: _ValidatorExecutionIdentity,
    stored_decisions: list[ValidationDecision],
) -> list[ValidationDecision]:
    """Replay the trusted semantic/objective gate and compare every Decision field."""

    semantic_findings = [
        candidate.claim.model_copy(update={"validated": True}) for candidate in candidates
    ]
    replay_store = cast(RunStore, _ReadOnlyValidationStore(path=root))
    replayed = validate_findings(
        campaign,
        results,
        semantic_findings,
        replay_store,
        validator_id=validator.validator_id,
        admitted_candidates=candidates,
        producer_authoritative_request_ids=authoritative_request_ids,
        producer_authoritative_claim_keys=authoritative_claim_keys,
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

    events = _load_events(root)
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


def _load_events(root: Path) -> list[AuditEvent]:
    try:
        return [
            AuditEvent.model_validate_json(line)
            for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("sealed KISA audit event lineage could not be loaded") from exc


def _matching_events(
    events: list[AuditEvent],
    event_type: str,
    payload: Mapping[str, object],
) -> list[AuditEvent]:
    return [
        event for event in events if event.event_type == event_type and event.payload == payload
    ]


def _load_planned_tool_results(root: Path, plan: AgentPlan) -> list[ToolResult]:
    """Reconstruct producer inputs from exact Gateway evidence, never Candidate files."""

    results: list[ToolResult] = []
    for step in plan.steps:
        reference = f"evidence/{step.request.request_id}.json"
        evidence_path = (root / reference).resolve()
        if root not in evidence_path.parents:
            raise ValueError("sealed KISA Plan evidence path escapes its source Run")
        if not evidence_path.is_file():
            continue
        payload = _read_object(evidence_path)
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


def _read_object(path: Path) -> dict[str, object]:
    try:
        parsed = json.loads(path.read_bytes())
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"sealed KISA source artifact could not be read: {path.name}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"sealed KISA source artifact must be an object: {path.name}")
    return parsed


def _read_array(path: Path) -> list[object]:
    try:
        parsed = json.loads(path.read_bytes())
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"sealed KISA source artifact could not be read: {path.name}") from exc
    if not isinstance(parsed, list):
        raise ValueError(f"sealed KISA source artifact must be an array: {path.name}")
    return parsed


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("KISA replay compilation time must include a UTC offset or Z")
    return value.astimezone(UTC)
