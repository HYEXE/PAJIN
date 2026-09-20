"""Bounded Dynamic Supervisor for campaign-local specialist orchestration."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self
from unicodedata import normalize

from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.frontier import (
    FrontierCandidate,
    PathScorer,
    PathScoringPolicy,
    ScoredFrontierCandidate,
    default_path_scoring_policy,
)
from pajin.agentic.graph_bindings import target_root_hypothesis_pairs
from pajin.agentic.models import (
    AGENTIC_CAMPAIGN_API_VERSION,
    AgentControlCommand,
    AgentControlCommandKind,
    AgentEvent,
    AgentEventKind,
    AgenticStrictModel,
    AgentSessionSnapshot,
    AgentSessionState,
    ExploitGroupDefinition,
    Identifier,
    PentestSpecialization,
    Sha256,
    _canonical_identifiers,
    _literal_false,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.graph.projection import GraphSnapshot


def _normalized_semantic_text(value: str) -> str:
    return " ".join(normalize("NFKC", value).casefold().split())


def _candidate_semantic_digest(candidate: FrontierCandidate) -> str:
    proposal = candidate.proposal
    return discovery_digest(
        "pajin.agentic.hypothesis-semantics/v1",
        {
            "campaignId": proposal.campaign_id,
            "targetId": proposal.target_id,
            "parentHypothesisId": proposal.parent_hypothesis_id,
            "ancestorHypothesisIds": proposal.ancestor_hypothesis_ids,
            "threatClass": proposal.threat_class,
            "specialization": proposal.specialization.value,
            "statement": _normalized_semantic_text(proposal.statement),
            "expectedObservable": _normalized_semantic_text(proposal.expected_observable),
            "requiredEvidenceTypes": proposal.required_evidence_types,
        },
    )


def _checkpoint_authority(checkpoint: DynamicSupervisorCheckpoint) -> tuple[object, ...]:
    return (
        checkpoint.campaign_id,
        checkpoint.supervisor_agent_id,
        checkpoint.source_snapshot_id,
        checkpoint.source_snapshot_digest,
        checkpoint.exploit_group_id,
        checkpoint.exploit_group_digest,
        checkpoint.supervisor_policy_id,
        checkpoint.supervisor_policy_digest,
        checkpoint.scoring_policy_id,
        checkpoint.scoring_policy_digest,
        checkpoint.allowed_target_ids,
        checkpoint.restart_resume_supported,
        checkpoint.durable_head_published,
    )


class FrontierDisposition(StrEnum):
    SELECTED = "selected"
    DEFERRED = "deferred"
    REJECTED = "rejected"


class FrontierDecisionReason(StrEnum):
    SELECTED_BY_SCORE = "selected-by-score"
    BELOW_SCORE_THRESHOLD = "below-score-threshold"
    BEAM_LIMIT = "beam-limit"
    PARENT_BRANCH_LIMIT = "parent-branch-limit"
    AGENT_CAPACITY = "agent-capacity"
    ASSIGNMENT_BUDGET = "assignment-budget"
    CROSS_CAMPAIGN = "cross-campaign"
    TARGET_OUT_OF_SCOPE = "target-out-of-scope"
    DEPTH_LIMIT = "depth-limit"
    UNKNOWN_SPECIALIST = "unknown-specialist"
    REPEATED_CANDIDATE = "repeated-candidate"
    REPEATED_SEMANTICS = "repeated-semantics"
    STALE_SNAPSHOT = "stale-snapshot"
    UNVERIFIED_LINEAGE = "unverified-lineage"
    SAFETY_RISK_LIMIT = "safety-risk-limit"


class DynamicSupervisorPolicy(AgenticStrictModel):
    """Code-owned limits for one bounded frontier scheduling cycle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DynamicSupervisorPolicy"] = "DynamicSupervisorPolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=96)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    max_depth: int = Field(default=4, alias="maxDepth", strict=True, ge=1, le=8)
    max_frontier_candidates: int = Field(
        default=64,
        alias="maxFrontierCandidates",
        strict=True,
        ge=1,
        le=500,
    )
    max_candidates_per_parent: int = Field(
        default=3,
        alias="maxCandidatesPerParent",
        strict=True,
        ge=1,
        le=20,
    )
    beam_width: int = Field(default=2, alias="beamWidth", strict=True, ge=1, le=20)
    min_score_bps: int = Field(default=3_000, alias="minScoreBps", strict=True, ge=0, le=10_000)
    max_active_agents: int = Field(
        default=8,
        alias="maxActiveAgents",
        strict=True,
        ge=1,
        le=64,
    )
    max_total_assignments: int = Field(
        default=64,
        alias="maxTotalAssignments",
        strict=True,
        ge=1,
        le=10_000,
    )
    max_safety_risk_bps: int = Field(
        default=5_000,
        alias="maxSafetyRiskBps",
        strict=True,
        ge=0,
        le=10_000,
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_authority: Literal[False] = Field(default=False, alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator(
        "scope_expansion_authorized",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.beam_width > self.max_frontier_candidates:
            raise ValueError("Dynamic Supervisor beam width exceeds its Frontier limit")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = discovery_digest("pajin.agentic.dynamic-supervisor-policy/v1", material)
        expected_id = f"dynamic-supervisor-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Dynamic Supervisor Policy Digest differs")
        if self.policy_id and self.policy_id != expected_id:
            raise ValueError("Dynamic Supervisor Policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", expected_id)
        return self


class FrontierDecision(AgenticStrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    candidate_id: str = Field(
        alias="candidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    disposition: FrontierDisposition
    reason: FrontierDecisionReason
    score_bps: int | None = Field(default=None, alias="scoreBps", ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_score(self) -> Self:
        structural_rejection = self.reason in {
            FrontierDecisionReason.CROSS_CAMPAIGN,
            FrontierDecisionReason.TARGET_OUT_OF_SCOPE,
            FrontierDecisionReason.DEPTH_LIMIT,
            FrontierDecisionReason.UNKNOWN_SPECIALIST,
            FrontierDecisionReason.REPEATED_CANDIDATE,
            FrontierDecisionReason.REPEATED_SEMANTICS,
            FrontierDecisionReason.STALE_SNAPSHOT,
            FrontierDecisionReason.UNVERIFIED_LINEAGE,
            FrontierDecisionReason.SAFETY_RISK_LIMIT,
        }
        if structural_rejection != (self.score_bps is None):
            raise ValueError("Frontier structural rejection score binding differs")
        if self.disposition is FrontierDisposition.SELECTED and (
            self.reason is not FrontierDecisionReason.SELECTED_BY_SCORE
        ):
            raise ValueError("selected Frontier Candidate requires selected-by-score")
        if self.disposition is FrontierDisposition.REJECTED and not structural_rejection:
            raise ValueError("rejected Frontier Candidate requires a structural reason")
        return self


class IssuedCommandBinding(AgenticStrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    agent_id: Identifier = Field(alias="agentId")
    command: AgentControlCommandKind
    command_sequence: int = Field(alias="commandSequence", strict=True, ge=1)
    task_id: Identifier | None = Field(default=None, alias="taskId")
    candidate_id: str | None = Field(
        default=None,
        alias="candidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    last_event_sequence: int = Field(
        default=0,
        alias="lastEventSequence",
        strict=True,
        ge=0,
    )
    terminal: bool = False

    @field_validator("terminal", mode="before")
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("issued command terminal marker must be a literal boolean")
        return value

    @model_validator(mode="after")
    def validate_assignment(self) -> Self:
        if (self.task_id is None) != (self.candidate_id is None):
            raise ValueError("issued command assignment identities differ")
        assignment = self.command in {
            AgentControlCommandKind.ASSIGN,
            AgentControlCommandKind.FOLLOW_UP,
        }
        if assignment != (self.task_id is not None):
            raise ValueError("issued command kind differs from its assignment identities")
        if not assignment and (
            self.last_event_sequence not in {0, 1}
            or self.terminal != (self.last_event_sequence == 1)
        ):
            raise ValueError("lifecycle command requires exactly one terminal acknowledgement")
        return self


def _require_checkpoint_assignment_sessions(
    sessions: tuple[AgentSessionSnapshot, ...],
    commands: tuple[IssuedCommandBinding, ...],
) -> None:
    session_by_id = {item.session_id: item for item in sessions}
    live_assignment_by_agent: dict[str, IssuedCommandBinding] = {}
    for binding in commands:
        assignment = binding.command in {
            AgentControlCommandKind.ASSIGN,
            AgentControlCommandKind.FOLLOW_UP,
        }
        if not assignment:
            continue
        session = session_by_id[binding.agent_id]
        if binding.terminal:
            if binding.last_event_sequence == 0:
                raise ValueError("checkpoint terminal assignment lacks an event")
            if (
                session.state is AgentSessionState.ASSIGNED
                and session.current_task_id == binding.task_id
                and session.current_candidate_id == binding.candidate_id
            ):
                raise ValueError("checkpoint terminal assignment remains live in its session")
            continue
        if binding.agent_id in live_assignment_by_agent:
            raise ValueError("checkpoint session has multiple live assignments")
        live_assignment_by_agent[binding.agent_id] = binding
        if (
            session.state is not AgentSessionState.ASSIGNED
            or session.current_task_id != binding.task_id
            or session.current_candidate_id != binding.candidate_id
        ):
            raise ValueError("checkpoint live assignment differs from its session")
    if any(
        session.state is AgentSessionState.ASSIGNED
        and session.session_id not in live_assignment_by_agent
        for session in sessions
    ):
        raise ValueError("checkpoint assigned session lacks one live command")


class DynamicSupervisorCheckpoint(AgenticStrictModel):
    """Content-addressed in-process audit state; restart resume is deliberately closed."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DynamicSupervisorCheckpoint"] = "DynamicSupervisorCheckpoint"
    checkpoint_id: str = Field(default="", alias="checkpointId", max_length=96)
    checkpoint_digest: str = Field(default="", alias="checkpointDigest", max_length=64)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    supervisor_agent_id: Identifier = Field(alias="supervisorAgentId")
    source_snapshot_id: Identifier = Field(alias="sourceSnapshotId")
    source_snapshot_digest: Sha256 = Field(alias="sourceSnapshotDigest")
    exploit_group_id: str = Field(alias="exploitGroupId", pattern=r"^exploit-group_[a-f0-9]{64}$")
    exploit_group_digest: Sha256 = Field(alias="exploitGroupDigest")
    supervisor_policy_id: str = Field(
        alias="supervisorPolicyId",
        pattern=r"^dynamic-supervisor-policy_[a-f0-9]{64}$",
    )
    supervisor_policy_digest: Sha256 = Field(alias="supervisorPolicyDigest")
    scoring_policy_id: str = Field(
        alias="scoringPolicyId",
        pattern=r"^path-scoring-policy_[a-f0-9]{64}$",
    )
    scoring_policy_digest: Sha256 = Field(alias="scoringPolicyDigest")
    allowed_target_ids: tuple[Identifier, ...] = Field(alias="allowedTargetIds", min_length=1)
    revision: int = Field(strict=True, ge=0)
    next_command_sequence: int = Field(alias="nextCommandSequence", strict=True, ge=1)
    total_assignments: int = Field(alias="totalAssignments", strict=True, ge=0)
    sessions: tuple[AgentSessionSnapshot, ...]
    seen_candidate_ids: tuple[str, ...] = Field(alias="seenCandidateIds")
    seen_semantic_digests: tuple[Sha256, ...] = Field(alias="seenSemanticDigests")
    issued_commands: tuple[IssuedCommandBinding, ...] = Field(alias="issuedCommands")
    restart_resume_supported: Literal[False] = Field(
        default=False,
        alias="restartResumeSupported",
    )
    durable_head_published: Literal[False] = Field(
        default=False,
        alias="durableHeadPublished",
    )

    @field_validator(
        "restart_resume_supported",
        "durable_head_published",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        _canonical_identifiers(self.allowed_target_ids, label="allowed Target IDs")
        session_ids = tuple(item.session_id for item in self.sessions)
        if session_ids != tuple(sorted(set(session_ids))):
            raise ValueError("checkpoint Agent Sessions must be unique and sorted")
        if self.seen_candidate_ids != tuple(sorted(set(self.seen_candidate_ids))):
            raise ValueError("checkpoint seen Candidate IDs must be unique and sorted")
        if self.seen_semantic_digests != tuple(sorted(set(self.seen_semantic_digests))):
            raise ValueError("checkpoint semantic digests must be unique and sorted")
        command_ids = tuple(item.command_id for item in self.issued_commands)
        if command_ids != tuple(sorted(set(command_ids))):
            raise ValueError("checkpoint issued commands must be unique and sorted")
        command_sequences = tuple(item.command_sequence for item in self.issued_commands)
        if set(command_sequences) != set(range(1, self.next_command_sequence)):
            raise ValueError("checkpoint command sequence is not complete and monotonic")
        session_set = set(session_ids)
        if any(item.agent_id not in session_set for item in self.issued_commands):
            raise ValueError("checkpoint issued command references an unknown session")
        assignment_count = sum(
            item.command in {
                AgentControlCommandKind.ASSIGN,
                AgentControlCommandKind.FOLLOW_UP,
            }
            for item in self.issued_commands
        )
        if (
            assignment_count != self.total_assignments
            or len(self.seen_candidate_ids) != self.total_assignments
            or len(self.seen_semantic_digests) != self.total_assignments
        ):
            raise ValueError("checkpoint assignment accounting differs")
        assigned_candidate_ids = {
            item.candidate_id
            for item in self.issued_commands
            if item.command
            in {AgentControlCommandKind.ASSIGN, AgentControlCommandKind.FOLLOW_UP}
        }
        if assigned_candidate_ids != set(self.seen_candidate_ids):
            raise ValueError("checkpoint seen Candidates differ from assignment commands")
        _require_checkpoint_assignment_sessions(self.sessions, self.issued_commands)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"checkpoint_id", "checkpoint_digest"},
        )
        digest = discovery_digest("pajin.agentic.dynamic-supervisor-checkpoint/v1", material)
        expected_id = f"agentic-checkpoint_{digest}"
        if self.checkpoint_digest and self.checkpoint_digest != digest:
            raise ValueError("Dynamic Supervisor Checkpoint Digest differs")
        if self.checkpoint_id and self.checkpoint_id != expected_id:
            raise ValueError("Dynamic Supervisor Checkpoint ID differs")
        object.__setattr__(self, "checkpoint_digest", digest)
        object.__setattr__(self, "checkpoint_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Dynamic Supervisor Checkpoint",
            max_bytes=4 * 1024 * 1024,
        )
        return self


def _replay_candidate_rejection(
    *,
    candidate: FrontierCandidate,
    source: DynamicSupervisorCheckpoint,
    target_root_pairs: frozenset[tuple[str, str]],
    exploit_group: ExploitGroupDefinition,
    supervisor_policy: DynamicSupervisorPolicy,
) -> FrontierDecisionReason | None:
    proposal = candidate.proposal
    if proposal.campaign_id != source.campaign_id:
        return FrontierDecisionReason.CROSS_CAMPAIGN
    if (
        proposal.source_snapshot_id != source.source_snapshot_id
        or proposal.source_snapshot_digest != source.source_snapshot_digest
    ):
        return FrontierDecisionReason.STALE_SNAPSHOT
    if proposal.target_id not in source.allowed_target_ids:
        return FrontierDecisionReason.TARGET_OUT_OF_SCOPE
    if proposal.depth > supervisor_policy.max_depth:
        return FrontierDecisionReason.DEPTH_LIMIT
    if (
        proposal.depth != 1
        or proposal.ancestor_hypothesis_ids != (proposal.parent_hypothesis_id,)
        or (proposal.target_id, proposal.parent_hypothesis_id) not in target_root_pairs
    ):
        return FrontierDecisionReason.UNVERIFIED_LINEAGE
    if candidate.trusted_features.safety_risk_bps > supervisor_policy.max_safety_risk_bps:
        return FrontierDecisionReason.SAFETY_RISK_LIMIT
    if candidate.candidate_id in source.seen_candidate_ids:
        return FrontierDecisionReason.REPEATED_CANDIDATE
    if _candidate_semantic_digest(candidate) in source.seen_semantic_digests:
        return FrontierDecisionReason.REPEATED_SEMANTICS
    specialist = exploit_group.specialist_for(
        proposal.specialization,
        proposal.threat_class,
    )
    if specialist is None or not specialist.skill_refs:
        return FrontierDecisionReason.UNKNOWN_SPECIALIST
    return None


def _replay_scored_frontier(
    *,
    candidates: tuple[FrontierCandidate, ...],
    source: DynamicSupervisorCheckpoint,
    source_snapshot: GraphSnapshot,
    exploit_group: ExploitGroupDefinition,
    supervisor_policy: DynamicSupervisorPolicy,
    scoring_policy: PathScoringPolicy,
) -> tuple[
    tuple[ScoredFrontierCandidate, ...],
    dict[str, FrontierDecisionReason],
    dict[str, FrontierCandidate],
]:
    target_root_pairs = target_root_hypothesis_pairs(source_snapshot)
    rejected: dict[str, FrontierDecisionReason] = {}
    eligible: list[FrontierCandidate] = []
    semantic_digests: dict[str, str] = {}
    for candidate in candidates:
        semantic = _candidate_semantic_digest(candidate)
        semantic_digests[candidate.candidate_id] = semantic
        reason = _replay_candidate_rejection(
            candidate=candidate,
            source=source,
            target_root_pairs=target_root_pairs,
            exploit_group=exploit_group,
            supervisor_policy=supervisor_policy,
        )
        if reason is None:
            eligible.append(candidate)
        else:
            rejected[candidate.candidate_id] = reason

    scorer = PathScorer(scoring_policy)
    cycle_semantics: set[str] = set()
    unique_eligible: list[FrontierCandidate] = []
    candidate_by_id = {item.candidate_id: item for item in eligible}
    for score in scorer.rank(tuple(eligible)):
        semantic = semantic_digests[score.candidate_id]
        if semantic in cycle_semantics:
            rejected[score.candidate_id] = FrontierDecisionReason.REPEATED_SEMANTICS
        else:
            cycle_semantics.add(semantic)
            unique_eligible.append(candidate_by_id[score.candidate_id])
    scores = scorer.rank(tuple(unique_eligible))
    return scores, rejected, candidate_by_id


def _replay_scheduling_decisions(
    *,
    candidates: tuple[FrontierCandidate, ...],
    scores: tuple[ScoredFrontierCandidate, ...],
    rejected: dict[str, FrontierDecisionReason],
    candidate_by_id: dict[str, FrontierCandidate],
    source: DynamicSupervisorCheckpoint,
    exploit_group: ExploitGroupDefinition,
    supervisor_policy: DynamicSupervisorPolicy,
) -> tuple[FrontierDecision, ...]:
    decisions: dict[str, FrontierDecision] = {
        candidate_id: FrontierDecision(
            candidateId=candidate_id,
            disposition=FrontierDisposition.REJECTED,
            reason=reason,
        )
        for candidate_id, reason in rejected.items()
    }
    active_sessions = [
        session
        for session in source.sessions
        if session.state
        not in {
            AgentSessionState.COMPLETED,
            AgentSessionState.FAILED,
            AgentSessionState.CANCELLED,
        }
    ]
    active_by_role = {
        specialization: sum(
            session.specialization is specialization for session in active_sessions
        )
        for specialization in PentestSpecialization
    }
    idle_by_role = {
        specialization: sum(
            session.specialization is specialization
            and session.state is AgentSessionState.IDLE
            for session in source.sessions
        )
        for specialization in PentestSpecialization
    }
    active_count = len(active_sessions)
    selected_count = 0
    selected_per_parent: dict[str, int] = {}
    for score in scores:
        candidate = candidate_by_id[score.candidate_id]
        proposal = candidate.proposal
        disposition = FrontierDisposition.DEFERRED
        if score.score_bps < supervisor_policy.min_score_bps:
            reason = FrontierDecisionReason.BELOW_SCORE_THRESHOLD
        elif source.total_assignments + selected_count >= supervisor_policy.max_total_assignments:
            reason = FrontierDecisionReason.ASSIGNMENT_BUDGET
        elif selected_count >= supervisor_policy.beam_width:
            reason = FrontierDecisionReason.BEAM_LIMIT
        elif (
            selected_per_parent.get(proposal.parent_hypothesis_id, 0)
            >= supervisor_policy.max_candidates_per_parent
        ):
            reason = FrontierDecisionReason.PARENT_BRANCH_LIMIT
        else:
            specialist = exploit_group.specialist_for(
                proposal.specialization,
                proposal.threat_class,
            )
            if idle_by_role[proposal.specialization] > 0:
                idle_by_role[proposal.specialization] -= 1
                capacity_available = True
            else:
                capacity_available = bool(
                    specialist is not None
                    and active_count < supervisor_policy.max_active_agents
                    and active_by_role[proposal.specialization] < specialist.max_sessions
                )
                if capacity_available:
                    active_count += 1
                    active_by_role[proposal.specialization] += 1
            if not capacity_available:
                reason = FrontierDecisionReason.AGENT_CAPACITY
            else:
                disposition = FrontierDisposition.SELECTED
                reason = FrontierDecisionReason.SELECTED_BY_SCORE
                selected_count += 1
                parent = proposal.parent_hypothesis_id
                selected_per_parent[parent] = selected_per_parent.get(parent, 0) + 1
        decisions[candidate.candidate_id] = FrontierDecision(
            candidateId=candidate.candidate_id,
            disposition=disposition,
            reason=reason,
            scoreBps=score.score_bps,
        )
    return tuple(decisions[item.candidate_id] for item in candidates)


def _replay_cycle_outcome(
    *,
    candidates: tuple[FrontierCandidate, ...],
    source: DynamicSupervisorCheckpoint,
    source_snapshot: GraphSnapshot,
    exploit_group: ExploitGroupDefinition,
    supervisor_policy: DynamicSupervisorPolicy,
    scoring_policy: PathScoringPolicy,
) -> tuple[tuple[ScoredFrontierCandidate, ...], tuple[FrontierDecision, ...]]:
    scores, rejected, candidate_by_id = _replay_scored_frontier(
        candidates=candidates,
        source=source,
        source_snapshot=source_snapshot,
        exploit_group=exploit_group,
        supervisor_policy=supervisor_policy,
        scoring_policy=scoring_policy,
    )
    decisions = _replay_scheduling_decisions(
        candidates=candidates,
        scores=scores,
        rejected=rejected,
        candidate_by_id=candidate_by_id,
        source=source,
        exploit_group=exploit_group,
        supervisor_policy=supervisor_policy,
    )
    return scores, decisions


def _replay_cycle_commands(
    *,
    scores: tuple[ScoredFrontierCandidate, ...],
    decisions: tuple[FrontierDecision, ...],
    candidate_by_id: dict[str, FrontierCandidate],
    source: DynamicSupervisorCheckpoint,
    exploit_group: ExploitGroupDefinition,
    supervisor_policy: DynamicSupervisorPolicy,
) -> tuple[AgentControlCommand, ...]:
    sessions = {item.session_id: item for item in source.sessions}
    selected_ids = {
        decision.candidate_id
        for decision in decisions
        if decision.disposition is FrontierDisposition.SELECTED
    }
    commands: list[AgentControlCommand] = []
    sequence = source.next_command_sequence
    assignment_ordinal = source.total_assignments
    for score in scores:
        if score.candidate_id not in selected_ids:
            continue
        candidate = candidate_by_id[score.candidate_id]
        specialization = candidate.proposal.specialization
        reusable = sorted(
            (
                session
                for session in sessions.values()
                if session.specialization is specialization
                and session.state is AgentSessionState.IDLE
            ),
            key=lambda item: item.session_id,
        )
        if reusable:
            session = reusable[0]
            assignment_kind = AgentControlCommandKind.FOLLOW_UP
        else:
            ordinal = 1 + sum(
                session.specialization is specialization for session in sessions.values()
            )
            session_id = "agent-session_" + discovery_digest(
                "pajin.agentic.agent-session/v1",
                {
                    "campaignId": source.campaign_id,
                    "supervisorAgentId": source.supervisor_agent_id,
                    "exploitGroupId": exploit_group.group_id,
                    "specialization": specialization.value,
                    "ordinal": ordinal,
                },
            )
            session = AgentSessionSnapshot(
                sessionId=session_id,
                campaignId=source.campaign_id,
                parentAgentId=source.supervisor_agent_id,
                specialization=specialization,
                state=AgentSessionState.IDLE,
            )
            sessions[session_id] = session
            commands.append(
                AgentControlCommand(
                    campaignId=source.campaign_id,
                    supervisorAgentId=source.supervisor_agent_id,
                    sourceSnapshotId=source.source_snapshot_id,
                    sourceSnapshotDigest=source.source_snapshot_digest,
                    supervisorPolicyDigest=supervisor_policy.policy_digest,
                    sequence=sequence,
                    command=AgentControlCommandKind.SPAWN,
                    targetAgentId=session_id,
                    specialization=specialization,
                    contextRefs=session.context_refs,
                )
            )
            sequence += 1
            assignment_kind = AgentControlCommandKind.ASSIGN

        assignment_ordinal += 1
        task_id = "agentic-task_" + discovery_digest(
            "pajin.agentic.task/v1",
            {
                "campaignId": source.campaign_id,
                "candidateId": candidate.candidate_id,
                "assignmentOrdinal": assignment_ordinal,
            },
        )
        sessions[session.session_id] = AgentSessionSnapshot.model_validate(
            session.model_copy(
                update={
                    "state": AgentSessionState.ASSIGNED,
                    "current_candidate_id": candidate.candidate_id,
                    "current_task_id": task_id,
                }
            ).model_dump(mode="json", by_alias=True)
        )
        commands.append(
            AgentControlCommand(
                campaignId=source.campaign_id,
                supervisorAgentId=source.supervisor_agent_id,
                sourceSnapshotId=source.source_snapshot_id,
                sourceSnapshotDigest=source.source_snapshot_digest,
                supervisorPolicyDigest=supervisor_policy.policy_digest,
                sequence=sequence,
                command=assignment_kind,
                targetAgentId=session.session_id,
                specialization=specialization,
                taskId=task_id,
                candidateId=candidate.candidate_id,
                contextRefs=session.context_refs,
            )
        )
        sequence += 1
    return tuple(commands)


class DynamicSupervisorCycle(AgenticStrictModel):
    """One immutable Frontier ranking and agent-control output."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DynamicSupervisorCycle"] = "DynamicSupervisorCycle"
    cycle_id: str = Field(default="", alias="cycleId", max_length=96)
    cycle_digest: str = Field(default="", alias="cycleDigest", max_length=64)
    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    revision: int = Field(strict=True, ge=1)
    source_checkpoint_id: str = Field(
        alias="sourceCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    source_checkpoint_digest: Sha256 = Field(alias="sourceCheckpointDigest")
    source_checkpoint: DynamicSupervisorCheckpoint = Field(alias="sourceCheckpoint")
    source_snapshot: GraphSnapshot = Field(alias="sourceSnapshot")
    exploit_group: ExploitGroupDefinition = Field(alias="exploitGroup")
    supervisor_policy: DynamicSupervisorPolicy = Field(alias="supervisorPolicy")
    scoring_policy: PathScoringPolicy = Field(alias="scoringPolicy")
    candidates: tuple[FrontierCandidate, ...]
    scores: tuple[ScoredFrontierCandidate, ...]
    decisions: tuple[FrontierDecision, ...]
    commands: tuple[AgentControlCommand, ...]
    resulting_checkpoint: DynamicSupervisorCheckpoint = Field(alias="resultingCheckpoint")
    task_graph_mutation_applied: Literal[False] = Field(
        default=False,
        alias="taskGraphMutationApplied",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    tool_execution_authorized: Literal[False] = Field(
        default=False,
        alias="toolExecutionAuthorized",
    )

    @field_validator(
        "task_graph_mutation_applied",
        "capability_granted",
        "permit_granted",
        "tool_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        candidate_by_id = self._validate_candidate_scoring()
        self._validate_checkpoint_transition()
        self._validate_command_delta(candidate_by_id)
        self._validate_selection_and_sessions(candidate_by_id)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"cycle_id", "cycle_digest"},
        )
        digest = discovery_digest("pajin.agentic.dynamic-supervisor-cycle/v1", material)
        expected_id = f"agentic-cycle_{digest}"
        if self.cycle_digest and self.cycle_digest != digest:
            raise ValueError("Dynamic Supervisor Cycle Digest differs")
        if self.cycle_id and self.cycle_id != expected_id:
            raise ValueError("Dynamic Supervisor Cycle ID differs")
        object.__setattr__(self, "cycle_digest", digest)
        object.__setattr__(self, "cycle_id", expected_id)
        return self

    def _validate_candidate_scoring(self) -> dict[str, FrontierCandidate]:
        candidate_ids = tuple(item.candidate_id for item in self.candidates)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("Dynamic Supervisor Cycle Candidates must be unique and sorted")
        decision_ids = tuple(item.candidate_id for item in self.decisions)
        if decision_ids != candidate_ids:
            raise ValueError("Dynamic Supervisor Cycle must decide every Candidate")
        candidate_by_id = {item.candidate_id: item for item in self.candidates}
        expected_scores, expected_decisions = _replay_cycle_outcome(
            candidates=self.candidates,
            source=self.source_checkpoint,
            source_snapshot=self.source_snapshot,
            exploit_group=self.exploit_group,
            supervisor_policy=self.supervisor_policy,
            scoring_policy=self.scoring_policy,
        )
        if self.scores != expected_scores:
            raise ValueError("Dynamic Supervisor Cycle Scores differ from deterministic replay")
        if self.decisions != expected_decisions:
            raise ValueError("Dynamic Supervisor Decisions differ from deterministic replay")
        return candidate_by_id

    def _validate_checkpoint_transition(self) -> None:
        source = self.source_checkpoint
        result = self.resulting_checkpoint
        if (
            self.source_checkpoint_id != source.checkpoint_id
            or self.source_checkpoint_digest != source.checkpoint_digest
            or source.revision + 1 != self.revision
            or result.revision != self.revision
            or _checkpoint_authority(source) != _checkpoint_authority(result)
            or result.campaign_id != self.campaign_id
            or self.source_snapshot.campaign_id != self.campaign_id
            or self.source_snapshot.snapshot_id != source.source_snapshot_id
            or self.source_snapshot.snapshot_digest != source.source_snapshot_digest
            or self.exploit_group.group_id != source.exploit_group_id
            or self.exploit_group.group_digest != source.exploit_group_digest
            or self.supervisor_policy.policy_id != source.supervisor_policy_id
            or self.supervisor_policy.policy_digest != source.supervisor_policy_digest
            or result.scoring_policy_id != self.scoring_policy.policy_id
            or result.scoring_policy_digest != self.scoring_policy.policy_digest
        ):
            raise ValueError("Dynamic Supervisor Cycle checkpoint transition differs")

    def _validate_command_delta(
        self,
        candidate_by_id: dict[str, FrontierCandidate],
    ) -> None:
        source = self.source_checkpoint
        result = self.resulting_checkpoint
        expected_commands = _replay_cycle_commands(
            scores=self.scores,
            decisions=self.decisions,
            candidate_by_id=candidate_by_id,
            source=source,
            exploit_group=self.exploit_group,
            supervisor_policy=self.supervisor_policy,
        )
        if self.commands != expected_commands:
            raise ValueError("Dynamic Supervisor Commands differ from deterministic replay")
        command_ids = tuple(command.command_id for command in self.commands)
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("Dynamic Supervisor Cycle repeats a Command")
        if tuple(command.sequence for command in self.commands) != tuple(
            range(source.next_command_sequence, result.next_command_sequence)
        ):
            raise ValueError("Dynamic Supervisor Cycle Command sequence differs")
        source_bindings = {item.command_id: item for item in source.issued_commands}
        result_bindings = {item.command_id: item for item in result.issued_commands}
        if any(
            result_bindings.get(command_id) != binding
            for command_id, binding in source_bindings.items()
        ):
            raise ValueError("Dynamic Supervisor Cycle rewrites a prior Command binding")
        new_binding_ids = set(result_bindings) - set(source_bindings)
        if new_binding_ids != set(command_ids):
            raise ValueError("Dynamic Supervisor Cycle Command delta differs")
        for command in self.commands:
            binding = result_bindings.get(command.command_id)
            expected_binding = IssuedCommandBinding(
                commandId=command.command_id,
                agentId=command.target_agent_id,
                command=command.command,
                commandSequence=command.sequence,
                taskId=command.task_id,
                candidateId=command.candidate_id,
            )
            if binding != expected_binding:
                raise ValueError("Dynamic Supervisor Command differs from resulting Checkpoint")

    def _validate_selection_and_sessions(
        self,
        candidate_by_id: dict[str, FrontierCandidate],
    ) -> None:
        source = self.source_checkpoint
        result = self.resulting_checkpoint
        selected_ids = {
            decision.candidate_id
            for decision in self.decisions
            if decision.disposition is FrontierDisposition.SELECTED
        }
        assignment_commands = tuple(
            command
            for command in self.commands
            if command.command
            in {AgentControlCommandKind.ASSIGN, AgentControlCommandKind.FOLLOW_UP}
        )
        if (
            len(assignment_commands) != len(selected_ids)
            or {command.candidate_id for command in assignment_commands} != selected_ids
            or result.total_assignments != source.total_assignments + len(selected_ids)
            or set(result.seen_candidate_ids) != set(source.seen_candidate_ids) | selected_ids
            or set(result.seen_semantic_digests)
            != set(source.seen_semantic_digests)
            | {_candidate_semantic_digest(candidate_by_id[item]) for item in selected_ids}
        ):
            raise ValueError("Dynamic Supervisor Cycle selection accounting differs")
        if any(
            command.command
            not in {
                AgentControlCommandKind.SPAWN,
                AgentControlCommandKind.ASSIGN,
                AgentControlCommandKind.FOLLOW_UP,
            }
            for command in self.commands
        ):
            raise ValueError("Dynamic Supervisor Cycle contains an unrelated lifecycle Command")

        source_sessions = {item.session_id: item for item in source.sessions}
        result_sessions = {item.session_id: item for item in result.sessions}
        targeted_sessions = {command.target_agent_id for command in assignment_commands}
        if set(result_sessions) != set(source_sessions) | {
            command.target_agent_id
            for command in self.commands
            if command.command is AgentControlCommandKind.SPAWN
        }:
            raise ValueError("Dynamic Supervisor Cycle Session delta differs")
        if any(
            result_sessions[session_id] != session
            for session_id, session in source_sessions.items()
            if session_id not in targeted_sessions
        ):
            raise ValueError("Dynamic Supervisor Cycle rewrites an unrelated Session")
        assignment_by_session = {
            command.target_agent_id: command for command in assignment_commands
        }
        if len(assignment_by_session) != len(assignment_commands):
            raise ValueError("Dynamic Supervisor Cycle assigns one Session more than once")
        for session_id, command in assignment_by_session.items():
            session = result_sessions.get(session_id)
            prior = source_sessions.get(session_id)
            if session is None or (
                session.state is not AgentSessionState.ASSIGNED
                or session.current_task_id != command.task_id
                or session.current_candidate_id != command.candidate_id
                or session.campaign_id != result.campaign_id
                or session.parent_agent_id != result.supervisor_agent_id
                or session.specialization is not command.specialization
                or (
                    prior is None
                    and (session.context_refs or session.completed_tasks != 0)
                )
                or (
                    prior is not None
                    and (
                        prior.context_refs != session.context_refs
                        or prior.completed_tasks != session.completed_tasks
                    )
                )
            ):
                raise ValueError("Dynamic Supervisor Cycle assignment Session differs")


class DynamicSupervisor:
    """Stateful in-process Scheduler for campaign-local logical specialists.

    The Scheduler only emits lifecycle commands. A separate Campaign/Capability/
    Permit/Gateway path is still required before any Tool can run.
    """

    def __init__(
        self,
        *,
        campaign_id: str,
        supervisor_agent_id: str,
        source_snapshot: GraphSnapshot,
        allowed_target_ids: tuple[str, ...],
        exploit_group: ExploitGroupDefinition,
        policy: DynamicSupervisorPolicy | None = None,
        scoring_policy: PathScoringPolicy | None = None,
    ) -> None:
        self.campaign_id = campaign_id
        self.supervisor_agent_id = supervisor_agent_id
        self.source_snapshot = GraphSnapshot.model_validate(
            source_snapshot.model_dump(mode="json", by_alias=True)
        )
        if self.source_snapshot.campaign_id != campaign_id:
            raise ValueError("Dynamic Supervisor Graph Snapshot belongs to another Campaign")
        self.source_snapshot_id = self.source_snapshot.snapshot_id
        self.source_snapshot_digest = self.source_snapshot.snapshot_digest
        self._source_target_root_pairs = target_root_hypothesis_pairs(self.source_snapshot)
        self.allowed_target_ids = _canonical_identifiers(
            allowed_target_ids,
            label="allowed Target IDs",
        )
        self.exploit_group = ExploitGroupDefinition.model_validate(
            exploit_group.model_dump(mode="json", by_alias=True)
        )
        supplied_policy = policy or DynamicSupervisorPolicy()
        self.policy = DynamicSupervisorPolicy.model_validate(
            supplied_policy.model_dump(mode="json", by_alias=True)
        )
        self.scorer = PathScorer(scoring_policy or default_path_scoring_policy())
        if self.policy.max_active_agents > self.exploit_group.max_active_sessions:
            raise ValueError("Supervisor active Agent limit exceeds Exploit Group capacity")
        self._configuration_pin = (
            self.campaign_id,
            self.supervisor_agent_id,
            self.source_snapshot_id,
            self.source_snapshot_digest,
            self.allowed_target_ids,
            self.exploit_group.group_id,
            self.exploit_group.group_digest,
            self.policy.policy_id,
            self.policy.policy_digest,
            self.scorer.policy.policy_id,
            self.scorer.policy.policy_digest,
        )

        self._revision = 0
        self._next_command_sequence = 1
        self._total_assignments = 0
        self._sessions: dict[str, AgentSessionSnapshot] = {}
        self._seen_candidate_ids: set[str] = set()
        self._seen_semantic_digests: set[str] = set()
        self._issued_commands: dict[str, IssuedCommandBinding] = {}

    def checkpoint(self) -> DynamicSupervisorCheckpoint:
        self._validate_configuration()
        return DynamicSupervisorCheckpoint(
            campaignId=self.campaign_id,
            supervisorAgentId=self.supervisor_agent_id,
            sourceSnapshotId=self.source_snapshot_id,
            sourceSnapshotDigest=self.source_snapshot_digest,
            exploitGroupId=self.exploit_group.group_id,
            exploitGroupDigest=self.exploit_group.group_digest,
            supervisorPolicyId=self.policy.policy_id,
            supervisorPolicyDigest=self.policy.policy_digest,
            scoringPolicyId=self.scorer.policy.policy_id,
            scoringPolicyDigest=self.scorer.policy.policy_digest,
            allowedTargetIds=self.allowed_target_ids,
            revision=self._revision,
            nextCommandSequence=self._next_command_sequence,
            totalAssignments=self._total_assignments,
            sessions=tuple(sorted(self._sessions.values(), key=lambda item: item.session_id)),
            seenCandidateIds=tuple(sorted(self._seen_candidate_ids)),
            seenSemanticDigests=tuple(sorted(self._seen_semantic_digests)),
            issuedCommands=tuple(
                sorted(self._issued_commands.values(), key=lambda item: item.command_id)
            ),
        )

    def plan_cycle(
        self,
        candidates: tuple[FrontierCandidate, ...],
    ) -> DynamicSupervisorCycle:
        if len(candidates) > self.policy.max_frontier_candidates:
            raise ValueError("Dynamic Supervisor input exceeds its Frontier limit")
        source = self.checkpoint()
        ordered = tuple(
            sorted(
                (
                    FrontierCandidate.model_validate(
                        item.model_dump(mode="json", by_alias=True)
                    )
                    for item in candidates
                ),
                key=lambda item: item.candidate_id,
            )
        )
        candidate_ids = tuple(item.candidate_id for item in ordered)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("Dynamic Supervisor input Candidate IDs must be unique")

        rejected: dict[str, FrontierDecisionReason] = {}
        eligible: list[FrontierCandidate] = []
        semantic_digests: dict[str, str] = {}
        for candidate in ordered:
            structural_reason = self._structural_rejection(candidate)
            semantic = self._semantic_digest(candidate)
            semantic_digests[candidate.candidate_id] = semantic
            if structural_reason is None and semantic in self._seen_semantic_digests:
                structural_reason = FrontierDecisionReason.REPEATED_SEMANTICS
            if structural_reason is None:
                eligible.append(candidate)
            else:
                rejected[candidate.candidate_id] = structural_reason

        ranked = self.scorer.rank(tuple(eligible))
        cycle_semantics: set[str] = set()
        scored_candidate_ids: list[str] = []
        for score in ranked:
            semantic = semantic_digests[score.candidate_id]
            if semantic in cycle_semantics:
                rejected[score.candidate_id] = FrontierDecisionReason.REPEATED_SEMANTICS
                continue
            cycle_semantics.add(semantic)
            scored_candidate_ids.append(score.candidate_id)
        candidate_by_id = {item.candidate_id: item for item in eligible}
        scores = list(
            self.scorer.rank(
                tuple(candidate_by_id[candidate_id] for candidate_id in scored_candidate_ids)
            )
        )
        decisions: dict[str, FrontierDecision] = {
            candidate_id: FrontierDecision(
                candidateId=candidate_id,
                disposition=FrontierDisposition.REJECTED,
                reason=reason,
            )
            for candidate_id, reason in rejected.items()
        }
        commands: list[AgentControlCommand] = []
        selected_count = 0
        selected_per_parent: dict[str, int] = {}

        for score in scores:
            candidate = candidate_by_id[score.candidate_id]
            parent = candidate.proposal.parent_hypothesis_id
            reason: FrontierDecisionReason
            disposition = FrontierDisposition.DEFERRED
            if score.score_bps < self.policy.min_score_bps:
                reason = FrontierDecisionReason.BELOW_SCORE_THRESHOLD
            elif self._total_assignments >= self.policy.max_total_assignments:
                reason = FrontierDecisionReason.ASSIGNMENT_BUDGET
            elif selected_count >= self.policy.beam_width:
                reason = FrontierDecisionReason.BEAM_LIMIT
            elif selected_per_parent.get(parent, 0) >= self.policy.max_candidates_per_parent:
                reason = FrontierDecisionReason.PARENT_BRANCH_LIMIT
            else:
                allocation = self._allocate(candidate)
                if allocation is None:
                    reason = FrontierDecisionReason.AGENT_CAPACITY
                else:
                    disposition = FrontierDisposition.SELECTED
                    reason = FrontierDecisionReason.SELECTED_BY_SCORE
                    selected_count += 1
                    selected_per_parent[parent] = selected_per_parent.get(parent, 0) + 1
                    commands.extend(allocation)
                    self._seen_candidate_ids.add(candidate.candidate_id)
                    self._seen_semantic_digests.add(semantic_digests[candidate.candidate_id])
                    self._total_assignments += 1
            decisions[candidate.candidate_id] = FrontierDecision(
                candidateId=candidate.candidate_id,
                disposition=disposition,
                reason=reason,
                scoreBps=score.score_bps,
            )

        self._revision += 1
        result_checkpoint = self.checkpoint()
        return DynamicSupervisorCycle(
            campaignId=self.campaign_id,
            revision=self._revision,
            sourceCheckpointId=source.checkpoint_id,
            sourceCheckpointDigest=source.checkpoint_digest,
            sourceCheckpoint=source,
            sourceSnapshot=self.source_snapshot,
            exploitGroup=self.exploit_group,
            supervisorPolicy=self.policy,
            scoringPolicy=self.scorer.policy,
            candidates=ordered,
            scores=tuple(scores),
            decisions=tuple(decisions[item].model_copy(deep=True) for item in candidate_ids),
            commands=tuple(commands),
            resultingCheckpoint=result_checkpoint,
        )

    def accept_event(self, event: AgentEvent) -> DynamicSupervisorCheckpoint:
        self._validate_configuration()
        event = AgentEvent.model_validate(event.model_dump(mode="json", by_alias=True))
        if event.campaign_id != self.campaign_id:
            raise ValueError("Agent Event belongs to another Campaign")
        binding = self._issued_commands.get(event.command_id)
        if binding is None or binding.agent_id != event.agent_id:
            raise ValueError("Agent Event is not bound to an issued command")
        binding = IssuedCommandBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        )
        if binding.task_id != event.task_id or binding.candidate_id != event.candidate_id:
            raise ValueError("Agent Event assignment differs from its issued command")
        if binding.terminal:
            raise ValueError("Agent Event command is already terminal")
        if event.sequence != binding.last_event_sequence + 1:
            raise ValueError("Agent Event sequence is not monotonic for its command")
        session = self._sessions.get(event.agent_id)
        if session is None:
            raise ValueError("Agent Event references an unknown session")
        session = AgentSessionSnapshot.model_validate(
            session.model_dump(mode="json", by_alias=True)
        )
        assignment = binding.command in {
            AgentControlCommandKind.ASSIGN,
            AgentControlCommandKind.FOLLOW_UP,
        }
        terminal_events = {
            AgentEventKind.FINAL,
            AgentEventKind.FAILED,
            AgentEventKind.BLOCKED,
            AgentEventKind.NEEDS_CAPABILITY,
            AgentEventKind.NEEDS_INPUT,
        }
        if not assignment and (
            event.event is not AgentEventKind.ACKNOWLEDGED
            or event.sequence != 1
            or event.artifact_refs
        ):
            raise ValueError("lifecycle command requires one content-free acknowledgement")
        if assignment and (
            session.state is not AgentSessionState.ASSIGNED
            or session.current_task_id != binding.task_id
            or session.current_candidate_id != binding.candidate_id
        ):
            raise ValueError("Agent Event does not match the current assignment")

        if event.event is AgentEventKind.FINAL:
            session = session.model_copy(
                update={
                    "state": AgentSessionState.IDLE,
                    "current_candidate_id": None,
                    "current_task_id": None,
                    "completed_tasks": session.completed_tasks + 1,
                    "context_refs": event.artifact_refs,
                }
            )
        elif event.event is AgentEventKind.FAILED:
            session = session.model_copy(
                update={
                    "state": AgentSessionState.FAILED,
                    "current_candidate_id": None,
                    "current_task_id": None,
                    "context_refs": event.artifact_refs,
                }
            )
        elif event.event in {
            AgentEventKind.BLOCKED,
            AgentEventKind.NEEDS_CAPABILITY,
            AgentEventKind.NEEDS_INPUT,
        }:
            session = session.model_copy(
                update={
                    "state": AgentSessionState.BLOCKED,
                    "current_candidate_id": None,
                    "current_task_id": None,
                    "context_refs": event.artifact_refs,
                }
            )
        elif event.artifact_refs:
            session = session.model_copy(update={"context_refs": event.artifact_refs})
        self._sessions[session.session_id] = AgentSessionSnapshot.model_validate(
            session.model_dump(mode="json", by_alias=True)
        )
        updated_binding = binding.model_copy(
            update={
                "last_event_sequence": event.sequence,
                "terminal": not assignment or event.event in terminal_events,
            }
        )
        self._issued_commands[binding.command_id] = IssuedCommandBinding.model_validate(
            updated_binding.model_dump(mode="json", by_alias=True)
        )
        self._revision += 1
        return self.checkpoint()

    def _validate_configuration(self) -> None:
        snapshot = GraphSnapshot.model_validate(
            self.source_snapshot.model_dump(mode="json", by_alias=True)
        )
        exploit_group = ExploitGroupDefinition.model_validate(
            self.exploit_group.model_dump(mode="json", by_alias=True)
        )
        policy = DynamicSupervisorPolicy.model_validate(
            self.policy.model_dump(mode="json", by_alias=True)
        )
        scoring_policy = PathScoringPolicy.model_validate(
            self.scorer.policy.model_dump(mode="json", by_alias=True)
        )
        allowed_targets = _canonical_identifiers(
            self.allowed_target_ids,
            label="allowed Target IDs",
        )
        actual_pin = (
            self.campaign_id,
            self.supervisor_agent_id,
            snapshot.snapshot_id,
            snapshot.snapshot_digest,
            allowed_targets,
            exploit_group.group_id,
            exploit_group.group_digest,
            policy.policy_id,
            policy.policy_digest,
            scoring_policy.policy_id,
            scoring_policy.policy_digest,
        )
        if actual_pin != self._configuration_pin:
            raise ValueError("Dynamic Supervisor configuration differs from its initial pin")
        self.source_snapshot = snapshot
        self.source_snapshot_id = snapshot.snapshot_id
        self.source_snapshot_digest = snapshot.snapshot_digest
        self.allowed_target_ids = allowed_targets
        self.exploit_group = exploit_group
        self.policy = policy
        self.scorer = PathScorer(scoring_policy)
        self._source_target_root_pairs = target_root_hypothesis_pairs(snapshot)

    def _structural_rejection(
        self,
        candidate: FrontierCandidate,
    ) -> FrontierDecisionReason | None:
        proposal = candidate.proposal
        if proposal.campaign_id != self.campaign_id:
            return FrontierDecisionReason.CROSS_CAMPAIGN
        if (
            proposal.source_snapshot_id != self.source_snapshot_id
            or proposal.source_snapshot_digest != self.source_snapshot_digest
        ):
            return FrontierDecisionReason.STALE_SNAPSHOT
        if proposal.target_id not in self.allowed_target_ids:
            return FrontierDecisionReason.TARGET_OUT_OF_SCOPE
        if proposal.depth > self.policy.max_depth:
            return FrontierDecisionReason.DEPTH_LIMIT
        if (
            proposal.depth != 1
            or proposal.ancestor_hypothesis_ids != (proposal.parent_hypothesis_id,)
            or (proposal.target_id, proposal.parent_hypothesis_id)
            not in self._source_target_root_pairs
        ):
            return FrontierDecisionReason.UNVERIFIED_LINEAGE
        if candidate.trusted_features.safety_risk_bps > self.policy.max_safety_risk_bps:
            return FrontierDecisionReason.SAFETY_RISK_LIMIT
        if candidate.candidate_id in self._seen_candidate_ids:
            return FrontierDecisionReason.REPEATED_CANDIDATE
        specialist = self.exploit_group.specialist_for(
            proposal.specialization,
            proposal.threat_class,
        )
        if specialist is None or not specialist.skill_refs:
            return FrontierDecisionReason.UNKNOWN_SPECIALIST
        return None

    def _allocate(
        self,
        candidate: FrontierCandidate,
    ) -> tuple[AgentControlCommand, ...] | None:
        specialization = candidate.proposal.specialization
        reusable = sorted(
            (
                session
                for session in self._sessions.values()
                if session.specialization is specialization
                and session.state is AgentSessionState.IDLE
            ),
            key=lambda item: item.session_id,
        )
        commands: list[AgentControlCommand] = []
        if reusable:
            session = reusable[0]
            assignment_kind = AgentControlCommandKind.FOLLOW_UP
        else:
            specialist = self.exploit_group.specialist_for(
                specialization,
                candidate.proposal.threat_class,
            )
            if specialist is None or not specialist.skill_refs:
                return None
            active = [
                session
                for session in self._sessions.values()
                if session.state
                not in {
                    AgentSessionState.COMPLETED,
                    AgentSessionState.FAILED,
                    AgentSessionState.CANCELLED,
                }
            ]
            same_role = [item for item in active if item.specialization is specialization]
            if (
                len(active) >= self.policy.max_active_agents
                or len(same_role) >= specialist.max_sessions
            ):
                return None
            session_id = self._new_session_id(specialization)
            session = AgentSessionSnapshot(
                sessionId=session_id,
                campaignId=self.campaign_id,
                parentAgentId=self.supervisor_agent_id,
                specialization=specialization,
                state=AgentSessionState.IDLE,
            )
            self._sessions[session_id] = session
            commands.append(
                self._issue_command(
                    command=AgentControlCommandKind.SPAWN,
                    session=session,
                )
            )
            assignment_kind = AgentControlCommandKind.ASSIGN

        task_id = "agentic-task_" + discovery_digest(
            "pajin.agentic.task/v1",
            {
                "campaignId": self.campaign_id,
                "candidateId": candidate.candidate_id,
                "assignmentOrdinal": self._total_assignments + 1,
            },
        )
        assigned = session.model_copy(
            update={
                "state": AgentSessionState.ASSIGNED,
                "current_candidate_id": candidate.candidate_id,
                "current_task_id": task_id,
            }
        )
        self._sessions[session.session_id] = AgentSessionSnapshot.model_validate(
            assigned.model_dump(mode="json", by_alias=True)
        )
        commands.append(
            self._issue_command(
                command=assignment_kind,
                session=self._sessions[session.session_id],
                task_id=task_id,
                candidate_id=candidate.candidate_id,
            )
        )
        return tuple(commands)

    def _issue_command(
        self,
        *,
        command: AgentControlCommandKind,
        session: AgentSessionSnapshot,
        task_id: str | None = None,
        candidate_id: str | None = None,
    ) -> AgentControlCommand:
        value = AgentControlCommand(
            campaignId=self.campaign_id,
            supervisorAgentId=self.supervisor_agent_id,
            sequence=self._next_command_sequence,
            command=command,
            targetAgentId=session.session_id,
            specialization=session.specialization,
            sourceSnapshotId=self.source_snapshot_id,
            sourceSnapshotDigest=self.source_snapshot_digest,
            supervisorPolicyDigest=self.policy.policy_digest,
            taskId=task_id,
            candidateId=candidate_id,
            contextRefs=session.context_refs,
        )
        self._next_command_sequence += 1
        self._issued_commands[value.command_id] = IssuedCommandBinding(
            commandId=value.command_id,
            agentId=value.target_agent_id,
            command=value.command,
            commandSequence=value.sequence,
            taskId=value.task_id,
            candidateId=value.candidate_id,
        )
        return value

    def _new_session_id(self, specialization: PentestSpecialization) -> str:
        ordinal = 1 + sum(
            session.specialization is specialization for session in self._sessions.values()
        )
        return "agent-session_" + discovery_digest(
            "pajin.agentic.agent-session/v1",
            {
                "campaignId": self.campaign_id,
                "supervisorAgentId": self.supervisor_agent_id,
                "exploitGroupId": self.exploit_group.group_id,
                "specialization": specialization.value,
                "ordinal": ordinal,
            },
        )

    @staticmethod
    def _semantic_digest(candidate: FrontierCandidate) -> str:
        return _candidate_semantic_digest(candidate)
