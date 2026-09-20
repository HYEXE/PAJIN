from __future__ import annotations

import json
from collections import UserDict, deque
from datetime import UTC, datetime
from types import MappingProxyType, MethodType
from typing import Any

import pytest
from pydantic import ValidationError

from pajin.agentic import (
    AgentControlCommand,
    AgentControlCommandKind,
    AgentEvent,
    AgentEventKind,
    AgentSessionState,
    ArtifactReference,
    DynamicSupervisor,
    DynamicSupervisorCheckpoint,
    DynamicSupervisorCycle,
    DynamicSupervisorPolicy,
    ExploitGroupDefinition,
    FrontierDecisionReason,
    FrontierDisposition,
    HypothesisExpansionContext,
    HypothesisExpansionDraft,
    HypothesisModelProjection,
    HypothesisObservation,
    HypothesisProposal,
    HypothesisSignal,
    ModelHypothesisDraft,
    ModelPathEstimate,
    PathScorer,
    PathScoringPolicy,
    PentestSpecialization,
    TrustedPathFeatures,
    build_hypothesis_model_projection,
    compile_frontier_candidate,
    default_path_scoring_policy,
    expand_hypothesis_frontier,
)
from pajin.agentic.runtime import (
    StructuredModelHypothesisRuntime,
    _compile_hypothesis_expansion,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.graph.models import (
    GraphContentOrigin,
    GraphEdge,
    GraphHypothesis,
    GraphRelation,
    GraphSurface,
    graph_node_ref,
)
from pajin.graph.projection import GraphProjection, GraphSnapshot, GraphSnapshotReason
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderUsage
from pajin.providers.receipts import (
    BoundProviderChatCall,
    ProviderBoundChatOutcome,
    ProviderChargedUsage,
    ProviderReportedUsage,
)
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.worker import WorkerStatus
from pajin.web_assessment.analysis_skill_projection import (
    registered_web_pentest_exploit_group,
)

CAMPAIGN = "juice-shop-agentic"
TARGET = "juice-shop-local"


def _graph_hypothesis(name: str) -> GraphHypothesis:
    return GraphHypothesis(
        campaignId=CAMPAIGN,
        hypothesisType="web.xss",
        statement=f"Canonical source Hypothesis {name}.",
        expectedObservable=f"Canonical observable for {name}.",
        producerId="pajin.agentic.tests",
        producerVersion="1.0.0",
        producerDigest=discovery_digest("pajin.test.producer/v1", {"name": name}),
        origin=GraphContentOrigin.TRUSTED_CORE,
        confidence=0.5,
    )


ROOT_XSS = _graph_hypothesis("root-xss")
ANOTHER_ROOT = _graph_hypothesis("another-root")
SECOND_ROOT = _graph_hypothesis("second-root")
SECOND_HOP = _graph_hypothesis("second-hop")
ROOT_SURFACE = GraphSurface(
    campaignId=CAMPAIGN,
    targetId=TARGET,
    surfaceType="web.http-operation",
    locatorSchema="pajin.test.target-neutral-locator",
    locatorDigest="d" * 64,
    origin=GraphContentOrigin.TRUSTED_CORE,
)
ROOT_EDGES = tuple(
    GraphEdge(
        campaignId=CAMPAIGN,
        relation=GraphRelation.MOTIVATES,
        source=graph_node_ref(ROOT_SURFACE),
        target=graph_node_ref(hypothesis),
        authorityId="agentic-test-authority",
        authorityDigest="a" * 64,
    )
    for hypothesis in (ROOT_XSS, ANOTHER_ROOT, SECOND_ROOT, SECOND_HOP)
)
GRAPH_PROJECTION = GraphProjection(
    campaignId=CAMPAIGN,
    revision=1,
    eventLogHeadDigest="e" * 64,
    nodes=tuple(
        sorted(
            (ROOT_SURFACE, ROOT_XSS, ANOTHER_ROOT, SECOND_ROOT, SECOND_HOP),
            key=lambda item: item.node_id,
        )
    ),
    edges=tuple(sorted(ROOT_EDGES, key=lambda item: item.edge_id)),
)
GRAPH_SNAPSHOT = GraphSnapshot(
    campaignId=CAMPAIGN,
    revision=GRAPH_PROJECTION.revision,
    eventLogHeadDigest=GRAPH_PROJECTION.event_log_head_digest,
    projectionId=GRAPH_PROJECTION.projection_id,
    projectionDigest=GRAPH_PROJECTION.projection_digest,
    nodeProjectionDigest=GRAPH_PROJECTION.node_projection_digest,
    edgeProjectionDigest=GRAPH_PROJECTION.edge_projection_digest,
    reason=GraphSnapshotReason.CHECKPOINT,
    createdAt=datetime(2026, 9, 17, tzinfo=UTC),
    creatorId="pajin.agentic.tests",
    creatorDigest=discovery_digest("pajin.test.snapshot-creator/v1", {"id": "agentic"}),
    projection=GRAPH_PROJECTION,
)
SNAPSHOT_ID = GRAPH_SNAPSHOT.snapshot_id
SNAPSHOT_DIGEST = GRAPH_SNAPSHOT.snapshot_digest


def _exploit_group() -> ExploitGroupDefinition:
    return registered_web_pentest_exploit_group()


def _candidate(
    name: str,
    *,
    campaign: str = CAMPAIGN,
    target: str = TARGET,
    specialization: PentestSpecialization = PentestSpecialization.XSS,
    threat_class: str = "xss",
    parent: str = ROOT_XSS.node_id,
    ancestors: tuple[str, ...] | None = None,
    depth: int = 1,
    likelihood: int = 7_000,
    evidence: int = 7_000,
    impact: int = 7_000,
    privilege: int = 5_000,
    reachability: int = 5_000,
    novelty: int = 7_000,
    cost: int = 2_000,
    safety: int = 1_000,
    snapshot_id: str = SNAPSHOT_ID,
    snapshot_digest: str = SNAPSHOT_DIGEST,
    required_evidence_types: tuple[str, ...] = (
        "web.independent-replay",
        "web.negative-control",
    ),
):
    ancestor_path = ancestors or (parent,)
    proposal = HypothesisProposal(
        campaignId=campaign,
        sourceSnapshotId=snapshot_id,
        sourceSnapshotDigest=snapshot_digest,
        parentHypothesisId=parent,
        ancestorHypothesisIds=ancestor_path,
        targetId=target,
        threatClass=threat_class,
        specialization=specialization,
        depth=depth,
        statement=f"Investigate bounded successor hypothesis {name}.",
        expectedObservable=f"Observe independently verifiable state transition {name}.",
        requiredEvidenceTypes=required_evidence_types,
        estimate=ModelPathEstimate(successLikelihoodBps=likelihood),
    )
    features = TrustedPathFeatures(
        sourceSnapshotId=snapshot_id,
        sourceSnapshotDigest=snapshot_digest,
        sourceEvidenceIds=(f"evidence:{name}",),
        expectedImpactBps=impact,
        privilegeGainBps=privilege,
        reachabilityGainBps=reachability,
        evidenceQualityBps=evidence,
        noveltyBps=novelty,
        executionCostBps=cost,
        safetyRiskBps=safety,
    )
    return compile_frontier_candidate(proposal, features)


def _supervisor(
    *,
    policy: DynamicSupervisorPolicy | None = None,
    allowed_targets: tuple[str, ...] = (TARGET,),
) -> DynamicSupervisor:
    return DynamicSupervisor(
        campaign_id=CAMPAIGN,
        supervisor_agent_id="agent:dynamic-supervisor",
        source_snapshot=GRAPH_SNAPSHOT,
        allowed_target_ids=allowed_targets,
        exploit_group=_exploit_group(),
        policy=policy,
    )


def _expansion_context() -> HypothesisExpansionContext:
    artifact = ArtifactReference(
        artifactId="artifact:juice-shop-observation",
        artifactSha256="b" * 64,
        mediaType="application/json",
        sourceRunId="run:juice-shop-agentic",
    )
    observation = HypothesisObservation(
        observationId="observation:search-reflection",
        targetId=TARGET,
        sourceArtifact=artifact,
        summary="The search value is reflected into a client-rendered result component.",
        signalIds=(HypothesisSignal.INPUT_REFLECTION,),
    )
    return HypothesisExpansionContext(
        campaignId=CAMPAIGN,
        sourceSnapshotId=SNAPSHOT_ID,
        sourceSnapshotDigest=SNAPSHOT_DIGEST,
        exploitGroup=_exploit_group(),
        parentHypothesisId=ROOT_XSS.node_id,
        ancestorHypothesisIds=(ROOT_XSS.node_id,),
        allowedTargetIds=(TARGET,),
        allowedSpecializations=(PentestSpecialization.XSS,),
        observations=(observation,),
        maxProposals=2,
    )


def _model_hypothesis(name: str = "reflected-xss") -> ModelHypothesisDraft:
    return ModelHypothesisDraft(
        threatClass="xss",
        specialization=PentestSpecialization.XSS,
        statement=f"Investigate the bounded {name} hypothesis.",
        expectedObservable=f"Observe a non-persistent rendering marker for {name}.",
        requiredEvidenceTypes=("web.independent-replay", "web.negative-control"),
        successLikelihoodBps=6_500,
    )


def _expansion_draft(
    projection: HypothesisModelProjection,
    *proposals: ModelHypothesisDraft,
) -> HypothesisExpansionDraft:
    return HypothesisExpansionDraft(
        apiVersion="pajin.dev/agentic-campaign/v1alpha1",
        kind="HypothesisExpansionDraft",
        projectionId=projection.projection_id,
        projectionDigest=projection.projection_digest,
        proposals=proposals,
    )


def _text_digest(label: str, value: str) -> str:
    return discovery_digest(f"pajin.provider.{label}/v1", {"text": value})


def _bound_call(
    *,
    chat: ProviderChatRequest,
    request_id: str,
    result: ProviderChatResult,
) -> BoundProviderChatCall:
    assert result.content is not None
    assert result.finish_reason is not None
    assert result.usage is not None
    evidence_reference = f"evidence/{request_id}.json"
    outcome = ProviderBoundChatOutcome(
        requestId=request_id,
        agentId="agent:hypothesis-frontier-expander",
        toolId="provider.local-test.chat",
        providerId=result.provider_id,
        model=result.model,
        providerRuntimeDigest="1" * 64,
        capabilityGrantDigest="2" * 64,
        chatRequestDigest=discovery_digest(
            "pajin.provider.chat-request/v1",
            chat.model_dump(mode="json", by_alias=True, exclude_none=False),
        ),
        toolRequestDigest="3" * 64,
        policyDecisionDigest="4" * 64,
        toolResultDigest="5" * 64,
        workerResultDigest="6" * 64,
        gatewayOutcomeDigest="7" * 64,
        providerResultDigest=discovery_digest(
            "pajin.provider.chat-result/v1",
            result.model_dump(mode="json", by_alias=True),
        ),
        responseIdDigest=_text_digest("response-id", result.response_id),
        responseIdBytes=len(result.response_id.encode()),
        targetDigest=_text_digest("target", result.target),
        contentDigest=_text_digest("content", result.content),
        contentBytes=len(result.content.encode()),
        refusalDigest=None,
        refusalBytes=0,
        finishReasonDigest=_text_digest("finish-reason", result.finish_reason),
        finishReasonBytes=len(result.finish_reason.encode()),
        toolCallsDigest=discovery_digest(
            "pajin.provider.normalized-tool-calls/v1",
            [],
        ),
        evidenceReferenceDigests=(_text_digest("evidence-reference", evidence_reference),),
        evidenceReferences=(evidence_reference,),
        toolCallCount=0,
        reportedUsage=ProviderReportedUsage(
            promptTokens=result.usage.prompt_tokens,
            completionTokens=result.usage.completion_tokens,
            totalTokens=result.usage.total_tokens,
            costUsd=0,
        ),
        chargedUsage=ProviderChargedUsage(
            promptTokens=10_000,
            completionTokens=4_096,
            totalTokens=14_096,
            costUsd=0,
            budgetScope="campaign",
        ),
        streamed=result.streamed,
        chunks=result.chunks,
        workerStatus=WorkerStatus.SUCCEEDED,
        workerExecutionIdDigest="8" * 64,
        workerBackendDigest="9" * 64,
        workerExitCode=0,
        networkLogTrusted=True,
    )
    return BoundProviderChatCall(result=result, outcome=outcome)


def test_default_exploit_group_uses_exact_installed_skill_references() -> None:
    group = _exploit_group()
    loaded = ExploitGroupDefinition.model_validate(
        group.model_dump(mode="json", by_alias=True)
    )

    assert loaded == group
    assert len(group.specialists) == 10
    assert {
        reference.skill_id
        for specialist in group.specialists
        for reference in specialist.skill_refs
    } == {
        "pajin.skill.web.assess-object-access",
        "pajin.skill.web.assess-sqli",
        "pajin.skill.web.assess-xss",
        "pajin.skill.web.compose-attack-path",
        "pajin.skill.web.write-security-finding",
    }
    assert group.scope_authority is False
    assert group.capability_authority is False
    assert group.permit_authority is False
    assert group.execution_authority is False


def test_hypothesis_wire_is_alias_only_and_cannot_smuggle_authority() -> None:
    candidate = _candidate("alias-contract")
    proposal = candidate.proposal
    raw = proposal.model_dump(mode="json", by_alias=True)

    assert HypothesisProposal.model_validate(raw) == proposal
    with pytest.raises(ValidationError):
        HypothesisProposal.model_validate(
            {
                **raw,
                "source_snapshot_id": raw.pop("sourceSnapshotId"),
            }
        )

    for field in (
        "scopeExpansionAuthorized",
        "capabilityGranted",
        "permitGranted",
        "executionAuthorized",
        "findingAuthority",
        "graphAdmissionAuthority",
    ):
        forged = proposal.model_dump(mode="json", by_alias=True)
        forged[field] = True
        with pytest.raises(ValidationError):
            HypothesisProposal.model_validate(forged)

    with pytest.raises(ValidationError):
        HypothesisProposal.model_validate(
            {
                **proposal.model_dump(mode="json", by_alias=True),
                "toolRequest": {"toolId": "browser.execute"},
            }
        )


def test_compiler_revalidates_hidden_model_copy_state() -> None:
    candidate = _candidate("hidden-state")
    forged = candidate.proposal.model_copy(update={"execution_authorized": True})

    with pytest.raises(ValidationError):
        compile_frontier_candidate(forged, candidate.trusted_features)


def test_path_scorer_is_deterministic_and_model_opinion_is_bounded() -> None:
    evidence_backed = _candidate(
        "evidence-backed",
        likelihood=3_000,
        evidence=9_500,
        impact=9_000,
        privilege=8_000,
        reachability=8_000,
        novelty=8_000,
        cost=1_000,
        safety=1_000,
    )
    model_only = _candidate(
        "model-only",
        likelihood=10_000,
        evidence=500,
        impact=3_000,
        privilege=1_000,
        reachability=1_000,
        novelty=2_000,
        cost=3_000,
        safety=4_000,
    )
    scorer = PathScorer()

    forward = scorer.rank((model_only, evidence_backed))
    reverse = scorer.rank((evidence_backed, model_only))

    assert forward == reverse
    assert forward[0].candidate_id == evidence_backed.candidate_id
    assert forward[0].score_bps > forward[1].score_bps
    assert all(item.decision_authority is False for item in forward)
    assert all(item.execution_authority is False for item in forward)

    raw = default_path_scoring_policy().model_dump(mode="json", by_alias=True)
    raw["modelLikelihoodWeightBps"] = 1_501
    raw["evidenceQualityWeightBps"] = 1_999
    raw.pop("policyId")
    raw.pop("policyDigest")
    with pytest.raises(ValidationError, match="advisory ceiling"):
        PathScoringPolicy.model_validate(raw)


def test_dynamic_supervisor_selects_bounded_top_k_and_only_emits_agent_control() -> None:
    policy = DynamicSupervisorPolicy(beamWidth=2, maxCandidatesPerParent=3, minScoreBps=0)
    supervisor = _supervisor(policy=policy)
    candidates = (
        _candidate("admin-api", impact=9_000, privilege=9_000),
        _candidate(
            "sql-injection",
            specialization=PentestSpecialization.SQL_INJECTION,
            threat_class="sql-injection",
            impact=8_000,
            reachability=9_000,
        ),
        _candidate(
            "object-access",
            specialization=PentestSpecialization.AUTHORIZATION,
            threat_class="authorization",
            impact=5_000,
        ),
    )

    cycle = supervisor.plan_cycle(tuple(reversed(candidates)))
    decisions = {item.candidate_id: item for item in cycle.decisions}
    selected = [
        item for item in cycle.decisions if item.disposition is FrontierDisposition.SELECTED
    ]

    assert len(selected) == 2
    assert sum(
        item.reason is FrontierDecisionReason.BEAM_LIMIT for item in cycle.decisions
    ) == 1
    assert [item.command for item in cycle.commands].count(AgentControlCommandKind.SPAWN) == 2
    assert [item.command for item in cycle.commands].count(AgentControlCommandKind.ASSIGN) == 2
    assert all(command.direct_peer_command is False for command in cycle.commands)
    assert all(command.scope_expansion_authorized is False for command in cycle.commands)
    assert all(command.capability_granted is False for command in cycle.commands)
    assert all(command.permit_granted is False for command in cycle.commands)
    assert all(command.tool_execution_authorized is False for command in cycle.commands)
    assert all(decisions[item.candidate_id].score_bps == item.score_bps for item in cycle.scores)
    wire = json.dumps(cycle.model_dump(mode="json", by_alias=True), sort_keys=True)
    assert "toolRequest" not in wire
    assert "actionPermit" not in wire
    assert cycle.task_graph_mutation_applied is False


def test_dynamic_supervisor_rejects_scope_depth_unknown_role_and_seen_semantics() -> None:
    policy = DynamicSupervisorPolicy(maxDepth=1, beamWidth=4, minScoreBps=0)
    supervisor = _supervisor(policy=policy)
    selected = _candidate("selected-once")
    first = supervisor.plan_cycle((selected,))
    assert first.decisions[0].disposition is FrontierDisposition.SELECTED

    repeated_semantics = _candidate(
        "selected-once",
        evidence=7_001,
    )
    second = supervisor.plan_cycle(
        (
            selected,
            repeated_semantics,
            _candidate("foreign-campaign", campaign="another-campaign"),
            _candidate("foreign-target", target="another-target"),
            _candidate(
                "too-deep",
                parent=SECOND_HOP.node_id,
                ancestors=(ROOT_XSS.node_id, SECOND_HOP.node_id),
                depth=2,
            ),
            _candidate(
                "unregistered-route",
                specialization=PentestSpecialization.API,
                threat_class="ssrf",
            ),
        )
    )
    reasons = {item.reason for item in second.decisions}

    assert FrontierDecisionReason.REPEATED_CANDIDATE in reasons
    assert FrontierDecisionReason.REPEATED_SEMANTICS in reasons
    assert FrontierDecisionReason.CROSS_CAMPAIGN in reasons
    assert FrontierDecisionReason.TARGET_OUT_OF_SCOPE in reasons
    assert FrontierDecisionReason.DEPTH_LIMIT in reasons
    assert FrontierDecisionReason.UNKNOWN_SPECIALIST in reasons
    assert second.commands == ()


def test_completed_specialist_session_is_reused_with_follow_up_command() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    first = supervisor.plan_cycle((_candidate("first-xss-task"),))
    assignment = next(
        command
        for command in first.commands
        if command.command is AgentControlCommandKind.ASSIGN
    )
    completed = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=assignment.target_agent_id,
        commandId=assignment.command_id,
        event=AgentEventKind.FINAL,
        taskId=assignment.task_id,
        candidateId=assignment.candidate_id,
        summary="The bounded specialist task completed and returned no command content.",
    )

    checkpoint = supervisor.accept_event(completed)
    assert checkpoint.sessions[0].state is AgentSessionState.IDLE
    assert checkpoint.sessions[0].completed_tasks == 1

    second = supervisor.plan_cycle(
        (
            _candidate(
                "second-xss-task",
                parent=SECOND_ROOT.node_id,
                ancestors=(SECOND_ROOT.node_id,),
            ),
        )
    )
    assert tuple(item.command for item in second.commands) == (
        AgentControlCommandKind.FOLLOW_UP,
    )
    assert second.commands[0].target_agent_id == assignment.target_agent_id


def test_needs_capability_event_blocks_session_but_cannot_grant_capability() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("needs-capability"),))
    assignment = next(
        command
        for command in cycle.commands
        if command.command is AgentControlCommandKind.ASSIGN
    )
    event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=assignment.target_agent_id,
        commandId=assignment.command_id,
        event=AgentEventKind.NEEDS_CAPABILITY,
        taskId=assignment.task_id,
        candidateId=assignment.candidate_id,
        summary="A separate trusted authority must decide any task-scoped capability request.",
    )

    checkpoint = supervisor.accept_event(event)

    assert checkpoint.sessions[0].state is AgentSessionState.BLOCKED
    assert event.capability_granted is False
    assert event.permit_granted is False
    assert event.execution_authorized is False


def test_checkpoint_round_trip_is_audit_only_and_restart_resume_is_closed() -> None:
    policy = DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0)
    original = _supervisor(policy=policy)
    original.plan_cycle((_candidate("checkpointed"),))
    checkpoint = original.checkpoint()
    loaded = DynamicSupervisorCheckpoint.model_validate(
        checkpoint.model_dump(mode="json", by_alias=True)
    )
    assert loaded == checkpoint
    assert loaded.restart_resume_supported is False
    assert loaded.durable_head_published is False
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        DynamicSupervisor(
            campaign_id=CAMPAIGN,
            supervisor_agent_id="agent:dynamic-supervisor",
            source_snapshot=GRAPH_SNAPSHOT,
            allowed_target_ids=(TARGET,),
            exploit_group=_exploit_group(),
            policy=policy,
            checkpoint=loaded,  # type: ignore[call-arg]
        )


def test_agent_event_rejects_unissued_or_cross_agent_report() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("event-binding"),))
    assignment = next(
        command
        for command in cycle.commands
        if command.command is AgentControlCommandKind.ASSIGN
    )
    foreign = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId="agent-session:foreign",
        commandId=assignment.command_id,
        event=AgentEventKind.FINAL,
        taskId=assignment.task_id,
        candidateId=assignment.candidate_id,
        summary="Attempted cross-agent terminal report.",
    )

    with pytest.raises(ValueError, match="issued command"):
        supervisor.accept_event(foreign)


def test_llm_expansion_compiler_injects_code_owned_path_and_authority() -> None:
    context = _expansion_context()
    projection = build_hypothesis_model_projection(context, source_snapshot=GRAPH_SNAPSHOT)
    draft = _expansion_draft(projection, _model_hypothesis())

    batch = _compile_hypothesis_expansion(
        context,
        projection,
        draft,
        source_snapshot=GRAPH_SNAPSHOT,
    )
    proposal = batch.proposals[0]

    assert proposal.campaign_id == CAMPAIGN
    assert proposal.source_snapshot_id == SNAPSHOT_ID
    assert proposal.source_snapshot_digest == SNAPSHOT_DIGEST
    assert proposal.parent_hypothesis_id == ROOT_XSS.node_id
    assert proposal.ancestor_hypothesis_ids == (ROOT_XSS.node_id,)
    assert proposal.depth == 1
    assert proposal.scope_expansion_authorized is False
    assert proposal.capability_granted is False
    assert proposal.permit_granted is False
    assert proposal.execution_authorized is False
    assert batch.task_graph_mutation_authorized is False
    assert batch.execution_authorized is False

    forged = draft.model_dump(mode="json", by_alias=True)
    forged["campaignId"] = CAMPAIGN
    with pytest.raises(ValidationError):
        HypothesisExpansionDraft.model_validate(forged)

    proposal_forgery = _model_hypothesis().model_dump(mode="json", by_alias=True)
    proposal_forgery["targetId"] = TARGET
    proposal_forgery["executionAuthorized"] = True
    with pytest.raises(ValidationError):
        ModelHypothesisDraft.model_validate(proposal_forgery)


def test_llm_expansion_rejects_projection_route_and_cardinality_drift() -> None:
    context = _expansion_context()
    projection = build_hypothesis_model_projection(context, source_snapshot=GRAPH_SNAPSHOT)
    foreign = _model_hypothesis().model_copy(update={"threat_class": "ssrf"})
    foreign_draft = _expansion_draft(projection, foreign)
    with pytest.raises(ValueError, match="no exact Exploit Group route"):
        _compile_hypothesis_expansion(
            context,
            projection,
            foreign_draft,
            source_snapshot=GRAPH_SNAPSHOT,
        )

    too_many = _expansion_draft(
        projection,
        _model_hypothesis("one"),
        _model_hypothesis("two"),
        _model_hypothesis("three"),
    )
    with pytest.raises(ValueError, match="proposal limit"):
        _compile_hypothesis_expansion(
            context,
            projection,
            too_many,
            source_snapshot=GRAPH_SNAPSHOT,
        )

    stale = HypothesisExpansionDraft(
        apiVersion="pajin.dev/agentic-campaign/v1alpha1",
        kind="HypothesisExpansionDraft",
        projectionId="hypothesis-projection_" + "c" * 64,
        projectionDigest="c" * 64,
        proposals=(_model_hypothesis(),),
    )
    with pytest.raises(ValueError, match="another Projection"):
        _compile_hypothesis_expansion(
            context,
            projection,
            stale,
            source_snapshot=GRAPH_SNAPSHOT,
        )

    forged_projection = projection.model_copy(update={"max_proposals": 1})
    with pytest.raises(ValueError, match=r"Projection Digest differs|private Context"):
        _compile_hypothesis_expansion(
            context,
            forged_projection,
            _expansion_draft(projection),
            source_snapshot=GRAPH_SNAPSHOT,
        )


@pytest.mark.asyncio
async def test_structured_model_runtime_uses_schema_only_and_compiles_output() -> None:
    context = _expansion_context()
    projection = build_hypothesis_model_projection(context, source_snapshot=GRAPH_SNAPSHOT)
    draft = _expansion_draft(projection, _model_hypothesis())
    calls: list[dict[str, Any]] = []
    provider_result = ProviderChatResult(
        provider_id="local-test",
        response_id="response-1",
        model="test-model",
        content=json.dumps(draft.model_dump(mode="json", by_alias=True)),
        refusal=None,
        finish_reason="stop",
        tool_calls=[],
        usage=ProviderUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
        streamed=False,
        chunks=1,
        target="http://127.0.0.1:11434/v1/chat/completions",
    )
    port = object.__new__(PolicyBoundProviderPort)

    async def chat_bound(_self: object, **kwargs: Any) -> BoundProviderChatCall:
        calls.append(kwargs)
        return _bound_call(
            chat=kwargs["chat"],
            request_id=kwargs["request_id"],
            result=provider_result,
        )

    port.chat_bound = MethodType(chat_bound, port)  # type: ignore[method-assign]
    runtime = StructuredModelHypothesisRuntime(
        port=port,
    )

    result = await expand_hypothesis_frontier(
        runtime,
        context,
        source_snapshot=GRAPH_SNAPSHOT,
    )

    assert len(result.batch.proposals) == 1
    assert result.batch.proposals[0].model_content_is_untrusted is True
    assert result.provider_call.result == provider_result
    assert len(calls) == 1
    call = calls[0]
    assert call["role"] == "hypothesis-frontier-expander"
    assert call["attempt"] == 1
    assert call["request_id"].startswith("agentic-hypothesis-")
    chat = call["chat"]
    assert chat.tools == []
    assert chat.tool_choice == "none"
    assert chat.parallel_tool_calls is False
    assert chat.temperature == 0
    assert "Do not call or request tools" in chat.messages[0].content
    model_input = chat.messages[1].content
    assert model_input is not None
    for private_value in (
        CAMPAIGN,
        TARGET,
        SNAPSHOT_ID,
        SNAPSHOT_DIGEST,
        "artifact:juice-shop-observation",
        "run:juice-shop-agentic",
        "The search value is reflected",
    ):
        assert private_value not in model_input

    with pytest.raises(RuntimeError, match="terminal after its first dispatch"):
        await expand_hypothesis_frontier(
            runtime,
            context,
            source_snapshot=GRAPH_SNAPSHOT,
        )
    assert len(calls) == 1


def test_dynamic_supervisor_hard_rejects_stale_snapshot_and_safety_limit() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=2, minScoreBps=0))
    stale = _candidate(
        "stale",
        snapshot_id="graph-snapshot:stale",
        snapshot_digest="d" * 64,
    )
    unsafe = _candidate("unsafe", safety=5_001)

    cycle = supervisor.plan_cycle((stale, unsafe))
    reasons = {item.candidate_id: item.reason for item in cycle.decisions}

    assert reasons[stale.candidate_id] is FrontierDecisionReason.STALE_SNAPSHOT
    assert reasons[unsafe.candidate_id] is FrontierDecisionReason.SAFETY_RISK_LIMIT
    assert cycle.scores == ()
    assert cycle.commands == ()


def test_same_cycle_semantic_duplicates_keep_only_highest_ranked_candidate() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=2, minScoreBps=0))
    higher = _candidate(
        "same-semantics",
        evidence=9_000,
        impact=9_000,
    )
    lower = _candidate(
        "same-semantics",
        evidence=1_000,
        impact=1_000,
    )

    cycle = supervisor.plan_cycle((lower, higher))
    decisions = {item.candidate_id: item for item in cycle.decisions}

    assert decisions[higher.candidate_id].disposition is FrontierDisposition.SELECTED
    assert decisions[lower.candidate_id].disposition is FrontierDisposition.REJECTED
    assert decisions[lower.candidate_id].reason is FrontierDecisionReason.REPEATED_SEMANTICS
    assert tuple(item.candidate_id for item in cycle.scores) == (higher.candidate_id,)


def test_taint_and_snapshot_bindings_survive_agent_control_round_trip() -> None:
    context = _expansion_context()
    observation = context.observations[0]
    assert observation.content_is_untrusted is True
    assert observation.instruction_authority is False
    assert observation.source_artifact.content_is_untrusted is True

    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("binding"),))
    commands = cycle.commands
    assert commands
    assert all(item.source_snapshot_id == SNAPSHOT_ID for item in commands)
    assert all(item.source_snapshot_digest == SNAPSHOT_DIGEST for item in commands)
    assert all(
        item.supervisor_policy_digest == supervisor.policy.policy_digest for item in commands
    )

    assignment = next(
        item for item in commands if item.command is AgentControlCommandKind.ASSIGN
    )
    event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=assignment.target_agent_id,
        commandId=assignment.command_id,
        event=AgentEventKind.PROGRESS,
        taskId=assignment.task_id,
        candidateId=assignment.candidate_id,
        summary="Target-derived progress remains untrusted status data.",
    )
    assert event.summary_is_untrusted is True
    assert event.instruction_authority is False


def test_agent_terminal_event_is_single_use_and_cannot_clear_a_follow_up() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    first = supervisor.plan_cycle((_candidate("single-use-event"),))
    assignment = next(
        item for item in first.commands if item.command is AgentControlCommandKind.ASSIGN
    )
    terminal = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=assignment.target_agent_id,
        commandId=assignment.command_id,
        event=AgentEventKind.FINAL,
        taskId=assignment.task_id,
        candidateId=assignment.candidate_id,
        summary="One terminal result.",
    )

    supervisor.accept_event(terminal)
    with pytest.raises(ValueError, match="already terminal"):
        supervisor.accept_event(terminal)

    second = supervisor.plan_cycle(
        (
            _candidate(
                "follow-up-after-terminal",
                parent=SECOND_ROOT.node_id,
                ancestors=(SECOND_ROOT.node_id,),
            ),
        )
    )
    follow_up = next(
        item for item in second.commands if item.command is AgentControlCommandKind.FOLLOW_UP
    )
    stale_terminal = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=2,
        agentId=assignment.target_agent_id,
        commandId=assignment.command_id,
        event=AgentEventKind.FINAL,
        taskId=assignment.task_id,
        candidateId=assignment.candidate_id,
        summary="A stale terminal event cannot clear the follow-up.",
    )
    with pytest.raises(ValueError, match="already terminal"):
        supervisor.accept_event(stale_terminal)
    session = supervisor.checkpoint().sessions[0]
    assert session.state is AgentSessionState.ASSIGNED
    assert session.current_task_id == follow_up.task_id


def test_agent_events_bind_command_kind_sequence_and_canonical_identity() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("event-state-machine"),))
    spawn = next(item for item in cycle.commands if item.command is AgentControlCommandKind.SPAWN)
    assignment = next(
        item for item in cycle.commands if item.command is AgentControlCommandKind.ASSIGN
    )
    invalid_spawn_terminal = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=spawn.target_agent_id,
        commandId=spawn.command_id,
        event=AgentEventKind.FINAL,
        summary="A spawn acknowledgement cannot terminate an assignment.",
    )
    with pytest.raises(ValueError, match="content-free acknowledgement"):
        supervisor.accept_event(invalid_spawn_terminal)

    out_of_order = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=2,
        agentId=assignment.target_agent_id,
        commandId=assignment.command_id,
        event=AgentEventKind.PROGRESS,
        taskId=assignment.task_id,
        candidateId=assignment.candidate_id,
        summary="Out-of-order progress.",
    )
    with pytest.raises(ValueError, match="not monotonic"):
        supervisor.accept_event(out_of_order)

    canonical_progress = out_of_order.model_copy(update={"sequence": 1})
    forged_terminal = canonical_progress.model_copy(update={"event": AgentEventKind.FINAL})
    with pytest.raises(ValidationError, match="Agent Event ID differs"):
        supervisor.accept_event(forged_terminal)

    acknowledgement = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=spawn.target_agent_id,
        commandId=spawn.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Spawn lifecycle acknowledged without assignment output.",
    )
    supervisor.accept_event(acknowledgement)
    forged_progress = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=2,
        agentId=spawn.target_agent_id,
        commandId=spawn.command_id,
        event=AgentEventKind.PROGRESS,
        summary="A lifecycle command cannot stream assignment artifacts.",
        artifactRefs=(
            ArtifactReference(
                artifactId="artifact:foreign-spawn-progress",
                artifactSha256="c" * 64,
                mediaType="application/json",
                sourceRunId="run:foreign-spawn-progress",
            ),
        ),
    )
    with pytest.raises(ValueError, match="already terminal"):
        supervisor.accept_event(forged_progress)
    assert supervisor.checkpoint().sessions[0].context_refs == ()


def test_policy_model_copy_and_half_bound_command_fail_closed() -> None:
    policy = DynamicSupervisorPolicy(maxSafetyRiskBps=1_000)
    forged_policy = policy.model_copy(update={"max_safety_risk_bps": 10_000})
    with pytest.raises(ValidationError, match="Policy Digest differs"):
        _supervisor(policy=forged_policy)

    scoring = default_path_scoring_policy()
    forged_scoring = scoring.model_copy(update={"model_likelihood_weight_bps": 10_000})
    with pytest.raises(ValidationError):
        PathScorer(forged_scoring)

    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    spawn = next(
        item
        for item in supervisor.plan_cycle((_candidate("half-bound"),)).commands
        if item.command is AgentControlCommandKind.SPAWN
    )
    wire = spawn.model_dump(mode="json", by_alias=True)
    wire.pop("commandId")
    wire["taskId"] = "agentic-task:orphan"
    with pytest.raises(ValidationError, match="must appear together"):
        AgentControlCommand.model_validate(wire)

    hidden_authority = spawn.model_copy(
        update={"tool_execution_authorized": True, "command_id": ""}
    )
    with pytest.raises(ValidationError, match="literal false"):
        AgentControlCommand.model_validate(hidden_authority)

    proposal = _candidate("nested-estimate-authority").proposal
    forged_estimate = proposal.estimate.model_copy(update={"evidence_authority": True})
    proposal_wire = proposal.model_dump(mode="json", by_alias=True)
    proposal_wire.pop("proposalId")
    proposal_wire.pop("proposalDigest")
    proposal_wire["estimate"] = forged_estimate
    with pytest.raises(ValidationError, match="literal false"):
        HypothesisProposal.model_validate(proposal_wire)
    with pytest.raises(ValidationError, match="literal false"):
        HypothesisProposal(**proposal_wire)

    artifact = ArtifactReference(
        artifactId="artifact:nested-command-authority",
        artifactSha256="d" * 64,
        mediaType="application/json",
        sourceRunId="run:nested-command-authority",
    )
    forged_artifact = artifact.model_copy(update={"instruction_authority": True})
    command_wire = spawn.model_dump(mode="json", by_alias=True)
    command_wire.pop("commandId")
    command_wire["contextRefs"] = (forged_artifact,)
    with pytest.raises(ValidationError, match="literal false"):
        AgentControlCommand.model_validate(command_wire)
    with pytest.raises(ValidationError, match="literal false"):
        AgentControlCommand(**command_wire)

    class LegacySequence:
        def __init__(self, value: ArtifactReference) -> None:
            self._value = value

        def __len__(self) -> int:
            return 1

        def __getitem__(self, index: int) -> ArtifactReference:
            if index != 0:
                raise IndexError
            return self._value

    unsupported_context_containers = (
        {forged_artifact},
        frozenset({forged_artifact}),
        deque((forged_artifact,)),
        iter((forged_artifact,)),
        (item for item in (forged_artifact,)),
        map(lambda item: item, (forged_artifact,)),
        UserDict({"artifact": forged_artifact}),
        MappingProxyType({"artifact": forged_artifact}),
        LegacySequence(forged_artifact),
    )
    for context_refs in unsupported_context_containers:
        unsupported_wire = spawn.model_dump(mode="json", by_alias=True)
        unsupported_wire.pop("commandId")
        unsupported_wire["contextRefs"] = context_refs
        with pytest.raises(ValidationError, match="unsupported value type"):
            AgentControlCommand.model_validate(unsupported_wire)

    running = _supervisor(policy=DynamicSupervisorPolicy(maxSafetyRiskBps=1_000))
    running.policy = running.policy.model_copy(update={"max_safety_risk_bps": 10_000})
    with pytest.raises(ValidationError, match="Policy Digest differs"):
        running.plan_cycle((_candidate("mutated-live-policy", safety=9_000),))


def test_graph_snapshot_membership_and_closed_signals_fail_closed() -> None:
    context = _expansion_context()
    forged = context.model_dump(mode="json", by_alias=True)
    forged["parentHypothesisId"] = "hypothesis:not-in-snapshot"
    forged["ancestorHypothesisIds"] = ["hypothesis:not-in-snapshot"]
    forged.pop("contextId")
    forged.pop("contextDigest")
    foreign_context = HypothesisExpansionContext.model_validate(forged)
    with pytest.raises(ValueError, match="absent from its Graph Snapshot"):
        build_hypothesis_model_projection(
            foreign_context,
            source_snapshot=GRAPH_SNAPSHOT,
        )

    observation = context.observations[0].model_dump(mode="json", by_alias=True)
    observation["signalIds"] = ["target.internal.example.com:8443"]
    with pytest.raises(ValidationError):
        HypothesisObservation.model_validate(observation)


def test_graph_root_must_be_motivated_by_the_exact_candidate_target() -> None:
    target_b = "juice-shop-secondary"
    surface_b = GraphSurface(
        campaignId=CAMPAIGN,
        targetId=target_b,
        surfaceType="web.http-operation",
        locatorSchema="pajin.test.target-neutral-locator",
        locatorDigest="e" * 64,
        origin=GraphContentOrigin.TRUSTED_CORE,
    )
    hypothesis_b = _graph_hypothesis("secondary-root")
    edge_b = GraphEdge(
        campaignId=CAMPAIGN,
        relation=GraphRelation.MOTIVATES,
        source=graph_node_ref(surface_b),
        target=graph_node_ref(hypothesis_b),
        authorityId="agentic-test-authority",
        authorityDigest="a" * 64,
    )
    projection = GraphProjection(
        campaignId=CAMPAIGN,
        revision=2,
        eventLogHeadDigest="f" * 64,
        nodes=tuple(
            sorted(
                (*GRAPH_PROJECTION.nodes, surface_b, hypothesis_b),
                key=lambda item: item.node_id,
            )
        ),
        edges=tuple(sorted((*GRAPH_PROJECTION.edges, edge_b), key=lambda item: item.edge_id)),
    )
    snapshot = GraphSnapshot(
        campaignId=CAMPAIGN,
        revision=projection.revision,
        eventLogHeadDigest=projection.event_log_head_digest,
        projectionId=projection.projection_id,
        projectionDigest=projection.projection_digest,
        nodeProjectionDigest=projection.node_projection_digest,
        edgeProjectionDigest=projection.edge_projection_digest,
        reason=GraphSnapshotReason.CHECKPOINT,
        createdAt=datetime(2026, 9, 17, tzinfo=UTC),
        creatorId="pajin.agentic.tests",
        creatorDigest=discovery_digest("pajin.test.snapshot-creator/v1", {"id": "multi"}),
        projection=projection,
    )
    context_wire = _expansion_context().model_dump(mode="json", by_alias=True)
    context_wire.pop("contextId")
    context_wire.pop("contextDigest")
    context_wire["sourceSnapshotId"] = snapshot.snapshot_id
    context_wire["sourceSnapshotDigest"] = snapshot.snapshot_digest
    context_wire["allowedTargetIds"] = [target_b]
    context_wire["observations"][0]["targetId"] = target_b
    foreign_target_context = HypothesisExpansionContext.model_validate(context_wire)

    with pytest.raises(ValueError, match="not motivated by its exact Target Surface"):
        build_hypothesis_model_projection(foreign_target_context, source_snapshot=snapshot)

    supervisor = DynamicSupervisor(
        campaign_id=CAMPAIGN,
        supervisor_agent_id="agent:dynamic-supervisor",
        source_snapshot=snapshot,
        allowed_target_ids=(target_b,),
        exploit_group=_exploit_group(),
        policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0),
    )
    candidate = _candidate(
        "cross-target-root",
        target=target_b,
        snapshot_id=snapshot.snapshot_id,
        snapshot_digest=snapshot.snapshot_digest,
    )
    cycle = supervisor.plan_cycle((candidate,))

    assert cycle.decisions[0].reason is FrontierDecisionReason.UNVERIFIED_LINEAGE
    assert cycle.commands == ()


def test_semantic_dedupe_preserves_distinct_evidence_contracts() -> None:
    supervisor = _supervisor(
        policy=DynamicSupervisorPolicy(
            beamWidth=2,
            maxCandidatesPerParent=2,
            minScoreBps=0,
        )
    )
    replay = _candidate(
        "same-statement",
        required_evidence_types=("web.independent-replay",),
    )
    control = _candidate(
        "same-statement",
        required_evidence_types=("web.negative-control",),
    )

    cycle = supervisor.plan_cycle((replay, control))

    assert len(cycle.scores) == 2
    assert all(
        item.disposition is FrontierDisposition.SELECTED for item in cycle.decisions
    )


def test_semantic_dedupe_normalizes_unicode_case_and_whitespace() -> None:
    supervisor = _supervisor(
        policy=DynamicSupervisorPolicy(
            beamWidth=2,
            maxCandidatesPerParent=2,
            minScoreBps=0,
        )
    )
    first = _candidate("normalized-semantics")
    for invisible in (
        "\u200b",
        "\u200c",
        "\u200d",
        "\ufeff",
        "\u2060",
        "\ufdd0",
        "\ufffe",
        "\ue000",
        "\U0010ffff",
        "\u2800",
    ):
        invisible_wire = first.proposal.model_dump(mode="json", by_alias=True)
        invisible_wire.pop("proposalId")
        invisible_wire.pop("proposalDigest")
        invisible_wire["statement"] = invisible_wire["statement"].replace(
            "bounded successor",
            f"bounded{invisible} successor",
        )
        with pytest.raises(ValidationError, match="default-ignorable"):
            HypothesisProposal.model_validate(invisible_wire)

    proposal_wire = first.proposal.model_dump(mode="json", by_alias=True)
    proposal_wire.pop("proposalId")
    proposal_wire.pop("proposalDigest")
    proposal_wire["statement"] = proposal_wire["statement"].replace(
        "bounded successor",
        "BOUNDED  successor",
    )
    feature_wire = first.trusted_features.model_dump(mode="json", by_alias=True)
    feature_wire.pop("featureSetId")
    feature_wire["sourceEvidenceIds"] = ["evidence:normalized-semantics-variant"]
    variant = compile_frontier_candidate(
        HypothesisProposal.model_validate(proposal_wire),
        TrustedPathFeatures.model_validate(feature_wire),
    )

    ordered = tuple(sorted((first, variant), key=lambda item: item.candidate_id))
    cycle = supervisor.plan_cycle(ordered)

    assert len(cycle.scores) == 1
    assert {
        decision.disposition for decision in cycle.decisions
    } == {FrontierDisposition.SELECTED, FrontierDisposition.REJECTED}
    assert FrontierDecisionReason.REPEATED_SEMANTICS in {
        decision.reason for decision in cycle.decisions
    }

    operator_supervisor = _supervisor(
        policy=DynamicSupervisorPolicy(
            beamWidth=2,
            maxCandidatesPerParent=2,
            minScoreBps=0,
        )
    )
    operator_candidates = []
    for operator, evidence_id in (("==", "evidence:role-equal"), ("!=", "evidence:role-not-equal")):
        operator_proposal_wire = first.proposal.model_dump(mode="json", by_alias=True)
        operator_proposal_wire.pop("proposalId")
        operator_proposal_wire.pop("proposalDigest")
        operator_proposal_wire["statement"] = f"Check whether role {operator} admin."
        operator_proposal_wire["expectedObservable"] = f"Observe whether role {operator} admin."
        operator_feature_wire = first.trusted_features.model_dump(mode="json", by_alias=True)
        operator_feature_wire.pop("featureSetId")
        operator_feature_wire["sourceEvidenceIds"] = [evidence_id]
        operator_candidates.append(
            compile_frontier_candidate(
                HypothesisProposal.model_validate(operator_proposal_wire),
                TrustedPathFeatures.model_validate(operator_feature_wire),
            )
        )

    operator_cycle = operator_supervisor.plan_cycle(tuple(operator_candidates))
    assert len(operator_cycle.scores) == 2
    assert all(
        decision.disposition is FrontierDisposition.SELECTED
        for decision in operator_cycle.decisions
    )


def test_cycle_strict_reload_recomputes_scores_and_cross_bindings() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("cycle-binding"),))
    wire = cycle.model_dump(mode="json", by_alias=True)
    wire["scores"][0]["candidateDigest"] = "f" * 64
    wire["scores"][0].pop("scoreId")
    wire.pop("cycleId")
    wire.pop("cycleDigest")

    with pytest.raises(ValidationError, match="Scores differ from deterministic replay"):
        DynamicSupervisorCycle.model_validate(wire)


def test_cycle_strict_reload_rejects_a_self_consistent_omitted_selection() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("omitted-selection"),))
    wire = cycle.model_dump(mode="json", by_alias=True)
    wire.pop("cycleId")
    wire.pop("cycleDigest")
    wire["scores"] = []
    wire["commands"] = []
    wire["decisions"][0] = {
        "candidateId": cycle.candidates[0].candidate_id,
        "disposition": "rejected",
        "reason": "repeated-semantics",
        "scoreBps": None,
    }
    wire["resultingCheckpoint"] = wire["sourceCheckpoint"] | {
        "checkpointId": "",
        "checkpointDigest": "",
        "revision": cycle.revision,
    }

    with pytest.raises(ValidationError, match="Scores differ from deterministic replay"):
        DynamicSupervisorCycle.model_validate(wire)


def test_cycle_strict_reload_rejects_a_resealed_forged_task_route() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("forged-task-route"),))
    assignment = next(
        item for item in cycle.commands if item.command is AgentControlCommandKind.ASSIGN
    )
    command_wire = assignment.model_dump(mode="json", by_alias=True)
    command_wire["commandId"] = ""
    command_wire["taskId"] = "agentic-task:forged-route"
    forged_command = AgentControlCommand.model_validate(command_wire)

    wire = cycle.model_dump(mode="json", by_alias=True)
    wire.pop("cycleId")
    wire.pop("cycleDigest")
    wire["commands"] = [
        forged_command.model_dump(mode="json", by_alias=True)
        if item["commandId"] == assignment.command_id
        else item
        for item in wire["commands"]
    ]
    checkpoint = wire["resultingCheckpoint"]
    checkpoint["checkpointId"] = ""
    checkpoint["checkpointDigest"] = ""
    for binding in checkpoint["issuedCommands"]:
        if binding["commandId"] == assignment.command_id:
            binding["commandId"] = forged_command.command_id
            binding["taskId"] = forged_command.task_id
    checkpoint["issuedCommands"].sort(key=lambda item: item["commandId"])
    for session in checkpoint["sessions"]:
        if session["sessionId"] == assignment.target_agent_id:
            session["currentTaskId"] = forged_command.task_id

    with pytest.raises(ValidationError, match="Commands differ from deterministic replay"):
        DynamicSupervisorCycle.model_validate(wire)


def test_cycle_strict_reload_rejects_a_preadvanced_new_command_binding() -> None:
    supervisor = _supervisor(policy=DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0))
    cycle = supervisor.plan_cycle((_candidate("preadvanced-binding"),))
    assignment = next(
        item for item in cycle.commands if item.command is AgentControlCommandKind.ASSIGN
    )
    wire = cycle.model_dump(mode="json", by_alias=True)
    wire.pop("cycleId")
    wire.pop("cycleDigest")
    checkpoint = wire["resultingCheckpoint"]
    checkpoint["checkpointId"] = ""
    checkpoint["checkpointDigest"] = ""
    for binding in checkpoint["issuedCommands"]:
        if binding["commandId"] == assignment.command_id:
            binding["lastEventSequence"] = 1
            binding["terminal"] = True

    with pytest.raises(ValidationError, match="terminal assignment remains live"):
        DynamicSupervisorCheckpoint.model_validate(checkpoint)
    with pytest.raises(ValidationError, match="terminal assignment remains live"):
        DynamicSupervisorCycle.model_validate(wire)


@pytest.mark.asyncio
async def test_provider_receipt_must_bind_the_exact_raw_result_and_failure_is_terminal() -> None:
    context = _expansion_context()
    projection = build_hypothesis_model_projection(context, source_snapshot=GRAPH_SNAPSHOT)
    draft = _expansion_draft(projection, _model_hypothesis())
    good = ProviderChatResult(
        provider_id="local-test",
        response_id="response-good",
        model="test-model",
        content=json.dumps(draft.model_dump(mode="json", by_alias=True)),
        refusal=None,
        finish_reason="stop",
        tool_calls=[],
        usage=ProviderUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
        streamed=False,
        chunks=1,
        target="http://127.0.0.1:11434/v1/chat/completions",
    )
    mismatched = good.model_copy(update={"response_id": "response-mismatched"})
    calls = 0
    port = object.__new__(PolicyBoundProviderPort)

    async def chat_bound(_self: object, **kwargs: Any) -> BoundProviderChatCall:
        nonlocal calls
        calls += 1
        bound = _bound_call(
            chat=kwargs["chat"],
            request_id=kwargs["request_id"],
            result=good,
        )
        return BoundProviderChatCall(result=mismatched, outcome=bound.outcome)

    port.chat_bound = MethodType(chat_bound, port)  # type: ignore[method-assign]
    runtime = StructuredModelHypothesisRuntime(port=port)

    with pytest.raises(ValueError, match="differs from its request or raw result"):
        await expand_hypothesis_frontier(
            runtime,
            context,
            source_snapshot=GRAPH_SNAPSHOT,
        )
    with pytest.raises(RuntimeError, match="terminal after its first dispatch"):
        await expand_hypothesis_frontier(
            runtime,
            context,
            source_snapshot=GRAPH_SNAPSHOT,
        )
    assert calls == 1


@pytest.mark.parametrize("value", [True, 1.0, "9000"])
def test_score_inputs_reject_boolean_float_and_string_coercion(value: object) -> None:
    raw = ModelPathEstimate(successLikelihoodBps=5_000).model_dump(
        mode="json",
        by_alias=True,
    )
    raw["successLikelihoodBps"] = value

    with pytest.raises(ValidationError):
        ModelPathEstimate.model_validate(raw)


def test_agentic_wire_rejects_cycles_without_recursion_error() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    with pytest.raises(ValidationError, match="contains a cycle"):
        ArtifactReference.model_validate(cyclic)


def test_agentic_wire_rejects_excessive_depth_and_nodes() -> None:
    deep: dict[str, object] = {}
    cursor = deep
    for index in range(40):
        nested: dict[str, object] = {}
        cursor[f"level-{index}"] = nested
        cursor = nested

    with pytest.raises(ValidationError, match="exceeds its depth limit"):
        ArtifactReference.model_validate(deep)

    oversized = {"items": [None] * 8_192}
    with pytest.raises(ValidationError, match="exceeds its node limit"):
        ArtifactReference.model_validate(oversized)


def test_agentic_wire_rejects_non_string_object_keys() -> None:
    with pytest.raises(ValidationError, match="object keys must be strings"):
        ArtifactReference.model_validate({1: "not-a-wire-key"})


def test_agentic_json_rejects_duplicate_keys_and_non_finite_numbers() -> None:
    with pytest.raises(ValueError, match="duplicate object key"):
        ArtifactReference.model_validate_json(
            '{"artifactId":"artifact-one","artifactId":"artifact-two"}'
        )
    with pytest.raises(ValueError, match="non-finite number"):
        ArtifactReference.model_validate_json('{"artifactId":NaN}')
