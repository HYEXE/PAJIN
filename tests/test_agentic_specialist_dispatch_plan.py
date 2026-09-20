from __future__ import annotations

import asyncio
import copy
import pickle
import socket
import sqlite3
import sys
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Event, Lock
from typing import Any, Protocol, cast

import pytest

import pajin.agentic.durable as durable_module
from pajin.agentic.durable import (
    AgenticCoordinationBinding,
    AgenticCoordinationError,
    AgenticCoordinationStore,
    AgenticSpecialistCapabilityGrantConsumptionReceipt,
    AgenticSpecialistDispatchPlanEntry,
    AgenticSpecialistDispatchPlanState,
    AgenticSpecialistExecutionState,
    VerifiedPlannedSpecialistDispatchStarted,
    VerifiedSpecialistDispatchPlan,
    VerifiedSpecialistExecutionReservation,
    VerifiedSpecialistPermitDispatcher,
)
from pajin.agentic.durable_graph import CurrentGraphHeadResolver, VerifiedCurrentGraphHead
from pajin.agentic.frontier import (
    FrontierCandidate,
    compile_frontier_candidate,
    default_path_scoring_policy,
)
from pajin.agentic.models import (
    AgentControlCommandKind,
    AgentEvent,
    AgentEventKind,
    HypothesisProposal,
    ModelPathEstimate,
    PentestSpecialization,
    TrustedPathFeatures,
)
from pajin.agentic.specialist_preparation import (
    AgenticSpecialistPreparation,
    AgenticSpecialistPreparationError,
    prepare_agentic_specialist_action,
)
from pajin.agentic.supervisor import DynamicSupervisor, DynamicSupervisorPolicy
from pajin.capabilities.activation import PreparedCapabilityAction
from pajin.capabilities.agentic_web_specialist import (
    WEB_SPECIALIST_REQUEST_UNITS,
    AgenticSpecialistPreparationRegistry,
    WebSpecialistCapabilityActivation,
    web_specialist_assessment_tools,
    web_specialist_capability_bundle,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph import (
    GraphAdmissionAuthority,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    SQLiteGraphStore,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_snapshot_ref,
)
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalEnvelope,
    ActionApprovalError,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionProposal,
    MissionEnvelope,
    action_permit_attempt_id,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.models import (
    GraphContentOrigin,
    GraphEdge,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphRelation,
    GraphSurface,
    graph_node_ref,
)
from pajin.graph.models import (
    HypothesisProposal as GraphHypothesisProposal,
)
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.web_assessment.analysis_skill_projection import registered_web_pentest_exploit_group
from pajin.web_assessment.governed import _campaign
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    GOVERNED_JUICE_SHOP_ORIGIN,
    GOVERNED_WEB_TARGET_ID,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_models import (
    SignedWebActionApproval,
    WebAssessmentSigningKeyState,
    WebAssessmentSigningRole,
    WebAssessmentVerificationKey,
    sign_web_action_approval,
    web_action_approval_issuer_binding,
    web_assessment_public_key_base64url,
)
from tests.test_agentic_web_specialist_capability import (
    SpecialistCapabilityFixture,
    _activation,
    _adapter_registry,
    _manifest,
    _receipt,
    _receipt_registry,
)

NOW = datetime(2026, 9, 18, 3, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


@dataclass(frozen=True, slots=True)
class GovernedDurableHarness:
    store: AgenticCoordinationStore
    binding: AgenticCoordinationBinding
    supervisor: DynamicSupervisor
    initial_head: object
    cycle: object
    snapshot: GraphSnapshot
    resolver: CurrentGraphHeadResolver
    graph_head: VerifiedCurrentGraphHead
    graph_store: SQLiteGraphStore
    campaign: CampaignManifest
    specialist_ledger: CapabilityLedger
    approval_key: WebAssessmentVerificationKey
    approval_private_key: bytes
    approval_clock: Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class SpecialistPlanFixture:
    harness: GovernedDurableHarness
    reservation: VerifiedSpecialistExecutionReservation
    preparation: AgenticSpecialistPreparation
    activation: WebSpecialistCapabilityActivation
    prepared_action: PreparedCapabilityAction
    ledger: CapabilityLedger
    root_grant: CapabilityGrant
    grant: CapabilityGrant
    approval: ActionApprovalEnvelope


class HarnessFactory(Protocol):
    def __call__(
        self,
        name: str,
        *,
        approval_clock: Callable[[], datetime] | None = None,
        coordination_clock: Callable[[], datetime] | None = None,
    ) -> GovernedDurableHarness: ...


class _FailingApprovalClock:
    """Keep the concrete signed verifier while failing one exact freshness check."""

    def __init__(self, *, fail_on_call: int) -> None:
        self.calls = 0
        self.fail_on_call = fail_on_call

    def __call__(self) -> datetime:
        self.calls += 1
        if self.calls == self.fail_on_call:
            return NOW + timedelta(minutes=6)
        return NOW + timedelta(seconds=10)


class _MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


def _governed_campaign() -> CampaignManifest:
    profile = production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    return _campaign(profile, now=NOW)


def _approval_signing_material(
    label: str,
) -> tuple[WebAssessmentVerificationKey, bytes]:
    key_label = sha256(label.encode()).hexdigest()[:16]
    private_key = sha256(f"agentic-c3b2:{label}".encode()).digest()
    key = WebAssessmentVerificationKey(
        keyId=f"agentic.c3b2.{key_label}",
        principalId=f"principal.agentic.c3b2.{key_label}",
        role=WebAssessmentSigningRole.ACTION_APPROVER,
        publicKeyBase64url=web_assessment_public_key_base64url(private_key),
        state=WebAssessmentSigningKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )
    return key, private_key


def _lineage(campaign_id: str, tag: str, *, producer_digest: str) -> GraphProposalLineage:
    digest = discovery_digest("pajin.agentic.c3b1-test-lineage/v1", {"tag": tag})
    return GraphProposalLineage(
        campaignId=campaign_id,
        runId=f"run:agentic-c3b1:{tag}",
        agentId="agent:agentic-c3b1-fixture",
        taskId=f"task:agentic-c3b1:{tag}",
        requestId=f"agentic_c3b1_{tag}",
        requestDigest=digest,
        capabilityGrantId=f"grant:agentic-c3b1:{tag}",
        capabilityGrantDigest=producer_digest,
        capabilityId="capability:agentic-c3b1-graph-fixture",
        capabilityVersion="1.0.0",
        capabilityDigest=SHA_C,
        sourceRootDigest=SHA_D,
        evidence=[
            GraphEvidenceBinding(
                reference=f"evidence/agentic-c3b1-{tag}.json",
                sha256=digest,
            )
        ],
        producedAt=NOW,
    )


def _candidate(
    name: str,
    *,
    campaign_id: str,
    snapshot: GraphSnapshot,
    parent_hypothesis_id: str,
) -> FrontierCandidate:
    proposal = HypothesisProposal(
        campaignId=campaign_id,
        sourceSnapshotId=snapshot.snapshot_id,
        sourceSnapshotDigest=snapshot.snapshot_digest,
        parentHypothesisId=parent_hypothesis_id,
        ancestorHypothesisIds=(parent_hypothesis_id,),
        targetId=GOVERNED_WEB_TARGET_ID,
        threatClass="xss",
        specialization=PentestSpecialization.XSS,
        depth=1,
        statement=f"Investigate the bounded governed XSS hypothesis {name}.",
        expectedObservable=f"Observe an independently replayable rendering marker {name}.",
        requiredEvidenceTypes=("web.independent-replay", "web.negative-control"),
        estimate=ModelPathEstimate(successLikelihoodBps=7_000),
    )
    features = TrustedPathFeatures(
        sourceSnapshotId=snapshot.snapshot_id,
        sourceSnapshotDigest=snapshot.snapshot_digest,
        sourceEvidenceIds=(f"evidence:{name}",),
        expectedImpactBps=7_000,
        privilegeGainBps=5_000,
        reachabilityGainBps=5_000,
        evidenceQualityBps=7_000,
        noveltyBps=7_000,
        executionCostBps=2_000,
        safetyRiskBps=1_000,
    )
    return compile_frontier_candidate(proposal, features)


def _seed_current_graph(
    path: Path,
    campaign_id: str,
) -> tuple[GraphSnapshot, GraphHypothesis, SQLiteGraphStore]:
    surface_producer_id = "pajin.agentic.c3b1-surface-fixture"
    surface_producer_digest = SHA_F
    surface = GraphSurface(
        campaignId=campaign_id,
        targetId=GOVERNED_WEB_TARGET_ID,
        surfaceType="web.http-operation",
        locatorSchema="pajin.test.target-neutral-locator",
        locatorDigest=SHA_D,
        origin=GraphContentOrigin.TRUSTED_CORE,
    )
    hypothesis = GraphHypothesis(
        campaignId=campaign_id,
        hypothesisType="web.xss",
        statement="Canonical governed XSS hypothesis for specialist dispatch planning.",
        expectedObservable="Observe one independently replayable DOM rendering marker.",
        producerId="pajin.agentic.c3b1-tests",
        producerVersion="1.0.0",
        producerDigest=SHA_E,
        origin=GraphContentOrigin.TRUSTED_CORE,
        confidence=0.5,
    )
    surface_proposal = SurfaceProposal(
        proposalId="proposal:agentic-c3b1:surface",
        producerId=surface_producer_id,
        producerVersion="1.0.0",
        producerDigest=surface_producer_digest,
        lineage=_lineage(campaign_id, "surface", producer_digest=surface_producer_digest),
        surface=surface,
    )
    hypothesis_proposal = GraphHypothesisProposal(
        proposalId="proposal:agentic-c3b1:hypothesis",
        producerId=hypothesis.producer_id,
        producerVersion=hypothesis.producer_version,
        producerDigest=hypothesis.producer_digest,
        lineage=_lineage(campaign_id, "hypothesis", producer_digest=hypothesis.producer_digest),
        hypothesis=hypothesis,
        edges=[
            GraphEdge(
                campaignId=campaign_id,
                relation=GraphRelation.MOTIVATES,
                source=graph_node_ref(surface),
                target=graph_node_ref(hypothesis),
                authorityId="agentic-c3b1-test-authority",
                authorityDigest=SHA_A,
            )
        ],
    )
    graph_store = SQLiteGraphStore(path, campaign_id=campaign_id)
    admission = GraphAdmissionAuthority(
        campaign_id=campaign_id,
        authority_id="pajin.agentic.c3b1-test-admission",
        authority_digest=SHA_A,
        producers=GraphProducerRegistry(
            (
                GraphProducerRegistration(
                    producerId=surface_producer_id,
                    producerVersion="1.0.0",
                    producerDigest=surface_producer_digest,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                GraphProducerRegistration(
                    producerId=hypothesis.producer_id,
                    producerVersion=hypothesis.producer_version,
                    producerDigest=hypothesis.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.HYPOTHESIS,),
                ),
            )
        ),
        lineage_verifier=TrustedGraphLineageRegistry(
            (surface_proposal.lineage, hypothesis_proposal.lineage)
        ),
        event_log=graph_store.event_log,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    admission.submit(surface_proposal)
    admission.submit(hypothesis_proposal)
    GraphProjectionCoordinator(
        event_log=graph_store.event_log,
        projection_store=graph_store.projection_store,
    ).refresh()
    snapshot = GraphSnapshotAuthority(
        creator_id="pajin.agentic.c3b1-test-snapshot",
        creator_digest=SHA_B,
        projection_store=graph_store.projection_store,
        snapshot_store=graph_store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=2),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    return snapshot, hypothesis, graph_store


def _make_harness(
    tmp_path: Path,
    name: str,
    *,
    approval_clock: Callable[[], datetime] | None = None,
    coordination_clock: Callable[[], datetime] | None = None,
) -> GovernedDurableHarness:
    campaign = _governed_campaign()
    graph_path = tmp_path / f"{name}-graph" / "canonical.sqlite3"
    snapshot, root_hypothesis, graph_store = _seed_current_graph(
        graph_path,
        campaign.metadata.name,
    )
    resolver = CurrentGraphHeadResolver(graph_path, campaign_id=campaign.metadata.name)
    graph_head = resolver.resolve(graph_snapshot_ref(snapshot))
    policy = DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0)
    group = registered_web_pentest_exploit_group()
    supervisor = DynamicSupervisor(
        campaign_id=campaign.metadata.name,
        supervisor_agent_id="agent:dynamic-supervisor",
        source_snapshot=snapshot,
        allowed_target_ids=(GOVERNED_WEB_TARGET_ID,),
        exploit_group=group,
        policy=policy,
    )
    initial = supervisor.checkpoint()
    cycle = supervisor.plan_cycle(
        (
            _candidate(
                name,
                campaign_id=campaign.metadata.name,
                snapshot=snapshot,
                parent_hypothesis_id=root_hypothesis.node_id,
            ),
        )
    )
    binding = AgenticCoordinationBinding.from_checkpoint(
        initial,
        control_plane_run_id=f"agentic-control-plane:{name}",
        campaign_manifest_digest=campaign_manifest_digest(campaign),
        deployment_digest=SHA_B,
        exploit_group=group,
        supervisor_policy=supervisor.policy,
        scoring_policy=default_path_scoring_policy(),
    )
    specialist_ledger = CapabilityLedger(
        max_depth=1,
        clock=lambda: NOW - timedelta(minutes=1),
    )
    approval_key, approval_private_key = _approval_signing_material(f"deployment:{name}")
    deployed_approval_clock = approval_clock or (lambda: NOW + timedelta(seconds=10))
    store_id = sha256(name.encode()).hexdigest()[:32]
    store = AgenticCoordinationStore(
        tmp_path / f"{name}-coordination.sqlite3",
        binding=binding,
        graph_resolver=resolver,
        graph_head=graph_head,
        specialist_graph_store=graph_store,
        specialist_capability_ledger=specialist_ledger,
        specialist_approval_keys=(approval_key,),
        specialist_approval_clock=deployed_approval_clock,
        clock=coordination_clock or (lambda: NOW + timedelta(seconds=10)),
        store_id_factory=lambda: f"agentic-store:{store_id}",
    )
    initial_head = store.initialize_head(initial, graph_resolver=resolver, graph_head=graph_head)
    return GovernedDurableHarness(
        store=store,
        binding=binding,
        supervisor=supervisor,
        initial_head=initial_head,
        cycle=cycle,
        snapshot=snapshot,
        resolver=resolver,
        graph_head=graph_head,
        graph_store=graph_store,
        campaign=campaign,
        specialist_ledger=specialist_ledger,
        approval_key=approval_key,
        approval_private_key=approval_private_key,
        approval_clock=deployed_approval_clock,
    )


@pytest.fixture
def harness_factory(tmp_path: Path) -> Iterator[HarnessFactory]:
    if sys.platform != "linux":
        pytest.skip("authoritative durable coordination requires Linux /proc descriptors")
    harnesses: list[GovernedDurableHarness] = []

    def factory(
        name: str,
        *,
        approval_clock: Callable[[], datetime] | None = None,
        coordination_clock: Callable[[], datetime] | None = None,
    ) -> GovernedDurableHarness:
        harness = _make_harness(
            tmp_path,
            name,
            approval_clock=approval_clock,
            coordination_clock=coordination_clock,
        )
        harnesses.append(harness)
        return harness

    yield factory
    for harness in harnesses:
        harness.store.close()
        harness.resolver.close()


def _graph_args(harness: GovernedDurableHarness) -> dict[str, object]:
    return {"graph_resolver": harness.resolver, "graph_head": harness.graph_head}


def _reserve_current_assignment(
    harness: GovernedDurableHarness,
) -> VerifiedSpecialistExecutionReservation:
    publication = harness.store.publish_cycle(
        cast(Any, harness.initial_head),
        cast(Any, harness.cycle),
        **cast(Any, _graph_args(harness)),
    )
    spawn_claim = harness.store.claim_next_delivery(**cast(Any, _graph_args(harness)))
    assert spawn_claim is not None
    assert spawn_claim.command.command is AgentControlCommandKind.SPAWN
    admission = harness.store.admit_delivery(
        spawn_claim,
        **cast(Any, _graph_args(harness)),
    )
    harness.store.acknowledge_delivery(
        spawn_claim,
        admission,
        **cast(Any, _graph_args(harness)),
    )
    spawn_event = AgentEvent(
        campaignId=spawn_claim.command.campaign_id,
        sequence=1,
        agentId=spawn_claim.command.target_agent_id,
        commandId=spawn_claim.command.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Spawn command durably admitted for C3B1 testing.",
    )
    current = harness.store.publish_event(
        publication.head,
        spawn_event,
        **cast(Any, _graph_args(harness)),
    )
    assignment_claim = harness.store.claim_next_delivery(**cast(Any, _graph_args(harness)))
    assert assignment_claim is not None
    assert assignment_claim.command.command is AgentControlCommandKind.ASSIGN
    assignment_admission = harness.store.admit_delivery(
        assignment_claim,
        **cast(Any, _graph_args(harness)),
    )
    harness.store.acknowledge_delivery(
        assignment_claim,
        assignment_admission,
        **cast(Any, _graph_args(harness)),
    )
    verified = harness.store.verified_admitted_specialist_assignment(
        current.head,
        command_id=assignment_claim.command.command_id,
        **cast(Any, _graph_args(harness)),
    )
    return harness.store.reserve_specialist_execution(
        verified,
        **cast(Any, _graph_args(harness)),
    )


def _approval(
    *,
    harness: GovernedDurableHarness,
    preparation: AgenticSpecialistPreparation,
    prepared_action: PreparedCapabilityAction,
) -> ActionApprovalEnvelope:
    campaign_digest = campaign_manifest_digest(harness.campaign)
    decision = GraphDecision(
        campaignId=harness.campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=preparation.preparation_digest,
        snapshot=graph_snapshot_ref(harness.snapshot),
        actorId="pajin.agentic.specialist-planner",
        actorDigest=SHA_C,
        createdAt=NOW + timedelta(seconds=3),
    )
    envelope = MissionEnvelope(
        campaignId=harness.campaign.metadata.name,
        runId=preparation.control_plane_run_id,
        profileId=preparation.profile.profile_id,
        profileVersion=preparation.profile.profile_version,
        profileDigest=preparation.profile.profile_digest,
        compilerId="pajin.agentic.specialist-compiler",
        compilerVersion="1.0.0",
        compilerDigest=SHA_D,
        sourceCampaignDigest=campaign_digest,
        allowedCapabilities=(prepared_action.capability,),
        allowedTargetDigests=(preparation.target_digest,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(
            toolCallLimit=1,
            requestUnitLimit=WEB_SPECIALIST_REQUEST_UNITS,
            costLimitMicrousd=0,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=harness.campaign.spec.authorization.approved_at,
        notBefore=NOW + timedelta(seconds=3),
        expiresAt=NOW + timedelta(minutes=10),
    )
    reservation = ActionBudgetReservation(
        requestUnits=WEB_SPECIALIST_REQUEST_UNITS,
        costMicrousd=0,
    )
    proposal = ActionProposal(
        campaignId=harness.campaign.metadata.name,
        runId=preparation.control_plane_run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        proposerId="pajin.agentic.specialist-planner",
        proposerDigest=SHA_C,
        capability=prepared_action.capability,
        targetDigest=preparation.target_digest,
        requestId=prepared_action.request.request_id,
        requestDigest=prepared_action.request_digest,
        normalizedParametersDigest=prepared_action.normalized_parameters_digest,
        riskTier=ToolRiskTier.T2,
        reservation=reservation,
        createdAt=NOW + timedelta(seconds=4),
    )
    return ActionApprovalEnvelope(
        issuer=ActionApprovalIssuerAuthorityBinding(
            authorityId="deployment:agentic-specialist-approval",
            authorityVersion="1.0.0",
            implementationType="tests.agentic.StaticSpecialistApprovalIssuer",
            contextDigest=SHA_E,
        ),
        requestedBy="principal:agentic-specialist-planner",
        approvedBy="principal:range-operator",
        campaignId=harness.campaign.metadata.name,
        campaignDigest=campaign_digest,
        runId=preparation.control_plane_run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=preparation.preparation_digest,
        activationSetDigest=prepared_action.activation_set_digest,
        release=ActionApprovalReleaseRef(
            releaseId=prepared_action.release.release_id,
            releaseDigest=prepared_action.release.release_digest,
            capabilityId=prepared_action.capability.capability_id,
            capabilityVersion=prepared_action.capability.capability_version,
            capabilityDigest=prepared_action.capability.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        cleanupRequired=False,
        reservation=reservation,
        approvedAt=NOW + timedelta(seconds=5),
        notBefore=NOW + timedelta(seconds=6),
        expiresAt=NOW + timedelta(minutes=5),
    )


def _specialist_fixture(harness: GovernedDurableHarness) -> SpecialistPlanFixture:
    reservation = _reserve_current_assignment(harness)
    preparation = prepare_agentic_specialist_action(
        store=harness.store,
        reservation=reservation,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        campaign=harness.campaign,
    )
    preparation_registry = AgenticSpecialistPreparationRegistry((preparation,))
    manifest = _manifest()
    receipt = _receipt(manifest)
    tools = web_specialist_assessment_tools(
        preparations=preparation_registry,
        adapters=_adapter_registry(manifest),
        account_receipts=_receipt_registry(receipt),
    )
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    bundle = web_specialist_capability_bundle(registry)
    capability_fixture = SpecialistCapabilityFixture(
        preparations=(preparation,),
        preparation_registry=preparation_registry,
        manifest=manifest,
        receipt=receipt,
        tools=tools,
        registry=registry,
        bundle=bundle,
    )
    activation = cast(
        WebSpecialistCapabilityActivation,
        _activation(capability_fixture, preparation.specialization),
    )
    prepared_action = activation.prepare_action(
        release=activation.activation_set.binding.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=receipt.reference(),
    )
    ledger = harness.specialist_ledger
    root_grant = ledger.issue_root(
        harness.campaign,
        subject="agent:agentic-specialist-root",
        tools={prepared_action.request.tool_id},
        targets={preparation.target_endpoint},
    )
    grant = ledger.delegate(
        root_grant.grant_id,
        subject=preparation.target_agent_id,
        tools={prepared_action.request.tool_id},
        targets={preparation.target_endpoint},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=NOW + timedelta(minutes=10),
        delegable=False,
    )
    approval = _approval(
        harness=harness,
        preparation=preparation,
        prepared_action=prepared_action,
    )
    return SpecialistPlanFixture(
        harness=harness,
        reservation=reservation,
        preparation=preparation,
        activation=activation,
        prepared_action=prepared_action,
        ledger=ledger,
        root_grant=root_grant,
        grant=grant,
        approval=approval,
    )


def _plan(fixture: SpecialistPlanFixture) -> VerifiedSpecialistDispatchPlan:
    return fixture.harness.store.plan_specialist_dispatch(
        fixture.reservation,
        preparation=fixture.preparation,
        activation=fixture.activation,
        prepared_action=cast(Any, fixture.prepared_action),
        campaign=fixture.harness.campaign,
        capability_ledger=fixture.ledger,
        capability_grant=fixture.grant,
        approval_envelope=fixture.approval,
        graph_resolver=fixture.harness.resolver,
        graph_head=fixture.harness.graph_head,
    )


def _signed_fixture(
    fixture: SpecialistPlanFixture,
    _label: str,
    *,
    key: WebAssessmentVerificationKey | None = None,
    private_key: bytes | None = None,
) -> tuple[SpecialistPlanFixture, SignedWebActionApproval]:
    if (key is None) != (private_key is None):
        raise ValueError("test approval key and private key must be supplied together")
    selected_key = key or fixture.harness.approval_key
    selected_private_key = private_key or fixture.harness.approval_private_key
    approval_values = fixture.approval.model_dump(mode="json", by_alias=True)
    approval_values.update(
        {
            "approvalId": "",
            "approvalDigest": "",
            "issuer": web_action_approval_issuer_binding(
                selected_key,
                role="source",
            ).model_dump(mode="json", by_alias=True),
            "approvedBy": selected_key.principal_id,
        }
    )
    approval = ActionApprovalEnvelope.model_validate(approval_values)
    signed = sign_web_action_approval(
        approval,
        role="source",
        key=selected_key,
        private_key=selected_private_key,
    )
    return replace(fixture, approval=approval), signed


def _bind_runtime(
    fixture: SpecialistPlanFixture,
    plan: VerifiedSpecialistDispatchPlan,
    signed_approval: SignedWebActionApproval,
) -> VerifiedSpecialistPermitDispatcher:
    return fixture.harness.store.bind_specialist_permit_dispatcher(
        plan,
        campaign=fixture.harness.campaign,
        preparation=fixture.preparation,
        capability_ledger=fixture.ledger,
        capability_grant=fixture.grant,
        activation=fixture.activation,
        prepared_action=fixture.prepared_action,
        approval_envelope=fixture.approval,
        signed_approval=signed_approval,
        graph_resolver=fixture.harness.resolver,
        graph_head=fixture.harness.graph_head,
    )


def test_plan_transfers_reservation_into_non_executing_awaiting_permit_authority(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _specialist_fixture(harness_factory("specialist-plan-transfer"))
    calls: list[str] = []

    def sync_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("sync")

    async def async_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("async")

    monkeypatch.setattr(CapabilityLedger, "consume", sync_tripwire)
    monkeypatch.setattr(durable_module, "_CAPABILITY_LEDGER_CONSUME_IMPLEMENTATION", sync_tripwire)
    monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
    monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
    monkeypatch.setattr(socket, "create_connection", sync_tripwire)

    plan = _plan(fixture)
    entry = plan.entry

    assert entry.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
    assert entry.reservation_id == fixture.reservation.entry.reservation_id
    assert entry.preparation_id == fixture.preparation.preparation_id
    assert entry.prepared_action == fixture.prepared_action
    assert entry.grant.grant_id == fixture.grant.grant_id
    assert entry.approval_envelope == fixture.approval
    assert entry.action_permit is None
    assert entry.approval_consumption_receipt is None
    assert entry.grant_consumption_receipt is None
    assert entry.callback_entered_at is None
    assert entry.reconciled_at is None
    assert entry.approval_authority is False
    assert entry.permit_authority is False
    assert entry.gateway_authority is False
    assert entry.worker_authority is False
    assert entry.execution_authority is False
    assert entry.finding_authority is False
    assert entry.graph_authority is False
    assert entry.automatic_redispatch_authorized is False
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls > 0
    assert (
        fixture.harness.store.specialist_execution_entry(
            command_id=fixture.reservation.entry.command_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistExecutionState.RESERVED
    )
    assert calls == []


def test_transferred_reservation_rejects_legacy_paths_and_plan_handle_is_noncopyable(
    harness_factory: HarnessFactory,
) -> None:
    fixture = _specialist_fixture(harness_factory("specialist-plan-one-use"))
    plan = _plan(fixture)

    with pytest.raises(AgenticSpecialistPreparationError, match="live store-local reservation"):
        prepare_agentic_specialist_action(
            store=fixture.harness.store,
            reservation=fixture.reservation,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
            campaign=fixture.harness.campaign,
        )
    with pytest.raises(AgenticCoordinationError, match="transferred to a Permit plan"):
        fixture.harness.store.begin_specialist_dispatch(
            fixture.reservation,
            **cast(Any, _graph_args(fixture.harness)),
        )
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(plan)
    with pytest.raises(AgenticCoordinationError, match="verified one-use reservation"):
        fixture.harness.store.begin_specialist_dispatch(
            cast(Any, plan.entry),
            **cast(Any, _graph_args(fixture.harness)),
        )


def test_reopen_recovers_audit_plan_without_reissuing_runtime_authority(
    harness_factory: HarnessFactory,
) -> None:
    fixture = _specialist_fixture(harness_factory("specialist-plan-reopen"))
    plan = _plan(fixture)
    reopened = AgenticCoordinationStore(
        fixture.harness.store.path,
        binding=fixture.harness.binding,
        graph_resolver=fixture.harness.resolver,
        graph_head=fixture.harness.graph_head,
        specialist_graph_store=fixture.harness.graph_store,
        specialist_capability_ledger=fixture.harness.specialist_ledger,
        specialist_approval_keys=(fixture.harness.approval_key,),
        specialist_approval_clock=fixture.harness.approval_clock,
        allow_create=False,
        expected_store_id=fixture.harness.store.store_id,
        clock=lambda: NOW + timedelta(seconds=20),
    )
    try:
        recovery = reopened.recovery_snapshot(**cast(Any, _graph_args(fixture.harness)))
        assert recovery.awaiting_specialist_dispatch_plans == (plan.entry,)
        assert recovery.terminal_specialist_dispatch_plans == ()
        assert recovery.automatic_redispatch_authorized is False
        audit = reopened.specialist_dispatch_plan_entry(
            plan_id=plan.entry.plan_id,
            **cast(Any, _graph_args(fixture.harness)),
        )
        assert audit == plan.entry
        assert type(audit) is AgenticSpecialistDispatchPlanEntry
        assert not isinstance(audit, VerifiedSpecialistDispatchPlan)
        with pytest.raises(AgenticCoordinationError, match="verified one-use reservation"):
            reopened.begin_specialist_dispatch(
                cast(Any, audit),
                **cast(Any, _graph_args(fixture.harness)),
            )
    finally:
        reopened.close()


def test_invalid_task_grant_preserves_reservation_and_all_capability_budget(
    harness_factory: HarnessFactory,
) -> None:
    fixture = _specialist_fixture(harness_factory("specialist-plan-invalid-grant"))
    root_remaining_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls
    wrong_grant = fixture.ledger.delegate(
        fixture.root_grant.grant_id,
        subject="agent:wrong-specialist",
        tools={cast(Any, fixture.prepared_action).request.tool_id},
        targets={fixture.preparation.target_endpoint},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=NOW + timedelta(minutes=10),
        delegable=False,
    )

    with pytest.raises(AgenticCoordinationError, match="not exact and consumable"):
        fixture.harness.store.plan_specialist_dispatch(
            fixture.reservation,
            preparation=fixture.preparation,
            activation=fixture.activation,
            prepared_action=cast(Any, fixture.prepared_action),
            campaign=fixture.harness.campaign,
            capability_ledger=fixture.ledger,
            capability_grant=wrong_grant,
            approval_envelope=fixture.approval,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )

    assert fixture.ledger.record(wrong_grant.grant_id).remaining_calls == 1
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
    assert (
        fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_remaining_before
    )
    recovery = fixture.harness.store.recovery_snapshot(**cast(Any, _graph_args(fixture.harness)))
    assert recovery.awaiting_specialist_dispatch_plans == ()
    assert recovery.terminal_specialist_dispatch_plans == ()
    assert recovery.reserved_specialist_executions == (fixture.reservation.entry,)
    assert (
        fixture.harness.store.specialist_preparation_entry(
            fixture.reservation,
            **cast(Any, _graph_args(fixture.harness)),
        )
        == fixture.reservation.entry
    )
    plan = _plan(fixture)
    assert plan.entry.grant.grant_id == fixture.grant.grant_id
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1


def test_failed_plan_commit_does_not_consume_the_original_reservation_handle(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _specialist_fixture(harness_factory("specialist-plan-commit-failure"))

    def fail_insert(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.IntegrityError("synthetic plan insertion failure")

    with monkeypatch.context() as patch:
        patch.setattr(durable_module, "_insert_specialist_dispatch_plan", fail_insert)
        with pytest.raises(AgenticCoordinationError, match="lost its one-use atomic race"):
            _plan(fixture)

    recovery = fixture.harness.store.recovery_snapshot(**cast(Any, _graph_args(fixture.harness)))
    assert recovery.awaiting_specialist_dispatch_plans == ()
    assert recovery.terminal_specialist_dispatch_plans == ()
    assert recovery.reserved_specialist_executions == (fixture.reservation.entry,)
    assert (
        fixture.harness.store.specialist_preparation_entry(
            fixture.reservation,
            **cast(Any, _graph_args(fixture.harness)),
        )
        == fixture.reservation.entry
    )
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1

    plan = _plan(fixture)
    assert plan.entry.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT


def test_signed_permit_callback_atomically_fences_plan_and_execution_without_target_io(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-happy"))
    fixture, signed_approval = _signed_fixture(unsigned, "specialist-permit-happy")
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    calls: list[str] = []

    async def async_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("async")

    def sync_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("sync")

    monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
    monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
    monkeypatch.setattr(socket, "create_connection", sync_tripwire)
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    result = asyncio.run(
        fixture.harness.store.dispatch_specialist_permit_once(
            plan,
            runtime,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
    )

    assert result.dispatched is True
    assert type(result.result) is VerifiedPlannedSpecialistDispatchStarted
    started = result.result
    assert started.plan.state is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    assert (
        started.execution.state is AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    )
    assert started.plan.callback_entered_at == started.execution.dispatch_started_at
    assert started.permit == result.authorization.action.permit
    assert started.approval_receipt == result.authorization.receipt
    grant_receipt = started.grant_consumption_receipt
    assert grant_receipt == started.plan.grant_consumption_receipt
    assert grant_receipt.store_id == plan.entry.store_id
    assert grant_receipt.coordination_binding_digest == plan.entry.coordination_binding_digest
    assert grant_receipt.plan_id == plan.entry.plan_id
    assert grant_receipt.plan_digest == plan.entry.plan_digest
    assert grant_receipt.reservation_id == plan.entry.reservation_id
    assert grant_receipt.reservation_digest == plan.entry.reservation_digest
    assert grant_receipt.command_id == plan.entry.command_id
    assert grant_receipt.command_digest == plan.entry.command_digest
    assert grant_receipt.capability_grant_id == fixture.grant.grant_id
    assert grant_receipt.capability_grant_digest == plan.entry.grant.grant_digest
    assert grant_receipt.action_permit_id == started.permit.permit_id
    assert grant_receipt.action_permit_digest == started.permit.permit_digest
    assert grant_receipt.approval_consumption_receipt_id == started.approval_receipt.receipt_id
    assert (
        grant_receipt.approval_consumption_receipt_digest == started.approval_receipt.receipt_digest
    )
    assert grant_receipt.consumed_calls == 1
    assert started.plan.callback_entered_at is not None
    assert started.plan.callback_entered_at <= grant_receipt.consumed_at
    assert grant_receipt.consumed_at < started.permit.expires_at
    receipt_material = grant_receipt.model_dump(
        mode="json",
        by_alias=True,
        exclude={"receipt_id", "receipt_digest"},
    )
    assert grant_receipt.receipt_digest == discovery_digest(
        "pajin.agentic.specialist-capability-grant-consumption-receipt/v1",
        receipt_material,
    )
    assert grant_receipt.receipt_id == (
        f"agentic-specialist-grant-consumption_{grant_receipt.receipt_digest}"
    )
    audit = fixture.harness.store.specialist_dispatch_plan_entry(
        plan_id=plan.entry.plan_id,
        **cast(Any, _graph_args(fixture.harness)),
    )
    assert audit.grant_consumption_receipt == grant_receipt
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before - 1
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before - 1
    assert calls == []
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(started)
    with pytest.raises(AgenticCoordinationError, match=r"belongs|consumed"):
        asyncio.run(
            fixture.harness.store.dispatch_specialist_permit_once(
                plan,
                runtime,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
        )


def test_foreign_signed_approval_is_rejected_before_permit_or_grant_consumption(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-foreign-approval"))
    foreign_key, foreign_private_key = _approval_signing_material("foreign-approval")
    fixture, foreign_signed_approval = _signed_fixture(
        unsigned,
        "foreign-approval",
        key=foreign_key,
        private_key=foreign_private_key,
    )
    plan = _plan(fixture)
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    with pytest.raises(AgenticCoordinationError, match="outside the deployment trust root"):
        _bind_runtime(fixture, plan, foreign_signed_approval)

    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert (
        fixture.harness.graph_store.permit_store.approved_authorization(
            fixture.approval.approval_id,
            fixture.approval.expected_action_permit_id,
        )
        is None
    )
    assert (
        fixture.harness.store.specialist_dispatch_plan_entry(
            plan_id=plan.entry.plan_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
    )


def test_same_path_graph_store_cannot_replace_deployment_or_enter_bind_api(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-pinned-graph-store"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-permit-pinned-graph-store",
    )
    plan = _plan(fixture)
    same_path_store = SQLiteGraphStore(
        fixture.harness.graph_store.path,
        campaign_id=fixture.harness.campaign.metadata.name,
        initialize=False,
    )
    # Inspect only the sealed owner identity: the public bind API deliberately has no
    # graph_store parameter, while this assertion proves even the same-path object is foreign.
    deployment = cast(
        Any,
        fixture.harness.store,
    )._AgenticCoordinationStore__specialist_deployment

    with pytest.raises(AgenticCoordinationError, match="authority changed"):
        deployment.require_runtime(
            graph_store=same_path_store,
            capability_ledger=fixture.ledger,
        )
    with pytest.raises(TypeError, match="unexpected keyword argument 'graph_store'"):
        cast(Any, fixture.harness.store).bind_specialist_permit_dispatcher(
            plan,
            campaign=fixture.harness.campaign,
            preparation=fixture.preparation,
            capability_ledger=fixture.ledger,
            capability_grant=fixture.grant,
            activation=fixture.activation,
            prepared_action=fixture.prepared_action,
            approval_envelope=fixture.approval,
            signed_approval=signed_approval,
            graph_store=same_path_store,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )

    runtime = _bind_runtime(fixture, plan, signed_approval)
    pinned_store = cast(
        Any,
        runtime,
    )._VerifiedSpecialistPermitDispatcher__graph_store
    assert pinned_store is fixture.harness.graph_store
    assert pinned_store is not same_path_store


def test_exact_same_plan_bind_reuses_deployment_dispatcher_and_approval_verifier(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-repeat-bind"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-permit-repeat-bind",
    )
    plan = _plan(fixture)
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    first = _bind_runtime(fixture, plan, signed_approval)
    second = _bind_runtime(fixture, plan, signed_approval)

    first_runtime = cast(Any, first)
    second_runtime = cast(Any, second)
    assert type(first) is VerifiedSpecialistPermitDispatcher
    assert type(second) is VerifiedSpecialistPermitDispatcher
    assert (
        first_runtime._VerifiedSpecialistPermitDispatcher__deployment
        is second_runtime._VerifiedSpecialistPermitDispatcher__deployment
    )
    assert (
        first_runtime._VerifiedSpecialistPermitDispatcher__dispatcher
        is second_runtime._VerifiedSpecialistPermitDispatcher__dispatcher
    )
    assert (
        first_runtime._VerifiedSpecialistPermitDispatcher__approval_authority
        is second_runtime._VerifiedSpecialistPermitDispatcher__approval_authority
    )
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert fixture.harness.graph_store.permit_store.approval_consumptions() == ()
    assert (
        fixture.harness.store.specialist_dispatch_plan_entry(
            plan_id=plan.entry.plan_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
    )


def test_concurrent_first_bind_atomically_configures_and_pins_shared_writer(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-first-bind-race"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-permit-first-bind-race",
    )
    plan = _plan(fixture)
    store = cast(Any, fixture.harness.store)
    deployment = store._AgenticCoordinationStore__specialist_deployment
    deployment_type = type(deployment)
    deployment_store_type = type(fixture.harness.store)
    original_require = deployment_store_type._require_specialist_deployment
    original_configure = deployment_type.configure_plan
    counter_lock = Lock()
    require_calls = 0
    second_require_entered = Event()
    configured = Event()
    release_first = Event()

    def observe_require(observed_store: Any) -> object:
        nonlocal require_calls
        with counter_lock:
            require_calls += 1
            ordinal = require_calls
        if ordinal == 2:
            second_require_entered.set()
        return original_require(observed_store)

    def pause_after_first_configuration(
        observed_deployment: object,
        **kwargs: object,
    ) -> object:
        result = original_configure(observed_deployment, **kwargs)
        if not configured.is_set():
            configured.set()
            assert release_first.wait(timeout=5)
        return result

    monkeypatch.setattr(
        deployment_store_type,
        "_require_specialist_deployment",
        observe_require,
    )
    monkeypatch.setattr(deployment_type, "configure_plan", pause_after_first_configuration)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(_bind_runtime, fixture, plan, signed_approval)
        assert configured.wait(timeout=5)
        second = executor.submit(_bind_runtime, fixture, plan, signed_approval)
        assert second_require_entered.wait(timeout=5)
        release_first.set()
        runtimes = (first.result(timeout=5), second.result(timeout=5))

    assert all(type(runtime) is VerifiedSpecialistPermitDispatcher for runtime in runtimes)
    first_runtime, second_runtime = (cast(Any, runtime) for runtime in runtimes)
    assert (
        first_runtime._VerifiedSpecialistPermitDispatcher__dispatcher
        is second_runtime._VerifiedSpecialistPermitDispatcher__dispatcher
    )
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1


def test_replaced_store_specialist_deployment_is_rejected_before_authority_consumption(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-replaced-deployment"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-permit-replaced-deployment",
    )
    plan = _plan(fixture)
    store = cast(Any, fixture.harness.store)
    deployment_field = "_AgenticCoordinationStore__specialist_deployment"
    identity_field = "_AgenticCoordinationStore__specialist_deployment_identity"
    original_deployment = getattr(store, deployment_field)
    pinned_identity = getattr(store, identity_field)
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls
    assert original_deployment is pinned_identity

    try:
        object.__setattr__(store, deployment_field, object())
        with pytest.raises(AgenticCoordinationError, match="not pinned by this deployment"):
            _bind_runtime(fixture, plan, signed_approval)
    finally:
        object.__setattr__(store, deployment_field, original_deployment)

    assert getattr(store, deployment_field) is original_deployment
    assert getattr(store, identity_field) is pinned_identity
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert fixture.harness.graph_store.permit_store.approval_consumptions() == ()
    assert (
        fixture.harness.store.specialist_dispatch_plan_entry(
            plan_id=plan.entry.plan_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
    )
    restored_runtime = _bind_runtime(fixture, plan, signed_approval)
    assert type(restored_runtime) is VerifiedSpecialistPermitDispatcher


def test_deployment_internal_graph_and_permit_swap_is_rejected_before_authority_consumption(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-inner-graph-swap"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-permit-inner-graph-swap",
    )
    plan = _plan(fixture)
    deployment = cast(
        Any,
        fixture.harness.store,
    )._AgenticCoordinationStore__specialist_deployment
    graph_field = "_AgenticSpecialistPermitDeployment__graph_store"
    permit_field = "_AgenticSpecialistPermitDeployment__permit_store"
    original_graph = getattr(deployment, graph_field)
    original_permit = getattr(deployment, permit_field)
    same_path_store = SQLiteGraphStore(
        fixture.harness.graph_store.path,
        campaign_id=fixture.harness.campaign.metadata.name,
        initialize=False,
    )
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    try:
        object.__setattr__(deployment, graph_field, same_path_store)
        object.__setattr__(deployment, permit_field, same_path_store.permit_store)
        with pytest.raises(AgenticCoordinationError, match="authority changed"):
            _bind_runtime(fixture, plan, signed_approval)
    finally:
        object.__setattr__(deployment, graph_field, original_graph)
        object.__setattr__(deployment, permit_field, original_permit)

    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert type(_bind_runtime(fixture, plan, signed_approval)) is VerifiedSpecialistPermitDispatcher


def test_deployment_approval_authority_swap_is_rejected_before_authority_consumption(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-approval-root-swap"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-permit-approval-root-swap",
    )
    plan = _plan(fixture)
    deployment = cast(
        Any,
        fixture.harness.store,
    )._AgenticCoordinationStore__specialist_deployment
    approval_field = "_AgenticSpecialistPermitDeployment__approval_input"
    original_approval = getattr(deployment, approval_field)
    replacement = durable_module._AgenticSpecialistApprovalInputAuthority(
        keys=(fixture.harness.approval_key,),
        clock=fixture.harness.approval_clock,
    )
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    try:
        object.__setattr__(deployment, approval_field, replacement)
        with pytest.raises(AgenticCoordinationError, match="authority changed"):
            _bind_runtime(fixture, plan, signed_approval)
    finally:
        object.__setattr__(deployment, approval_field, original_approval)

    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert type(_bind_runtime(fixture, plan, signed_approval)) is VerifiedSpecialistPermitDispatcher


@pytest.mark.parametrize("field_name", ("trusted", "clock", "authorities"))
def test_deployment_approval_internal_swap_is_rejected_before_authority_consumption(
    harness_factory: HarnessFactory,
    field_name: str,
) -> None:
    label = f"specialist-permit-approval-{field_name}-swap"
    unsigned = _specialist_fixture(harness_factory(label))
    fixture, signed_approval = _signed_fixture(unsigned, label)
    plan = _plan(fixture)
    deployment = cast(
        Any,
        fixture.harness.store,
    )._AgenticCoordinationStore__specialist_deployment
    approval = deployment.approval_input
    private_field = f"_AgenticSpecialistApprovalInputAuthority__{field_name}"
    original = getattr(approval, private_field)

    def replacement_clock() -> datetime:
        return fixture.harness.approval_clock()

    if field_name == "trusted":
        replacement: object = type(original)(dict(original))
    elif field_name == "clock":
        replacement = replacement_clock
    else:
        replacement = dict(original)
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    try:
        object.__setattr__(approval, private_field, replacement)
        with pytest.raises(AgenticCoordinationError, match=r"runtime changed|authority changed"):
            _bind_runtime(fixture, plan, signed_approval)
    finally:
        object.__setattr__(approval, private_field, original)

    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert type(_bind_runtime(fixture, plan, signed_approval)) is VerifiedSpecialistPermitDispatcher


@pytest.mark.parametrize(
    "method_name",
    ("verifier_for", "register", "require_registered", "runtime_identity"),
)
def test_replaced_shared_approval_registry_method_is_rejected_before_authority_consumption(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    label = f"specialist-permit-approval-method-{method_name}"
    unsigned = _specialist_fixture(harness_factory(label))
    fixture, signed_approval = _signed_fixture(unsigned, label)
    plan = _plan(fixture)
    authority_type = durable_module._AgenticSpecialistApprovalInputAuthority
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    with monkeypatch.context() as patch:
        patch.setattr(authority_type, method_name, lambda *_args, **_kwargs: None)
        with pytest.raises(AgenticCoordinationError, match=r"runtime changed|authority changed"):
            _bind_runtime(fixture, plan, signed_approval)

    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert type(_bind_runtime(fixture, plan, signed_approval)) is VerifiedSpecialistPermitDispatcher


@pytest.mark.parametrize("field_name", ("_clock", "_permit_ttl"))
def test_configured_graph_authority_clock_and_ttl_are_pinned_before_permit_consumption(
    harness_factory: HarnessFactory,
    field_name: str,
) -> None:
    label = f"specialist-permit-graph-authority-{field_name.removeprefix('_')}"
    unsigned = _specialist_fixture(harness_factory(label))
    fixture, signed_approval = _signed_fixture(unsigned, label)
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    graph_authority = cast(
        Any,
        runtime,
    )._VerifiedSpecialistPermitDispatcher__graph_authority
    deployment = cast(
        Any,
        runtime,
    )._VerifiedSpecialistPermitDispatcher__deployment
    original = getattr(graph_authority, field_name)
    deployment_field = (
        "_AgenticSpecialistPermitDeployment__graph_authority_clock"
        if field_name == "_clock"
        else "_AgenticSpecialistPermitDeployment__graph_authority_permit_ttl"
    )
    original_deployment_pin = getattr(deployment, deployment_field)

    def replacement_clock() -> datetime:
        return fixture.harness.approval_clock()

    replacement: object = replacement_clock if field_name == "_clock" else timedelta(seconds=31)
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    try:
        object.__setattr__(graph_authority, field_name, replacement)
        object.__setattr__(deployment, deployment_field, replacement)
        with pytest.raises(AgenticCoordinationError, match="writer authority changed"):
            asyncio.run(
                fixture.harness.store.dispatch_specialist_permit_once(
                    plan,
                    runtime,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )
            )
    finally:
        object.__setattr__(graph_authority, field_name, original)
        object.__setattr__(deployment, deployment_field, original_deployment_pin)

    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert type(_bind_runtime(fixture, plan, signed_approval)) is VerifiedSpecialistPermitDispatcher


def test_graph_transaction_verifier_failure_rolls_back_permit_and_preserves_grant(
    harness_factory: HarnessFactory,
) -> None:
    clock = _FailingApprovalClock(fail_on_call=6)
    unsigned = _specialist_fixture(
        harness_factory(
            "specialist-permit-store-rollback",
            approval_clock=clock,
        )
    )
    fixture, signed_approval = _signed_fixture(unsigned, "specialist-permit-store-rollback")
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    with pytest.raises(ActionApprovalError, match="durable claim"):
        asyncio.run(
            fixture.harness.store.dispatch_specialist_permit_once(
                plan,
                runtime,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
        )

    assert clock.calls == 6
    assert fixture.harness.graph_store.permit_store.action_approvals() == ()
    assert fixture.harness.graph_store.permit_store.permits() == ()
    assert fixture.harness.graph_store.permit_store.approval_consumptions() == ()
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert (
        fixture.harness.store.specialist_dispatch_plan_entry(
            plan_id=plan.entry.plan_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
    )
    assert (
        fixture.harness.store.specialist_execution_entry(
            command_id=plan.entry.command_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistExecutionState.RESERVED
    )


def test_post_commit_verifier_failure_reconciles_permit_without_callback_or_grant(
    harness_factory: HarnessFactory,
) -> None:
    clock = _FailingApprovalClock(fail_on_call=8)
    unsigned = _specialist_fixture(
        harness_factory(
            "specialist-permit-post-commit",
            approval_clock=clock,
        )
    )
    fixture, signed_approval = _signed_fixture(unsigned, "specialist-permit-post-commit")
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls

    with pytest.raises(AgenticCoordinationError, match="callback entry is unproven"):
        asyncio.run(
            fixture.harness.store.dispatch_specialist_permit_once(
                plan,
                runtime,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
        )

    terminal = fixture.harness.graph_store.permit_store.approved_authorization(
        fixture.approval.approval_id,
        fixture.approval.expected_action_permit_id,
    )
    assert clock.calls == 8
    assert terminal is not None
    assert terminal.action.newly_consumed is False
    audit = fixture.harness.store.specialist_dispatch_plan_entry(
        plan_id=plan.entry.plan_id,
        **cast(Any, _graph_args(fixture.harness)),
    )
    assert audit.state is AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN
    assert audit.action_permit == terminal.action.permit
    assert audit.approval_consumption_receipt == terminal.receipt
    assert audit.grant_consumption_receipt is None
    assert audit.callback_entered_at is None
    assert audit.reconciled_at is not None
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before
    assert (
        fixture.harness.store.specialist_execution_entry(
            command_id=plan.entry.command_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistExecutionState.RESERVED
    )


def test_clock_rewind_before_planned_at_never_consumes_grant_or_enters_dispatch(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _MutableClock(NOW + timedelta(seconds=10))
    unsigned = _specialist_fixture(
        harness_factory(
            "specialist-permit-clock-rewind",
            approval_clock=clock,
            coordination_clock=clock,
        )
    )
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-permit-clock-rewind",
    )
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    child_before = fixture.ledger.record(fixture.grant.grant_id).remaining_calls
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls
    clock.current = plan.entry.planned_at - timedelta(microseconds=1)
    original_terminal = VerifiedSpecialistPermitDispatcher._terminal_authorization

    def restore_clock_before_reconciliation(
        dispatcher: VerifiedSpecialistPermitDispatcher,
        authority: object,
        bound_plan: VerifiedSpecialistDispatchPlan,
    ) -> ActionApprovalAuthorization | None:
        clock.current = plan.entry.planned_at + timedelta(seconds=1)
        return original_terminal(dispatcher, authority, bound_plan)

    monkeypatch.setattr(
        VerifiedSpecialistPermitDispatcher,
        "_terminal_authorization",
        restore_clock_before_reconciliation,
    )

    with pytest.raises(AgenticCoordinationError, match="callback entry is unproven"):
        asyncio.run(
            fixture.harness.store.dispatch_specialist_permit_once(
                plan,
                runtime,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
        )

    audit = fixture.harness.store.specialist_dispatch_plan_entry(
        plan_id=plan.entry.plan_id,
        **cast(Any, _graph_args(fixture.harness)),
    )
    execution = fixture.harness.store.specialist_execution_entry(
        command_id=plan.entry.command_id,
        **cast(Any, _graph_args(fixture.harness)),
    )
    assert audit.state is AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN
    assert audit.action_permit is not None
    assert audit.action_permit.issued_at < plan.entry.planned_at
    assert audit.approval_consumption_receipt is not None
    assert audit.grant_consumption_receipt is None
    assert audit.callback_entered_at is None
    assert audit.reconciled_at is not None
    assert audit.reconciled_at >= plan.entry.planned_at
    assert execution.state is AgenticSpecialistExecutionState.RESERVED
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == child_before
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before


def test_post_grant_plan_cas_failure_burns_budget_and_reconciles_entry_unknown(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-cas-failure"))
    fixture, signed_approval = _signed_fixture(unsigned, "specialist-permit-cas-failure")
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    root_before = fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls
    original = durable_module._cas_specialist_dispatch_plan_terminal
    calls = 0

    def fail_first_plan_cas(
        connection: sqlite3.Connection,
        *,
        before: AgenticSpecialistDispatchPlanEntry,
        after: AgenticSpecialistDispatchPlanEntry,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("synthetic post-Grant plan CAS failure")
        original(connection, before=before, after=after)

    monkeypatch.setattr(
        durable_module,
        "_cas_specialist_dispatch_plan_terminal",
        fail_first_plan_cas,
    )

    with pytest.raises(AgenticCoordinationError, match="callback entry is unproven"):
        asyncio.run(
            fixture.harness.store.dispatch_specialist_permit_once(
                plan,
                runtime,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
        )

    audit = fixture.harness.store.specialist_dispatch_plan_entry(
        plan_id=plan.entry.plan_id,
        **cast(Any, _graph_args(fixture.harness)),
    )
    execution = fixture.harness.store.specialist_execution_entry(
        command_id=plan.entry.command_id,
        **cast(Any, _graph_args(fixture.harness)),
    )
    assert audit.state is AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN
    assert audit.action_permit is not None
    assert audit.approval_consumption_receipt is not None
    assert audit.grant_consumption_receipt is None
    assert audit.callback_entered_at is None
    assert audit.reconciled_at is not None
    assert execution.state is AgenticSpecialistExecutionState.RESERVED
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 0
    assert fixture.ledger.record(fixture.root_grant.grant_id).remaining_calls == root_before - 1
    assert calls == 2


def test_same_process_concurrent_dispatch_has_one_plan_bound_winner(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-permit-concurrency"))
    fixture, signed_approval = _signed_fixture(unsigned, "specialist-permit-concurrency")
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)

    async def race() -> list[object]:
        async def attempt() -> object:
            try:
                return await fixture.harness.store.dispatch_specialist_permit_once(
                    plan,
                    runtime,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )
            except BaseException as exc:
                return exc

        return list(await asyncio.gather(attempt(), attempt()))

    outcomes = asyncio.run(race())
    winners = [
        item
        for item in outcomes
        if not isinstance(item, BaseException) and cast(Any, item).dispatched is True
    ]
    failures = [item for item in outcomes if isinstance(item, AgenticCoordinationError)]
    assert len(winners) == 1
    assert len(failures) == 1
    assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 0
    assert (
        fixture.harness.store.specialist_dispatch_plan_entry(
            plan_id=plan.entry.plan_id,
            **cast(Any, _graph_args(fixture.harness)),
        ).state
        is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    )


def test_dispatch_started_handle_transfers_once_inside_its_callback_task(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-started-transfer-once"))
        fixture, signed_approval = _signed_fixture(
            unsigned,
            "specialist-started-transfer-once",
        )
        plan = _plan(fixture)
        runtime = _bind_runtime(fixture, plan, signed_approval)
        dispatched = await fixture.harness.store.dispatch_specialist_permit_once(
            plan,
            runtime,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        started = cast(VerifiedPlannedSpecialistDispatchStarted, dispatched.result)
        capsule = fixture.harness.store._transfer_planned_specialist_dispatch_started(started)
        assert capsule.preparation is fixture.preparation
        assert capsule.capability_grant is fixture.grant
        with pytest.raises(AgenticCoordinationError, match="foreign or consumed"):
            fixture.harness.store._transfer_planned_specialist_dispatch_started(started)

    asyncio.run(scenario())


def test_specialist_grant_receipt_rejects_validly_rehashed_foreign_grant_binding(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-grant-receipt-tamper"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-grant-receipt-tamper",
    )
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    dispatched = asyncio.run(
        fixture.harness.store.dispatch_specialist_permit_once(
            plan,
            runtime,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
    )
    started = cast(VerifiedPlannedSpecialistDispatchStarted, dispatched.result)
    receipt_values = started.grant_consumption_receipt.model_dump(
        mode="json",
        by_alias=True,
    )
    receipt_values.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "capabilityGrantId": "grant:foreign-agentic-specialist",
        }
    )
    foreign_receipt = AgenticSpecialistCapabilityGrantConsumptionReceipt.model_validate(
        receipt_values
    )
    assert foreign_receipt.receipt_digest != started.grant_consumption_receipt.receipt_digest

    plan_values = started.plan.model_dump(mode="json", by_alias=True)
    plan_values.update(
        {
            "stateDigest": "",
            "grantConsumptionReceipt": foreign_receipt.model_dump(
                mode="json",
                by_alias=True,
            ),
        }
    )
    with pytest.raises(ValueError, match="Grant consumption receipt differs"):
        AgenticSpecialistDispatchPlanEntry.model_validate(plan_values)


def test_specialist_dispatch_schema_v6_persists_grant_and_job_receipt_tables(
    harness_factory: HarnessFactory,
) -> None:
    harness = harness_factory("specialist-grant-receipt-schema-v6")
    uri = f"file:{harness.store.path}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        columns = {
            cast(str, row[1])
            for row in connection.execute("PRAGMA table_info(agentic_specialist_dispatch_plans)")
        }
        tables = {
            cast(str, row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {
        "grant_consumption_receipt_id",
        "grant_consumption_receipt_digest",
        "grant_consumed_at",
    } <= columns
    assert {
        "agentic_specialist_job_attempts",
        "agentic_specialist_terminal_receipts",
    } <= tables


def _downgrade_empty_v6_additions_to_frozen_v5(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("BEGIN EXCLUSIVE")
        for kind, name in reversed(durable_module._SCHEMA_V6_ADDITION_KEYS):
            connection.execute(f"DROP {kind.upper()} {name}")
        connection.execute("DROP TRIGGER agentic_coordination_metadata_immutable")
        connection.execute("DROP TRIGGER agentic_coordination_metadata_no_delete")
        connection.execute(
            "DELETE FROM agentic_coordination_metadata "
            "WHERE key = 'specialist_runtime_generation'"
        )
        connection.execute(
            "UPDATE agentic_coordination_metadata SET value = '5' "
            "WHERE key = 'schema_version'"
        )
        connection.execute(
            "UPDATE agentic_coordination_metadata SET value = ? "
            "WHERE key = 'schema_digest'",
            (durable_module.AGENTIC_COORDINATION_SCHEMA_V5_DIGEST,),
        )
        connection.execute(durable_module._METADATA_IMMUTABLE_SQL)
        connection.execute(durable_module._METADATA_NO_DELETE_SQL)
        connection.execute("PRAGMA user_version = 5")
        connection.execute("COMMIT")


def _legacy_insert_dump(path: Path) -> tuple[str, ...]:
    with sqlite3.connect(path) as connection:
        return tuple(
            statement
            for statement in connection.iterdump()
            if statement.startswith("INSERT INTO")
            and not (
                "agentic_coordination_metadata" in statement
                and (
                    "'schema_version'" in statement
                    or "'schema_digest'" in statement
                    or "'specialist_runtime_generation'" in statement
                )
            )
        )


def test_explicit_offline_schema_v5_to_v6_migration_preserves_legacy_rows(
    harness_factory: HarnessFactory,
) -> None:
    harness = harness_factory("specialist-schema-v5-to-v6")
    store_path = harness.store.path
    store_id = harness.store.store_id
    harness.store.close()
    _downgrade_empty_v6_additions_to_frozen_v5(store_path)
    legacy_rows = _legacy_insert_dump(store_path)

    durable_module.migrate_agentic_coordination_schema_v5_to_v6(
        store_path,
        binding=harness.binding,
        expected_store_id=store_id,
    )
    assert _legacy_insert_dump(store_path) == legacy_rows
    with sqlite3.connect(store_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        assert connection.execute(
            "SELECT COUNT(*) FROM agentic_specialist_job_attempts"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM agentic_specialist_terminal_receipts"
        ).fetchone() == (0,)

    durable_module.migrate_agentic_coordination_schema_v5_to_v6(
        store_path,
        binding=harness.binding,
        expected_store_id=store_id,
    )
    reopened = AgenticCoordinationStore(
        store_path,
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        specialist_graph_store=harness.graph_store,
        specialist_capability_ledger=harness.specialist_ledger,
        specialist_approval_keys=(harness.approval_key,),
        specialist_approval_clock=harness.approval_clock,
        allow_create=False,
        expected_store_id=store_id,
        clock=lambda: NOW + timedelta(seconds=20),
    )
    reopened.close()


def test_failed_offline_schema_v5_to_v6_migration_rolls_back_exactly(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = harness_factory("specialist-schema-v5-rollback")
    store_path = harness.store.path
    store_id = harness.store.store_id
    harness.store.close()
    _downgrade_empty_v6_additions_to_frozen_v5(store_path)
    legacy_rows = _legacy_insert_dump(store_path)
    terminal_table_key = ("table", "agentic_specialist_terminal_receipts")
    monkeypatch.setitem(
        durable_module._SCHEMA_OBJECTS,
        terminal_table_key,
        "CREATE TABLE agentic_specialist_terminal_receipts(",
    )

    with pytest.raises(
        AgenticCoordinationError,
        match="migration failed closed",
    ):
        durable_module.migrate_agentic_coordination_schema_v5_to_v6(
            store_path,
            binding=harness.binding,
            expected_store_id=store_id,
        )

    assert _legacy_insert_dump(store_path) == legacy_rows
    with sqlite3.connect(store_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        tables = {
            cast(str, row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "agentic_specialist_job_attempts" not in tables
    assert "agentic_specialist_terminal_receipts" not in tables


def test_successful_terminal_plan_survives_close_reopen_and_recovery(
    harness_factory: HarnessFactory,
) -> None:
    unsigned = _specialist_fixture(harness_factory("specialist-terminal-reopen"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        "specialist-terminal-reopen",
    )
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    dispatched = asyncio.run(
        fixture.harness.store.dispatch_specialist_permit_once(
            plan,
            runtime,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
    )
    started = cast(VerifiedPlannedSpecialistDispatchStarted, dispatched.result)
    store_path = fixture.harness.store.path
    store_id = fixture.harness.store.store_id
    fixture.harness.store.close()

    reopened = AgenticCoordinationStore(
        store_path,
        binding=fixture.harness.binding,
        graph_resolver=fixture.harness.resolver,
        graph_head=fixture.harness.graph_head,
        specialist_graph_store=fixture.harness.graph_store,
        specialist_capability_ledger=fixture.harness.specialist_ledger,
        specialist_approval_keys=(fixture.harness.approval_key,),
        specialist_approval_clock=fixture.harness.approval_clock,
        allow_create=False,
        expected_store_id=store_id,
        clock=lambda: NOW + timedelta(seconds=20),
    )
    try:
        audit = reopened.specialist_dispatch_plan_entry(
            plan_id=plan.entry.plan_id,
            **cast(Any, _graph_args(fixture.harness)),
        )
        recovery = reopened.recovery_snapshot(**cast(Any, _graph_args(fixture.harness)))
        assert audit == started.plan
        assert audit.grant_consumption_receipt == started.grant_consumption_receipt
        assert recovery.awaiting_specialist_dispatch_plans == ()
        assert recovery.terminal_specialist_dispatch_plans == (started.plan,)
        assert recovery.reserved_specialist_executions == ()
        assert recovery.unknown_specialist_executions == (started.execution,)
        assert recovery.automatic_redispatch_authorized is False
    finally:
        reopened.close()


@pytest.mark.parametrize(
    "tamper",
    ("grant-receipt-digest", "grant-consumed-at"),
)
def test_schema_v6_terminal_grant_receipt_index_tamper_is_rejected_on_reopen(
    harness_factory: HarnessFactory,
    tamper: str,
) -> None:
    unsigned = _specialist_fixture(harness_factory(f"specialist-terminal-tamper-{tamper}"))
    fixture, signed_approval = _signed_fixture(
        unsigned,
        f"specialist-terminal-tamper-{tamper}",
    )
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, signed_approval)
    dispatched = asyncio.run(
        fixture.harness.store.dispatch_specialist_permit_once(
            plan,
            runtime,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
    )
    assert dispatched.dispatched is True
    store_path = fixture.harness.store.path
    store_id = fixture.harness.store.store_id
    fixture.harness.store.close()

    with sqlite3.connect(store_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        connection.execute("DROP TRIGGER agentic_specialist_dispatch_plans_monotonic")
        if tamper == "grant-receipt-digest":
            connection.execute(
                """
                UPDATE agentic_specialist_dispatch_plans
                SET grant_consumption_receipt_digest = ?
                WHERE plan_id = ?
                """,
                (SHA_F, plan.entry.plan_id),
            )
        else:
            connection.execute(
                """
                UPDATE agentic_specialist_dispatch_plans
                SET grant_consumed_at = ?
                WHERE plan_id = ?
                """,
                ("2026-09-18T02:59:59.000000Z", plan.entry.plan_id),
            )
        connection.executescript(durable_module._SPECIALIST_DISPATCH_PLAN_MONOTONIC_SQL)

    with pytest.raises(AgenticCoordinationError, match="state index differs"):
        AgenticCoordinationStore(
            store_path,
            binding=fixture.harness.binding,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
            specialist_graph_store=fixture.harness.graph_store,
            specialist_capability_ledger=fixture.harness.specialist_ledger,
            specialist_approval_keys=(fixture.harness.approval_key,),
            specialist_approval_clock=fixture.harness.approval_clock,
            allow_create=False,
            expected_store_id=store_id,
            clock=lambda: NOW + timedelta(seconds=20),
        )
