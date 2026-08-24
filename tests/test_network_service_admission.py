from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from test_network_service_identification import (
    HOST,
    NOW,
    PORT,
    _activation,
    _campaign,
    _connected_output,
    _surface,
)

from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    capability_gateway_outcome_digest,
    capability_grant_digest,
)
from pajin.capabilities.network_service import (
    NetworkServiceCapabilityActivation,
    NetworkServiceIdentificationPreparation,
    prepare_network_service_identification,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphProducerRegistration,
    GraphProducerRegistry,
    TrustedGraphLineageRegistry,
)
from pajin.graph.approval import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionPermit,
    ActionProposal,
    MissionEnvelope,
    action_permit_attempt_id,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.models import (
    GraphContentOrigin,
    GraphEvidenceBinding,
    GraphNodeKind,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSurface,
    SurfaceProposal,
)
from pajin.graph.projection import (
    GraphProjectionCoordinator,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend, WorkerResult, WorkerStatus
from pajin.tools.base import EGRESS_HTTPS_CONNECT_RECEIPT_VERSION, ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway
from pajin.tools.network import NetworkServiceIdentificationTool
from pajin.workflow.network_service_admission import (
    NetworkGraphAdmissionBinding,
    NetworkProtocolKnowledgeAdmissionError,
    NetworkProtocolKnowledgeAdmissionGate,
    NetworkProtocolKnowledgeCandidate,
    NetworkServiceObservationSourceInputs,
    network_protocol_knowledge_producer_registration,
)

RUN_ID = "run_20260824T120000Z_deadbeef"
AUTHORITY_ID = "pajin.graph.network-protocol-admission"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


class _ApprovalInputAuthority:
    def __init__(self, expected: ActionApprovalEnvelope) -> None:
        self.expected = expected

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        if (
            approval != self.expected
            or approval.mission_envelope != envelope
            or approval.proposal != proposal
            or approval.graph_decision != decision
        ):
            raise RuntimeError("external approval authority rejected the Network claim")


@dataclass
class _Context:
    activation: NetworkServiceCapabilityActivation
    campaign: CampaignManifest
    preparation: NetworkServiceIdentificationPreparation
    job: CapabilityGraphCampaignJobInput
    graph_store: SQLiteGraphStore
    graph_admission: GraphAdmissionAuthority
    graph_lineages: TrustedGraphLineageRegistry
    graph_binding: NetworkGraphAdmissionBinding
    run_store: RunStore
    source_inputs: NetworkServiceObservationSourceInputs
    worker_calls: list[Any]


def _graph_authority(
    tmp_path: Path,
    campaign_id: str,
    *,
    decision_payload_digest: str,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    TrustedGraphLineageRegistry,
    NetworkGraphAdmissionBinding,
    GraphDecision,
]:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=campaign_id)
    seed_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=RUN_ID,
        agentId="agent:network-surface-seed",
        taskId="task:network-surface-seed",
        requestId="tool_network_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:network-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.network.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/network-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=NOW,
    )
    seed = SurfaceProposal(
        proposalId="proposal:surface:network-service-admission",
        producerId="pajin.graph.network-service-admission-test",
        producerVersion="1.0.0",
        producerDigest=DIGEST_D,
        lineage=seed_lineage,
        surface=GraphSurface(
            campaignId=campaign_id,
            targetId="target:network-service-admission",
            surfaceType="network.host-service",
            locatorSchema="pajin.locator.network.host-service.v1",
            locatorDigest=DIGEST_A,
            origin=GraphContentOrigin.TRUSTED_CORE,
        ),
    )
    lineages = TrustedGraphLineageRegistry([seed_lineage])
    authority = GraphAdmissionAuthority(
        campaign_id=campaign_id,
        authority_id=AUTHORITY_ID,
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId="pajin.graph.network-service-admission-test",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                network_protocol_knowledge_producer_registration(),
            ]
        ),
        lineage_verifier=lineages,
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=20),
    )
    assert authority.submit(seed).event.decision is GraphAdmissionDecision.ADMITTED
    projection = GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    )
    projection.refresh()
    snapshots = GraphSnapshotAuthority(
        creator_id="pajin.graph.network-snapshot-authority",
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW,
    )
    snapshot = snapshots.capture(GraphSnapshotReason.CHECKPOINT)
    decision = GraphDecision(
        campaignId=campaign_id,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=decision_payload_digest,
        snapshot=graph_snapshot_ref(snapshot),
        actorId="pajin.graph.network-planner",
        actorDigest=DIGEST_C,
        createdAt=NOW + timedelta(seconds=1),
    )
    binding = NetworkGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return store, authority, lineages, binding, decision


async def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    run_id: str = RUN_ID,
    request_id: str = "tool_network_service_observation",
    banner: bytes = b"SSH-2.0-OpenSSH\r\n",
    service_name: str | None = "ssh",
    trusted_receipt: bool = True,
) -> _Context:
    activation, release = _activation()
    campaign = _campaign(sample_campaign)
    preparation = prepare_network_service_identification(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=_surface(),
        request_id=request_id,
        agent_id="agent:network-service",
    )
    prepared = preparation.prepared_action
    graph_store, graph_admission, graph_lineages, graph_binding, decision = _graph_authority(
        tmp_path,
        campaign.metadata.name,
        decision_payload_digest=preparation.preparation_digest,
    )
    target_digest = sha256(prepared.request.target.encode("utf-8")).hexdigest()
    capability = activation.activation_set.binding.action_capability
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=run_id,
        profileId="network-passive-service-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.network.action-compiler",
        compilerVersion="1.0.0",
        compilerDigest=DIGEST_B,
        sourceCampaignDigest=campaign_manifest_digest(campaign),
        allowedCapabilities=(capability.reference(),),
        allowedTargetDigests=(target_digest,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(toolCallLimit=1, requestUnitLimit=1),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=NOW - timedelta(seconds=2),
        notBefore=NOW - timedelta(seconds=1),
        expiresAt=NOW + timedelta(minutes=2),
    )
    proposal = ActionProposal(
        campaignId=campaign.metadata.name,
        runId=run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        proposerId="pajin.graph.network-planner",
        proposerDigest=DIGEST_C,
        capability=prepared.capability,
        targetDigest=target_digest,
        requestId=prepared.request.request_id,
        requestDigest=prepared.request_digest,
        normalizedParametersDigest=prepared.normalized_parameters_digest,
        riskTier=ToolRiskTier.T2,
        reservation=ActionBudgetReservation(requestUnits=1),
        createdAt=NOW + timedelta(seconds=2),
    )
    approval = ActionApprovalEnvelope(
        issuer=ActionApprovalIssuerAuthorityBinding(
            authorityId="deployment:network-operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.network.ExternalApprovalAuthority",
            contextDigest=DIGEST_D,
        ),
        requestedBy="principal:network-requester",
        approvedBy="principal:network-approver",
        campaignId=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        runId=run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=preparation.preparation_digest,
        activationSetDigest=prepared.activation_set_digest,
        release=ActionApprovalReleaseRef(
            releaseId=release.release_id,
            releaseDigest=release.release_digest,
            capabilityId=prepared.capability.capability_id,
            capabilityVersion=prepared.capability.capability_version,
            capabilityDigest=prepared.capability.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        reservation=proposal.reservation,
        approvedAt=NOW + timedelta(seconds=3),
        notBefore=NOW + timedelta(seconds=4),
        expiresAt=NOW + timedelta(minutes=1),
    )
    grant = CapabilityGrant(
        grant_id="grant_network_service_observation",
        subject=prepared.request.agent_id,
        campaign=campaign.metadata.name,
        tools={prepared.request.tool_id},
        targets={prepared.request.target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    job = CapabilityGraphCampaignJobInput(
        profile="capability-graph-v1",
        proposal=proposal,
        decision=decision,
        release=release,
        request=prepared.request,
        grant=grant,
        approval=approval,
    )
    approved_authority = GraphApprovedActionPermitAuthority(
        campaign_id=campaign.metadata.name,
        compiler_id=envelope.compiler_id,
        compiler_version=envelope.compiler_version,
        compiler_digest=envelope.compiler_digest,
        capabilities=activation.action_registry(),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=prepared.capability,
                    sideEffectClass="read-only",
                    approvalRequired=True,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=graph_store.permit_store,
        input_authority=_ApprovalInputAuthority(approval),
        clock=lambda: NOW + timedelta(seconds=5),
        permit_ttl=timedelta(seconds=30),
    )
    run_store = RunStore.create(
        tmp_path / "runs",
        campaign.metadata.name,
        run_id=run_id,
    )
    tools = ToolRegistry()
    tools.register(NetworkServiceIdentificationTool())
    worker = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    worker_calls: list[Any] = []

    async def run(job: Any, *, secrets: Any = None) -> WorkerResult:
        worker_calls.append((job, secrets))
        output = _connected_output(banner)
        if service_name is None:
            output.pop("serviceName", None)
        else:
            output["serviceName"] = service_name
        authority = f"{HOST}:{PORT}" if trusted_receipt else f"{HOST}:{PORT + 1}"
        network_log = "\n".join(
            (
                json.dumps({"event": "ready", "port": 8080}),
                json.dumps(
                    {
                        "event": "allow",
                        "receiptVersion": EGRESS_HTTPS_CONNECT_RECEIPT_VERSION,
                        "sequence": 1,
                        "method": "CONNECT",
                        "authority": authority,
                        "authoritySha256": sha256(authority.encode("utf-8")).hexdigest(),
                        "address": HOST,
                        "applicationVisibility": "opaque",
                        "methodEnforcement": "trusted-worker-only",
                        "pathEnforcement": "authority-only",
                    }
                ),
            )
        )
        return WorkerResult(
            execution_id=job.execution_id,
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            network_log=network_log,
            started_at=NOW + timedelta(seconds=6),
            finished_at=NOW + timedelta(seconds=7),
        )

    worker.run = run  # type: ignore[method-assign]
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=tools,
        worker=worker,
        store=run_store,
        clock=lambda: NOW + timedelta(seconds=6),
    )
    dispatcher = GraphApprovedActionPermitDispatcher(approved_authority)

    async def dispatch(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> GatewayOutcome:
        assert receipt.action_permit == permit
        claimed = CapabilityDispatchAuditEvent(
            stage=CapabilityDispatchStage.CLAIMED,
            occurredAt=NOW + timedelta(seconds=5),
            activationSetDigest=prepared.activation_set_digest,
            release=release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantDigest=capability_grant_digest(grant),
        )
        run_store.append_event(
            "capability.dispatch.claimed",
            claimed.model_dump(mode="json", by_alias=True),
            occurred_at=claimed.occurred_at,
        )
        outcome = await gateway.execute(campaign, grant, prepared.request, used_calls=0)
        completed = CapabilityDispatchAuditEvent(
            stage=CapabilityDispatchStage.COMPLETED,
            occurredAt=NOW + timedelta(seconds=8),
            activationSetDigest=prepared.activation_set_digest,
            release=release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantDigest=capability_grant_digest(grant),
            gatewayOutcomeDigest=capability_gateway_outcome_digest(outcome),
            gatewayExecutionId=(
                outcome.worker_result.execution_id if outcome.worker_result is not None else None
            ),
            executed=outcome.executed,
            policyAllowed=outcome.decision.allowed,
            toolSuccess=outcome.result.success,
            evidence=tuple(sorted(set(outcome.result.evidence))),
        )
        run_store.append_event(
            "capability.dispatch.completed",
            completed.model_dump(mode="json", by_alias=True),
            occurred_at=completed.occurred_at,
        )
        return outcome

    dispatched = await dispatcher.dispatch_once(
        envelope,
        proposal,
        decision,
        approval,
        dispatch,
    )
    assert dispatched.dispatched is True
    assert dispatched.result is not None
    run_store.seal()
    source_inputs = NetworkServiceObservationSourceInputs(
        run_path=run_store.path,
        expected_run_id=run_id,
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
    )
    return _Context(
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
        graph_store=graph_store,
        graph_admission=graph_admission,
        graph_lineages=graph_lineages,
        graph_binding=graph_binding,
        run_store=run_store,
        source_inputs=source_inputs,
        worker_calls=worker_calls,
    )


@pytest.mark.asyncio
async def test_sealed_network_result_admits_neutral_observation_and_open_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    gate = NetworkProtocolKnowledgeAdmissionGate(
        graph_store=context.graph_store,
        graph_admission=context.graph_admission,
        trusted_lineages=context.graph_lineages,
    )

    candidate = gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admitted = gate.admit(context.source_inputs, candidate)
    retry = gate.admit(context.source_inputs, candidate)

    assert candidate.service_name == "ssh"
    assert candidate.domain_graph_type_set.domain_classification.domain.value == "network"
    assert admitted.state == "registered-not-authorized"
    assert admitted.observation_graph_event.decision is GraphAdmissionDecision.ADMITTED
    assert admitted.hypothesis_graph_event is not None
    assert admitted.hypothesis_graph_event.decision is GraphAdmissionDecision.ADMITTED
    assert admitted.bounded_hypothesis_admitted is True
    assert [node.kind for node in admitted.observation_graph_event.admitted_nodes].count(
        GraphNodeKind.OBSERVATION.value
    ) == 1
    assert [node.kind for node in admitted.observation_graph_event.admitted_nodes].count(
        GraphNodeKind.EVIDENCE.value
    ) == 2
    assert all(
        node.kind not in {GraphNodeKind.SURFACE.value, GraphNodeKind.HYPOTHESIS.value}
        for node in admitted.observation_graph_event.admitted_nodes
    )
    hypothesis = candidate.hypothesis_proposal
    assert hypothesis is not None
    assert admitted.hypothesis_graph_event.admitted_nodes == [hypothesis.hypothesis]
    assert "OpenSSH" not in hypothesis.hypothesis.statement
    assert retry == admitted
    assert len(context.worker_calls) == 1
    assert all(
        value is False
        for key, value in admitted.model_dump(mode="python").items()
        if key.endswith("authority") or key.endswith("authorized")
    )

    substituted = admitted.model_dump(mode="json", by_alias=True)
    substituted["admissionId"] = ""
    substituted["admissionDigest"] = ""
    substituted["hypothesisGraphEvent"]["eventId"] = ""
    substituted["hypothesisGraphEvent"]["eventDigest"] = ""
    substituted["hypothesisGraphEvent"]["agentId"] = "agent:foreign-network-admission"
    with pytest.raises(ValidationError, match="bounded Proposal"):
        type(admitted).model_validate(substituted)


@pytest.mark.asyncio
async def test_unknown_service_admits_observation_without_negative_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, service_name=None)
    gate = NetworkProtocolKnowledgeAdmissionGate(
        graph_store=context.graph_store,
        graph_admission=context.graph_admission,
        trusted_lineages=context.graph_lineages,
    )

    candidate = gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admitted = gate.admit(context.source_inputs, candidate)

    assert candidate.service_name is None
    assert candidate.hypothesis_proposal is None
    assert admitted.hypothesis_graph_event is None
    assert admitted.bounded_hypothesis_admitted is False
    assert admitted.observation_graph_event.decision is GraphAdmissionDecision.ADMITTED
    assert len(context.worker_calls) == 1


@pytest.mark.asyncio
async def test_network_knowledge_rejects_authority_and_approval_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    gate = NetworkProtocolKnowledgeAdmissionGate(
        graph_store=context.graph_store,
        graph_admission=context.graph_admission,
        trusted_lineages=context.graph_lineages,
    )
    candidate = gate.prepare_candidate(context.source_inputs, context.graph_binding)

    mutated = candidate.model_dump(mode="json", by_alias=True)
    mutated["serviceLabelAuthority"] = True
    with pytest.raises(ValidationError, match="authority flags"):
        NetworkProtocolKnowledgeCandidate.model_validate(mutated)

    relabeled = candidate.model_dump(mode="json", by_alias=True)
    relabeled["candidateId"] = ""
    relabeled["candidateDigest"] = ""
    relabeled["serviceName"] = "smtp"
    with pytest.raises(ValidationError, match="bounded Hypothesis"):
        NetworkProtocolKnowledgeCandidate.model_validate(relabeled)

    foreign_job = context.job.model_copy(
        update={"grant": context.job.grant.model_copy(update={"grant_id": "grant_foreign_network"})}
    )
    foreign_inputs = NetworkServiceObservationSourceInputs(
        run_path=context.source_inputs.run_path,
        expected_run_id=context.source_inputs.expected_run_id,
        activation=context.activation,
        campaign=context.campaign,
        preparation=context.preparation,
        job=foreign_job,
    )
    with pytest.raises(NetworkProtocolKnowledgeAdmissionError, match="evidence differs"):
        gate.prepare_candidate(foreign_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_network_knowledge_rejects_untrusted_or_tampered_sealed_evidence(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    untrusted = await _context(
        tmp_path / "untrusted",
        sample_campaign,
        trusted_receipt=False,
    )
    untrusted_gate = NetworkProtocolKnowledgeAdmissionGate(
        graph_store=untrusted.graph_store,
        graph_admission=untrusted.graph_admission,
        trusted_lineages=untrusted.graph_lineages,
    )
    with pytest.raises(NetworkProtocolKnowledgeAdmissionError, match="unsuccessful"):
        untrusted_gate.prepare_candidate(
            untrusted.source_inputs,
            untrusted.graph_binding,
        )

    tampered = await _context(tmp_path / "tampered", sample_campaign)
    evidence_path = tampered.run_store.path / "evidence" / f"{tampered.job.request.request_id}.json"
    evidence_path.write_bytes(evidence_path.read_bytes() + b" ")
    tampered_gate = NetworkProtocolKnowledgeAdmissionGate(
        graph_store=tampered.graph_store,
        graph_admission=tampered.graph_admission,
        trusted_lineages=tampered.graph_lineages,
    )
    with pytest.raises(NetworkProtocolKnowledgeAdmissionError, match="source authority"):
        tampered_gate.prepare_candidate(
            tampered.source_inputs,
            tampered.graph_binding,
        )


@pytest.mark.asyncio
async def test_network_knowledge_rejects_preparation_scope_drift_after_execution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    drifted = context.campaign.model_dump(mode="json", by_alias=True)
    drifted["spec"]["scope"]["allow"] = ["https://8.8.8.8:23/**"]
    inputs = NetworkServiceObservationSourceInputs(
        run_path=context.source_inputs.run_path,
        expected_run_id=context.source_inputs.expected_run_id,
        activation=context.activation,
        campaign=CampaignManifest.model_validate(drifted),
        preparation=context.preparation,
        job=context.job,
    )
    gate = NetworkProtocolKnowledgeAdmissionGate(
        graph_store=context.graph_store,
        graph_admission=context.graph_admission,
        trusted_lineages=context.graph_lineages,
    )

    with pytest.raises(NetworkProtocolKnowledgeAdmissionError, match="source authority"):
        gate.prepare_candidate(inputs, context.graph_binding)
