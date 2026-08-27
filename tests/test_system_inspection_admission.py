from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_system_read_only_inspection import (
    EXECUTABLE_DIGEST,
    NOW,
    _activation,
    _campaign,
    _deployment,
    _operation,
    _surface,
)

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.system_inspection import (
    BoundedSystemHostAgentAdapter,
    SystemReadOnlyInspectionPreparation,
    SystemReadOnlyInspectionTool,
    prepare_system_read_only_inspection,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.control_plane.worker_identity import WorkerMTLSAdmission
from pajin.discovery import SystemSurfaceClass
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
    GraphRelation,
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
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.workflow.system_inspection_admission import (
    SYSTEM_INSPECTION_KNOWLEDGE_PRODUCER_DIGEST,
    SystemGraphAdmissionBinding,
    SystemInspectionExecutionAttestor,
    SystemInspectionExecutionKeyState,
    SystemInspectionExecutionStatement,
    SystemInspectionExecutionTrustAnchor,
    SystemInspectionExecutionVerificationKey,
    SystemInspectionKnowledgeAdmissionError,
    SystemInspectionKnowledgeAdmissionGate,
    SystemInspectionKnowledgeCandidate,
    SystemInspectionObservationSourceInputs,
    SystemInspectionResultReceipt,
    SystemInspectionReviewSignal,
    SystemInspectionSourceKind,
    SystemNonRootRuntimeReceipt,
    load_verified_system_inspection_observation_source,
    system_inspection_execution_bundle_bytes,
    system_inspection_execution_public_key,
    system_inspection_gateway_outcome_digest,
    system_inspection_knowledge_producer_registration,
    system_inspection_result_receipt_bytes,
)

RUN_ID = "run_20260825T120000Z_systemcafe"
AUTHORITY_ID = "pajin.graph.system-inspection-knowledge-admission"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ATTESTATION_REFERENCE = "evidence/system-inspection-attestation.json"
RESULT_REFERENCE = "evidence/system-inspection-result-receipt.json"

_CANDIDATE_FALSE_MARKERS = (
    "graphAdmitted",
    "rawHostMetadataEmbedded",
    "hostExistenceAuthority",
    "processRunningAuthority",
    "filesystemContentAuthority",
    "serviceStateAuthority",
    "configurationValueAuthority",
    "hypothesisConfirmationAuthority",
    "surfaceMutationAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalAuthority",
    "permitIssuanceAuthorized",
    "hostAccessAuthorized",
    "agentSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "credentialAccessAuthorized",
    "rootAuthorityAsserted",
    "privilegeEscalationAuthorized",
    "serviceControlAuthorized",
    "hostMutationAuthorized",
    "replayAuthorized",
    "findingConfirmationAuthorized",
    "executionAuthorized",
)


class _SQLiteGraphStoreSubclass(SQLiteGraphStore):
    """Test-only subtype that must not cross the exact store boundary."""


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
            raise RuntimeError("external approval authority rejected the System claim")


@dataclass
class _Context:
    preparation: SystemReadOnlyInspectionPreparation
    graph_store: SQLiteGraphStore
    graph_admission: GraphAdmissionAuthority
    graph_lineages: TrustedGraphLineageRegistry
    graph_binding: SystemGraphAdmissionBinding
    gate: SystemInspectionKnowledgeAdmissionGate
    source_inputs: SystemInspectionObservationSourceInputs
    trust_anchor: SystemInspectionExecutionTrustAnchor
    private_key: bytes
    attestation_path: Path
    result_path: Path


def _seed(label: str) -> bytes:
    return sha256(f"system-inspection-admission:{label}".encode()).digest()


def _graph_authority(
    tmp_path: Path,
    campaign_id: str,
    preparation: SystemReadOnlyInspectionPreparation,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    TrustedGraphLineageRegistry,
    SystemGraphAdmissionBinding,
    GraphDecision,
]:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=campaign_id)
    seed_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=RUN_ID,
        agentId="agent:system-surface-seed",
        taskId="task:system-surface-seed",
        requestId="tool_system_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:system-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.system.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/system-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=NOW,
    )
    surface = preparation.surface
    seed = SurfaceProposal(
        proposalId="proposal:surface:system-inspection-admission",
        producerId="pajin.graph.system-inspection-admission-test",
        producerVersion="1.0.0",
        producerDigest=DIGEST_D,
        lineage=seed_lineage,
        surface=GraphSurface(
            campaignId=campaign_id,
            targetId=surface.surface_id,
            surfaceType=surface.surface_type,
            locatorSchema=surface.locator_schema,
            locatorDigest=surface.surface_digest,
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
                    producerId="pajin.graph.system-inspection-admission-test",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                system_inspection_knowledge_producer_registration(),
            ]
        ),
        lineage_verifier=lineages,
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=20),
    )
    assert authority.submit(seed).event.decision is GraphAdmissionDecision.ADMITTED
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshot = GraphSnapshotAuthority(
        creator_id="pajin.graph.system-snapshot-authority",
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW,
    ).capture(GraphSnapshotReason.CHECKPOINT)
    decision = GraphDecision(
        campaignId=campaign_id,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=preparation.preparation_digest,
        snapshot=graph_snapshot_ref(snapshot),
        actorId="pajin.graph.system-planner",
        actorDigest=DIGEST_C,
        createdAt=NOW + timedelta(seconds=1),
    )
    binding = SystemGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return store, authority, lineages, binding, decision


def _trust_anchor(
    preparation: SystemReadOnlyInspectionPreparation,
) -> tuple[SystemInspectionExecutionTrustAnchor, bytes]:
    private_key = _seed("attestation")
    key = SystemInspectionExecutionVerificationKey(
        keyId="system-inspection.attestation",
        publicKeyBase64url=system_inspection_execution_public_key(private_key),
        state=SystemInspectionExecutionKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )
    return (
        SystemInspectionExecutionTrustAnchor(
            trustDomain="pajin.system-inspection-test",
            issuer="deployment.system-inspection-test",
            deployment=preparation.host_agent_deployment,
            capability=preparation.binding.capability,
            capabilityRelease=preparation.release,
            keys=(key,),
        ),
        private_key,
    )


def _default_review_signal(
    surface_class: SystemSurfaceClass,
) -> SystemInspectionReviewSignal | None:
    if surface_class is SystemSurfaceClass.CONFIGURATION:
        return SystemInspectionReviewSignal.CONFIGURATION_METADATA_DRIFT
    if surface_class is SystemSurfaceClass.SERVICE:
        return SystemInspectionReviewSignal.SERVICE_STATUS_REVIEW
    return None


async def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: SystemSurfaceClass = SystemSurfaceClass.HOST,
    review_signal: SystemInspectionReviewSignal | None | object = ...,
    result_size: int = 4_096,
    result_body: bytes = b"external-system-result",
    source_kind: SystemInspectionSourceKind = (SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST),
    immutable_snapshot_sha256: str | None = None,
    execution_time_offset: timedelta = timedelta(0),
    run_id: str = RUN_ID,
    request_id: str = "tool_system_inspection_observation",
    execution_id: str = "system-execution:host-agent-test",
    statement_update: dict[str, object] | None = None,
) -> _Context:
    surface = _surface(surface_class)
    campaign = _campaign(sample_campaign, surface=surface)
    activation, release = _activation()
    deployment = _deployment()
    preparation = prepare_system_read_only_inspection(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=surface,
        operation=_operation(surface),
        host_agent=BoundedSystemHostAgentAdapter(deployment),
        request_id=request_id,
        agent_id="agent:system-inspection",
    )
    prepared = preparation.prepared_action
    graph_store, graph_admission, graph_lineages, graph_binding, decision = _graph_authority(
        tmp_path,
        campaign.metadata.name,
        preparation,
    )
    target_digest = sha256(prepared.request.target.encode()).hexdigest()
    capability = activation.activation_set.binding.action_capability
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=run_id,
        profileId="system-read-only-inspection-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.system.action-compiler",
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
        proposerId="pajin.graph.system-planner",
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
            authorityId="deployment:system-operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.system.ExternalApprovalAuthority",
            contextDigest=DIGEST_D,
        ),
        requestedBy="principal:system-requester",
        approvedBy="principal:system-approver",
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
        grant_id=f"grant_{request_id}",
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
    trust_anchor, private_key = _trust_anchor(preparation)
    authority = GraphApprovedActionPermitAuthority(
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
    evidence_root = tmp_path / "external-system-source"
    evidence_directory = evidence_root / "evidence"
    evidence_directory.mkdir(parents=True)
    attestation_path = evidence_root / ATTESTATION_REFERENCE
    result_path = evidence_root / RESULT_REFERENCE
    selected_signal = (
        _default_review_signal(surface_class) if review_signal is ... else review_signal
    )

    async def external_runtime_receipts(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> str:
        result = SystemInspectionResultReceipt(
            executionId=execution_id,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            operation=preparation.operation,
            surface=preparation.surface.reference(),
            sourceKind=source_kind,
            immutableSnapshotSha256=immutable_snapshot_sha256,
            resultBodySha256=sha256(result_body).hexdigest(),
            resultBytes=result_size,
            reviewSignal=selected_signal,
            receivedAt=NOW + timedelta(seconds=8) + execution_time_offset,
        )
        result_content = system_inspection_result_receipt_bytes(result)
        result_path.write_bytes(result_content)
        worker = trust_anchor.deployment
        started_at = NOW + timedelta(seconds=6) + execution_time_offset
        worker_admission = WorkerMTLSAdmission(
            policy_id=worker.worker_mtls_policy.policy_id,
            principal_subject=worker.certificate_binding.principal_subject,
            certificate_spki_sha256=worker.certificate_binding.certificate_spki_sha256,
        )
        gateway_decision = PolicyEngine().evaluate_tool_request(
            campaign,
            grant,
            prepared.request,
            SystemReadOnlyInspectionTool.spec,
            used_calls=0,
            now=started_at,
        )
        statement = SystemInspectionExecutionStatement(
            trustDomain=trust_anchor.trust_domain,
            issuer=trust_anchor.issuer,
            deploymentBindingId=worker.deployment_binding_id,
            deploymentBindingDigest=worker.deployment_binding_digest,
            deploymentId=worker.deployment_id,
            workerMTLSAdmission=worker_admission,
            gatewayPolicyDecision=gateway_decision,
            gatewayOutcomeDigest=system_inspection_gateway_outcome_digest(
                policy_decision=gateway_decision,
                request_digest=permit.request_digest,
                permit_digest=permit.permit_digest,
                worker_mtls_admission_digest=worker_admission.admission_digest,
                result_receipt_digest=result.receipt_digest,
            ),
            executionId=result.execution_id,
            campaignId=campaign.metadata.name,
            campaignDigest=campaign_manifest_digest(campaign),
            runId=run_id,
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            inspectionRequest=preparation.inspection_request,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            actionPermitId=permit.permit_id,
            actionPermitDigest=permit.permit_digest,
            approvalReceiptId=receipt.receipt_id,
            approvalReceiptDigest=receipt.receipt_digest,
            nonRootRuntime=SystemNonRootRuntimeReceipt(
                deploymentBindingId=worker.deployment_binding_id,
                deploymentBindingDigest=worker.deployment_binding_digest,
                authorizedHostId=worker.authorized_host_id,
                runAsIdentity=worker.run_as_identity,
                agentExecutableSHA256=EXECUTABLE_DIGEST,
                runtimeIdentityDigest=sha256(b"runtime-identity").hexdigest(),
                confinementDigest=sha256(b"runtime-confinement").hexdigest(),
                attestedAt=NOW + timedelta(seconds=7) + execution_time_offset,
            ),
            resultReceiptReference=RESULT_REFERENCE,
            resultReceiptSha256=sha256(result_content).hexdigest(),
            resultReceiptId=result.receipt_id,
            resultReceiptDigest=result.receipt_digest,
            startedAt=started_at,
            finishedAt=NOW + timedelta(seconds=8) + execution_time_offset,
            issuedAt=NOW + timedelta(seconds=9) + execution_time_offset,
        )
        if statement_update:
            statement = statement.model_copy(update=statement_update)
        bundle = SystemInspectionExecutionAttestor.from_private_key_bytes(
            active_key_id=trust_anchor.keys[0].key_id,
            private_key=private_key,
            trust_anchor=trust_anchor,
        ).attest(statement)
        attestation_path.write_bytes(system_inspection_execution_bundle_bytes(bundle))
        return result.receipt_id

    dispatched = await GraphApprovedActionPermitDispatcher(authority).dispatch_once(
        envelope,
        proposal,
        decision,
        approval,
        external_runtime_receipts,
    )
    assert dispatched.dispatched is True
    assert dispatched.result is not None
    inputs = SystemInspectionObservationSourceInputs(
        source_root=evidence_root,
        attestation_reference=ATTESTATION_REFERENCE,
        expected_run_id=run_id,
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
    )
    gate = SystemInspectionKnowledgeAdmissionGate(
        graph_store=graph_store,
        graph_admission=graph_admission,
        trusted_lineages=graph_lineages,
        trust_anchor=trust_anchor,
    )
    return _Context(
        preparation=preparation,
        graph_store=graph_store,
        graph_admission=graph_admission,
        graph_lineages=graph_lineages,
        graph_binding=graph_binding,
        gate=gate,
        source_inputs=inputs,
        trust_anchor=trust_anchor,
        private_key=private_key,
        attestation_path=attestation_path,
        result_path=result_path,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("surface_class", "review_signal"),
    (
        (
            SystemSurfaceClass.SERVICE,
            SystemInspectionReviewSignal.SERVICE_STATUS_REVIEW,
        ),
        (
            SystemSurfaceClass.CONFIGURATION,
            SystemInspectionReviewSignal.CONFIGURATION_METADATA_DRIFT,
        ),
    ),
)
async def test_sealed_non_root_result_admits_observation_and_bounded_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: SystemSurfaceClass,
    review_signal: SystemInspectionReviewSignal,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        review_signal=review_signal,
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    observation_event = admission.observation_graph_event
    hypothesis_event = admission.hypothesis_graph_event
    payload = candidate.model_dump(mode="json", by_alias=True)

    assert candidate.review_signal is review_signal
    assert candidate.observation_proposal.observation.observation_type == (
        "system.host-observation"
    )
    assert candidate.hypothesis_proposal is not None
    assert candidate.hypothesis_proposal.hypothesis.hypothesis_type == (
        "system.security-configuration"
    )
    assert candidate.observation_proposal.lineage.action_permit_id is not None
    assert (
        candidate.observation_proposal.lineage.capability_grant_digest
        == capability_grant_digest(context.source_inputs.job.grant)
    )
    assert observation_event.decision is GraphAdmissionDecision.ADMITTED
    assert hypothesis_event is not None
    assert hypothesis_event.decision is GraphAdmissionDecision.ADMITTED
    assert [node.kind for node in observation_event.admitted_nodes].count(
        GraphNodeKind.ACTION.value
    ) == 1
    assert [node.kind for node in observation_event.admitted_nodes].count(
        GraphNodeKind.OBSERVATION.value
    ) == 1
    assert [node.kind for node in observation_event.admitted_nodes].count(
        GraphNodeKind.EVIDENCE.value
    ) == 2
    assert {edge.relation for edge in observation_event.admitted_edges} == {
        GraphRelation.PRODUCES,
        GraphRelation.SUPPORTED_BY,
    }
    assert hypothesis_event.admitted_edges[0].relation is GraphRelation.ENABLES
    assert all(payload[alias] is False for alias in _CANDIDATE_FALSE_MARKERS)

    graph_text = json.dumps(
        {
            "observation": observation_event.model_dump(mode="json", by_alias=True),
            "hypothesis": hypothesis_event.model_dump(mode="json", by_alias=True),
        },
        sort_keys=True,
    )
    assert "pajin-agent.service" not in graph_text
    assert "hardening/restart-policy" not in graph_text
    assert "external-system-result" not in graph_text


@pytest.mark.asyncio
async def test_neutral_host_receipt_admits_no_negative_or_open_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, review_signal=None)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)

    assert candidate.review_signal is None
    assert candidate.hypothesis_proposal is None
    assert admission.hypothesis_graph_event is None
    assert admission.bounded_hypothesis_admitted is False
    assert len(context.graph_store.event_log.events()) == 2


@pytest.mark.asyncio
async def test_graph_store_subclass_is_rejected_at_gate_and_source_loader(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, review_signal=None)
    subclass_store = _SQLiteGraphStoreSubclass(
        tmp_path / "subclass-graph.sqlite3",
        campaign_id=context.graph_store.campaign_id,
    )

    with pytest.raises(TypeError, match="exact SQLite Graph Store"):
        SystemInspectionKnowledgeAdmissionGate(
            graph_store=subclass_store,
            graph_admission=context.graph_admission,
            trusted_lineages=context.graph_lineages,
            trust_anchor=context.trust_anchor,
        )
    with pytest.raises(TypeError, match="exact SQLite Graph Store"):
        load_verified_system_inspection_observation_source(
            context.source_inputs,
            graph_store=subclass_store,
            trust_anchor=context.trust_anchor,
        )


@pytest.mark.asyncio
async def test_candidate_rejects_foreign_source_execution_snapshot(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, review_signal=None)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    payload = candidate.model_dump(mode="json", by_alias=True)
    payload["candidateId"] = ""
    payload["candidateDigest"] = ""
    payload["sourceExecutionSnapshot"]["snapshotDigest"] = "f" * 64

    with pytest.raises(ValidationError, match="sealed semantics"):
        SystemInspectionKnowledgeCandidate.model_validate(payload)


@pytest.mark.asyncio
async def test_system_knowledge_admission_exact_retry_is_idempotent(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=SystemSurfaceClass.SERVICE,
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    first = context.gate.admit(context.source_inputs, candidate)
    second = context.gate.admit(context.source_inputs, candidate)

    assert first == second
    assert len(context.graph_store.event_log.events()) == 3


@pytest.mark.asyncio
async def test_signature_tampering_is_rejected_before_graph_admission(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))
    signature = payload["signatureBase64url"]
    payload["signatureBase64url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    context.attestation_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemInspectionKnowledgeAdmissionError, match="signature"):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_detached_result_receipt_tampering_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.result_path.read_text(encoding="utf-8"))
    payload["resultBytes"] += 1
    payload["receiptId"] = ""
    payload["receiptDigest"] = ""
    context.result_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_foreign_or_missing_consumed_permit_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    foreign_inputs = SystemInspectionObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id="run_20260825T120000Z_foreign",
        activation=context.source_inputs.activation,
        campaign=context.source_inputs.campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )

    with pytest.raises(SystemInspectionKnowledgeAdmissionError, match="ActionPermit"):
        context.gate.prepare_candidate(foreign_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_statement_cannot_substitute_permit_digest(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        statement_update={"action_permit_digest": "0" * 64},
    )

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_gateway_outcome_must_match_current_policy_and_execution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        statement_update={"gateway_outcome_digest": "0" * 64},
    )

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_gateway_policy_decision_is_recomputed_from_current_inputs(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    bundle_payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))
    statement_payload = bundle_payload["statement"]
    statement_payload["gatewayPolicyDecision"] = {
        "allowed": True,
        "reason": "forged policy explanation",
        "policy": "allow",
    }
    forged_decision = PolicyDecision.model_validate(statement_payload["gatewayPolicyDecision"])
    permit = context.graph_store.permit_store.permits()[0]
    result = SystemInspectionResultReceipt.model_validate(
        json.loads(context.result_path.read_text(encoding="utf-8"))
    )
    worker_admission = WorkerMTLSAdmission.model_validate(statement_payload["workerMTLSAdmission"])
    statement_payload["gatewayOutcomeDigest"] = system_inspection_gateway_outcome_digest(
        policy_decision=forged_decision,
        request_digest=permit.request_digest,
        permit_digest=permit.permit_digest,
        worker_mtls_admission_digest=worker_admission.admission_digest,
        result_receipt_digest=result.receipt_digest,
    )
    statement = SystemInspectionExecutionStatement.model_validate(statement_payload)
    bundle = SystemInspectionExecutionAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    ).attest(statement)
    context.attestation_path.write_bytes(system_inspection_execution_bundle_bytes(bundle))

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_result_size_cannot_exceed_prepared_artifact_budget(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, result_size=131_073)

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_trust_anchor_substitution_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = context.trust_anchor.model_dump(mode="json", by_alias=True)
    payload["issuer"] = "deployment.untrusted-system-agent"
    foreign_anchor = SystemInspectionExecutionTrustAnchor.model_validate(payload)
    foreign_gate = SystemInspectionKnowledgeAdmissionGate(
        graph_store=context.graph_store,
        graph_admission=context.graph_admission,
        trusted_lineages=context.graph_lineages,
        trust_anchor=foreign_anchor,
    )

    with pytest.raises(SystemInspectionKnowledgeAdmissionError, match="not trusted"):
        foreign_gate.prepare_candidate(context.source_inputs, context.graph_binding)

    ambiguous = context.trust_anchor.model_dump(mode="json", by_alias=True)
    duplicate = deepcopy(ambiguous["keys"][0])
    duplicate["state"] = SystemInspectionExecutionKeyState.RETIRED.value
    duplicate["publicKeyBase64url"] = system_inspection_execution_public_key(
        _seed("foreign-attestation")
    )
    ambiguous["keys"] = sorted(
        [ambiguous["keys"][0], duplicate],
        key=lambda item: (item["keyId"], item["publicKeyBase64url"]),
    )
    with pytest.raises(ValidationError, match="unique and sorted"):
        SystemInspectionExecutionTrustAnchor.model_validate(ambiguous)


@pytest.mark.asyncio
@pytest.mark.parametrize("substituted_identity", ("root", "svc:foreign-agent"))
async def test_non_root_runtime_identity_cannot_be_substituted(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    substituted_identity: str,
) -> None:
    base = await _context(tmp_path, sample_campaign)
    bundle_payload = json.loads(base.attestation_path.read_text(encoding="utf-8"))
    statement_payload = bundle_payload["statement"]
    statement_payload["nonRootRuntime"]["runAsIdentity"] = substituted_identity
    statement_payload.pop("statementSha256", None)
    statement = SystemInspectionExecutionStatement.model_validate(statement_payload)
    bundle = SystemInspectionExecutionAttestor.from_private_key_bytes(
        active_key_id=base.trust_anchor.keys[0].key_id,
        private_key=base.private_key,
        trust_anchor=base.trust_anchor,
    ).attest(statement)
    base.attestation_path.write_bytes(system_inspection_execution_bundle_bytes(bundle))

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        base.gate.prepare_candidate(base.source_inputs, base.graph_binding)


@pytest.mark.asyncio
async def test_current_campaign_scope_drift_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    campaign_payload = context.source_inputs.campaign.model_dump(mode="json", by_alias=True)
    campaign_payload["spec"]["scope"]["allow"] = ["https://unrelated.example.test/"]
    changed_campaign = CampaignManifest.model_validate(campaign_payload)
    changed_inputs = SystemInspectionObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id=context.source_inputs.expected_run_id,
        activation=context.source_inputs.activation,
        campaign=changed_campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="source authority is invalid",
    ):
        context.gate.prepare_candidate(changed_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_stale_graph_snapshot_is_rejected_before_candidate_build(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    context.gate.admit(context.source_inputs, candidate)

    with pytest.raises(
        SystemInspectionKnowledgeAdmissionError,
        match="current canonical head",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


def test_producer_registration_allows_only_observation_and_hypothesis() -> None:
    registration = system_inspection_knowledge_producer_registration()

    assert registration.allowed_proposal_kinds == (
        GraphProposalKind.HYPOTHESIS,
        GraphProposalKind.OBSERVATION,
    )
    assert registration.producer_digest == SYSTEM_INSPECTION_KNOWLEDGE_PRODUCER_DIGEST


@pytest.mark.asyncio
async def test_candidate_rejects_authority_marker_escalation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    payload = candidate.model_dump(mode="json", by_alias=True)

    for alias in _CANDIDATE_FALSE_MARKERS:
        for escalated in (True, 1, "false"):
            changed = deepcopy(payload)
            changed[alias] = escalated
            changed["candidateId"] = ""
            changed["candidateDigest"] = ""
            with pytest.raises(ValidationError):
                SystemInspectionKnowledgeCandidate.model_validate(changed)


@pytest.mark.asyncio
async def test_result_receipt_rejects_raw_content_or_authority_claims(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.result_path.read_text(encoding="utf-8"))

    for alias in (
        "rawResultEmbedded",
        "rawHostMetadataEmbedded",
        "hostPathEmbedded",
        "configurationValueEmbedded",
        "hostExistenceAuthority",
        "serviceStateAuthority",
        "findingConfirmationAuthority",
        "executionAuthority",
    ):
        changed = deepcopy(payload)
        changed[alias] = True
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError):
            SystemInspectionResultReceipt.model_validate(changed)


@pytest.mark.asyncio
async def test_result_receipt_requires_exact_signed_input_provenance(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.result_path.read_text(encoding="utf-8"))

    for source_kind, snapshot_digest in (
        (SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT.value, None),
        (SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST.value, DIGEST_A),
    ):
        changed = deepcopy(payload)
        changed["sourceKind"] = source_kind
        changed["immutableSnapshotSha256"] = snapshot_digest
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError, match="source kind"):
            SystemInspectionResultReceipt.model_validate(changed)


@pytest.mark.asyncio
async def test_execution_statement_rejects_budget_integer_coercion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    statement = json.loads(context.attestation_path.read_text(encoding="utf-8"))["statement"]

    for alias, coerced_values in (
        ("requestCount", (True, 1.0, "1")),
        ("filesystemContentReads", (False, 0.0, "0")),
        ("configurationValueReads", (False, 0.0, "0")),
        ("processSignals", (False, 0.0, "0")),
        ("serviceControlOperations", (False, 0.0, "0")),
        ("hostWriteOperations", (False, 0.0, "0")),
    ):
        for coerced in coerced_values:
            changed = deepcopy(statement)
            changed[alias] = coerced
            with pytest.raises(ValidationError, match="budget values"):
                SystemInspectionExecutionStatement.model_validate(changed)


@pytest.mark.parametrize(
    ("surface_class", "review_signal"),
    (
        (
            SystemSurfaceClass.HOST,
            SystemInspectionReviewSignal.SERVICE_STATUS_REVIEW,
        ),
        (
            SystemSurfaceClass.SERVICE,
            SystemInspectionReviewSignal.CONFIGURATION_METADATA_DRIFT,
        ),
    ),
)
def test_review_signal_cannot_escape_exact_surface_class(
    surface_class: SystemSurfaceClass,
    review_signal: SystemInspectionReviewSignal,
) -> None:
    surface = _surface(surface_class)

    with pytest.raises(ValidationError, match="review signal"):
        SystemInspectionResultReceipt(
            executionId="system-execution:review-signal",
            requestId="tool_system_review_signal",
            requestDigest=DIGEST_A,
            preparationId="system-preparation:review-signal",
            preparationDigest=DIGEST_B,
            operation=_operation(surface),
            surface=surface.reference(),
            sourceKind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
            resultBodySha256=DIGEST_C,
            resultBytes=128,
            reviewSignal=review_signal,
            receivedAt=NOW,
        )
