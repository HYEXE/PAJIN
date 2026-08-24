from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_cloud_read_only_inventory_policy import (
    NOW,
    SECRET_REF,
    SECRET_VALUE,
    _activation,
    _adapter,
    _broker_lease,
    _campaign,
    _iam_surface,
    _resource_surface,
)

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.cloud_inventory import (
    CloudReadOnlyInventoryPolicyPreparation,
    CloudReadOnlyOperation,
    prepare_cloud_read_only_inventory_policy,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSAdmission,
    WorkerMTLSTrustPolicy,
)
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
from pajin.workflow.cloud_provider_admission import (
    CLOUD_PROVIDER_OBSERVATION_PRODUCER_DIGEST,
    CloudCredentialUseReceipt,
    CloudGraphAdmissionBinding,
    CloudProviderExecutionAttestor,
    CloudProviderExecutionKeyState,
    CloudProviderExecutionStatement,
    CloudProviderExecutionTrustAnchor,
    CloudProviderExecutionVerificationKey,
    CloudProviderExecutionWorkerBinding,
    CloudProviderObservationAdmissionError,
    CloudProviderObservationAdmissionGate,
    CloudProviderObservationCandidate,
    CloudProviderObservationSourceInputs,
    CloudProviderResponseReceipt,
    cloud_provider_execution_bundle_bytes,
    cloud_provider_execution_public_key,
    cloud_provider_observation_producer_registration,
    cloud_provider_response_receipt_bytes,
)

RUN_ID = "run_20260824T120000Z_cloudcafe"
AUTHORITY_ID = "pajin.graph.cloud-provider-observation-admission"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ATTESTATION_REFERENCE = "evidence/cloud-provider-attestation.json"
RESPONSE_REFERENCE = "evidence/cloud-provider-response-receipt.json"

_CANDIDATE_FALSE_MARKERS = (
    "graphAdmitted",
    "rawProviderResponseEmbedded",
    "resourceExistenceAuthority",
    "resourceOwnershipAuthority",
    "policyEffectAuthority",
    "effectivePermissionAuthority",
    "surfaceMutationAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalAuthority",
    "permitIssuanceAuthorized",
    "providerSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "credentialUseAuthorized",
    "policyMutationAuthorized",
    "iamMutationAuthorized",
    "containerWriteAuthorized",
    "replayAuthorized",
    "findingConfirmationAuthorized",
    "executionAuthorized",
)


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
            raise RuntimeError("external approval authority rejected the Cloud claim")


@dataclass
class _Context:
    preparation: CloudReadOnlyInventoryPolicyPreparation
    graph_store: SQLiteGraphStore
    graph_admission: GraphAdmissionAuthority
    graph_lineages: TrustedGraphLineageRegistry
    graph_binding: CloudGraphAdmissionBinding
    gate: CloudProviderObservationAdmissionGate
    source_inputs: CloudProviderObservationSourceInputs
    trust_anchor: CloudProviderExecutionTrustAnchor
    private_key: bytes
    raw_lease_id: str
    attestation_path: Path
    response_path: Path


def _seed(label: str) -> bytes:
    return sha256(f"cloud-provider-observation:{label}".encode()).digest()


def _graph_authority(
    tmp_path: Path,
    campaign_id: str,
    preparation: CloudReadOnlyInventoryPolicyPreparation,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    TrustedGraphLineageRegistry,
    CloudGraphAdmissionBinding,
    GraphDecision,
]:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=campaign_id)
    seed_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=RUN_ID,
        agentId="agent:cloud-surface-seed",
        taskId="task:cloud-surface-seed",
        requestId="tool_cloud_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:cloud-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.cloud.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/cloud-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=NOW,
    )
    surface = preparation.surface
    seed = SurfaceProposal(
        proposalId="proposal:surface:cloud-provider-admission",
        producerId="pajin.graph.cloud-provider-admission-test",
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
                    producerId="pajin.graph.cloud-provider-admission-test",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                cloud_provider_observation_producer_registration(),
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
        creator_id="pajin.graph.cloud-snapshot-authority",
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
        actorId="pajin.graph.cloud-planner",
        actorDigest=DIGEST_C,
        createdAt=NOW + timedelta(seconds=1),
    )
    binding = CloudGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return store, authority, lineages, binding, decision


def _trust_anchor(
    preparation: CloudReadOnlyInventoryPolicyPreparation,
) -> tuple[CloudProviderExecutionTrustAnchor, bytes]:
    worker_identity = WorkerCertificateBinding(
        principal_subject="worker:cloud-read-only",
        certificate_spki_sha256="e" * 64,
    )
    worker_policy = WorkerMTLSTrustPolicy(
        policy_id="worker-mtls-policy_" + "f" * 32,
        bindings=(worker_identity,),
    )
    binding = CloudProviderExecutionWorkerBinding(
        deploymentId="deployment:cloud-provider-test",
        capability=preparation.binding.capability,
        capabilityRelease=preparation.release,
        workerProfile=preparation.binding.worker_profile,
        workerMTLSPolicy=worker_policy,
        workerIdentity=worker_identity,
        providerAdapter=preparation.provider_adapter.reference(),
        credentialAudience=preparation.credential_lease.audience,
    )
    private_key = _seed("attestation")
    key = CloudProviderExecutionVerificationKey(
        keyId="cloud-provider.attestation",
        publicKeyBase64url=cloud_provider_execution_public_key(private_key),
        state=CloudProviderExecutionKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )
    return (
        CloudProviderExecutionTrustAnchor(
            trustDomain="pajin.cloud-provider-test",
            issuer="deployment.cloud-provider-test",
            workerBinding=binding,
            keys=(key,),
        ),
        private_key,
    )


async def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    operation: CloudReadOnlyOperation = CloudReadOnlyOperation.INVENTORY,
    response_size: int = 4_096,
    response_body: bytes = b"external-provider-response",
    run_id: str = RUN_ID,
    request_id: str = "tool_cloud_provider_observation",
    execution_id: str = "cloud-execution:provider-test",
    statement_update: dict[str, object] | None = None,
) -> _Context:
    surface = _iam_surface() if operation is CloudReadOnlyOperation.POLICY else _resource_surface()
    adapter = _adapter(surface, operation)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    activation, release = _activation()
    broker, lease = _broker_lease(campaign, adapter)
    preparation = prepare_cloud_read_only_inventory_policy(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=surface,
        operation=operation,
        provider_adapter=adapter,
        secret_broker=broker,
        credential_lease=lease,
        evaluated_at=NOW,
        request_id=request_id,
        agent_id="agent:cloud-provider",
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
        profileId="cloud-read-only-provider-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.cloud.action-compiler",
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
        proposerId="pajin.graph.cloud-planner",
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
            authorityId="deployment:cloud-operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.cloud.ExternalApprovalAuthority",
            contextDigest=DIGEST_D,
        ),
        requestedBy="principal:cloud-requester",
        approvedBy="principal:cloud-approver",
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
    evidence_root = tmp_path / "external-cloud-source"
    evidence_directory = evidence_root / "evidence"
    evidence_directory.mkdir(parents=True)
    attestation_path = evidence_root / ATTESTATION_REFERENCE
    response_path = evidence_root / RESPONSE_REFERENCE

    async def external_runtime_receipts(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> str:
        response = CloudProviderResponseReceipt(
            executionId=execution_id,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            routeDigest=preparation.provider_request.route_digest,
            operation=preparation.operation,
            surface=preparation.surface.reference(),
            httpStatus=200,
            responseBodySha256=sha256(response_body).hexdigest(),
            responseBytes=response_size,
            mediaType="application/json",
            receivedAt=NOW + timedelta(seconds=10),
        )
        response_content = cloud_provider_response_receipt_bytes(response)
        response_path.write_bytes(response_content)
        worker = trust_anchor.worker_binding
        statement = CloudProviderExecutionStatement(
            trustDomain=trust_anchor.trust_domain,
            issuer=trust_anchor.issuer,
            deploymentId=worker.deployment_id,
            workerBindingId=worker.binding_id,
            workerBindingDigest=worker.binding_digest,
            workerMTLSAdmission=WorkerMTLSAdmission(
                policy_id=worker.worker_mtls_policy.policy_id,
                principal_subject=worker.worker_identity.principal_subject,
                certificate_spki_sha256=(worker.worker_identity.certificate_spki_sha256),
            ),
            executionId=response.execution_id,
            campaignId=campaign.metadata.name,
            campaignDigest=campaign_manifest_digest(campaign),
            runId=run_id,
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            providerRequest=preparation.provider_request,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            actionPermitId=permit.permit_id,
            actionPermitDigest=permit.permit_digest,
            approvalReceiptId=receipt.receipt_id,
            approvalReceiptDigest=receipt.receipt_digest,
            credentialUse=CloudCredentialUseReceipt(
                credentialLease=preparation.credential_lease,
                brokerRecheckedAt=NOW + timedelta(seconds=6),
                materializedAt=NOW + timedelta(seconds=7),
                usedAt=NOW + timedelta(seconds=9),
                discardedAt=NOW + timedelta(seconds=11),
            ),
            responseReceiptReference=RESPONSE_REFERENCE,
            responseReceiptSha256=sha256(response_content).hexdigest(),
            responseReceiptId=response.receipt_id,
            responseReceiptDigest=response.receipt_digest,
            startedAt=NOW + timedelta(seconds=8),
            finishedAt=NOW + timedelta(seconds=10),
            issuedAt=NOW + timedelta(seconds=12),
        )
        if statement_update:
            statement = statement.model_copy(update=statement_update)
        bundle = CloudProviderExecutionAttestor.from_private_key_bytes(
            active_key_id=trust_anchor.keys[0].key_id,
            private_key=private_key,
            trust_anchor=trust_anchor,
        ).attest(statement)
        attestation_path.write_bytes(cloud_provider_execution_bundle_bytes(bundle))
        return response.receipt_id

    dispatched = await GraphApprovedActionPermitDispatcher(authority).dispatch_once(
        envelope,
        proposal,
        decision,
        approval,
        external_runtime_receipts,
    )
    assert dispatched.dispatched is True
    assert dispatched.result is not None
    inputs = CloudProviderObservationSourceInputs(
        source_root=evidence_root,
        attestation_reference=ATTESTATION_REFERENCE,
        expected_run_id=run_id,
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
    )
    gate = CloudProviderObservationAdmissionGate(
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
        raw_lease_id=lease.lease_id,
        attestation_path=attestation_path,
        response_path=response_path,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    (CloudReadOnlyOperation.INVENTORY, CloudReadOnlyOperation.POLICY),
)
async def test_sealed_cloud_receipts_admit_only_neutral_observation_and_evidence(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    operation: CloudReadOnlyOperation,
) -> None:
    context = await _context(tmp_path, sample_campaign, operation=operation)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    event = admission.observation_graph_event
    payload = candidate.model_dump(mode="json", by_alias=True)

    assert candidate.operation is operation
    assert candidate.observation_proposal.observation.observation_type == "cloud.api-observation"
    assert candidate.observation_proposal.lineage.action_permit_id is not None
    assert (
        candidate.observation_proposal.lineage.capability_grant_digest
        == capability_grant_digest(context.source_inputs.job.grant)
    )
    assert event.decision is GraphAdmissionDecision.ADMITTED
    assert [node.kind for node in event.admitted_nodes].count(GraphNodeKind.ACTION.value) == 1
    assert [node.kind for node in event.admitted_nodes].count(GraphNodeKind.OBSERVATION.value) == 1
    assert [node.kind for node in event.admitted_nodes].count(GraphNodeKind.EVIDENCE.value) == 2
    assert {edge.relation for edge in event.admitted_edges} == {
        GraphRelation.PRODUCES,
        GraphRelation.SUPPORTED_BY,
    }
    assert all(payload[alias] is False for alias in _CANDIDATE_FALSE_MARKERS)
    assert "effectivePermissions" not in json.dumps(payload)
    assert "external-provider-response" not in json.dumps(payload)
    sealed_text = "\n".join(
        (
            json.dumps(payload),
            context.attestation_path.read_text(encoding="utf-8"),
            context.response_path.read_text(encoding="utf-8"),
        )
    )
    assert SECRET_REF not in sealed_text
    assert SECRET_VALUE not in sealed_text
    assert context.raw_lease_id not in sealed_text


@pytest.mark.asyncio
async def test_cloud_observation_admission_is_idempotent(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    first = context.gate.admit(context.source_inputs, candidate)
    second = context.gate.admit(context.source_inputs, candidate)

    assert first == second
    assert len(context.graph_store.event_log.events()) == 2


@pytest.mark.asyncio
async def test_current_campaign_private_network_authority_drift_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    campaign_payload = context.source_inputs.campaign.model_dump(mode="json", by_alias=True)
    current = campaign_payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"]
    campaign_payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"] = not current
    changed_campaign = CampaignManifest.model_validate(campaign_payload)
    changed_inputs = CloudProviderObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id=context.source_inputs.expected_run_id,
        activation=context.source_inputs.activation,
        campaign=changed_campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )

    with pytest.raises(
        CloudProviderObservationAdmissionError,
        match="preparation and approved execution inputs differ",
    ):
        context.gate.prepare_candidate(changed_inputs, context.graph_binding)


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

    with pytest.raises(CloudProviderObservationAdmissionError, match="signature"):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_detached_response_receipt_tampering_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.response_path.read_text(encoding="utf-8"))
    payload["responseBytes"] += 1
    payload["receiptId"] = ""
    payload["receiptDigest"] = ""
    context.response_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        CloudProviderObservationAdmissionError,
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
    foreign_inputs = CloudProviderObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id="run_20260824T120000Z_foreign",
        activation=context.source_inputs.activation,
        campaign=context.source_inputs.campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )

    with pytest.raises(CloudProviderObservationAdmissionError, match="ActionPermit"):
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
        CloudProviderObservationAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_provider_response_size_cannot_exceed_prepared_budget(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, response_size=131_073)

    with pytest.raises(
        CloudProviderObservationAdmissionError,
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
    payload["issuer"] = "deployment.untrusted-cloud-provider"
    foreign_anchor = CloudProviderExecutionTrustAnchor.model_validate(payload)
    foreign_gate = CloudProviderObservationAdmissionGate(
        graph_store=context.graph_store,
        graph_admission=context.graph_admission,
        trusted_lineages=context.graph_lineages,
        trust_anchor=foreign_anchor,
    )

    with pytest.raises(CloudProviderObservationAdmissionError, match="not trusted"):
        foreign_gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_response_receipt_cannot_substitute_execution_identity(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        statement_update={"execution_id": "cloud-execution:foreign"},
    )

    with pytest.raises(
        CloudProviderObservationAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_stale_graph_snapshot_is_rejected_before_candidate_build(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    context.gate.admit(context.source_inputs, candidate)

    with pytest.raises(CloudProviderObservationAdmissionError, match="current canonical head"):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


def test_producer_registration_is_observation_only() -> None:
    registration = cloud_provider_observation_producer_registration()

    assert registration.allowed_proposal_kinds == (GraphProposalKind.OBSERVATION,)
    assert registration.producer_digest == CLOUD_PROVIDER_OBSERVATION_PRODUCER_DIGEST


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
                CloudProviderObservationCandidate.model_validate(changed)


@pytest.mark.asyncio
async def test_response_receipt_rejects_interpretation_or_mutation_claims(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.response_path.read_text(encoding="utf-8"))

    for alias in (
        "rawProviderResponseEmbedded",
        "resourceFieldsInterpreted",
        "policyFieldsInterpreted",
        "effectivePermissionsEvaluated",
        "resourceExistenceVerified",
        "resourceOwnershipVerified",
        "credentialMaterialPresent",
        "mutationPerformed",
    ):
        changed = deepcopy(payload)
        changed[alias] = True
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError):
            CloudProviderResponseReceipt.model_validate(changed)
