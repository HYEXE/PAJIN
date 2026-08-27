from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_application_static_analysis import (
    NOW,
    _activation,
    _campaign,
    _custody,
    _operation,
    _sandbox,
    _surface,
)

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.application_static_analysis import (
    ApplicationStaticAnalysisPreparation,
    ApplicationStaticAnalysisTool,
    BoundedApplicationStaticAnalyzerAdapter,
    prepare_application_static_analysis,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery import ApplicationSurfaceClass
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
from pajin.workflow.application_static_analysis_admission import (
    APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
    ApplicationGraphAdmissionBinding,
    ApplicationSandboxRuntimeReceipt,
    ApplicationStaticAnalysisExecutionAttestor,
    ApplicationStaticAnalysisExecutionKeyState,
    ApplicationStaticAnalysisExecutionStatement,
    ApplicationStaticAnalysisExecutionTrustAnchor,
    ApplicationStaticAnalysisExecutionVerificationKey,
    ApplicationStaticAnalysisKnowledgeAdmissionError,
    ApplicationStaticAnalysisKnowledgeAdmissionGate,
    ApplicationStaticAnalysisKnowledgeCandidate,
    ApplicationStaticAnalysisObservationSourceInputs,
    ApplicationStaticAnalysisResultReceipt,
    ApplicationStaticAnalysisReviewSignal,
    application_static_analysis_execution_bundle_bytes,
    application_static_analysis_execution_public_key,
    application_static_analysis_gateway_outcome_digest,
    application_static_analysis_knowledge_producer_registration,
    application_static_analysis_result_receipt_bytes,
    load_verified_application_static_analysis_observation_source,
)

RUN_ID = "run_20260826T120000Z_applicationcafe"
AUTHORITY_ID = "pajin.graph.application-static-analysis-knowledge-admission"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ATTESTATION_REFERENCE = "evidence/application-analysis-attestation.json"
RESULT_REFERENCE = "evidence/application-analysis-result-receipt.json"

_CANDIDATE_FALSE_MARKERS = (
    "graphAdmitted",
    "rawArtifactEmbedded",
    "rawAnalysisOutputEmbedded",
    "artifactFormatAuthority",
    "configurationValueAuthority",
    "runtimeSupportAuthority",
    "dependencyRelationshipAuthority",
    "vulnerabilityConfirmationAuthority",
    "hypothesisConfirmationAuthority",
    "artifactMutationAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalAuthority",
    "permitIssuanceAuthorized",
    "artifactAccessAuthorized",
    "custodyAuthorizationAuthority",
    "sandboxInvocationAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "dynamicTargetExecutionAuthorized",
    "debuggerAttachAuthorized",
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
            raise RuntimeError("external approval authority rejected the Application claim")


@dataclass
class _Context:
    preparation: ApplicationStaticAnalysisPreparation
    graph_store: SQLiteGraphStore
    graph_admission: GraphAdmissionAuthority
    graph_lineages: TrustedGraphLineageRegistry
    graph_binding: ApplicationGraphAdmissionBinding
    gate: ApplicationStaticAnalysisKnowledgeAdmissionGate
    source_inputs: ApplicationStaticAnalysisObservationSourceInputs
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor
    private_key: bytes
    attestation_path: Path
    result_path: Path


def _seed(label: str) -> bytes:
    return sha256(f"application-static-analysis-admission:{label}".encode()).digest()


def _graph_authority(
    tmp_path: Path,
    campaign_id: str,
    preparation: ApplicationStaticAnalysisPreparation,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    TrustedGraphLineageRegistry,
    ApplicationGraphAdmissionBinding,
    GraphDecision,
]:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=campaign_id)
    seed_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=RUN_ID,
        agentId="agent:application-surface-seed",
        taskId="task:application-surface-seed",
        requestId="tool_application_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:application-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.application.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/application-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=NOW,
    )
    surface = preparation.surface
    seed = SurfaceProposal(
        proposalId="proposal:surface:application-analysis-admission",
        producerId="pajin.graph.application-analysis-admission-test",
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
                    producerId="pajin.graph.application-analysis-admission-test",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                application_static_analysis_knowledge_producer_registration(),
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
        creator_id="pajin.graph.application-snapshot-authority",
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
        actorId="pajin.graph.application-planner",
        actorDigest=DIGEST_C,
        createdAt=NOW + timedelta(seconds=1),
    )
    binding = ApplicationGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return store, authority, lineages, binding, decision


def _trust_anchor(
    preparation: ApplicationStaticAnalysisPreparation,
) -> tuple[ApplicationStaticAnalysisExecutionTrustAnchor, bytes]:
    private_key = _seed("attestation")
    key = ApplicationStaticAnalysisExecutionVerificationKey(
        keyId="application-analysis.attestation",
        publicKeyBase64url=application_static_analysis_execution_public_key(private_key),
        state=ApplicationStaticAnalysisExecutionKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )
    return (
        ApplicationStaticAnalysisExecutionTrustAnchor(
            trustDomain="pajin.application-analysis-test",
            issuer="deployment.application-analysis-test",
            sandbox=preparation.sandbox,
            capability=preparation.binding.capability,
            capabilityRelease=preparation.release,
            keys=(key,),
        ),
        private_key,
    )


def _default_review_signal(
    surface_class: ApplicationSurfaceClass,
) -> ApplicationStaticAnalysisReviewSignal:
    return {
        ApplicationSurfaceClass.BINARY: (
            ApplicationStaticAnalysisReviewSignal.BINARY_SECURITY_METADATA_REVIEW
        ),
        ApplicationSurfaceClass.CONFIGURATION: (
            ApplicationStaticAnalysisReviewSignal.CONFIGURATION_STRUCTURE_REVIEW
        ),
        ApplicationSurfaceClass.RUNTIME: (
            ApplicationStaticAnalysisReviewSignal.RUNTIME_METADATA_REVIEW
        ),
        ApplicationSurfaceClass.LIBRARY: (
            ApplicationStaticAnalysisReviewSignal.LIBRARY_METADATA_REVIEW
        ),
    }[surface_class]


async def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: ApplicationSurfaceClass = ApplicationSurfaceClass.BINARY,
    review_signal: ApplicationStaticAnalysisReviewSignal | None | object = ...,
    result_size: int = 4_096,
    result_body: bytes = b"external-application-analysis-result",
    run_id: str = RUN_ID,
    request_id: str = "tool_application_analysis_observation",
    execution_id: str = "application-execution:sandbox-test",
    execution_offset: timedelta = timedelta(),
    statement_update: dict[str, object] | None = None,
) -> _Context:
    surface = _surface(surface_class)
    campaign = _campaign(sample_campaign, surface=surface)
    activation, release = _activation()
    operation = _operation(surface)
    custody = _custody(surface)
    sandbox = _sandbox(operation)
    preparation = prepare_application_static_analysis(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=surface,
        operation=operation,
        analyzer=BoundedApplicationStaticAnalyzerAdapter(custody, sandbox),
        request_id=request_id,
        agent_id="agent:application-static-analysis",
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
        profileId="application-static-analysis-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.application.action-compiler",
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
        proposerId="pajin.graph.application-planner",
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
            authorityId="deployment:application-operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.application.ExternalApprovalAuthority",
            contextDigest=DIGEST_D,
        ),
        requestedBy="principal:application-requester",
        approvedBy="principal:application-approver",
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
        clock=lambda: NOW + timedelta(seconds=5) + execution_offset,
        permit_ttl=timedelta(seconds=30),
    )
    evidence_root = tmp_path / "external-application-source"
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
        result = ApplicationStaticAnalysisResultReceipt(
            executionId=execution_id,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            operation=preparation.operation,
            surface=preparation.surface.reference(),
            artifactSHA256=custody.artifact_sha256,
            resultBodySha256=sha256(result_body).hexdigest(),
            resultBytes=result_size,
            reviewSignal=selected_signal,
            receivedAt=NOW + timedelta(seconds=8) + execution_offset,
        )
        result_content = application_static_analysis_result_receipt_bytes(result)
        result_path.write_bytes(result_content)
        started_at = NOW + timedelta(seconds=6) + execution_offset
        runtime = ApplicationSandboxRuntimeReceipt(
            sandboxBindingId=sandbox.sandbox_binding_id,
            sandboxBindingDigest=sandbox.sandbox_binding_digest,
            deploymentId=sandbox.deployment_id,
            operation=sandbox.operation,
            parser=sandbox.parser,
            parserExecutableSHA256=sandbox.parser_executable_sha256,
            sandboxImageSHA256=sandbox.sandbox_image_sha256,
            runAsIdentity=sandbox.run_as_identity,
            artifactSHA256=custody.artifact_sha256,
            artifactBytes=custody.artifact_bytes,
            custodyBindingId=custody.custody_binding_id,
            custodyBindingDigest=custody.custody_binding_digest,
            authorizationDigest=custody.authorization_digest,
            runtimeIdentityDigest=sha256(b"application-runtime-identity").hexdigest(),
            confinementDigest=sha256(b"application-runtime-confinement").hexdigest(),
            attestedAt=NOW + timedelta(seconds=7) + execution_offset,
        )
        gateway_decision = PolicyEngine().evaluate_tool_request(
            campaign,
            grant,
            prepared.request,
            ApplicationStaticAnalysisTool.spec,
            used_calls=0,
            now=started_at,
        )
        statement = ApplicationStaticAnalysisExecutionStatement(
            trustDomain=trust_anchor.trust_domain,
            issuer=trust_anchor.issuer,
            sandboxBindingId=sandbox.sandbox_binding_id,
            sandboxBindingDigest=sandbox.sandbox_binding_digest,
            deploymentId=sandbox.deployment_id,
            gatewayPolicyDecision=gateway_decision,
            gatewayOutcomeDigest=application_static_analysis_gateway_outcome_digest(
                policy_decision=gateway_decision,
                request_digest=permit.request_digest,
                permit_digest=permit.permit_digest,
                sandbox_runtime_receipt_digest=runtime.receipt_digest,
                result_receipt_digest=result.receipt_digest,
            ),
            executionId=result.execution_id,
            campaignId=campaign.metadata.name,
            campaignDigest=campaign_manifest_digest(campaign),
            runId=run_id,
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            analysisRequest=preparation.analysis_request,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            actionPermitId=permit.permit_id,
            actionPermitDigest=permit.permit_digest,
            approvalReceiptId=receipt.receipt_id,
            approvalReceiptDigest=receipt.receipt_digest,
            sandboxRuntime=runtime,
            resultReceiptReference=RESULT_REFERENCE,
            resultReceiptSha256=sha256(result_content).hexdigest(),
            resultReceiptId=result.receipt_id,
            resultReceiptDigest=result.receipt_digest,
            startedAt=started_at,
            finishedAt=NOW + timedelta(seconds=8) + execution_offset,
            issuedAt=NOW + timedelta(seconds=9) + execution_offset,
        )
        if statement_update:
            statement = statement.model_copy(update=statement_update)
        bundle = ApplicationStaticAnalysisExecutionAttestor.from_private_key_bytes(
            active_key_id=trust_anchor.keys[0].key_id,
            private_key=private_key,
            trust_anchor=trust_anchor,
        ).attest(statement)
        attestation_path.write_bytes(application_static_analysis_execution_bundle_bytes(bundle))
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
    inputs = ApplicationStaticAnalysisObservationSourceInputs(
        source_root=evidence_root,
        attestation_reference=ATTESTATION_REFERENCE,
        expected_run_id=run_id,
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
    )
    gate = ApplicationStaticAnalysisKnowledgeAdmissionGate(
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
@pytest.mark.parametrize("surface_class", tuple(ApplicationSurfaceClass))
async def test_sealed_result_admits_neutral_observation_and_bounded_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: ApplicationSurfaceClass,
) -> None:
    context = await _context(tmp_path, sample_campaign, surface_class=surface_class)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    observation_event = admission.observation_graph_event
    hypothesis_event = admission.hypothesis_graph_event
    payload = candidate.model_dump(mode="json", by_alias=True)

    assert candidate.artifact_sha256 == context.preparation.artifact_custody.artifact_sha256
    assert candidate.observation_proposal.observation.observation_type == (
        "application.analysis-observation"
    )
    assert candidate.hypothesis_proposal is not None
    assert candidate.hypothesis_proposal.hypothesis.hypothesis_type == ("application.vulnerability")
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
    assert "external-application-analysis-result" not in graph_text
    assert "/pajin/input/artifact" not in graph_text


@pytest.mark.asyncio
async def test_neutral_receipt_admits_no_negative_or_open_hypothesis(
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
        ApplicationStaticAnalysisKnowledgeAdmissionGate(
            graph_store=subclass_store,
            graph_admission=context.graph_admission,
            trusted_lineages=context.graph_lineages,
            trust_anchor=context.trust_anchor,
        )
    with pytest.raises(TypeError, match="exact SQLite Graph Store"):
        load_verified_application_static_analysis_observation_source(
            context.source_inputs,
            graph_store=subclass_store,
            trust_anchor=context.trust_anchor,
        )


@pytest.mark.asyncio
async def test_application_knowledge_admission_exact_retry_is_idempotent(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
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

    with pytest.raises(ApplicationStaticAnalysisKnowledgeAdmissionError, match="signature"):
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
        ApplicationStaticAnalysisKnowledgeAdmissionError,
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
    foreign_inputs = ApplicationStaticAnalysisObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id="run_20260826T120000Z_foreign",
        activation=context.source_inputs.activation,
        campaign=context.source_inputs.campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )

    with pytest.raises(ApplicationStaticAnalysisKnowledgeAdmissionError, match="ActionPermit"):
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
        ApplicationStaticAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_gateway_policy_decision_is_recomputed(
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
    result = ApplicationStaticAnalysisResultReceipt.model_validate(
        json.loads(context.result_path.read_text(encoding="utf-8"))
    )
    runtime = ApplicationSandboxRuntimeReceipt.model_validate(statement_payload["sandboxRuntime"])
    statement_payload["gatewayOutcomeDigest"] = application_static_analysis_gateway_outcome_digest(
        policy_decision=forged_decision,
        request_digest=permit.request_digest,
        permit_digest=permit.permit_digest,
        sandbox_runtime_receipt_digest=runtime.receipt_digest,
        result_receipt_digest=result.receipt_digest,
    )
    statement = ApplicationStaticAnalysisExecutionStatement.model_validate(statement_payload)
    bundle = ApplicationStaticAnalysisExecutionAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    ).attest(statement)
    context.attestation_path.write_bytes(application_static_analysis_execution_bundle_bytes(bundle))

    with pytest.raises(
        ApplicationStaticAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_result_size_cannot_exceed_prepared_output_budget(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, result_size=131_073)

    with pytest.raises(
        ApplicationStaticAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("artifactSHA256", "0" * 64),
        ("sandboxImageSHA256", "0" * 64),
        ("runAsIdentity", "root"),
    ),
)
async def test_signed_sandbox_runtime_cannot_substitute_exact_binding(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    field: str,
    value: str,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    bundle_payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))
    statement_payload = bundle_payload["statement"]
    runtime_payload = deepcopy(statement_payload["sandboxRuntime"])
    runtime_payload[field] = value
    runtime_payload["receiptId"] = ""
    runtime_payload["receiptDigest"] = ""
    runtime = ApplicationSandboxRuntimeReceipt.model_validate(runtime_payload)
    statement_payload["sandboxRuntime"] = runtime.model_dump(mode="json", by_alias=True)
    result = ApplicationStaticAnalysisResultReceipt.model_validate(
        json.loads(context.result_path.read_text(encoding="utf-8"))
    )
    permit = context.graph_store.permit_store.permits()[0]
    decision = PolicyDecision.model_validate(statement_payload["gatewayPolicyDecision"])
    statement_payload["gatewayOutcomeDigest"] = application_static_analysis_gateway_outcome_digest(
        policy_decision=decision,
        request_digest=permit.request_digest,
        permit_digest=permit.permit_digest,
        sandbox_runtime_receipt_digest=runtime.receipt_digest,
        result_receipt_digest=result.receipt_digest,
    )
    statement = ApplicationStaticAnalysisExecutionStatement.model_validate(statement_payload)
    bundle = ApplicationStaticAnalysisExecutionAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    ).attest(statement)
    context.attestation_path.write_bytes(application_static_analysis_execution_bundle_bytes(bundle))

    with pytest.raises(
        ApplicationStaticAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_current_campaign_scope_drift_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    campaign_payload = context.source_inputs.campaign.model_dump(mode="json", by_alias=True)
    campaign_payload["spec"]["scope"]["allow"] = ["https://unrelated.example.test/"]
    changed_campaign = CampaignManifest.model_validate(campaign_payload)
    changed_inputs = ApplicationStaticAnalysisObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id=context.source_inputs.expected_run_id,
        activation=context.source_inputs.activation,
        campaign=changed_campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )

    with pytest.raises(
        ApplicationStaticAnalysisKnowledgeAdmissionError,
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
        ApplicationStaticAnalysisKnowledgeAdmissionError,
        match="current canonical head",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


def test_producer_registration_allows_only_observation_and_hypothesis() -> None:
    registration = application_static_analysis_knowledge_producer_registration()

    assert registration.allowed_proposal_kinds == (
        GraphProposalKind.HYPOTHESIS,
        GraphProposalKind.OBSERVATION,
    )
    assert registration.producer_digest == (APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST)


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
                ApplicationStaticAnalysisKnowledgeCandidate.model_validate(changed)


@pytest.mark.asyncio
async def test_result_receipt_rejects_raw_content_or_truth_claims(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.result_path.read_text(encoding="utf-8"))

    for alias in (
        "rawResultEmbedded",
        "rawArtifactEmbedded",
        "artifactPathEmbedded",
        "configurationValueEmbedded",
        "artifactFormatAuthority",
        "runtimeSupportAuthority",
        "dependencyRelationshipAuthority",
        "vulnerabilityConfirmationAuthority",
        "findingConfirmationAuthority",
        "executionAuthority",
    ):
        changed = deepcopy(payload)
        changed[alias] = True
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError):
            ApplicationStaticAnalysisResultReceipt.model_validate(changed)


@pytest.mark.asyncio
async def test_execution_statement_rejects_budget_integer_coercion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    statement = json.loads(context.attestation_path.read_text(encoding="utf-8"))["statement"]

    for alias, coerced_values in (
        ("requestCount", (True, 1.0, "1")),
        ("artifactReads", (True, 1.0, "1")),
        ("networkRequests", (False, 0.0, "0")),
        ("artifactWriteOperations", (False, 0.0, "0")),
    ):
        for coerced in coerced_values:
            changed = deepcopy(statement)
            changed[alias] = coerced
            with pytest.raises(ValidationError, match="budget values"):
                ApplicationStaticAnalysisExecutionStatement.model_validate(changed)


def test_review_signal_cannot_escape_exact_surface_class() -> None:
    surface = _surface(ApplicationSurfaceClass.BINARY)

    with pytest.raises(ValidationError, match="review signal"):
        ApplicationStaticAnalysisResultReceipt(
            executionId="application-execution:review-signal",
            requestId="tool_application_review_signal",
            requestDigest=DIGEST_A,
            preparationId="application-preparation:review-signal",
            preparationDigest=DIGEST_B,
            operation=_operation(surface),
            surface=surface.reference(),
            artifactSHA256=surface.locator.artifact_sha256,
            resultBodySha256=DIGEST_C,
            resultBytes=128,
            reviewSignal=(ApplicationStaticAnalysisReviewSignal.CONFIGURATION_STRUCTURE_REVIEW),
            receivedAt=NOW,
        )
