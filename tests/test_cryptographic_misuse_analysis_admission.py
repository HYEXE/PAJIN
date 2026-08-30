from __future__ import annotations

import json
import os
import socket
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_cryptographic_misuse_analysis import (
    _ANALYZER_BY_CLASS,
    _INPUT_KIND_BY_CLASS,
    _OPERATION_BY_CLASS,
    ANALYZER_DIGEST,
    NOW,
    SANDBOX_IMAGE_DIGEST,
    _activation,
    _adapter,
    _campaign,
    _surface,
)

import pajin.workflow.cryptographic_misuse_analysis_admission as admission_module
from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.cryptographic_misuse_analysis import (
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
    CryptographicMisuseAnalysisPreparation,
    CryptographicMisuseAnalysisTool,
    CryptographicMisuseSignalKind,
    prepare_cryptographic_misuse_analysis,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery import CryptographySurfaceClass
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
from pajin.workflow.cryptographic_misuse_analysis_admission import (
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
    CryptographicGraphAdmissionBinding,
    CryptographicMisuseAnalysisExecutionAttestor,
    CryptographicMisuseAnalysisExecutionKeyState,
    CryptographicMisuseAnalysisExecutionStatement,
    CryptographicMisuseAnalysisExecutionTrustAnchor,
    CryptographicMisuseAnalysisExecutionVerificationKey,
    CryptographicMisuseAnalysisKnowledgeAdmissionError,
    CryptographicMisuseAnalysisKnowledgeAdmissionGate,
    CryptographicMisuseAnalysisKnowledgeCandidate,
    CryptographicMisuseAnalysisObservationSourceInputs,
    CryptographicMisuseAnalysisOraclePolicy,
    CryptographicMisuseAnalysisOracleVerdict,
    CryptographicMisuseAnalysisResultDisposition,
    CryptographicMisuseAnalysisResultReceipt,
    CryptographicMisuseAnalysisSandboxRuntimeReceipt,
    CryptographicMisuseOracleDisposition,
    cryptographic_misuse_analysis_execution_bundle_bytes,
    cryptographic_misuse_analysis_execution_public_key,
    cryptographic_misuse_analysis_gateway_outcome_digest,
    cryptographic_misuse_analysis_knowledge_producer_registration,
    cryptographic_misuse_analysis_result_receipt_bytes,
    cryptographic_misuse_analysis_source_root_digest,
    load_verified_cryptographic_misuse_analysis_observation_source,
    recompute_cryptographic_misuse_analysis_oracle_verdict,
    registered_cryptographic_misuse_analysis_oracle_policy,
)

RUN_ID = "run_20260827T120000Z_cryptographiccafe"
AUTHORITY_ID = "pajin.graph.cryptographic-misuse-analysis-knowledge-admission"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ATTESTATION_REFERENCE = "evidence/cryptographic-analysis-attestation.json"
RESULT_REFERENCE = "evidence/cryptographic-analysis-result-receipt.json"

_SIGNAL_BY_CLASS = {
    CryptographySurfaceClass.PROTOCOL: CryptographicMisuseSignalKind.PROTOCOL_POLICY,
    CryptographySurfaceClass.KEY_USAGE: CryptographicMisuseSignalKind.KEY_USAGE_POLICY,
    CryptographySurfaceClass.CIPHERTEXT: CryptographicMisuseSignalKind.CIPHERTEXT_STRUCTURE,
    CryptographySurfaceClass.CONFIGURATION: CryptographicMisuseSignalKind.CONFIGURATION_POLICY,
}

_CANDIDATE_FALSE_MARKERS = (
    "graphAdmitted",
    "rawArtifactEmbedded",
    "rawAnalysisOutputEmbedded",
    "rawKeyMaterialEmbedded",
    "keyReferenceEmbedded",
    "rawCiphertextEmbedded",
    "rawPlaintextEmbedded",
    "rawConfigurationEmbedded",
    "artifactFormatAuthority",
    "configurationValueAuthority",
    "runtimeSupportAuthority",
    "dependencyRelationshipAuthority",
    "vulnerabilityConfirmationAuthority",
    "semanticMisuseTruthAuthority",
    "negativeSecurityClaimAuthorized",
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
    "dnsAccessAuthorized",
    "keyMaterialAccessAuthorized",
    "credentialUseAuthorized",
    "cryptographicOperationAuthorized",
    "keySearchAuthorized",
    "protocolNegotiationAuthorized",
    "newOracleInvocationAuthorized",
    "plaintextOutputAuthorized",
    "keyMaterialOutputAuthorized",
    "dynamicTargetExecutionAuthorized",
    "debuggerAttachAuthorized",
    "replayAuthorized",
    "findingConfirmationAuthorized",
    "executionAuthorized",
)

_ZERO_CHANNEL_FIELDS = (
    "networkRequests",
    "dnsQueries",
    "artifactWriteOperations",
    "hostFilesystemReads",
    "credentialReads",
    "keyMaterialReads",
    "keyStoreSessions",
    "cryptographicOperations",
    "keySearchAttempts",
    "protocolNegotiations",
    "oracleInvocations",
    "plaintextOutputs",
    "keyMaterialOutputs",
    "targetProcessExecutions",
    "shellCommands",
)

_RESULT_FALSE_MARKERS = (
    "rawResultEmbedded",
    "rawArtifactEmbedded",
    "artifactPathEmbedded",
    "rawKeyMaterialEmbedded",
    "keyReferenceEmbedded",
    "rawCiphertextEmbedded",
    "rawPlaintextEmbedded",
    "rawConfigurationEmbedded",
    "rawParameterMaterialEmbedded",
    "credentialMaterialEmbedded",
    "callerRuleOrPluginEmbedded",
    "resultBodyRead",
    "semanticResultVerified",
    "misuseConfirmed",
    "negativeSecurityClaim",
    "findingConfirmationAuthority",
    "executionAuthority",
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
            raise RuntimeError("external approval authority rejected the Cryptographic claim")


@dataclass
class _Context:
    preparation: CryptographicMisuseAnalysisPreparation
    graph_store: SQLiteGraphStore
    graph_admission: GraphAdmissionAuthority
    graph_lineages: TrustedGraphLineageRegistry
    graph_binding: CryptographicGraphAdmissionBinding
    gate: CryptographicMisuseAnalysisKnowledgeAdmissionGate
    source_inputs: CryptographicMisuseAnalysisObservationSourceInputs
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor
    private_key: bytes
    attestation_path: Path
    result_path: Path


def _seed(label: str) -> bytes:
    return sha256(f"cryptographic-misuse-analysis-admission:{label}".encode()).digest()


def _graph_authority(
    tmp_path: Path,
    campaign_id: str,
    preparation: CryptographicMisuseAnalysisPreparation,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    TrustedGraphLineageRegistry,
    CryptographicGraphAdmissionBinding,
    GraphDecision,
]:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=campaign_id)
    seed_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=RUN_ID,
        agentId="agent:cryptographic-surface-seed",
        taskId="task:cryptographic-surface-seed",
        requestId="tool_cryptographic_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:cryptographic-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.cryptography.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/cryptographic-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=NOW,
    )
    surface = preparation.surface
    seed = SurfaceProposal(
        proposalId="proposal:surface:cryptographic-analysis-admission",
        producerId="pajin.graph.cryptographic-analysis-admission-test",
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
                    producerId="pajin.graph.cryptographic-analysis-admission-test",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                cryptographic_misuse_analysis_knowledge_producer_registration(),
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
        creator_id="pajin.graph.cryptographic-snapshot-authority",
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
        actorId="pajin.graph.cryptographic-planner",
        actorDigest=DIGEST_C,
        createdAt=NOW + timedelta(seconds=1),
    )
    binding = CryptographicGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return store, authority, lineages, binding, decision


def _trust_anchor(
    preparation: CryptographicMisuseAnalysisPreparation,
    *,
    signing_seed: str = "attestation",
    signing_key_id: str = "cryptographic-analysis.attestation",
) -> tuple[CryptographicMisuseAnalysisExecutionTrustAnchor, bytes]:
    private_key = _seed(signing_seed)
    key = CryptographicMisuseAnalysisExecutionVerificationKey(
        keyId=signing_key_id,
        publicKeyBase64url=cryptographic_misuse_analysis_execution_public_key(private_key),
        state=CryptographicMisuseAnalysisExecutionKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )
    return (
        CryptographicMisuseAnalysisExecutionTrustAnchor(
            trustDomain="pajin.cryptographic-analysis-test",
            issuer="deployment.cryptographic-analysis-test",
            sandbox=preparation.sandbox,
            capability=preparation.binding.capability,
            capabilityRelease=preparation.release,
            keys=(key,),
        ),
        private_key,
    )


async def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: CryptographySurfaceClass = CryptographySurfaceClass.PROTOCOL,
    result_disposition: CryptographicMisuseAnalysisResultDisposition = (
        CryptographicMisuseAnalysisResultDisposition.REVIEW
    ),
    result_size: int = 4_096,
    result_body: bytes = b"external-cryptographic-analysis-result",
    run_id: str = RUN_ID,
    request_id: str = "tool_cryptographic_analysis_observation",
    execution_id: str = "cryptographic-execution:sandbox-test",
    execution_offset: timedelta = timedelta(),
    signing_seed: str = "attestation",
    signing_key_id: str = "cryptographic-analysis.attestation",
    analyzer_executable_sha256: str = ANALYZER_DIGEST,
    sandbox_image_sha256: str = SANDBOX_IMAGE_DIGEST,
    evidence_directory_label: str = "external-cryptographic-source",
    statement_update: dict[str, object] | None = None,
) -> _Context:
    surface = _surface(surface_class)
    campaign = _campaign(sample_campaign, surface=surface)
    activation, release = _activation()
    operation = _OPERATION_BY_CLASS[surface.surface_class]
    analyzer_adapter = _adapter(
        surface,
        analyzer_executable_sha256=analyzer_executable_sha256,
        sandbox_image_sha256=sandbox_image_sha256,
    )
    preparation = prepare_cryptographic_misuse_analysis(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=surface,
        operation=operation,
        analyzer=analyzer_adapter,
        request_id=request_id,
        agent_id="agent:cryptographic-misuse-analysis",
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
        profileId="cryptographic-misuse-analysis-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.cryptographic.action-compiler",
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
        proposerId="pajin.graph.cryptographic-planner",
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
            authorityId="deployment:cryptographic-operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.cryptographic.ExternalApprovalAuthority",
            contextDigest=DIGEST_D,
        ),
        requestedBy="principal:cryptographic-requester",
        approvedBy="principal:cryptographic-approver",
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
    trust_anchor, private_key = _trust_anchor(
        preparation,
        signing_seed=signing_seed,
        signing_key_id=signing_key_id,
    )
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
    evidence_root = tmp_path / evidence_directory_label
    evidence_directory = evidence_root / "evidence"
    evidence_directory.mkdir(parents=True)
    attestation_path = evidence_root / ATTESTATION_REFERENCE
    result_path = evidence_root / RESULT_REFERENCE

    async def external_runtime_receipts(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> str:
        custody = preparation.artifact_custody
        sandbox = preparation.sandbox
        result = CryptographicMisuseAnalysisResultReceipt(
            executionId=execution_id,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            inputKind=preparation.input_kind,
            operation=preparation.operation,
            analyzer=preparation.analysis_request.analyzer,
            ruleSet=preparation.analysis_request.rule_set,
            surface=preparation.surface.reference(),
            artifactSHA256=custody.artifact_sha256,
            artifactBytes=custody.artifact_bytes,
            resultBodySha256=sha256(result_body).hexdigest(),
            resultBytes=result_size,
            resultDisposition=result_disposition,
            receivedAt=NOW + timedelta(seconds=8) + execution_offset,
        )
        result_content = cryptographic_misuse_analysis_result_receipt_bytes(result)
        result_path.write_bytes(result_content)
        started_at = NOW + timedelta(seconds=6) + execution_offset
        runtime = CryptographicMisuseAnalysisSandboxRuntimeReceipt(
            sandboxBindingId=sandbox.sandbox_binding_id,
            sandboxBindingDigest=sandbox.sandbox_binding_digest,
            deploymentId=sandbox.deployment_id,
            surface=preparation.surface.reference(),
            inputKind=preparation.input_kind,
            ruleSet=sandbox.rule_set,
            operation=sandbox.operation,
            analyzer=sandbox.analyzer,
            analyzerExecutableSHA256=sandbox.analyzer_executable_sha256,
            sandboxImageSHA256=sandbox.sandbox_image_sha256,
            runAsIdentity=sandbox.run_as_identity,
            maxArtifactBytes=sandbox.max_artifact_bytes,
            maxOutputBytes=sandbox.max_output_bytes,
            maxRuntimeSeconds=sandbox.max_runtime_seconds,
            maxMemoryMiB=sandbox.max_memory_mib,
            maxProcessCount=sandbox.max_process_count,
            artifactSHA256=custody.artifact_sha256,
            artifactBytes=custody.artifact_bytes,
            custodyBindingId=custody.custody_binding_id,
            custodyBindingDigest=custody.custody_binding_digest,
            authorizationDigest=custody.authorization_digest,
            runtimeIdentityDigest=sha256(b"cryptographic-runtime-identity").hexdigest(),
            confinementDigest=sha256(b"cryptographic-runtime-confinement").hexdigest(),
            attestedAt=NOW + timedelta(seconds=7) + execution_offset,
        )
        gateway_decision = PolicyEngine().evaluate_tool_request(
            campaign,
            grant,
            prepared.request,
            CryptographicMisuseAnalysisTool.spec,
            used_calls=0,
            now=started_at,
        )
        statement = CryptographicMisuseAnalysisExecutionStatement(
            trustDomain=trust_anchor.trust_domain,
            issuer=trust_anchor.issuer,
            sandboxBindingId=sandbox.sandbox_binding_id,
            sandboxBindingDigest=sandbox.sandbox_binding_digest,
            deploymentId=sandbox.deployment_id,
            gatewayPolicyDecision=gateway_decision,
            gatewayOutcomeDigest=cryptographic_misuse_analysis_gateway_outcome_digest(
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
        bundle = CryptographicMisuseAnalysisExecutionAttestor.from_private_key_bytes(
            active_key_id=trust_anchor.keys[0].key_id,
            private_key=private_key,
            trust_anchor=trust_anchor,
        ).attest(statement)
        attestation_path.write_bytes(cryptographic_misuse_analysis_execution_bundle_bytes(bundle))
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
    inputs = CryptographicMisuseAnalysisObservationSourceInputs(
        source_root=evidence_root,
        attestation_reference=ATTESTATION_REFERENCE,
        expected_run_id=run_id,
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
    )
    gate = CryptographicMisuseAnalysisKnowledgeAdmissionGate(
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


def _resign_source(
    context: _Context,
    *,
    runtime_update: dict[str, object] | None = None,
    result_update: dict[str, object] | None = None,
    statement_update: dict[str, object] | None = None,
) -> None:
    bundle_payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))
    statement_payload = deepcopy(bundle_payload["statement"])
    result_payload = json.loads(context.result_path.read_text(encoding="utf-8"))
    if result_update:
        result_payload.update(result_update)
        result_payload["receiptId"] = ""
        result_payload["receiptDigest"] = ""
    result = CryptographicMisuseAnalysisResultReceipt.model_validate(result_payload)
    result_content = cryptographic_misuse_analysis_result_receipt_bytes(result)
    context.result_path.write_bytes(result_content)

    runtime_payload = deepcopy(statement_payload["sandboxRuntime"])
    if runtime_update:
        runtime_payload.update(runtime_update)
        runtime_payload["receiptId"] = ""
        runtime_payload["receiptDigest"] = ""
    runtime = CryptographicMisuseAnalysisSandboxRuntimeReceipt.model_validate(runtime_payload)
    permit = context.graph_store.permit_store.permits()[0]
    decision = PolicyDecision.model_validate(statement_payload["gatewayPolicyDecision"])
    statement_payload.update(
        {
            "sandboxRuntime": runtime.model_dump(mode="json", by_alias=True),
            "gatewayOutcomeDigest": cryptographic_misuse_analysis_gateway_outcome_digest(
                policy_decision=decision,
                request_digest=permit.request_digest,
                permit_digest=permit.permit_digest,
                sandbox_runtime_receipt_digest=runtime.receipt_digest,
                result_receipt_digest=result.receipt_digest,
            ),
            "resultReceiptSha256": sha256(result_content).hexdigest(),
            "resultReceiptId": result.receipt_id,
            "resultReceiptDigest": result.receipt_digest,
        }
    )
    if statement_update:
        statement_payload.update(statement_update)
    statement = CryptographicMisuseAnalysisExecutionStatement.model_validate(statement_payload)
    bundle = CryptographicMisuseAnalysisExecutionAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    ).attest(statement)
    context.attestation_path.write_bytes(
        cryptographic_misuse_analysis_execution_bundle_bytes(bundle)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("surface_class", tuple(CryptographySurfaceClass))
async def test_sealed_result_admits_neutral_observation_and_exact_open_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: CryptographySurfaceClass,
) -> None:
    context = await _context(tmp_path, sample_campaign, surface_class=surface_class)
    source = load_verified_cryptographic_misuse_analysis_observation_source(
        context.source_inputs,
        graph_store=context.graph_store,
        trust_anchor=context.trust_anchor,
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    observation_event = admission.observation_graph_event
    hypothesis_event = admission.hypothesis_graph_event
    payload = candidate.model_dump(mode="json", by_alias=True)

    assert source.oracle_verdict.review_signal is _SIGNAL_BY_CLASS[surface_class]
    assert source.oracle_verdict.disposition is (
        CryptographicMisuseOracleDisposition.STRUCTURALLY_CONSISTENT_REVIEW
    )
    assert source.oracle_verdict.result_body_read_performed is False
    assert source.oracle_verdict.artifact_read_performed is False
    assert source.oracle_verdict.semantic_truth_established is False
    assert candidate.review_signal is _SIGNAL_BY_CLASS[surface_class]
    assert candidate.oracle_verdict_digest == source.oracle_verdict.verdict_digest
    assert candidate.observation_proposal.observation.observation_type == (
        "cryptography.analysis-observation"
    )
    assert candidate.hypothesis_proposal is not None
    assert candidate.hypothesis_proposal.hypothesis.hypothesis_type == (
        "cryptography.misuse-weakness"
    )
    assert candidate.hypothesis_proposal.hypothesis.confidence == 0.5
    assert (
        candidate.observation_proposal.lineage.capability_grant_digest
        == capability_grant_digest(context.source_inputs.job.grant)
    )
    assert observation_event.decision is GraphAdmissionDecision.ADMITTED
    assert hypothesis_event is not None
    assert hypothesis_event.decision is GraphAdmissionDecision.ADMITTED
    kinds = [node.kind for node in observation_event.admitted_nodes]
    assert kinds.count(GraphNodeKind.ACTION.value) == 1
    assert kinds.count(GraphNodeKind.OBSERVATION.value) == 1
    assert kinds.count(GraphNodeKind.EVIDENCE.value) == 2
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
    assert "external-cryptographic-analysis-result" not in graph_text
    assert "ctf.crypto-single-byte-xor" not in graph_text
    assert "PAJIN{" not in graph_text


@pytest.mark.asyncio
@pytest.mark.parametrize("surface_class", tuple(CryptographySurfaceClass))
async def test_no_signal_admits_observation_without_negative_or_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: CryptographySurfaceClass,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        result_disposition=CryptographicMisuseAnalysisResultDisposition.NO_SIGNAL,
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)

    assert candidate.surface.surface_class is surface_class
    assert candidate.review_signal is None
    assert candidate.oracle_verdict.disposition is (
        CryptographicMisuseOracleDisposition.INCONCLUSIVE_NO_SIGNAL
    )
    assert candidate.oracle_verdict.negative_security_claim is False
    assert candidate.hypothesis_proposal is None
    assert admission.hypothesis_graph_event is None
    assert admission.bounded_hypothesis_admitted is False
    assert len(context.graph_store.event_log.events()) == 2


@pytest.mark.asyncio
async def test_structural_oracle_is_deterministic_code_owned_and_copy_isolated(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    result = CryptographicMisuseAnalysisResultReceipt.model_validate_json(
        context.result_path.read_bytes()
    )
    first = recompute_cryptographic_misuse_analysis_oracle_verdict(
        preparation=context.preparation,
        result_receipt=result,
    )
    second = recompute_cryptographic_misuse_analysis_oracle_verdict(
        preparation=context.preparation,
        result_receipt=result,
    )

    assert first == second
    assert first.verdict_digest == second.verdict_digest
    assert first.oracle_policy == registered_cryptographic_misuse_analysis_oracle_policy()
    poisoned = registered_cryptographic_misuse_analysis_oracle_policy()
    object.__setattr__(poisoned, "oracle_digest", "0" * 64)
    assert registered_cryptographic_misuse_analysis_oracle_policy().oracle_digest != "0" * 64
    poisoned_row = poisoned.surface_signal_mapping[0]
    canonical_row = CryptographicMisuseAnalysisOraclePolicy().surface_signal_mapping[0]
    replacement_signal = next(
        signal
        for signal in CryptographicMisuseSignalKind
        if signal is not canonical_row.review_signal
    )
    object.__setattr__(poisoned_row, "review_signal", replacement_signal)

    assert CryptographicMisuseAnalysisOraclePolicy().surface_signal_mapping[0] == canonical_row
    assert registered_cryptographic_misuse_analysis_oracle_policy().surface_signal_mapping[0] == (
        canonical_row
    )
    assert (
        recompute_cryptographic_misuse_analysis_oracle_verdict(
            preparation=context.preparation,
            result_receipt=result,
        ).oracle_policy.surface_signal_mapping[0]
        == canonical_row
    )


def test_source_root_digest_binds_exact_evidence_coordinates() -> None:
    coordinates = {
        "attestation_reference": ATTESTATION_REFERENCE,
        "attestation_sha256": DIGEST_A,
        "result_receipt_reference": RESULT_REFERENCE,
        "result_receipt_sha256": DIGEST_B,
        "trust_anchor_digest": DIGEST_C,
        "statement_sha256": DIGEST_D,
        "oracle_policy_digest": sha256(b"oracle-policy").hexdigest(),
        "oracle_verdict_digest": sha256(b"oracle-verdict").hexdigest(),
    }
    expected = cryptographic_misuse_analysis_source_root_digest(**coordinates)

    assert expected != cryptographic_misuse_analysis_source_root_digest(
        **(coordinates | {"attestation_reference": "evidence/renamed-attestation.json"})
    )
    assert expected != cryptographic_misuse_analysis_source_root_digest(
        **(coordinates | {"result_receipt_reference": "evidence/renamed-result.json"})
    )
    with pytest.raises(ValueError, match="references must be distinct"):
        cryptographic_misuse_analysis_source_root_digest(
            **(coordinates | {"result_receipt_reference": ATTESTATION_REFERENCE})
        )


def test_structural_oracle_rejects_repeated_digest_with_conflicting_byte_counts(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(CryptographySurfaceClass.PROTOCOL)
    campaign = _campaign(sample_campaign, surface=surface)
    activation, release = _activation()
    preparation = prepare_cryptographic_misuse_analysis(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
        analyzer=_adapter(surface),
        request_id="tool_cryptographic_digest_collision_oracle",
        agent_id="agent:cryptographic-misuse-analysis",
    )
    custody = preparation.artifact_custody
    receipt = CryptographicMisuseAnalysisResultReceipt(
        executionId="cryptographic-execution:digest-collision-oracle",
        requestId=preparation.prepared_action.request.request_id,
        requestDigest=preparation.prepared_action.request_digest,
        preparationId=preparation.preparation_id,
        preparationDigest=preparation.preparation_digest,
        inputKind=preparation.input_kind,
        operation=preparation.operation,
        analyzer=preparation.analysis_request.analyzer,
        ruleSet=preparation.analysis_request.rule_set,
        surface=preparation.surface.reference(),
        artifactSHA256=custody.artifact_sha256,
        artifactBytes=custody.artifact_bytes,
        resultBodySha256=custody.artifact_sha256,
        resultBytes=custody.artifact_bytes + 1,
        resultDisposition=CryptographicMisuseAnalysisResultDisposition.REVIEW,
        receivedAt=NOW,
    )

    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="declared result body byte count conflicts with artifact",
    ):
        recompute_cryptographic_misuse_analysis_oracle_verdict(
            preparation=preparation,
            result_receipt=receipt,
        )


@pytest.mark.asyncio
async def test_source_loader_rejects_repeated_digest_with_conflicting_byte_counts(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pajin.workflow.cryptographic_misuse_analysis_admission as admission_module

    context = await _context(tmp_path, sample_campaign, result_size=4_097)
    attestation_bytes = context.attestation_path.read_bytes()
    result_bytes = context.result_path.read_bytes()
    result = CryptographicMisuseAnalysisResultReceipt.model_validate_json(result_bytes)
    custody = context.preparation.artifact_custody
    real_sha256 = admission_module.__dict__["sha256"]

    class _FixedSha256:
        def __init__(self, digest: str) -> None:
            self._digest = digest

        def hexdigest(self) -> str:
            return self._digest

        def digest(self) -> bytes:
            return bytes.fromhex(self._digest)

    scenarios = (
        ((attestation_bytes, sha256(result_bytes).hexdigest()),),
        ((attestation_bytes, custody.artifact_sha256),),
        ((attestation_bytes, result.result_body_sha256),),
        ((result_bytes, custody.artifact_sha256),),
        ((result_bytes, result.result_body_sha256),),
    )
    byte_counts = (
        len(attestation_bytes),
        len(result_bytes),
        custody.artifact_bytes,
        result.result_bytes,
    )
    assert len(set(byte_counts)) == len(byte_counts)

    for overrides in scenarios:

        def collision_sha256(
            data: bytes = b"",
            *,
            digest_overrides: tuple[tuple[bytes, str], ...] = overrides,
        ) -> object:
            for content, digest in digest_overrides:
                if data == content:
                    return _FixedSha256(digest)
            return real_sha256(data)

        monkeypatch.setattr(admission_module, "sha256", collision_sha256)
        with pytest.raises(
            CryptographicMisuseAnalysisKnowledgeAdmissionError,
            match="byte count conflicts",
        ):
            load_verified_cryptographic_misuse_analysis_observation_source(
                context.source_inputs,
                graph_store=context.graph_store,
                trust_anchor=context.trust_anchor,
            )

    monkeypatch.setattr(admission_module, "sha256", real_sha256)
    _resign_source(
        context,
        result_update={
            "resultBodySha256": custody.artifact_sha256,
            "resultBytes": custody.artifact_bytes + 1,
        },
    )
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="declared result body byte count conflicts with artifact",
    ):
        load_verified_cryptographic_misuse_analysis_observation_source(
            context.source_inputs,
            graph_store=context.graph_store,
            trust_anchor=context.trust_anchor,
        )


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

    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError, match="signature"):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


def test_execution_key_lifecycle_and_anchor_require_exact_one_active_key() -> None:
    private_key = _seed("key-lifecycle")
    public_key = cryptographic_misuse_analysis_execution_public_key(private_key)
    with pytest.raises(ValidationError, match="requires not_after"):
        CryptographicMisuseAnalysisExecutionVerificationKey(
            keyId="retired-key",
            publicKeyBase64url=public_key,
            state=CryptographicMisuseAnalysisExecutionKeyState.RETIRED,
            notBefore=NOW - timedelta(days=2),
        )
    with pytest.raises(ValidationError, match="requires revoked_at"):
        CryptographicMisuseAnalysisExecutionVerificationKey(
            keyId="revoked-key",
            publicKeyBase64url=public_key,
            state=CryptographicMisuseAnalysisExecutionKeyState.REVOKED,
            notBefore=NOW - timedelta(days=2),
        )


@pytest.mark.asyncio
async def test_trust_anchor_rejects_duplicate_active_keys_and_foreign_signature(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    other_private = _seed("foreign-attestation")
    other_key = CryptographicMisuseAnalysisExecutionVerificationKey(
        keyId="cryptographic-analysis.foreign",
        publicKeyBase64url=cryptographic_misuse_analysis_execution_public_key(other_private),
        state=CryptographicMisuseAnalysisExecutionKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )
    with pytest.raises(ValidationError, match="requires one active key"):
        CryptographicMisuseAnalysisExecutionTrustAnchor(
            trustDomain=context.trust_anchor.trust_domain,
            issuer=context.trust_anchor.issuer,
            sandbox=context.preparation.sandbox,
            capability=context.preparation.binding.capability,
            capabilityRelease=context.preparation.release,
            keys=tuple(
                sorted((*context.trust_anchor.keys, other_key), key=lambda item: item.key_id)
            ),
        )

    foreign_anchor = CryptographicMisuseAnalysisExecutionTrustAnchor(
        trustDomain=context.trust_anchor.trust_domain,
        issuer=context.trust_anchor.issuer,
        sandbox=context.preparation.sandbox,
        capability=context.preparation.binding.capability,
        capabilityRelease=context.preparation.release,
        keys=(other_key,),
    )
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError, match="signing key"):
        load_verified_cryptographic_misuse_analysis_observation_source(
            context.source_inputs,
            graph_store=context.graph_store,
            trust_anchor=foreign_anchor,
        )


@pytest.mark.asyncio
async def test_detached_result_receipt_tampering_and_extra_sensitive_fields_are_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    original = json.loads(context.result_path.read_text(encoding="utf-8"))
    payload = deepcopy(original)
    payload["resultBodySha256"] = "0" * 64
    payload["receiptId"] = ""
    payload["receiptDigest"] = ""
    context.result_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    for field in ("rawKey", "kmsKeyAlias", "pkcs11Handle", "resultBody", "ctfOracleResult"):
        changed = deepcopy(original)
        changed[field] = "sensitive"
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError):
            CryptographicMisuseAnalysisResultReceipt.model_validate(changed)


@pytest.mark.asyncio
async def test_result_receipt_rejects_leakage_and_authority_markers(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.result_path.read_text(encoding="utf-8"))

    for alias in _RESULT_FALSE_MARKERS:
        for escalated in (True, 1, "false"):
            changed = deepcopy(payload)
            changed[alias] = escalated
            changed["receiptId"] = ""
            changed["receiptDigest"] = ""
            with pytest.raises(ValidationError):
                CryptographicMisuseAnalysisResultReceipt.model_validate(changed)


@pytest.mark.asyncio
async def test_cross_class_result_manifest_is_rejected_after_valid_resigning(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    other = _surface(CryptographySurfaceClass.CIPHERTEXT)
    _resign_source(
        context,
        result_update={
            "surface": other.reference().model_dump(mode="json", by_alias=True),
            "inputKind": _INPUT_KIND_BY_CLASS[other.surface_class].value,
            "operation": _OPERATION_BY_CLASS[other.surface_class].value,
            "analyzer": _ANALYZER_BY_CLASS[other.surface_class].value,
        },
    )

    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match=r"differs from current authority|structural Oracle",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_result_size_and_output_schema_are_bounded(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign, result_size=131_073)
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match=r"differs from current authority|structural Oracle",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    payload = json.loads(context.result_path.read_text(encoding="utf-8"))
    payload["outputSchema"] = "pajin.cryptography.unreviewed-result.v9"
    context.result_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_runtime_cannot_substitute_exact_surface_mapping_custody_or_budget(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    other = _surface(CryptographySurfaceClass.CIPHERTEXT)
    substitutions: tuple[dict[str, object], ...] = (
        {"surface": other.reference().model_dump(mode="json", by_alias=True)},
        {"inputKind": _INPUT_KIND_BY_CLASS[other.surface_class].value},
        {"operation": _OPERATION_BY_CLASS[other.surface_class].value},
        {"analyzer": _ANALYZER_BY_CLASS[other.surface_class].value},
        {"artifactSHA256": "0" * 64},
        {"artifactBytes": context.preparation.artifact_custody.artifact_bytes + 1},
        {"custodyBindingDigest": "0" * 64},
        {"authorizationDigest": "0" * 64},
        {"analyzerExecutableSHA256": "0" * 64},
        {"sandboxImageSHA256": "0" * 64},
        {"runAsIdentity": "root"},
        {"maxArtifactBytes": context.preparation.sandbox.max_artifact_bytes - 1},
        {"maxOutputBytes": context.preparation.sandbox.max_output_bytes - 1},
        {"maxRuntimeSeconds": context.preparation.sandbox.max_runtime_seconds - 1},
        {"maxMemoryMiB": context.preparation.sandbox.max_memory_mib - 1},
        {"maxProcessCount": context.preparation.sandbox.max_process_count - 1},
    )
    for update in substitutions:
        _resign_source(context, runtime_update=update)
        with pytest.raises(
            CryptographicMisuseAnalysisKnowledgeAdmissionError,
            match="differs from current authority",
        ):
            context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
        context = await _context(
            tmp_path / next(iter(update)),
            sample_campaign,
            request_id=f"tool_crypto_{next(iter(update))}",
        )


@pytest.mark.asyncio
async def test_statement_zero_channels_require_exact_zero_integers(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    statement = json.loads(context.attestation_path.read_text(encoding="utf-8"))["statement"]

    for alias in _ZERO_CHANNEL_FIELDS:
        for invalid in (1, False, 0.0, "0"):
            changed = deepcopy(statement)
            changed[alias] = invalid
            with pytest.raises(ValidationError):
                CryptographicMisuseAnalysisExecutionStatement.model_validate(changed)


@pytest.mark.asyncio
async def test_missing_or_foreign_consumed_permit_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    foreign_inputs = CryptographicMisuseAnalysisObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id="run_20260827T120000Z_foreign",
        activation=context.source_inputs.activation,
        campaign=context.source_inputs.campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError, match="ActionPermit"):
        context.gate.prepare_candidate(foreign_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_permit_approval_and_gateway_coordinates_are_recomputed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    _resign_source(context, statement_update={"actionPermitDigest": "0" * 64})
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    context = await _context(
        tmp_path / "approval", sample_campaign, request_id="tool_crypto_approval"
    )
    _resign_source(context, statement_update={"approvalReceiptDigest": "0" * 64})
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    context = await _context(
        tmp_path / "gateway", sample_campaign, request_id="tool_crypto_gateway"
    )
    bundle_payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))
    statement_payload = bundle_payload["statement"]
    statement_payload["gatewayPolicyDecision"] = {
        "allowed": True,
        "reason": "forged policy explanation",
        "policy": "allow",
    }
    forged = PolicyDecision.model_validate(statement_payload["gatewayPolicyDecision"])
    permit = context.graph_store.permit_store.permits()[0]
    result = CryptographicMisuseAnalysisResultReceipt.model_validate_json(
        context.result_path.read_bytes()
    )
    runtime = CryptographicMisuseAnalysisSandboxRuntimeReceipt.model_validate(
        statement_payload["sandboxRuntime"]
    )
    statement_payload["gatewayOutcomeDigest"] = (
        cryptographic_misuse_analysis_gateway_outcome_digest(
            policy_decision=forged,
            request_digest=permit.request_digest,
            permit_digest=permit.permit_digest,
            sandbox_runtime_receipt_digest=runtime.receipt_digest,
            result_receipt_digest=result.receipt_digest,
        )
    )
    statement = CryptographicMisuseAnalysisExecutionStatement.model_validate(statement_payload)
    bundle = CryptographicMisuseAnalysisExecutionAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    ).attest(statement)
    context.attestation_path.write_bytes(
        cryptographic_misuse_analysis_execution_bundle_bytes(bundle)
    )
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_current_b_preparation_and_campaign_scope_are_rebuilt(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    campaign_payload = context.source_inputs.campaign.model_dump(mode="json", by_alias=True)
    campaign_payload["spec"]["scope"]["allow"] = ["https://unrelated.example.test/"]
    changed_campaign = CampaignManifest.model_validate(campaign_payload)
    changed_inputs = CryptographicMisuseAnalysisObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference=context.source_inputs.attestation_reference,
        expected_run_id=context.source_inputs.expected_run_id,
        activation=context.source_inputs.activation,
        campaign=changed_campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="source authority is invalid",
    ):
        context.gate.prepare_candidate(changed_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_artifact_result_body_network_key_and_ctf_oracle_are_not_invoked(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = await _context(tmp_path, sample_campaign)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("forbidden runtime path was invoked")

    import pajin.capabilities.existing as existing_capabilities

    monkeypatch.setattr(existing_capabilities, "_solve_single_byte_xor", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    assert candidate.oracle_verdict.result_body_read_performed is False
    assert candidate.oracle_verdict.artifact_read_performed is False
    assert candidate.oracle_verdict.key_material_accessed is False
    assert candidate.oracle_verdict.cryptographic_operation_performed is False
    assert sorted(path.name for path in context.result_path.parent.iterdir()) == sorted(
        (context.attestation_path.name, context.result_path.name)
    )


@pytest.mark.asyncio
async def test_strict_json_and_artifact_reference_fail_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    context.result_path.write_text('{"resultBytes":1,"resultBytes":2}', encoding="utf-8")
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    traversal_inputs = CryptographicMisuseAnalysisObservationSourceInputs(
        source_root=context.source_inputs.source_root,
        attestation_reference="../cryptographic-analysis-attestation.json",
        expected_run_id=context.source_inputs.expected_run_id,
        activation=context.source_inputs.activation,
        campaign=context.source_inputs.campaign,
        preparation=context.source_inputs.preparation,
        job=context.source_inputs.job,
    )
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError, match="reference"):
        context.gate.prepare_candidate(traversal_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_hardlinked_and_symlinked_evidence_are_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    hardlink_context = await _context(tmp_path / "hardlink", sample_campaign)
    original = hardlink_context.result_path.with_name("hardlink-source.json")
    original.write_bytes(hardlink_context.result_path.read_bytes())
    hardlink_context.result_path.unlink()
    os.link(original, hardlink_context.result_path)
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError):
        hardlink_context.gate.prepare_candidate(
            hardlink_context.source_inputs,
            hardlink_context.graph_binding,
        )

    symlink_context = await _context(
        tmp_path / "symlink",
        sample_campaign,
        request_id="tool_crypto_symlink",
    )
    target = symlink_context.result_path.with_name("symlink-target.json")
    target.write_bytes(symlink_context.result_path.read_bytes())
    symlink_context.result_path.unlink()
    try:
        os.symlink(target, symlink_context.result_path)
    except OSError:
        pytest.skip("symlink creation is unavailable in this Windows environment")
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError):
        symlink_context.gate.prepare_candidate(
            symlink_context.source_inputs,
            symlink_context.graph_binding,
        )


@pytest.mark.asyncio
async def test_graph_admission_exact_retry_is_idempotent_and_stale_head_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    observation = candidate.observation_proposal
    expected_head = candidate.graph.snapshot.event_log_head_digest
    assert expected_head is not None
    context.graph_lineages.register(observation.lineage)
    interrupted = context.graph_admission.submit_if_current(
        observation,
        expected_event_log_head_digest=expected_head,
    )
    assert interrupted.event.decision is GraphAdmissionDecision.ADMITTED
    assert len(context.graph_store.event_log.events()) == 2

    first = context.gate.admit(context.source_inputs, candidate)
    oracle_calls = 0
    original_oracle = admission_module.recompute_cryptographic_misuse_analysis_oracle_verdict

    def count_oracle_recomputation(
        *,
        preparation: CryptographicMisuseAnalysisPreparation,
        result_receipt: CryptographicMisuseAnalysisResultReceipt,
    ) -> CryptographicMisuseAnalysisOracleVerdict:
        nonlocal oracle_calls
        oracle_calls += 1
        return original_oracle(
            preparation=preparation,
            result_receipt=result_receipt,
        )

    monkeypatch.setattr(
        admission_module,
        "recompute_cryptographic_misuse_analysis_oracle_verdict",
        count_oracle_recomputation,
    )
    second = context.gate.admit(context.source_inputs, candidate)

    assert first == second
    assert oracle_calls == 1
    assert first.observation_graph_event == interrupted.event
    assert len(context.graph_store.event_log.events()) == 3
    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="current canonical head",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    context.result_path.write_bytes(context.result_path.read_bytes() + b" ")
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError):
        context.gate.admit(context.source_inputs, candidate)
    assert len(context.graph_store.event_log.events()) == 3


@pytest.mark.asyncio
async def test_intervening_graph_event_preserves_observation_and_blocks_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    observation = candidate.observation_proposal
    hypothesis = candidate.hypothesis_proposal
    expected_head = candidate.graph.snapshot.event_log_head_digest
    assert hypothesis is not None
    assert expected_head is not None
    context.graph_lineages.register(observation.lineage)
    observation_result = context.graph_admission.submit_if_current(
        observation,
        expected_event_log_head_digest=expected_head,
    )
    assert observation_result.event.decision is GraphAdmissionDecision.ADMITTED

    surface = context.preparation.surface
    intervening = SurfaceProposal(
        proposalId="proposal:surface:cryptographic-analysis-intervening",
        producerId="pajin.graph.cryptographic-analysis-admission-test",
        producerVersion="1.0.0",
        producerDigest=DIGEST_D,
        lineage=observation.lineage,
        surface=GraphSurface(
            campaignId=context.graph_store.campaign_id,
            targetId=surface.surface_id,
            surfaceType=surface.surface_type,
            locatorSchema=surface.locator_schema,
            locatorDigest=surface.surface_digest,
            origin=GraphContentOrigin.TRUSTED_CORE,
        ),
    )
    context.graph_admission.submit(intervening)
    assert len(context.graph_store.event_log.events()) == 3

    with pytest.raises(
        CryptographicMisuseAnalysisKnowledgeAdmissionError,
        match="bounded Hypothesis source is no longer the current Graph head",
    ):
        context.gate.admit(context.source_inputs, candidate)

    assert (
        context.graph_store.event_log.event_for_attempt(
            hypothesis.proposal_id,
            hypothesis.digest(),
        )
        is None
    )
    assert context.graph_store.event_log.events()[1] == observation_result.event


@pytest.mark.asyncio
async def test_candidate_rejects_authority_escalation_and_equivocation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    payload = candidate.model_dump(mode="json", by_alias=True)

    for alias in _CANDIDATE_FALSE_MARKERS:
        changed = deepcopy(payload)
        changed[alias] = True
        changed["candidateId"] = ""
        changed["candidateDigest"] = ""
        with pytest.raises(ValidationError):
            CryptographicMisuseAnalysisKnowledgeCandidate.model_validate(changed)

    forged = candidate.model_copy(
        update={"oracle_verdict_digest": "0" * 64},
        deep=True,
    )
    with pytest.raises(CryptographicMisuseAnalysisKnowledgeAdmissionError):
        context.gate.admit(context.source_inputs, forged)


@pytest.mark.asyncio
async def test_graph_store_subclass_is_rejected_at_gate_and_source_loader(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    subclass_store = _SQLiteGraphStoreSubclass(
        tmp_path / "subclass-graph.sqlite3",
        campaign_id=context.graph_store.campaign_id,
    )
    with pytest.raises(TypeError, match="exact SQLite Graph Store"):
        CryptographicMisuseAnalysisKnowledgeAdmissionGate(
            graph_store=subclass_store,
            graph_admission=context.graph_admission,
            trusted_lineages=context.graph_lineages,
            trust_anchor=context.trust_anchor,
        )
    with pytest.raises(TypeError, match="exact SQLite Graph Store"):
        load_verified_cryptographic_misuse_analysis_observation_source(
            context.source_inputs,
            graph_store=subclass_store,
            trust_anchor=context.trust_anchor,
        )


def test_producer_registration_allows_only_observation_and_hypothesis() -> None:
    registration = cryptographic_misuse_analysis_knowledge_producer_registration()

    assert registration.allowed_proposal_kinds == (
        GraphProposalKind.HYPOTHESIS,
        GraphProposalKind.OBSERVATION,
    )
    assert registration.producer_digest == (CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST)


def test_oracle_policy_rejects_caller_mapping_and_authority_drift() -> None:
    policy = registered_cryptographic_misuse_analysis_oracle_policy()
    payload = policy.model_dump(mode="json", by_alias=True)

    for field in (
        "callerDecisionAllowed",
        "artifactReadAllowed",
        "resultBodyReadAllowed",
        "keyMaterialAccessAllowed",
        "cryptographicOperationAllowed",
        "semanticTruthAuthority",
        "findingAuthority",
        "executionAuthorized",
    ):
        changed = deepcopy(payload)
        changed[field] = True
        changed["oracleDigest"] = ""
        with pytest.raises(ValidationError):
            CryptographicMisuseAnalysisOraclePolicy.model_validate(changed)

    changed = deepcopy(payload)
    changed["surfaceSignalMapping"] = list(reversed(changed["surfaceSignalMapping"]))
    changed["oracleDigest"] = ""
    with pytest.raises(ValidationError, match="differs from code authority"):
        CryptographicMisuseAnalysisOraclePolicy.model_validate(changed)


def test_output_schema_constant_remains_exact() -> None:
    assert CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA == (
        "pajin.cryptography.offline-misuse-analysis-result.v1"
    )
