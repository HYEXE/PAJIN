from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError
from test_mobile_package_analysis import (
    NOW,
    _activation,
    _campaign,
    _custody,
    _operation,
    _prepare,
    _sandbox,
    _surface,
)

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.mobile_package_analysis import (
    BoundedMobilePackageAnalyzerAdapter,
    MobilePackageAnalysisPreparation,
    MobilePackageAnalysisTool,
    MobilePackageParser,
    prepare_mobile_package_analysis,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery import MobilePlatform, MobileSurfaceClass
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
from pajin.workflow.mobile_package_analysis_admission import (
    MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
    MobileGraphAdmissionBinding,
    MobilePackageAnalysisExecutionAttestor,
    MobilePackageAnalysisExecutionKeyState,
    MobilePackageAnalysisExecutionStatement,
    MobilePackageAnalysisExecutionTrustAnchor,
    MobilePackageAnalysisExecutionVerificationKey,
    MobilePackageAnalysisKnowledgeAdmissionError,
    MobilePackageAnalysisKnowledgeAdmissionGate,
    MobilePackageAnalysisKnowledgeCandidate,
    MobilePackageAnalysisObservationSourceInputs,
    MobilePackageAnalysisResultReceipt,
    MobilePackageAnalysisReviewSignal,
    MobilePackageSandboxRuntimeReceipt,
    mobile_package_analysis_execution_bundle_bytes,
    mobile_package_analysis_execution_public_key,
    mobile_package_analysis_gateway_outcome_digest,
    mobile_package_analysis_knowledge_producer_registration,
    mobile_package_analysis_result_receipt_bytes,
)

RUN_ID = "run_20260827T120000Z_mobilecafe"
AUTHORITY_ID = "pajin.graph.mobile-package-analysis-knowledge-admission"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ATTESTATION_REFERENCE = "evidence/mobile-package-analysis-attestation.json"
RESULT_REFERENCE = "evidence/mobile-package-analysis-result-receipt.json"

_CANDIDATE_FALSE_MARKERS = (
    "graphAdmitted",
    "rawArtifactEmbedded",
    "rawAnalysisOutputEmbedded",
    "rawPackageEmbedded",
    "rawParserOutputEmbedded",
    "rawManifestEmbedded",
    "signingMaterialEmbedded",
    "rawSecurityConfigurationEmbedded",
    "deviceStateEmbedded",
    "credentialMaterialEmbedded",
    "packagePathEmbedded",
    "artifactFormatAuthority",
    "packageFormatAuthority",
    "manifestTruthAuthority",
    "applicationDeclarationTruthAuthority",
    "signingIdentityAuthority",
    "runtimeDeclarationTruthAuthority",
    "storageValueAuthority",
    "deeplinkReachabilityAuthority",
    "tlsEnforcementAuthority",
    "authenticationSafetyAuthority",
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
    "packageAccessAuthorized",
    "custodyAuthorizationAuthority",
    "sandboxInvocationAuthorized",
    "workerSelectionAuthorized",
    "workerJobMaterializationAuthorized",
    "domainWorkerProfileBound",
    "deviceBoundRuntimeProfileApplied",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "emulatorOrDeviceAccessAuthorized",
    "packageInstallationAuthorized",
    "applicationLaunchAuthorized",
    "instrumentationAuthorized",
    "dynamicTargetExecutionAuthorized",
    "debuggerAttachAuthorized",
    "storageReadAuthorized",
    "tlsInvocationAuthorized",
    "authenticationInvocationAuthorized",
    "credentialAccessAuthorized",
    "packageMutationAuthorized",
    "replayAuthorized",
    "findingConfirmationAuthorized",
    "executionAuthorized",
)

_TRUST_ANCHOR_FALSE_MARKERS = (
    "currentActivationBound",
    "campaignAuthorityBound",
    "approvalSatisfied",
    "permitBound",
    "artifactAccessAuthorized",
    "sandboxInvocationAuthorized",
    "domainWorkerProfileBound",
    "deviceBoundRuntimeProfileApplied",
    "packageAccessAuthorized",
    "workerJobMaterializationAuthorized",
    "graphAdmissionAuthorized",
    "executionAuthorized",
)

_RESULT_FALSE_MARKERS = (
    "rawResultEmbedded",
    "rawPackageEmbedded",
    "rawManifestEmbedded",
    "signingMaterialEmbedded",
    "rawSecurityConfigurationEmbedded",
    "deviceStateEmbedded",
    "credentialMaterialEmbedded",
    "packagePathEmbedded",
    "packageFormatAuthority",
    "manifestTruthAuthority",
    "signingIdentityAuthority",
    "applicationDeclarationTruthAuthority",
    "runtimeDeclarationTruthAuthority",
    "storageValueAuthority",
    "deeplinkReachabilityAuthority",
    "tlsEnforcementAuthority",
    "authenticationSafetyAuthority",
    "runtimeSupportAuthority",
    "vulnerabilityConfirmationAuthority",
    "findingConfirmationAuthority",
    "securityPropertyConfirmationAuthority",
    "domainWorkerProfileBound",
    "deviceBoundRuntimeProfileApplied",
    "workerJobMaterialized",
    "scopeExpansionAuthorized",
    "approvalAuthority",
    "permitIssuanceAuthorized",
    "custodyAuthorizationAuthority",
    "packageAccessAuthorized",
    "sandboxInvocationAuthorized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "emulatorOrDeviceAccessAuthorized",
    "packageInstallationAuthorized",
    "applicationLaunchAuthorized",
    "instrumentationAuthorized",
    "dynamicTargetExecutionAuthorized",
    "storageReadAuthorized",
    "tlsInvocationAuthorized",
    "authenticationInvocationAuthorized",
    "credentialAccessAuthorized",
    "packageMutationAuthorized",
    "replayAuthorized",
    "executionAuthority",
)

_RUNTIME_FALSE_MARKERS = (
    "rawIdentityMetadataEmbedded",
    "rawPackageEmbedded",
    "rawParserOutputEmbedded",
    "domainWorkerProfileBound",
    "deviceBoundRuntimeProfileApplied",
    "workerJobMaterialized",
    "scopeExpansionAuthorized",
    "approvalAuthority",
    "permitIssuanceAuthorized",
    "custodyAuthorizationAuthority",
    "packageAccessAuthorized",
    "sandboxInvocationAuthorized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "emulatorOrDeviceAccessAuthorized",
    "packageInstallationAuthorized",
    "applicationLaunchAuthorized",
    "instrumentationAuthorized",
    "dynamicTargetExecutionAuthorized",
    "debuggerAttachAuthorized",
    "hostFilesystemAccessAuthorized",
    "storageReadAuthorized",
    "tlsInvocationAuthorized",
    "authenticationInvocationAuthorized",
    "credentialAccessAuthorized",
    "packageMutationAuthorized",
    "replayAuthorized",
    "executionAuthority",
)

_STATEMENT_ZERO_BUDGETS = (
    "networkRequests",
    "dnsRequests",
    "emulatorSessions",
    "deviceSessions",
    "packageInstallations",
    "applicationLaunches",
    "instrumentationSessions",
    "dynamicTargetExecutions",
    "debuggerAttaches",
    "storageReads",
    "tlsConnections",
    "authenticationInvocations",
    "packageWriteOperations",
    "hostFilesystemReads",
    "credentialReads",
)

_STATEMENT_FALSE_MARKERS = (
    "rawParserOutputEmbedded",
    "newPackageAccessAuthorized",
    "newSandboxInvocationAuthorized",
    "newWorkerSelectionAuthorized",
    "newDomainWorkerProfileBindingAuthorized",
    "workerJobMaterializationAuthorized",
    "domainWorkerProfileBound",
    "deviceBoundRuntimeProfileApplied",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "emulatorOrDeviceAccessAuthorized",
    "packageInstallationAuthorized",
    "applicationLaunchAuthorized",
    "instrumentationAuthorized",
    "dynamicTargetExecutionAuthorized",
    "debuggerAttachAuthorized",
    "storageReadAuthorized",
    "tlsInvocationAuthorized",
    "authenticationInvocationAuthorized",
    "credentialAccessAuthorized",
    "packageMutationAuthorized",
    "replayAuthorized",
    "graphAdmissionAuthorized",
    "findingConfirmationAuthorized",
    "newExecutionAuthorized",
)

_NON_BOOLEAN_FALSE_MARKER_VALUES: tuple[object, ...] = (0, 1, "false")
_INVALID_TRUE_MARKER_VALUES: tuple[object, ...] = (False, 0, "true")


def _assert_false_markers_reject_values(
    model: type[BaseModel],
    payload: dict[str, object],
    aliases: tuple[str, ...],
    *,
    identity_fields: tuple[str, ...] = (),
) -> None:
    assert set(aliases).issubset(payload)
    for value in (True, *_NON_BOOLEAN_FALSE_MARKER_VALUES):
        changed = deepcopy(payload)
        changed.update(dict.fromkeys(aliases, value))
        changed.update(dict.fromkeys(identity_fields, ""))
        with pytest.raises(ValidationError) as caught:
            model.model_validate(changed)
        rejected_aliases = {str(error["loc"][0]) for error in caught.value.errors()}
        assert set(aliases).issubset(rejected_aliases)


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
            raise RuntimeError("external approval authority rejected the Mobile claim")


@dataclass
class _Context:
    preparation: MobilePackageAnalysisPreparation
    graph_store: SQLiteGraphStore
    graph_admission: GraphAdmissionAuthority
    graph_lineages: TrustedGraphLineageRegistry
    graph_binding: MobileGraphAdmissionBinding
    gate: MobilePackageAnalysisKnowledgeAdmissionGate
    source_inputs: MobilePackageAnalysisObservationSourceInputs
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor
    private_key: bytes
    attestation_path: Path
    result_path: Path


def _seed(label: str) -> bytes:
    return sha256(f"mobile-package-analysis-admission:{label}".encode()).digest()


def _graph_authority(
    tmp_path: Path,
    campaign_id: str,
    preparation: MobilePackageAnalysisPreparation,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    TrustedGraphLineageRegistry,
    MobileGraphAdmissionBinding,
    GraphDecision,
]:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=campaign_id)
    seed_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=RUN_ID,
        agentId="agent:mobile-surface-seed",
        taskId="task:mobile-surface-seed",
        requestId="tool_mobile_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:mobile-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.mobile.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/mobile-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=NOW,
    )
    surface = preparation.surface
    seed = SurfaceProposal(
        proposalId="proposal:surface:mobile-package-analysis-admission",
        producerId="pajin.graph.mobile-package-analysis-admission-test",
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
                    producerId="pajin.graph.mobile-package-analysis-admission-test",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                mobile_package_analysis_knowledge_producer_registration(),
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
        creator_id="pajin.graph.mobile-snapshot-authority",
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
        actorId="pajin.graph.mobile-planner",
        actorDigest=DIGEST_C,
        createdAt=NOW + timedelta(seconds=1),
    )
    binding = MobileGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return store, authority, lineages, binding, decision


def _trust_anchor(
    preparation: MobilePackageAnalysisPreparation,
) -> tuple[MobilePackageAnalysisExecutionTrustAnchor, bytes]:
    private_key = _seed("attestation")
    key = MobilePackageAnalysisExecutionVerificationKey(
        keyId="mobile-package-analysis.attestation",
        publicKeyBase64url=mobile_package_analysis_execution_public_key(private_key),
        state=MobilePackageAnalysisExecutionKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )
    return (
        MobilePackageAnalysisExecutionTrustAnchor(
            trustDomain="pajin.mobile-package-analysis-test",
            issuer="deployment.mobile-package-analysis-test",
            sandbox=preparation.sandbox,
            capability=preparation.binding.capability,
            capabilityRelease=preparation.release,
            keys=(key,),
        ),
        private_key,
    )


def test_trust_anchor_rejects_authority_escalation_and_false_marker_coercion(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    trust_anchor, _ = _trust_anchor(preparation)
    payload = trust_anchor.model_dump(mode="json", by_alias=True)
    _assert_false_markers_reject_values(
        MobilePackageAnalysisExecutionTrustAnchor,
        payload,
        _TRUST_ANCHOR_FALSE_MARKERS,
    )


def _default_review_signal(
    surface_class: MobileSurfaceClass,
) -> MobilePackageAnalysisReviewSignal:
    return {
        MobileSurfaceClass.APK: (MobilePackageAnalysisReviewSignal.APK_PACKAGE_STRUCTURE_REVIEW),
        MobileSurfaceClass.IPA: (MobilePackageAnalysisReviewSignal.IPA_PACKAGE_STRUCTURE_REVIEW),
        MobileSurfaceClass.APPLICATION: (
            MobilePackageAnalysisReviewSignal.APPLICATION_DECLARATION_REVIEW
        ),
        MobileSurfaceClass.RUNTIME: (MobilePackageAnalysisReviewSignal.RUNTIME_DECLARATION_REVIEW),
        MobileSurfaceClass.STORAGE: (MobilePackageAnalysisReviewSignal.STORAGE_DECLARATION_REVIEW),
        MobileSurfaceClass.DEEPLINK: (
            MobilePackageAnalysisReviewSignal.DEEP_LINK_DECLARATION_REVIEW
        ),
        MobileSurfaceClass.TLS: (MobilePackageAnalysisReviewSignal.TLS_POLICY_DECLARATION_REVIEW),
        MobileSurfaceClass.AUTH: (
            MobilePackageAnalysisReviewSignal.AUTHENTICATION_FLOW_DECLARATION_REVIEW
        ),
    }[surface_class]


def _runtime_receipt(
    preparation: MobilePackageAnalysisPreparation,
    *,
    attested_at: object,
    update: dict[str, object] | None = None,
) -> MobilePackageSandboxRuntimeReceipt:
    sandbox = preparation.sandbox
    custody = preparation.package_custody
    platform = (
        MobilePlatform.ANDROID
        if preparation.package_surface.surface_class is MobileSurfaceClass.APK
        else MobilePlatform.IOS
    )
    payload: dict[str, object] = {
        "sandboxBindingId": sandbox.sandbox_binding_id,
        "sandboxBindingDigest": sandbox.sandbox_binding_digest,
        "deploymentId": sandbox.deployment_id,
        "surface": preparation.surface.reference(),
        "packageSurface": preparation.package_surface.reference(),
        "operation": sandbox.operation,
        "platform": platform,
        "parser": sandbox.parser,
        "parserExecutableSHA256": sandbox.parser_executable_sha256,
        "sandboxImageSHA256": sandbox.sandbox_image_sha256,
        "runAsIdentity": sandbox.run_as_identity,
        "artifactMountTarget": sandbox.artifact_mount_target,
        "outputSchema": sandbox.output_schema,
        "outputTransport": sandbox.output_transport,
        "artifactSHA256": custody.artifact_sha256,
        "artifactBytes": custody.artifact_bytes,
        "custodyBindingId": custody.custody_binding_id,
        "custodyBindingDigest": custody.custody_binding_digest,
        "custodyAuthorityId": custody.custody_authority_id,
        "custodyObjectId": custody.custody_object_id,
        "authorizationId": custody.authorization_id,
        "authorizationDigest": custody.authorization_digest,
        "maxArtifactBytes": sandbox.max_artifact_bytes,
        "maxOutputBytes": sandbox.max_output_bytes,
        "maxRuntimeSeconds": sandbox.max_runtime_seconds,
        "maxMemoryMiB": sandbox.max_memory_mib,
        "maxProcessCount": sandbox.max_process_count,
        "maxArchiveEntries": sandbox.max_archive_entries,
        "maxTotalUncompressedBytes": sandbox.max_total_uncompressed_bytes,
        "maxSingleUncompressedBytes": sandbox.max_single_uncompressed_bytes,
        "maxArchivePathBytes": sandbox.max_archive_path_bytes,
        "maxArchiveNestingDepth": sandbox.max_archive_nesting_depth,
        "maxCompressionRatio": sandbox.max_compression_ratio,
        "observedArchiveEntries": 32,
        "observedTotalUncompressedBytes": 16_384,
        "observedLargestUncompressedBytes": 4_096,
        "observedMaxArchivePathBytes": 96,
        "observedArchiveNestingDepth": 2,
        "observedMaxCompressionRatio": 8,
        "runtimeIdentityDigest": sha256(b"mobile-runtime-identity").hexdigest(),
        "confinementDigest": sha256(b"mobile-runtime-confinement").hexdigest(),
        "attestedAt": attested_at,
    }
    if update:
        payload.update(update)
    return MobilePackageSandboxRuntimeReceipt.model_validate(payload)


async def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: MobileSurfaceClass = MobileSurfaceClass.APK,
    platform: MobilePlatform | None = None,
    review_signal: MobilePackageAnalysisReviewSignal | None | object = ...,
    result_size: int = 4_096,
    result_body: bytes = b"external-mobile-package-analysis-result",
    run_id: str = RUN_ID,
    request_id: str = "tool_mobile_package_analysis_observation",
    execution_id: str = "mobile-execution:static-sandbox-test",
    execution_offset: timedelta = timedelta(),
    runtime_update: dict[str, object] | None = None,
    result_update: dict[str, object] | None = None,
    statement_update: dict[str, object] | None = None,
) -> _Context:
    surface = _surface(surface_class, platform=platform)
    campaign = _campaign(sample_campaign, surface=surface)
    activation, release = _activation()
    operation = _operation(surface)
    custody = _custody(surface)
    sandbox = _sandbox(surface)
    preparation = prepare_mobile_package_analysis(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=surface,
        operation=operation,
        analyzer=BoundedMobilePackageAnalyzerAdapter(custody, sandbox),
        request_id=request_id,
        agent_id="agent:mobile-package-analysis",
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
        profileId="mobile-package-analysis-static-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.mobile.action-compiler",
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
        proposerId="pajin.graph.mobile-planner",
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
            authorityId="deployment:mobile-operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.mobile.ExternalApprovalAuthority",
            contextDigest=DIGEST_D,
        ),
        requestedBy="principal:mobile-requester",
        approvedBy="principal:mobile-approver",
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
    evidence_root = tmp_path / "external-mobile-package-source"
    evidence_directory = evidence_root / "evidence"
    evidence_directory.mkdir(parents=True)
    attestation_path = evidence_root / ATTESTATION_REFERENCE
    result_path = evidence_root / RESULT_REFERENCE
    selected_signal = (
        _default_review_signal(surface_class) if review_signal is ... else review_signal
    )
    selected_platform = (
        MobilePlatform.ANDROID
        if preparation.package_surface.surface_class is MobileSurfaceClass.APK
        else MobilePlatform.IOS
    )

    async def external_runtime_receipts(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> str:
        result_payload: dict[str, object] = {
            "executionId": execution_id,
            "requestId": permit.request_id,
            "requestDigest": permit.request_digest,
            "preparationId": preparation.preparation_id,
            "preparationDigest": preparation.preparation_digest,
            "operation": preparation.operation,
            "platform": selected_platform,
            "parser": sandbox.parser,
            "surface": preparation.surface.reference(),
            "packageSurface": preparation.package_surface.reference(),
            "artifactSHA256": custody.artifact_sha256,
            "resultBodySha256": sha256(result_body).hexdigest(),
            "resultBytes": result_size,
            "reviewSignal": selected_signal,
            "receivedAt": NOW + timedelta(seconds=8) + execution_offset,
        }
        if result_update:
            result_payload.update(result_update)
        result = MobilePackageAnalysisResultReceipt.model_validate(result_payload)
        result_content = mobile_package_analysis_result_receipt_bytes(result)
        result_path.write_bytes(result_content)
        started_at = NOW + timedelta(seconds=6) + execution_offset
        runtime = _runtime_receipt(
            preparation,
            attested_at=NOW + timedelta(seconds=7) + execution_offset,
            update=runtime_update,
        )
        gateway_decision = PolicyEngine().evaluate_tool_request(
            campaign,
            grant,
            prepared.request,
            MobilePackageAnalysisTool.spec,
            used_calls=0,
            now=started_at,
        )
        statement_payload: dict[str, object] = {
            "trustDomain": trust_anchor.trust_domain,
            "issuer": trust_anchor.issuer,
            "sandboxBindingId": sandbox.sandbox_binding_id,
            "sandboxBindingDigest": sandbox.sandbox_binding_digest,
            "deploymentId": sandbox.deployment_id,
            "gatewayPolicyDecision": gateway_decision,
            "gatewayOutcomeDigest": mobile_package_analysis_gateway_outcome_digest(
                policy_decision=gateway_decision,
                request_digest=permit.request_digest,
                permit_digest=permit.permit_digest,
                sandbox_runtime_receipt_digest=runtime.receipt_digest,
                result_receipt_digest=result.receipt_digest,
            ),
            "executionId": result.execution_id,
            "campaignId": campaign.metadata.name,
            "campaignDigest": campaign_manifest_digest(campaign),
            "runId": run_id,
            "preparationId": preparation.preparation_id,
            "preparationDigest": preparation.preparation_digest,
            "analysisRequest": preparation.analysis_request,
            "requestId": permit.request_id,
            "requestDigest": permit.request_digest,
            "normalizedParametersDigest": permit.normalized_parameters_digest,
            "actionPermitId": permit.permit_id,
            "actionPermitDigest": permit.permit_digest,
            "approvalReceiptId": receipt.receipt_id,
            "approvalReceiptDigest": receipt.receipt_digest,
            "sandboxRuntime": runtime,
            "resultReceiptReference": RESULT_REFERENCE,
            "resultReceiptSha256": sha256(result_content).hexdigest(),
            "resultReceiptId": result.receipt_id,
            "resultReceiptDigest": result.receipt_digest,
            "startedAt": started_at,
            "finishedAt": NOW + timedelta(seconds=8) + execution_offset,
            "issuedAt": NOW + timedelta(seconds=9) + execution_offset,
        }
        if statement_update:
            statement_payload.update(statement_update)
        statement = MobilePackageAnalysisExecutionStatement.model_validate(statement_payload)
        bundle = MobilePackageAnalysisExecutionAttestor.from_private_key_bytes(
            active_key_id=trust_anchor.keys[0].key_id,
            private_key=private_key,
            trust_anchor=trust_anchor,
        ).attest(statement)
        attestation_path.write_bytes(mobile_package_analysis_execution_bundle_bytes(bundle))
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
    inputs = MobilePackageAnalysisObservationSourceInputs(
        source_root=evidence_root,
        attestation_reference=ATTESTATION_REFERENCE,
        expected_run_id=run_id,
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
    )
    gate = MobilePackageAnalysisKnowledgeAdmissionGate(
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
    result = MobilePackageAnalysisResultReceipt.model_validate(result_payload)
    result_content = mobile_package_analysis_result_receipt_bytes(result)
    context.result_path.write_bytes(result_content)

    runtime_payload = deepcopy(statement_payload["sandboxRuntime"])
    if runtime_update:
        runtime_payload.update(runtime_update)
        runtime_payload["receiptId"] = ""
        runtime_payload["receiptDigest"] = ""
    runtime = MobilePackageSandboxRuntimeReceipt.model_validate(runtime_payload)
    permit = context.graph_store.permit_store.permits()[0]
    decision = PolicyDecision.model_validate(statement_payload["gatewayPolicyDecision"])
    statement_payload.update(
        {
            "sandboxRuntime": runtime.model_dump(mode="json", by_alias=True),
            "gatewayOutcomeDigest": mobile_package_analysis_gateway_outcome_digest(
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
    statement = MobilePackageAnalysisExecutionStatement.model_validate(statement_payload)
    bundle = MobilePackageAnalysisExecutionAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    ).attest(statement)
    context.attestation_path.write_bytes(mobile_package_analysis_execution_bundle_bytes(bundle))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("surface_class", "platform"),
    (
        (MobileSurfaceClass.APK, MobilePlatform.ANDROID),
        (MobileSurfaceClass.IPA, MobilePlatform.IOS),
        (MobileSurfaceClass.APPLICATION, MobilePlatform.ANDROID),
        (MobileSurfaceClass.APPLICATION, MobilePlatform.IOS),
        (MobileSurfaceClass.RUNTIME, MobilePlatform.ANDROID),
        (MobileSurfaceClass.RUNTIME, MobilePlatform.IOS),
        (MobileSurfaceClass.STORAGE, MobilePlatform.ANDROID),
        (MobileSurfaceClass.STORAGE, MobilePlatform.IOS),
        (MobileSurfaceClass.DEEPLINK, MobilePlatform.ANDROID),
        (MobileSurfaceClass.DEEPLINK, MobilePlatform.IOS),
        (MobileSurfaceClass.TLS, MobilePlatform.ANDROID),
        (MobileSurfaceClass.TLS, MobilePlatform.IOS),
        (MobileSurfaceClass.AUTH, MobilePlatform.ANDROID),
        (MobileSurfaceClass.AUTH, MobilePlatform.IOS),
    ),
)
async def test_sealed_mobile_result_admits_only_neutral_knowledge(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: MobileSurfaceClass,
    platform: MobilePlatform,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        platform=platform,
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    observation_event = admission.observation_graph_event
    hypothesis_event = admission.hypothesis_graph_event
    payload = candidate.model_dump(mode="json", by_alias=True)

    assert candidate.surface == context.preparation.surface.reference()
    assert candidate.package_surface == context.preparation.package_surface.reference()
    assert candidate.operation is context.preparation.operation
    assert candidate.platform is (
        MobilePlatform.ANDROID
        if context.preparation.package_surface.surface_class is MobileSurfaceClass.APK
        else MobilePlatform.IOS
    )
    assert candidate.parser is context.preparation.sandbox.parser
    assert candidate.observation_proposal.observation.observation_type == (
        "mobile.analysis-observation"
    )
    assert candidate.hypothesis_proposal is not None
    assert candidate.hypothesis_proposal.hypothesis.hypothesis_type == ("mobile.security-property")
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
    assert payload["domainWorkerProfileBindingDeferred"] is True
    assert payload["exactSurfaceAndPackageBound"] is True
    assert payload["externalStaticSandboxVerified"] is True
    assert all(payload[alias] is False for alias in _CANDIDATE_FALSE_MARKERS)

    graph_text = json.dumps(
        {
            "observation": observation_event.model_dump(mode="json", by_alias=True),
            "hypothesis": hypothesis_event.model_dump(mode="json", by_alias=True),
        },
        sort_keys=True,
    )
    assert "external-mobile-package-analysis-result" not in graph_text
    assert "/pajin/input/package" not in graph_text


@pytest.mark.asyncio
async def test_signal_free_receipt_admits_no_hypothesis(
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
async def test_mobile_knowledge_exact_retry_is_idempotent(
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

    with pytest.raises(MobilePackageAnalysisKnowledgeAdmissionError, match="signature"):
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
        MobilePackageAnalysisKnowledgeAdmissionError,
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
    foreign_inputs = replace(
        context.source_inputs,
        expected_run_id="run_20260827T120000Z_foreign",
    )

    with pytest.raises(MobilePackageAnalysisKnowledgeAdmissionError, match="ActionPermit"):
        context.gate.prepare_candidate(foreign_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_statement_cannot_substitute_permit_digest(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        statement_update={"actionPermitDigest": "0" * 64},
    )

    with pytest.raises(
        MobilePackageAnalysisKnowledgeAdmissionError,
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
        MobilePackageAnalysisKnowledgeAdmissionError,
        match="differs from current authority",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_runtime_cannot_substitute_surface_package_parser_or_archive_binding(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=MobileSurfaceClass.APPLICATION,
        platform=MobilePlatform.ANDROID,
    )
    original_attestation = context.attestation_path.read_bytes()
    original_result = context.result_path.read_bytes()
    foreign_surface = _surface(
        MobileSurfaceClass.APPLICATION,
        platform=MobilePlatform.ANDROID,
        variant="foreign",
    )
    foreign_package = _surface(MobileSurfaceClass.IPA)
    sandbox = context.preparation.sandbox
    substitutions: tuple[dict[str, object], ...] = (
        {"surface": foreign_surface.reference()},
        {"packageSurface": foreign_package.reference()},
        {"parser": MobilePackageParser.IOS_IPA_STRUCTURE},
        {"artifactSHA256": "0" * 64},
        {"maxArchiveEntries": sandbox.max_archive_entries + 1},
        {"maxCompressionRatio": sandbox.max_compression_ratio + 1},
    )

    for update in substitutions:
        context.attestation_path.write_bytes(original_attestation)
        context.result_path.write_bytes(original_result)
        _resign_source(context, runtime_update=update)
        with pytest.raises(
            MobilePackageAnalysisKnowledgeAdmissionError,
            match="differs from current authority",
        ):
            context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


@pytest.mark.asyncio
async def test_signed_result_cannot_substitute_selected_or_root_package_surface(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=MobileSurfaceClass.APPLICATION,
        platform=MobilePlatform.ANDROID,
    )
    original_attestation = context.attestation_path.read_bytes()
    original_result = context.result_path.read_bytes()
    foreign_surface = _surface(
        MobileSurfaceClass.APPLICATION,
        platform=MobilePlatform.ANDROID,
        variant="foreign-result",
    )
    foreign_package = _surface(MobileSurfaceClass.IPA)
    substitutions: tuple[dict[str, object], ...] = (
        {"surface": foreign_surface.reference()},
        {
            "packageSurface": foreign_package.reference(),
            "parser": MobilePackageParser.IOS_IPA_STRUCTURE,
        },
        {"artifactSHA256": "0" * 64},
    )

    for update in substitutions:
        context.attestation_path.write_bytes(original_attestation)
        context.result_path.write_bytes(original_result)
        _resign_source(context, result_update=update)
        with pytest.raises(
            MobilePackageAnalysisKnowledgeAdmissionError,
            match="differs from current authority",
        ):
            context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


def test_runtime_receipt_rejects_archive_ceiling_overrun_and_profile_authority(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    sandbox = preparation.sandbox

    invalid_updates: tuple[dict[str, object], ...] = (
        {"observedArchiveEntries": sandbox.max_archive_entries + 1},
        {"observedTotalUncompressedBytes": (sandbox.max_total_uncompressed_bytes + 1)},
        {"observedLargestUncompressedBytes": (sandbox.max_single_uncompressed_bytes + 1)},
        {"observedMaxArchivePathBytes": sandbox.max_archive_path_bytes + 1},
        {"observedArchiveNestingDepth": sandbox.max_archive_nesting_depth + 1},
        {"observedMaxCompressionRatio": sandbox.max_compression_ratio + 1},
        {"domainWorkerProfileBound": True},
        {"deviceBoundRuntimeProfileApplied": True},
        {"workerJobMaterialized": True},
    )
    for update in invalid_updates:
        with pytest.raises(ValidationError):
            _runtime_receipt(preparation, attested_at=NOW, update=update)


@pytest.mark.asyncio
async def test_models_reject_zero_budget_authority_escalation_and_unknown_instance_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    attestation = json.loads(context.attestation_path.read_text(encoding="utf-8"))
    statement_payload = attestation["statement"]

    for alias in _STATEMENT_ZERO_BUDGETS:
        changed = deepcopy(statement_payload)
        changed[alias] = 1
        with pytest.raises(ValidationError):
            MobilePackageAnalysisExecutionStatement.model_validate(changed)

    _assert_false_markers_reject_values(
        MobilePackageAnalysisExecutionStatement,
        statement_payload,
        _STATEMENT_FALSE_MARKERS,
    )

    for value in _INVALID_TRUE_MARKER_VALUES:
        changed = deepcopy(statement_payload)
        changed["externalStaticSandboxVerified"] = value
        with pytest.raises(ValidationError):
            MobilePackageAnalysisExecutionStatement.model_validate(changed)

    for alias, values in (
        ("requestCount", (True, 1.0, "1")),
        ("packageReads", (True, 1.0, "1")),
        ("networkRequests", (False, 0.0, "0")),
        ("dnsRequests", (False, 0.0, "0")),
    ):
        for value in values:
            changed = deepcopy(statement_payload)
            changed[alias] = value
            with pytest.raises(ValidationError, match="budget values"):
                MobilePackageAnalysisExecutionStatement.model_validate(changed)

    runtime_payload = statement_payload["sandboxRuntime"]
    _assert_false_markers_reject_values(
        MobilePackageSandboxRuntimeReceipt,
        runtime_payload,
        _RUNTIME_FALSE_MARKERS,
        identity_fields=("receiptId", "receiptDigest"),
    )

    for value in _INVALID_TRUE_MARKER_VALUES:
        changed = deepcopy(runtime_payload)
        changed["externalStaticSandboxVerified"] = value
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError):
            MobilePackageSandboxRuntimeReceipt.model_validate(changed)

    result_payload = json.loads(context.result_path.read_text(encoding="utf-8"))
    _assert_false_markers_reject_values(
        MobilePackageAnalysisResultReceipt,
        result_payload,
        _RESULT_FALSE_MARKERS,
        identity_fields=("receiptId", "receiptDigest"),
    )

    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    candidate_payload = candidate.model_dump(mode="json", by_alias=True)
    _assert_false_markers_reject_values(
        MobilePackageAnalysisKnowledgeCandidate,
        candidate_payload,
        _CANDIDATE_FALSE_MARKERS,
        identity_fields=("candidateId", "candidateDigest"),
    )

    for value in _INVALID_TRUE_MARKER_VALUES:
        changed = deepcopy(candidate_payload)
        changed["sealedSourceVerified"] = value
        changed["candidateId"] = ""
        changed["candidateDigest"] = ""
        with pytest.raises(ValidationError):
            MobilePackageAnalysisKnowledgeCandidate.model_validate(changed)

    forged_candidate = candidate.model_copy(update={"unmodeledAuthority": True})
    with pytest.raises(
        MobilePackageAnalysisKnowledgeAdmissionError,
        match="unmodeled instance state",
    ):
        context.gate.admit(context.source_inputs, forged_candidate)

    forged_preparation = context.preparation.model_copy(update={"unmodeledAuthority": True})
    forged_inputs = replace(context.source_inputs, preparation=forged_preparation)
    with pytest.raises(
        MobilePackageAnalysisKnowledgeAdmissionError,
        match="unmodeled instance state",
    ):
        context.gate.prepare_candidate(forged_inputs, context.graph_binding)

    canonical_statement = MobilePackageAnalysisExecutionStatement.model_validate(statement_payload)
    forged_statement = canonical_statement.model_copy(update={"unmodeledAuthority": True})
    attestor = MobilePackageAnalysisExecutionAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    )
    with pytest.raises(
        MobilePackageAnalysisKnowledgeAdmissionError,
        match="unmodeled instance state",
    ):
        attestor.attest(forged_statement)


@pytest.mark.asyncio
async def test_review_signal_cannot_escape_exact_surface_class(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.result_path.read_text(encoding="utf-8"))
    payload["reviewSignal"] = MobilePackageAnalysisReviewSignal.RUNTIME_DECLARATION_REVIEW.value
    payload["receiptId"] = ""
    payload["receiptDigest"] = ""

    with pytest.raises(ValidationError, match="review signal"):
        MobilePackageAnalysisResultReceipt.model_validate(payload)


@pytest.mark.asyncio
async def test_current_campaign_selected_and_root_scope_drift_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=MobileSurfaceClass.APPLICATION,
    )
    campaign_payload = context.source_inputs.campaign.model_dump(mode="json", by_alias=True)
    campaign_payload["spec"]["scope"]["allow"] = ["https://unrelated.example.test/"]
    changed_campaign = CampaignManifest.model_validate(campaign_payload)
    changed_inputs = replace(context.source_inputs, campaign=changed_campaign)

    with pytest.raises(
        MobilePackageAnalysisKnowledgeAdmissionError,
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
        MobilePackageAnalysisKnowledgeAdmissionError,
        match="current canonical head",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)


def test_producer_registration_allows_only_observation_and_hypothesis() -> None:
    registration = mobile_package_analysis_knowledge_producer_registration()

    assert registration.allowed_proposal_kinds == (
        GraphProposalKind.HYPOTHESIS,
        GraphProposalKind.OBSERVATION,
    )
    assert registration.producer_digest == (MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST)
