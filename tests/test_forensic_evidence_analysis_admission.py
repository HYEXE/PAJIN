from __future__ import annotations

import json
import os
import socket
from copy import deepcopy
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal, get_args, get_origin

import pytest
from pydantic import BaseModel, ValidationError
from test_forensic_evidence_analysis import (
    _INPUT_KIND_BY_CLASS,
    _OPERATION_BY_CLASS,
    NOW,
    PARSER_CONFIGURATION_DIGEST,
    PARSER_EXECUTABLE_DIGEST,
    SANDBOX_IMAGE_DIGEST,
    _activation,
    _adapter,
    _campaign,
    _prepare,
    _surface,
)

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.forensic_evidence_analysis import (
    FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
    FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY,
    FORENSIC_EVIDENCE_MOUNT_TARGET,
    FORENSIC_PARSER_WORK_UNIT,
    ForensicEvidenceAnalysisPreparation,
    ForensicEvidenceAnalysisTool,
    ForensicEvidenceSignalKind,
    prepare_forensic_evidence_analysis,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery import ForensicSurfaceClass
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
from pajin.workflow.forensic_evidence_analysis_admission import (
    ForensicEvidenceAnalysisAdmissionOraclePolicy,
    ForensicEvidenceAnalysisAdmissionOracleVerdict,
    ForensicEvidenceAnalysisExecutionAttestor,
    ForensicEvidenceAnalysisExecutionKeyState,
    ForensicEvidenceAnalysisExecutionStatement,
    ForensicEvidenceAnalysisExecutionTrustAnchor,
    ForensicEvidenceAnalysisExecutionVerificationKey,
    ForensicEvidenceAnalysisKnowledgeAdmission,
    ForensicEvidenceAnalysisKnowledgeAdmissionError,
    ForensicEvidenceAnalysisKnowledgeAdmissionGate,
    ForensicEvidenceAnalysisKnowledgeCandidate,
    ForensicEvidenceAnalysisObservationSourceInputs,
    ForensicEvidenceAnalysisOracleDisposition,
    ForensicEvidenceAnalysisResultDisposition,
    ForensicEvidenceAnalysisResultReceipt,
    ForensicEvidenceAnalysisSandboxRuntimeReceipt,
    ForensicEvidenceSourceMembershipAttestation,
    ForensicEvidenceSourceMembershipAttestor,
    ForensicEvidenceSourceMembershipBundle,
    ForensicEvidenceSourceMembershipKeyState,
    ForensicEvidenceSourceMembershipTrustAnchor,
    ForensicEvidenceSourceMembershipVerificationKey,
    ForensicEvidenceSourceState,
    ForensicGraphAdmissionBinding,
    forensic_evidence_analysis_execution_bundle_bytes,
    forensic_evidence_analysis_execution_bundle_reference,
    forensic_evidence_analysis_execution_public_key,
    forensic_evidence_analysis_gateway_outcome_digest,
    forensic_evidence_analysis_knowledge_producer_registration,
    forensic_evidence_analysis_result_receipt_bytes,
    forensic_evidence_analysis_result_receipt_reference,
    forensic_evidence_analysis_source_root_digest,
    forensic_evidence_source_membership_public_key,
    load_verified_forensic_evidence_analysis_observation_source,
    recompute_forensic_evidence_analysis_oracle_verdict,
    registered_forensic_evidence_analysis_oracle_policy,
    verify_forensic_evidence_source_membership_bundle,
)

RUN_ID = "run_20260828T120000Z_forensicscafe"
AUTHORITY_ID = "pajin.graph.forensic-evidence-analysis-knowledge-admission"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ATTESTATION_ALIAS_REFERENCE = "evidence/forensic-analysis-attestation-alias.json"
RESULT_ALIAS_REFERENCE = "evidence/forensic-analysis-result-receipt-alias.json"

_SIGNAL_BY_CLASS = {
    ForensicSurfaceClass.DISK: ForensicEvidenceSignalKind.DISK_EVIDENCE,
    ForensicSurfaceClass.MEMORY: ForensicEvidenceSignalKind.MEMORY_EVIDENCE,
    ForensicSurfaceClass.LOG: ForensicEvidenceSignalKind.LOG_EVIDENCE,
    ForensicSurfaceClass.ARTIFACT: ForensicEvidenceSignalKind.ARTIFACT_EVIDENCE,
}

_NON_BOOLEAN_FALSE_MARKER_VALUES: tuple[object, ...] = (0, 1, "false")
_INVALID_TRUE_MARKER_VALUES: tuple[object, ...] = (False, 0, "true")

_SOURCE_ANCHOR_TRUE_MARKERS = ("deploymentOwned", "verificationOnly")
_SOURCE_ANCHOR_FALSE_MARKERS = (
    "currentActivationBound",
    "campaignAuthorityBound",
    "sourceAccessAuthorized",
    "sourceMountAuthorized",
    "sourceCopyAuthorized",
    "custodyAuthorizationAuthority",
    "mutationAuthorized",
    "graphAdmissionAuthorized",
    "executionAuthorized",
)
_EXECUTION_ANCHOR_TRUE_MARKERS = ("deploymentOwned", "verificationOnly")
_EXECUTION_ANCHOR_FALSE_MARKERS = (
    "sourceMembershipAuthority",
    "currentActivationBound",
    "campaignAuthorityBound",
    "approvalSatisfied",
    "permitBound",
    "sourceAccessAuthorized",
    "sandboxInvocationAuthorized",
    "graphAdmissionAuthorized",
    "executionAuthorized",
)
_MEMBERSHIP_FALSE_MARKERS = (
    "sourceTruthAuthority",
    "provenanceTruthAuthority",
    "custodyTruthAuthority",
    "sourceAccessAuthorized",
    "sourceMutationAuthorized",
    "graphAdmissionAuthorized",
    "executionAuthorized",
)
_MEMBERSHIP_TRUE_MARKERS = (
    "membershipAttested",
    "sourceRootAttested",
    "artifactRecordAttested",
    "provenanceRecordAttested",
    "custodyCoordinatesAttested",
    "artifactDigestAndSizeAttested",
    "provenancePreservedAttested",
    "noMutationAttested",
)
_RUNTIME_TRUE_MARKERS = (
    "sourceMembershipChecked",
    "custodyCoordinatesChecked",
    "parserExecutableChecked",
    "parserConfigurationChecked",
    "sandboxImageChecked",
    "exactWorkerProfileChecked",
    "exactSurfaceChecked",
    "exactRuleSetChecked",
    "exactParserChecked",
    "exactMountChecked",
    "nonRootChecked",
    "networkDisabledChecked",
    "dnsDisabledChecked",
    "coreDumpDisabledChecked",
    "readOnlyRootChecked",
    "readOnlyEvidenceMountChecked",
    "evidenceMountNoexecChecked",
    "noNewPrivilegesChecked",
    "confinementChecked",
    "resourceLimitsChecked",
    "provenancePreservedAttested",
    "noMutationAttested",
)
_RUNTIME_ZERO_COUNTERS = (
    "sourceWriteOperations",
    "sourceCopyOperations",
    "evidenceMutationOperations",
    "sourceRootWriteOperations",
    "artifactWriteOperations",
    "artifactCopyOperations",
    "custodyRecordWriteOperations",
    "provenanceRecordWriteOperations",
    "networkRequests",
    "dnsQueries",
    "hostFilesystemReads",
    "credentialReads",
    "credentialUses",
    "secretMaterialReads",
    "deviceSessions",
    "pluginLoads",
    "lateralMovementAttempts",
    "targetProcessExecutions",
    "shellCommands",
)
_RUNTIME_FALSE_MARKERS = (
    "rawSourceEmbedded",
    "rawParserOutputEmbedded",
    "sourcePathEmbedded",
    "identityMaterialEmbedded",
    "secretMaterialEmbedded",
    "credentialMaterialEmbedded",
    "sourceTruthAuthority",
    "sourceAccessAuthorized",
    "sandboxInvocationAuthorized",
    "networkAccessAuthorized",
    "sourceMutationAuthorized",
    "artifactMutationAuthorized",
    "executionAuthority",
)
_RESULT_TRUE_MARKERS = ("completed", "digestOnly")
_RESULT_FALSE_MARKERS = (
    "rawSourceEmbedded",
    "rawResultEmbedded",
    "rawProvenanceEmbedded",
    "sourcePathEmbedded",
    "identityMaterialEmbedded",
    "secretMaterialEmbedded",
    "credentialMaterialEmbedded",
    "sourceTruthAuthority",
    "provenanceTruthAuthority",
    "semanticTruthAuthority",
    "evidenceClassVerified",
    "sourceFormatVerified",
    "parserCorrectnessEstablished",
    "negativeSecurityClaim",
    "findingConfirmationAuthority",
    "executionAuthority",
)
_STATEMENT_TRUE_MARKERS = (
    "gatewayPolicyReentered",
    "consumedPermitVerified",
    "approvalReceiptVerified",
    "exactPreparationBound",
    "sourceMembershipAttestationAuthenticated",
    "exactSourceStateBound",
    "offlineSandboxVerified",
    "resultSealed",
)
_STATEMENT_ZERO_COUNTERS = (
    "networkRequests",
    "dnsQueries",
    "hostFilesystemReads",
    "sourceWriteOperations",
    "sourceCopyOperations",
    "evidenceMutationOperations",
    "credentialReads",
    "credentialUses",
    "secretMaterialReads",
    "deviceSessions",
    "pluginLoads",
    "lateralMovementAttempts",
    "targetProcessExecutions",
    "shellCommands",
)
_STATEMENT_FALSE_MARKERS = (
    "independentSourceTruthEstablished",
    "rawSourceEmbedded",
    "rawResultEmbedded",
    "rawProvenanceEmbedded",
    "sourcePathEmbedded",
    "identityMaterialEmbedded",
    "secretMaterialEmbedded",
    "credentialMaterialEmbedded",
    "newSourceAccessAuthorized",
    "newSandboxInvocationAuthorized",
    "newWorkerSelectionAuthorized",
    "networkAccessAuthorized",
    "sourceMutationAuthorized",
    "artifactMutationAuthorized",
    "replayAuthorized",
    "graphAdmissionAuthorized",
    "findingConfirmationAuthorized",
    "newExecutionAuthorized",
)
_CANDIDATE_FALSE_MARKERS = (
    "rawSourceEmbedded",
    "rawResultEmbedded",
    "rawProvenanceEmbedded",
    "sourcePathEmbedded",
    "identityMaterialEmbedded",
    "secretMaterialEmbedded",
    "credentialMaterialEmbedded",
    "sourceTruthAuthority",
    "provenanceTruthAuthority",
    "custodyTruthAuthority",
    "semanticTruthAuthority",
    "evidenceClassVerified",
    "sourceFormatVerified",
    "parserCorrectnessEstablished",
    "negativeSecurityClaim",
    "findingProductionAuthorized",
    "hypothesisConfirmationAuthority",
    "sourceMutationAuthorized",
    "sourceMountAuthorized",
    "sourceCopyAuthorized",
    "artifactMutationAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalAuthority",
    "permitIssuanceAuthorized",
    "sourceAccessAuthorized",
    "custodyAuthorizationAuthority",
    "sandboxInvocationAuthorized",
    "parserInvocationAuthorized",
    "workerJobMaterializationAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "credentialUseAuthorized",
    "secretMaterialAccessAuthorized",
    "deviceAccessAuthorized",
    "pluginLoadingAuthorized",
    "lateralMovementAuthorized",
    "targetExecutionAuthorized",
    "shellCommandAuthorized",
    "graphAdmissionAuthorized",
    "replayAuthorized",
    "findingConfirmationAuthorized",
    "executionAuthorized",
    "independentSourceTruthEstablished",
    "graphAdmitted",
)
_CANDIDATE_TRUE_MARKERS = (
    "sealedSourceAssertionAuthenticated",
    "sourceMembershipAttestationAuthenticated",
    "executionAttestationAuthenticated",
    "consumedPermitVerified",
    "approvalReceiptVerified",
    "structuralOracleRecomputed",
    "neutralObservationProduced",
    "evidenceSealed",
)
_ADMISSION_FALSE_MARKERS = tuple(
    alias for alias in _CANDIDATE_FALSE_MARKERS if alias != "graphAdmitted"
)
_ADMISSION_TRUE_MARKERS = (
    "sealedSourceAssertionAuthenticated",
    "neutralObservationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "graphSingleWriterReused",
)
_ORACLE_POLICY_TRUE_MARKERS = ("structuralOnly", "digestDeclaredOnly")
_ORACLE_POLICY_FALSE_MARKERS = (
    "callerSignalAccepted",
    "sourceReadAuthorized",
    "resultBodyReadAuthorized",
    "keyMaterialAccessAuthorized",
    "cryptographicValidationAuthority",
    "semanticTruthAuthority",
    "findingProductionAuthorized",
    "executionAuthorized",
)
_ORACLE_VERDICT_TRUE_MARKERS = ("structurallyConsistent", "digestDeclaredOnly")
_ORACLE_VERDICT_FALSE_MARKERS = (
    "sourceReadPerformed",
    "resultBodyReadPerformed",
    "keyMaterialReadPerformed",
    "cryptographicValidationPerformed",
    "semanticTruthEstablished",
    "evidenceClassVerified",
    "sourceFormatVerified",
    "parserCorrectnessEstablished",
    "negativeSecurityClaim",
    "findingProduced",
    "executionAuthorized",
)


def _literal_marker_aliases(
    model: type[BaseModel],
    expected: bool,
) -> set[str]:
    aliases: set[str] = set()
    for name, field in model.model_fields.items():
        arguments = get_args(field.annotation)
        if (
            get_origin(field.annotation) is Literal
            and len(arguments) == 1
            and arguments[0] is expected
        ):
            aliases.add(field.alias or name)
    return aliases


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


def _assert_true_markers_reject_values(
    model: type[BaseModel],
    payload: dict[str, object],
    aliases: tuple[str, ...],
    *,
    identity_fields: tuple[str, ...] = (),
) -> None:
    assert set(aliases).issubset(payload)
    for value in _INVALID_TRUE_MARKER_VALUES:
        changed = deepcopy(payload)
        changed.update(dict.fromkeys(aliases, value))
        changed.update(dict.fromkeys(identity_fields, ""))
        with pytest.raises(ValidationError) as caught:
            model.model_validate(changed)
        rejected_aliases = {str(error["loc"][0]) for error in caught.value.errors()}
        assert set(aliases).issubset(rejected_aliases)


def _seed(label: str) -> bytes:
    return sha256(f"forensic-evidence-analysis-admission:{label}".encode()).digest()


def _source_state(
    preparation: ForensicEvidenceAnalysisPreparation,
    *,
    update: dict[str, object] | None = None,
) -> ForensicEvidenceSourceState:
    provenance = preparation.surface.locator.provenance
    custody = preparation.artifact_custody
    payload: dict[str, object] = {
        "sourceRootKind": provenance.source_root_kind,
        "sourceRootSHA256": provenance.source_root_sha256,
        "sourceArtifactRecordSHA256": provenance.source_artifact_record_sha256,
        "provenanceRecordSHA256": provenance.provenance_record_sha256,
        "artifactSHA256": provenance.artifact_sha256,
        "artifactBytes": provenance.artifact_bytes,
        "custodyBindingId": custody.custody_binding_id,
        "custodyBindingDigest": custody.custody_binding_digest,
        "custodyAuthorityId": custody.custody_authority_id,
        "custodyObjectId": custody.custody_object_id,
        "authorizationId": custody.authorization_id,
        "authorizationDigest": custody.authorization_digest,
        "immutableObjectVersion": "forensic-source-version:1",
    }
    if update:
        payload.update(update)
    return ForensicEvidenceSourceState.model_validate(payload)


def _source_trust_anchor(
    preparation: ForensicEvidenceAnalysisPreparation,
    *,
    signing_seed: str = "source-membership",
    key_id: str = "forensic-source.membership",
    state: ForensicEvidenceSourceMembershipKeyState = (
        ForensicEvidenceSourceMembershipKeyState.ACTIVE
    ),
    not_before_offset: timedelta = -timedelta(days=1),
    not_after_offset: timedelta | None = timedelta(days=1),
    revoked_at: datetime | None = None,
) -> tuple[ForensicEvidenceSourceMembershipTrustAnchor, bytes]:
    private_key = _seed(signing_seed)
    provenance = preparation.surface.locator.provenance
    key = ForensicEvidenceSourceMembershipVerificationKey(
        keyId=key_id,
        publicKeyBase64url=forensic_evidence_source_membership_public_key(private_key),
        state=state,
        notBefore=NOW + not_before_offset,
        notAfter=(NOW + not_after_offset if not_after_offset is not None else None),
        revokedAt=revoked_at,
    )
    return (
        ForensicEvidenceSourceMembershipTrustAnchor(
            trustDomain="pajin.forensic-source-membership-test",
            issuer="deployment.forensic-source-membership-test",
            surface=preparation.surface,
            sourceRootKind=provenance.source_root_kind,
            sourceRootSHA256=provenance.source_root_sha256,
            sourceArtifactRecordSHA256=provenance.source_artifact_record_sha256,
            provenanceRecordSHA256=provenance.provenance_record_sha256,
            artifactCustody=preparation.artifact_custody,
            immutableObjectVersion="forensic-source-version:1",
            keys=(key,),
        ),
        private_key,
    )


def _source_membership_bundle(
    preparation: ForensicEvidenceAnalysisPreparation,
    trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    private_key: bytes,
    *,
    pre_state_update: dict[str, object] | None = None,
    post_state_update: dict[str, object] | None = None,
    attestation_update: dict[str, object] | None = None,
) -> ForensicEvidenceSourceMembershipBundle:
    provenance = preparation.surface.locator.provenance
    custody = preparation.artifact_custody
    payload: dict[str, object] = {
        "trustDomain": trust_anchor.trust_domain,
        "issuer": trust_anchor.issuer,
        "surface": preparation.surface,
        "sourceRootKind": provenance.source_root_kind,
        "sourceRootSHA256": provenance.source_root_sha256,
        "sourceArtifactRecordSHA256": provenance.source_artifact_record_sha256,
        "provenanceRecordSHA256": provenance.provenance_record_sha256,
        "artifactSHA256": provenance.artifact_sha256,
        "artifactBytes": provenance.artifact_bytes,
        "custodyBindingId": custody.custody_binding_id,
        "custodyBindingDigest": custody.custody_binding_digest,
        "custodyAuthorityId": custody.custody_authority_id,
        "custodyObjectId": custody.custody_object_id,
        "authorizationId": custody.authorization_id,
        "authorizationDigest": custody.authorization_digest,
        "immutableObjectVersion": trust_anchor.immutable_object_version,
        "preState": _source_state(preparation, update=pre_state_update),
        "postState": _source_state(preparation, update=post_state_update),
        "validFrom": NOW - timedelta(minutes=1),
        "validUntil": NOW + timedelta(minutes=5),
        "attestedAt": NOW + timedelta(milliseconds=8_500),
    }
    if attestation_update:
        payload.update(attestation_update)
    attestation = ForensicEvidenceSourceMembershipAttestation.model_validate(payload)
    return ForensicEvidenceSourceMembershipAttestor.from_private_key_bytes(
        active_key_id=trust_anchor.keys[0].key_id,
        private_key=private_key,
        trust_anchor=trust_anchor,
    ).attest(attestation)


def _execution_trust_anchor(
    preparation: ForensicEvidenceAnalysisPreparation,
    *,
    signing_seed: str = "execution-attestation",
    key_id: str = "forensic-analysis.execution",
    state: ForensicEvidenceAnalysisExecutionKeyState = (
        ForensicEvidenceAnalysisExecutionKeyState.ACTIVE
    ),
    not_before_offset: timedelta = -timedelta(days=1),
    not_after_offset: timedelta | None = timedelta(days=1),
    revoked_at: datetime | None = None,
) -> tuple[ForensicEvidenceAnalysisExecutionTrustAnchor, bytes]:
    private_key = _seed(signing_seed)
    key = ForensicEvidenceAnalysisExecutionVerificationKey(
        keyId=key_id,
        publicKeyBase64url=forensic_evidence_analysis_execution_public_key(private_key),
        state=state,
        notBefore=NOW + not_before_offset,
        notAfter=(NOW + not_after_offset if not_after_offset is not None else None),
        revokedAt=revoked_at,
    )
    return (
        ForensicEvidenceAnalysisExecutionTrustAnchor(
            trustDomain="pajin.forensic-analysis-execution-test",
            issuer="deployment.forensic-analysis-execution-test",
            sandbox=preparation.sandbox,
            capability=preparation.binding.capability,
            capabilityRelease=preparation.release,
            keys=(key,),
        ),
        private_key,
    )


def _result_receipt(
    preparation: ForensicEvidenceAnalysisPreparation,
    *,
    execution_id: str = "forensic-execution:sandbox-test",
    result_disposition: ForensicEvidenceAnalysisResultDisposition = (
        ForensicEvidenceAnalysisResultDisposition.REVIEW
    ),
    result_size: int = 4_096,
    result_body: bytes = b"external-forensic-analysis-result",
    received_at: datetime = NOW + timedelta(seconds=8),
    update: dict[str, object] | None = None,
) -> ForensicEvidenceAnalysisResultReceipt:
    custody = preparation.artifact_custody
    prepared = preparation.prepared_action
    payload: dict[str, object] = {
        "executionId": execution_id,
        "requestId": prepared.request.request_id,
        "requestDigest": prepared.request_digest,
        "preparationId": preparation.preparation_id,
        "preparationDigest": preparation.preparation_digest,
        "inputKind": preparation.input_kind,
        "operation": preparation.operation,
        "parser": preparation.analysis_request.parser,
        "ruleSet": preparation.analysis_request.rule_set,
        "surface": preparation.surface.reference(),
        "artifactSHA256": custody.artifact_sha256,
        "artifactBytes": custody.artifact_bytes,
        "outputSchema": preparation.analysis_request.output_schema,
        "resultBodySha256": sha256(result_body).hexdigest(),
        "resultBytes": result_size,
        "disposition": result_disposition,
        "receivedAt": received_at,
    }
    if update:
        payload.update(update)
    return ForensicEvidenceAnalysisResultReceipt.model_validate(payload)


def _runtime_receipt(
    preparation: ForensicEvidenceAnalysisPreparation,
    *,
    observed_output_bytes: int = 4_096,
    update: dict[str, object] | None = None,
) -> ForensicEvidenceAnalysisSandboxRuntimeReceipt:
    sandbox = preparation.sandbox
    custody = preparation.artifact_custody
    source_state = _source_state(preparation)
    artifact_bytes = custody.artifact_bytes
    payload: dict[str, object] = {
        "sandboxBindingId": sandbox.sandbox_binding_id,
        "sandboxBindingDigest": sandbox.sandbox_binding_digest,
        "deploymentId": sandbox.deployment_id,
        "workerProfile": sandbox.worker_profile,
        "surface": preparation.surface.reference(),
        "ruleSet": sandbox.rule_set,
        "operation": sandbox.operation,
        "parser": sandbox.parser,
        "parserExecutableSHA256": sandbox.parser_executable_sha256,
        "parserConfigurationSHA256": sandbox.parser_configuration_sha256,
        "sandboxImageSHA256": sandbox.sandbox_image_sha256,
        "runAsIdentity": sandbox.run_as_identity,
        "evidenceMountTarget": sandbox.evidence_mount_target,
        "outputSchema": sandbox.output_schema,
        "outputTransport": sandbox.output_transport,
        "artifactSHA256": custody.artifact_sha256,
        "artifactBytes": artifact_bytes,
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
        "parserWorkUnit": sandbox.parser_work_unit,
        "maxParserWorkUnits": sandbox.max_parser_work_units,
        "maxRecursionDepth": sandbox.max_recursion_depth,
        "maxDecompressionRatio": sandbox.max_decompression_ratio,
        "maxDecompressedBytes": sandbox.max_decompressed_bytes,
        "observedArtifactBytes": artifact_bytes,
        "observedOutputBytes": observed_output_bytes,
        "observedRuntimeSeconds": 5,
        "observedPeakMemoryMiB": 128,
        "observedPeakProcessCount": 1,
        "observedParserWorkUnits": max(1, artifact_bytes),
        "observedRecursionDepth": 1,
        "observedDecompressionRatio": (1 if artifact_bytes else 0),
        "observedDecompressedBytes": artifact_bytes,
        "preState": source_state,
        "postState": source_state,
        "runtimeIdentityDigest": sha256(b"forensic-runtime-identity").hexdigest(),
        "confinementDigest": sha256(b"forensic-runtime-confinement").hexdigest(),
        "attestedAt": NOW + timedelta(seconds=7),
    }
    if update:
        payload.update(update)
    return ForensicEvidenceAnalysisSandboxRuntimeReceipt.model_validate(payload)


@pytest.mark.parametrize("surface_class", tuple(ForensicSurfaceClass))
def test_structural_oracle_maps_each_surface_to_exact_neutral_review_signal(
    sample_campaign: CampaignManifest,
    surface_class: ForensicSurfaceClass,
) -> None:
    preparation = _prepare(
        sample_campaign,
        surface=_surface(surface_class=surface_class),
    )
    receipt = _result_receipt(preparation)
    first = recompute_forensic_evidence_analysis_oracle_verdict(preparation, receipt)
    second = recompute_forensic_evidence_analysis_oracle_verdict(preparation, receipt)

    assert first == second
    assert first.disposition is ForensicEvidenceAnalysisOracleDisposition.REVIEW
    assert first.review_signal is _SIGNAL_BY_CLASS[surface_class]
    assert first.mapping.surface_class is surface_class
    assert first.input_kind is _INPUT_KIND_BY_CLASS[surface_class]
    assert first.policy == registered_forensic_evidence_analysis_oracle_policy()
    assert first.structurally_consistent is True
    assert first.digest_declared_only is True
    assert first.semantic_truth_established is False
    assert first.finding_produced is False


@pytest.mark.parametrize("surface_class", tuple(ForensicSurfaceClass))
def test_structural_oracle_no_signal_has_no_review_signal_or_negative_claim(
    sample_campaign: CampaignManifest,
    surface_class: ForensicSurfaceClass,
) -> None:
    preparation = _prepare(
        sample_campaign,
        surface=_surface(surface_class=surface_class),
    )
    receipt = _result_receipt(
        preparation,
        result_disposition=ForensicEvidenceAnalysisResultDisposition.NO_SIGNAL,
    )
    verdict = recompute_forensic_evidence_analysis_oracle_verdict(preparation, receipt)

    assert verdict.disposition is ForensicEvidenceAnalysisOracleDisposition.NO_SIGNAL
    assert verdict.review_signal is None
    assert verdict.negative_security_claim is False
    assert verdict.evidence_class_verified is False
    assert verdict.source_format_verified is False
    assert verdict.parser_correctness_established is False


def test_zero_byte_source_remains_structurally_reviewable_with_bounded_result(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign, surface=_surface(artifact_bytes=0))
    receipt = _result_receipt(preparation, result_size=2, result_body=b"{}")
    runtime = _runtime_receipt(preparation, observed_output_bytes=2)
    verdict = recompute_forensic_evidence_analysis_oracle_verdict(preparation, receipt)

    assert receipt.artifact_bytes == 0
    assert runtime.observed_artifact_bytes == 0
    assert runtime.observed_decompressed_bytes == 0
    assert runtime.observed_decompression_ratio == 0
    assert verdict.artifact_bytes == 0
    assert verdict.disposition is ForensicEvidenceAnalysisOracleDisposition.REVIEW


def test_source_root_digest_binds_two_distinct_evidence_references_and_all_trust() -> None:
    coordinates = {
        "attestation_reference": forensic_evidence_analysis_execution_bundle_reference(DIGEST_A),
        "attestation_sha256": DIGEST_A,
        "result_receipt_reference": forensic_evidence_analysis_result_receipt_reference(DIGEST_B),
        "result_receipt_sha256": DIGEST_B,
        "source_membership_trust_anchor_digest": DIGEST_C,
        "execution_trust_anchor_digest": DIGEST_D,
        "source_membership_attestation_sha256": sha256(b"membership").hexdigest(),
        "statement_sha256": sha256(b"statement").hexdigest(),
        "oracle_verdict_digest": sha256(b"oracle").hexdigest(),
    }
    expected = forensic_evidence_analysis_source_root_digest(**coordinates)

    for field, value in (
        ("source_membership_trust_anchor_digest", "0" * 64),
        ("execution_trust_anchor_digest", "0" * 64),
        ("source_membership_attestation_sha256", "0" * 64),
        ("statement_sha256", "0" * 64),
        ("oracle_verdict_digest", "0" * 64),
    ):
        assert expected != forensic_evidence_analysis_source_root_digest(
            **(coordinates | {field: value})
        )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="content-addressed",
    ):
        forensic_evidence_analysis_source_root_digest(
            **(coordinates | {"attestation_reference": ATTESTATION_ALIAS_REFERENCE})
        )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="content-addressed",
    ):
        forensic_evidence_analysis_source_root_digest(
            **(coordinates | {"result_receipt_reference": RESULT_ALIAS_REFERENCE})
        )
    changed_attestation = "0" * 64
    assert expected != forensic_evidence_analysis_source_root_digest(
        **(
            coordinates
            | {
                "attestation_reference": (
                    forensic_evidence_analysis_execution_bundle_reference(changed_attestation)
                ),
                "attestation_sha256": changed_attestation,
            }
        )
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="content-addressed",
    ):
        forensic_evidence_analysis_source_root_digest(
            **(coordinates | {"attestation_sha256": changed_attestation})
        )


@pytest.mark.parametrize(
    ("model", "true_aliases", "false_aliases"),
    (
        (
            ForensicEvidenceSourceMembershipTrustAnchor,
            _SOURCE_ANCHOR_TRUE_MARKERS,
            _SOURCE_ANCHOR_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisExecutionTrustAnchor,
            _EXECUTION_ANCHOR_TRUE_MARKERS,
            _EXECUTION_ANCHOR_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceSourceMembershipAttestation,
            _MEMBERSHIP_TRUE_MARKERS,
            _MEMBERSHIP_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisSandboxRuntimeReceipt,
            _RUNTIME_TRUE_MARKERS,
            _RUNTIME_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisResultReceipt,
            _RESULT_TRUE_MARKERS,
            _RESULT_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisExecutionStatement,
            _STATEMENT_TRUE_MARKERS,
            _STATEMENT_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisAdmissionOraclePolicy,
            _ORACLE_POLICY_TRUE_MARKERS,
            _ORACLE_POLICY_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisAdmissionOracleVerdict,
            _ORACLE_VERDICT_TRUE_MARKERS,
            _ORACLE_VERDICT_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisKnowledgeCandidate,
            _CANDIDATE_TRUE_MARKERS,
            _CANDIDATE_FALSE_MARKERS,
        ),
        (
            ForensicEvidenceAnalysisKnowledgeAdmission,
            _ADMISSION_TRUE_MARKERS,
            _ADMISSION_FALSE_MARKERS,
        ),
    ),
)
def test_literal_marker_alias_contract_is_exhaustive(
    model: type[BaseModel],
    true_aliases: tuple[str, ...],
    false_aliases: tuple[str, ...],
) -> None:
    assert _literal_marker_aliases(model, True) == set(true_aliases)
    assert _literal_marker_aliases(model, False) == set(false_aliases)


def test_structural_oracle_markers_reject_authority_and_coercion(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    receipt = _result_receipt(preparation)
    policy = registered_forensic_evidence_analysis_oracle_policy()
    verdict = recompute_forensic_evidence_analysis_oracle_verdict(preparation, receipt)
    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisAdmissionOraclePolicy,
        policy.model_dump(mode="json", by_alias=True),
        _ORACLE_POLICY_FALSE_MARKERS,
        identity_fields=("policyId", "policyDigest"),
    )
    _assert_true_markers_reject_values(
        ForensicEvidenceAnalysisAdmissionOraclePolicy,
        policy.model_dump(mode="json", by_alias=True),
        _ORACLE_POLICY_TRUE_MARKERS,
        identity_fields=("policyId", "policyDigest"),
    )
    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisAdmissionOracleVerdict,
        verdict.model_dump(mode="json", by_alias=True),
        _ORACLE_VERDICT_FALSE_MARKERS,
        identity_fields=("verdictId", "verdictDigest"),
    )
    _assert_true_markers_reject_values(
        ForensicEvidenceAnalysisAdmissionOracleVerdict,
        verdict.model_dump(mode="json", by_alias=True),
        _ORACLE_VERDICT_TRUE_MARKERS,
        identity_fields=("verdictId", "verdictDigest"),
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
            raise RuntimeError("external approval authority rejected the Forensics claim")


@dataclass
class _Context:
    preparation: ForensicEvidenceAnalysisPreparation
    graph_store: SQLiteGraphStore
    graph_admission: GraphAdmissionAuthority
    graph_lineages: TrustedGraphLineageRegistry
    graph_binding: ForensicGraphAdmissionBinding
    gate: ForensicEvidenceAnalysisKnowledgeAdmissionGate
    source_inputs: ForensicEvidenceAnalysisObservationSourceInputs
    source_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor
    source_private_key: bytes
    execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor
    execution_private_key: bytes
    attestation_path: Path
    result_path: Path


def _context_source_root(context: _Context) -> Path:
    return context.attestation_path.parent.parent


def _install_source_bytes(
    context: _Context,
    *,
    attestation_content: bytes,
    result_content: bytes,
) -> None:
    source_root = _context_source_root(context)
    attestation_reference = forensic_evidence_analysis_execution_bundle_reference(
        sha256(attestation_content).hexdigest()
    )
    result_reference = forensic_evidence_analysis_result_receipt_reference(
        sha256(result_content).hexdigest()
    )
    attestation_path = source_root / attestation_reference
    result_path = source_root / result_reference
    attestation_path.write_bytes(attestation_content)
    result_path.write_bytes(result_content)
    if context.attestation_path != attestation_path and context.attestation_path.exists():
        context.attestation_path.unlink()
    if context.result_path != result_path and context.result_path.exists():
        context.result_path.unlink()
    context.attestation_path = attestation_path
    context.result_path = result_path
    context.source_inputs = replace(
        context.source_inputs,
        attestation_reference=attestation_reference,
    )


def _graph_authority(
    tmp_path: Path,
    campaign_id: str,
    preparation: ForensicEvidenceAnalysisPreparation,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    TrustedGraphLineageRegistry,
    ForensicGraphAdmissionBinding,
    GraphDecision,
]:
    store = SQLiteGraphStore(tmp_path / "graph.sqlite3", campaign_id=campaign_id)
    seed_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=RUN_ID,
        agentId="agent:forensic-surface-seed",
        taskId="task:forensic-surface-seed",
        requestId="tool_forensic_surface_seed",
        requestDigest=DIGEST_A,
        capabilityGrantId="grant:forensic-surface-seed",
        capabilityGrantDigest=DIGEST_B,
        capabilityId="pajin.forensics.surface-seed",
        capabilityVersion="1.0.0",
        capabilityDigest=DIGEST_C,
        sourceRootDigest=DIGEST_D,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/forensic-surface-seed.json",
                sha256=DIGEST_A,
            )
        ],
        producedAt=NOW,
    )
    surface = preparation.surface
    seed = SurfaceProposal(
        proposalId="proposal:surface:forensic-analysis-admission",
        producerId="pajin.graph.forensic-analysis-admission-test",
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
                    producerId="pajin.graph.forensic-analysis-admission-test",
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_D,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                forensic_evidence_analysis_knowledge_producer_registration(),
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
        creator_id="pajin.graph.forensic-snapshot-authority",
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
        actorId="pajin.graph.forensic-planner",
        actorDigest=DIGEST_C,
        createdAt=NOW + timedelta(seconds=1),
    )
    binding = ForensicGraphAdmissionBinding(
        snapshot=graph_snapshot_ref(snapshot),
        authorityId=AUTHORITY_ID,
        authorityDigest=DIGEST_A,
    )
    return store, authority, lineages, binding, decision


async def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: ForensicSurfaceClass = ForensicSurfaceClass.DISK,
    artifact_bytes: int = 4_096,
    result_disposition: ForensicEvidenceAnalysisResultDisposition = (
        ForensicEvidenceAnalysisResultDisposition.REVIEW
    ),
    result_size: int = 4_096,
    result_body: bytes = b"external-forensic-analysis-result",
    run_id: str = RUN_ID,
    request_id: str = "tool_forensic_evidence_analysis_prepare",
    execution_id: str = "forensic-execution:sandbox-test",
    execution_offset: timedelta = timedelta(),
    evidence_directory_label: str = "external-forensic-source",
    parser_executable_sha256: str = PARSER_EXECUTABLE_DIGEST,
    parser_configuration_sha256: str = PARSER_CONFIGURATION_DIGEST,
    sandbox_image_sha256: str = SANDBOX_IMAGE_DIGEST,
    execution_signing_seed: str = "execution-attestation",
    execution_key_id: str = "forensic-analysis.execution",
    statement_update: dict[str, object] | None = None,
) -> _Context:
    activation, release = _activation()
    if (
        surface_class is ForensicSurfaceClass.DISK
        and artifact_bytes == 4_096
        and request_id == "tool_forensic_evidence_analysis_prepare"
        and parser_executable_sha256 == PARSER_EXECUTABLE_DIGEST
        and parser_configuration_sha256 == PARSER_CONFIGURATION_DIGEST
        and sandbox_image_sha256 == SANDBOX_IMAGE_DIGEST
    ):
        preparation = _prepare(sample_campaign)
        surface = preparation.surface
        campaign = _campaign(sample_campaign, surface=surface)
    else:
        surface = _surface(surface_class, artifact_bytes=artifact_bytes)
        campaign = _campaign(sample_campaign, surface=surface)
        preparation = prepare_forensic_evidence_analysis(
            activation=activation,
            release=release,
            campaign=campaign,
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
            parser=_adapter(
                surface,
                parser_executable_sha256=parser_executable_sha256,
                parser_configuration_sha256=parser_configuration_sha256,
                sandbox_image_sha256=sandbox_image_sha256,
            ),
            request_id=request_id,
            agent_id="agent:forensic-evidence-analysis",
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
        profileId="forensic-evidence-analysis-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.forensics.action-compiler",
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
        proposerId="pajin.graph.forensic-planner",
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
            authorityId="deployment:forensic-operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.forensics.ExternalApprovalAuthority",
            contextDigest=DIGEST_D,
        ),
        requestedBy="principal:forensic-requester",
        approvedBy="principal:forensic-approver",
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
    source_trust_anchor, source_private_key = _source_trust_anchor(preparation)
    execution_trust_anchor, execution_private_key = _execution_trust_anchor(
        preparation,
        signing_seed=execution_signing_seed,
        key_id=execution_key_id,
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
    evidence_root = evidence_root.resolve(strict=True)
    attestation_path: Path | None = None
    result_path: Path | None = None

    async def external_runtime_receipts(
        permit: ActionPermit,
        approval_receipt: ActionApprovalConsumptionReceipt,
    ) -> str:
        nonlocal attestation_path, result_path
        result = _result_receipt(
            preparation,
            execution_id=execution_id,
            result_disposition=result_disposition,
            result_size=result_size,
            result_body=result_body,
            received_at=NOW + timedelta(seconds=8) + execution_offset,
            update={
                "requestId": permit.request_id,
                "requestDigest": permit.request_digest,
            },
        )
        result_content = forensic_evidence_analysis_result_receipt_bytes(result)
        result_sha256 = sha256(result_content).hexdigest()
        result_reference = forensic_evidence_analysis_result_receipt_reference(result_sha256)
        result_path = evidence_root / result_reference
        result_path.write_bytes(result_content)
        source_membership = _source_membership_bundle(
            preparation,
            source_trust_anchor,
            source_private_key,
            attestation_update={
                "attestedAt": NOW + timedelta(milliseconds=8_500) + execution_offset
            },
        )
        source_verification = verify_forensic_evidence_source_membership_bundle(
            source_membership,
            trust_anchor=source_trust_anchor,
        )
        started_at = NOW + timedelta(seconds=6) + execution_offset
        runtime = _runtime_receipt(
            preparation,
            observed_output_bytes=result_size,
            update={"attestedAt": NOW + timedelta(seconds=7) + execution_offset},
        )
        gateway_decision = PolicyEngine().evaluate_tool_request(
            campaign,
            grant,
            prepared.request,
            ForensicEvidenceAnalysisTool.spec,
            used_calls=0,
            now=started_at,
        )
        statement = ForensicEvidenceAnalysisExecutionStatement(
            trustDomain=execution_trust_anchor.trust_domain,
            issuer=execution_trust_anchor.issuer,
            sandboxBindingId=preparation.sandbox.sandbox_binding_id,
            sandboxBindingDigest=preparation.sandbox.sandbox_binding_digest,
            deploymentId=preparation.sandbox.deployment_id,
            gatewayPolicyDecision=gateway_decision,
            gatewayOutcomeDigest=forensic_evidence_analysis_gateway_outcome_digest(
                policy_decision=gateway_decision,
                request_digest=permit.request_digest,
                permit_digest=permit.permit_digest,
                approval_receipt_digest=approval_receipt.receipt_digest,
                capability_grant_digest=capability_grant_digest(grant),
                source_membership_verification_digest=(source_verification.verification_digest),
                sandbox_runtime_receipt_digest=runtime.receipt_digest,
                result_receipt_digest=result.receipt_digest,
            ),
            executionId=result.execution_id,
            campaignId=campaign.metadata.name,
            campaignDigest=campaign_manifest_digest(campaign),
            runId=run_id,
            preparation=preparation,
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            analysisRequest=preparation.analysis_request,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantId=grant.grant_id,
            capabilityGrantDigest=capability_grant_digest(grant),
            actionPermit=permit,
            actionPermitId=permit.permit_id,
            actionPermitDigest=permit.permit_digest,
            approvalReceipt=approval_receipt,
            approvalReceiptId=approval_receipt.receipt_id,
            approvalReceiptDigest=approval_receipt.receipt_digest,
            sourceMembership=source_membership,
            sourceMembershipVerificationDigest=source_verification.verification_digest,
            sandboxRuntime=runtime,
            resultReceiptReference=result_reference,
            resultReceiptSha256=result_sha256,
            resultReceiptId=result.receipt_id,
            resultReceiptDigest=result.receipt_digest,
            startedAt=started_at,
            finishedAt=NOW + timedelta(seconds=8) + execution_offset,
            issuedAt=NOW + timedelta(seconds=9) + execution_offset,
        )
        if statement_update:
            statement = statement.model_copy(update=statement_update)
        bundle = ForensicEvidenceAnalysisExecutionAttestor.from_private_key_bytes(
            active_key_id=execution_trust_anchor.keys[0].key_id,
            private_key=execution_private_key,
            trust_anchor=execution_trust_anchor,
            source_membership_trust_anchor=source_trust_anchor,
        ).attest(statement)
        bundle_content = forensic_evidence_analysis_execution_bundle_bytes(bundle)
        attestation_reference = forensic_evidence_analysis_execution_bundle_reference(
            sha256(bundle_content).hexdigest()
        )
        attestation_path = evidence_root / attestation_reference
        attestation_path.write_bytes(bundle_content)
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
    assert attestation_path is not None
    assert result_path is not None
    source_inputs = ForensicEvidenceAnalysisObservationSourceInputs(
        attestation_reference=attestation_path.relative_to(evidence_root).as_posix(),
        expected_run_id=run_id,
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
    )
    gate = ForensicEvidenceAnalysisKnowledgeAdmissionGate(
        graph_store=graph_store,
        graph_admission=graph_admission,
        trusted_lineages=graph_lineages,
        source_root=evidence_root,
        source_membership_trust_anchor=source_trust_anchor,
        execution_trust_anchor=execution_trust_anchor,
    )
    return _Context(
        preparation=preparation,
        graph_store=graph_store,
        graph_admission=graph_admission,
        graph_lineages=graph_lineages,
        graph_binding=graph_binding,
        gate=gate,
        source_inputs=source_inputs,
        source_trust_anchor=source_trust_anchor,
        source_private_key=source_private_key,
        execution_trust_anchor=execution_trust_anchor,
        execution_private_key=execution_private_key,
        attestation_path=attestation_path,
        result_path=result_path,
    )


def _resign_source(
    context: _Context,
    *,
    runtime_update: dict[str, object] | None = None,
    result_update: dict[str, object] | None = None,
    source_attestation_update: dict[str, object] | None = None,
    source_pre_state_update: dict[str, object] | None = None,
    source_post_state_update: dict[str, object] | None = None,
    statement_update: dict[str, object] | None = None,
) -> None:
    source_root = _context_source_root(context)
    old_attestation_path = context.attestation_path
    old_result_path = context.result_path
    bundle_payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))
    statement_payload = deepcopy(bundle_payload["statement"])
    result_payload = json.loads(context.result_path.read_text(encoding="utf-8"))
    if result_update:
        result_payload.update(result_update)
        result_payload["receiptId"] = ""
        result_payload["receiptDigest"] = ""
    result = ForensicEvidenceAnalysisResultReceipt.model_validate(result_payload)
    result_content = forensic_evidence_analysis_result_receipt_bytes(result)
    result_sha256 = sha256(result_content).hexdigest()
    result_reference = forensic_evidence_analysis_result_receipt_reference(result_sha256)
    result_path = source_root / result_reference
    result_path.write_bytes(result_content)

    source_bundle = ForensicEvidenceSourceMembershipBundle.model_validate(
        statement_payload["sourceMembership"]
    )
    if source_attestation_update or source_pre_state_update or source_post_state_update:
        source_payload = source_bundle.attestation.model_dump(mode="json", by_alias=True)
        source_payload.update(source_attestation_update or {})
        if source_pre_state_update:
            pre_payload = deepcopy(source_payload["preState"])
            pre_payload.update(source_pre_state_update)
            source_payload["preState"] = pre_payload
        if source_post_state_update:
            post_payload = deepcopy(source_payload["postState"])
            post_payload.update(source_post_state_update)
            source_payload["postState"] = post_payload
        source_payload["attestationId"] = ""
        source_payload["attestationDigest"] = ""
        source_attestation = ForensicEvidenceSourceMembershipAttestation.model_validate(
            source_payload
        )
        source_bundle = ForensicEvidenceSourceMembershipAttestor.from_private_key_bytes(
            active_key_id=context.source_trust_anchor.keys[0].key_id,
            private_key=context.source_private_key,
            trust_anchor=context.source_trust_anchor,
        ).attest(source_attestation)
    source_verification = verify_forensic_evidence_source_membership_bundle(
        source_bundle,
        trust_anchor=context.source_trust_anchor,
    )

    runtime_payload = deepcopy(statement_payload["sandboxRuntime"])
    if runtime_update:
        runtime_payload.update(runtime_update)
        runtime_payload["receiptId"] = ""
        runtime_payload["receiptDigest"] = ""
    runtime = ForensicEvidenceAnalysisSandboxRuntimeReceipt.model_validate(runtime_payload)
    permit = context.graph_store.permit_store.permits()[0]
    approval_receipt = context.graph_store.permit_store.approval_consumptions()[0]
    policy_decision = PolicyDecision.model_validate(statement_payload["gatewayPolicyDecision"])
    grant = context.source_inputs.job.grant
    statement_payload.update(
        {
            "sourceMembership": source_bundle.model_dump(mode="json", by_alias=True),
            "sourceMembershipVerificationDigest": (source_verification.verification_digest),
            "sandboxRuntime": runtime.model_dump(mode="json", by_alias=True),
            "gatewayOutcomeDigest": forensic_evidence_analysis_gateway_outcome_digest(
                policy_decision=policy_decision,
                request_digest=permit.request_digest,
                permit_digest=permit.permit_digest,
                approval_receipt_digest=approval_receipt.receipt_digest,
                capability_grant_digest=capability_grant_digest(grant),
                source_membership_verification_digest=(source_verification.verification_digest),
                sandbox_runtime_receipt_digest=runtime.receipt_digest,
                result_receipt_digest=result.receipt_digest,
            ),
            "capabilityGrantId": grant.grant_id,
            "capabilityGrantDigest": capability_grant_digest(grant),
            "resultReceiptReference": result_reference,
            "resultReceiptSha256": result_sha256,
            "resultReceiptId": result.receipt_id,
            "resultReceiptDigest": result.receipt_digest,
        }
    )
    if statement_update:
        statement_payload.update(statement_update)
    statement = ForensicEvidenceAnalysisExecutionStatement.model_validate(statement_payload)
    bundle = ForensicEvidenceAnalysisExecutionAttestor.from_private_key_bytes(
        active_key_id=context.execution_trust_anchor.keys[0].key_id,
        private_key=context.execution_private_key,
        trust_anchor=context.execution_trust_anchor,
        source_membership_trust_anchor=context.source_trust_anchor,
    ).attest(statement)
    bundle_content = forensic_evidence_analysis_execution_bundle_bytes(bundle)
    attestation_reference = forensic_evidence_analysis_execution_bundle_reference(
        sha256(bundle_content).hexdigest()
    )
    attestation_path = source_root / attestation_reference
    attestation_path.write_bytes(bundle_content)
    if old_result_path != result_path:
        old_result_path.unlink()
    if old_attestation_path != attestation_path:
        old_attestation_path.unlink()
    context.result_path = result_path
    context.attestation_path = attestation_path
    context.source_inputs = replace(
        context.source_inputs,
        attestation_reference=attestation_reference,
    )


def test_source_membership_attests_exact_state_without_independent_truth(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    trust_anchor, private_key = _source_trust_anchor(preparation)
    bundle = _source_membership_bundle(preparation, trust_anchor, private_key)
    verification = verify_forensic_evidence_source_membership_bundle(
        bundle,
        trust_anchor=trust_anchor,
    )
    provenance = preparation.surface.locator.provenance
    attestation = bundle.attestation

    assert attestation.surface == preparation.surface
    assert attestation.source_root_kind is provenance.source_root_kind
    assert attestation.source_root_sha256 == provenance.source_root_sha256
    assert attestation.source_artifact_record_sha256 == provenance.source_artifact_record_sha256
    assert attestation.provenance_record_sha256 == provenance.provenance_record_sha256
    assert attestation.artifact_sha256 == provenance.artifact_sha256
    assert attestation.artifact_bytes == provenance.artifact_bytes
    assert attestation.pre_state == attestation.post_state == _source_state(preparation)
    assert verification.valid is True
    assert verification.deployment_assertion_only is True
    assert verification.independent_source_truth_established is False

    _assert_false_markers_reject_values(
        ForensicEvidenceSourceMembershipTrustAnchor,
        trust_anchor.model_dump(mode="json", by_alias=True),
        _SOURCE_ANCHOR_FALSE_MARKERS,
    )
    _assert_false_markers_reject_values(
        ForensicEvidenceSourceMembershipAttestation,
        attestation.model_dump(mode="json", by_alias=True),
        _MEMBERSHIP_FALSE_MARKERS,
        identity_fields=("attestationId", "attestationDigest"),
    )
    payload = attestation.model_dump(mode="json", by_alias=True)
    for value in _INVALID_TRUE_MARKER_VALUES:
        changed = deepcopy(payload)
        changed.update(dict.fromkeys(_MEMBERSHIP_TRUE_MARKERS, value))
        changed["attestationId"] = ""
        changed["attestationDigest"] = ""
        with pytest.raises(ValidationError) as caught:
            ForensicEvidenceSourceMembershipAttestation.model_validate(changed)
        rejected_aliases = {str(error["loc"][0]) for error in caught.value.errors()}
        assert set(_MEMBERSHIP_TRUE_MARKERS).issubset(rejected_aliases)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sourceRootSHA256", "0" * 64),
        ("sourceArtifactRecordSHA256", "0" * 64),
        ("provenanceRecordSHA256", "0" * 64),
        ("artifactSHA256", "0" * 64),
        ("artifactBytes", 4_097),
        ("custodyBindingId", "forensic-custody:foreign"),
        ("custodyBindingDigest", "0" * 64),
        ("custodyAuthorityId", "foreign.forensic-custody"),
        ("custodyObjectId", "forensic-object:foreign"),
        ("authorizationId", "forensic-authorization:foreign"),
        ("authorizationDigest", "0" * 64),
        ("immutableObjectVersion", "forensic-source-version:foreign"),
    ),
)
def test_source_membership_rejects_exact_coordinate_drift(
    sample_campaign: CampaignManifest,
    field: str,
    value: object,
) -> None:
    preparation = _prepare(sample_campaign)
    trust_anchor, private_key = _source_trust_anchor(preparation)
    with pytest.raises(
        (ForensicEvidenceAnalysisKnowledgeAdmissionError, ValidationError, ValueError)
    ):
        _source_membership_bundle(
            preparation,
            trust_anchor,
            private_key,
            pre_state_update={field: value},
            post_state_update={field: value},
            attestation_update={field: value},
        )


def test_source_membership_rejects_one_sided_and_same_foreign_pre_post_state(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    trust_anchor, private_key = _source_trust_anchor(preparation)
    foreign_digest = "0" * 64

    with pytest.raises(ValidationError, match="immutable state"):
        _source_membership_bundle(
            preparation,
            trust_anchor,
            private_key,
            post_state_update={"artifactSHA256": foreign_digest},
        )

    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError, match="anchor"):
        _source_membership_bundle(
            preparation,
            trust_anchor,
            private_key,
            pre_state_update={"artifactSHA256": foreign_digest},
            post_state_update={"artifactSHA256": foreign_digest},
            attestation_update={"artifactSHA256": foreign_digest},
        )


def test_source_membership_rejects_signature_foreign_anchor_and_key_lifecycle(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    trust_anchor, private_key = _source_trust_anchor(preparation)
    bundle = _source_membership_bundle(preparation, trust_anchor, private_key)
    payload = bundle.model_dump(mode="json", by_alias=True)
    signature = payload["signatureBase64url"]
    assert isinstance(signature, str)
    payload["signatureBase64url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = ForensicEvidenceSourceMembershipBundle.model_validate(payload)
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError, match="signature"):
        verify_forensic_evidence_source_membership_bundle(
            tampered,
            trust_anchor=trust_anchor,
        )

    foreign_anchor, _ = _source_trust_anchor(
        preparation,
        signing_seed="foreign-source-membership",
        key_id="forensic-source.foreign",
    )
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError, match="signing key"):
        verify_forensic_evidence_source_membership_bundle(
            bundle,
            trust_anchor=foreign_anchor,
        )

    key_payload = trust_anchor.keys[0].model_dump(mode="json", by_alias=True)
    key_payload["notAfter"] = (NOW - timedelta(seconds=1)).isoformat()
    expired_key = ForensicEvidenceSourceMembershipVerificationKey.model_validate(key_payload)
    expired_anchor = trust_anchor.model_copy(update={"keys": (expired_key,)}, deep=True)
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="validity window",
    ):
        verify_forensic_evidence_source_membership_bundle(
            bundle,
            trust_anchor=expired_anchor,
        )

    revoked_payload = trust_anchor.keys[0].model_dump(mode="json", by_alias=True)
    revoked_payload.update(
        {
            "state": ForensicEvidenceSourceMembershipKeyState.REVOKED.value,
            "revokedAt": (NOW - timedelta(seconds=1)).isoformat(),
        }
    )
    revoked_key = ForensicEvidenceSourceMembershipVerificationKey.model_validate(revoked_payload)
    active_foreign = foreign_anchor.keys[0]
    revoked_anchor = ForensicEvidenceSourceMembershipTrustAnchor.model_validate(
        trust_anchor.model_dump(mode="json", by_alias=True)
        | {
            "keys": [
                item.model_dump(mode="json", by_alias=True)
                for item in sorted(
                    (revoked_key, active_foreign),
                    key=lambda item: item.key_id,
                )
            ]
        }
    )
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError, match="revoked"):
        verify_forensic_evidence_source_membership_bundle(
            bundle,
            trust_anchor=revoked_anchor,
        )


def test_source_and_execution_trust_roles_are_disjoint_and_non_substitutable(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    source_anchor, source_private_key = _source_trust_anchor(preparation)
    execution_anchor, execution_private_key = _execution_trust_anchor(preparation)
    shared_execution_anchor, _ = _execution_trust_anchor(
        preparation,
        signing_seed="source-membership",
    )

    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="trust roles must be disjoint",
    ):
        ForensicEvidenceAnalysisExecutionAttestor.from_private_key_bytes(
            active_key_id=shared_execution_anchor.keys[0].key_id,
            private_key=source_private_key,
            trust_anchor=shared_execution_anchor,
            source_membership_trust_anchor=source_anchor,
        )
    with pytest.raises(ValueError, match="private key does not match"):
        ForensicEvidenceAnalysisExecutionAttestor.from_private_key_bytes(
            active_key_id=execution_anchor.keys[0].key_id,
            private_key=source_private_key,
            trust_anchor=execution_anchor,
            source_membership_trust_anchor=source_anchor,
        )
    with pytest.raises(ValueError, match="private key does not match"):
        ForensicEvidenceSourceMembershipAttestor.from_private_key_bytes(
            active_key_id=source_anchor.keys[0].key_id,
            private_key=execution_private_key,
            trust_anchor=source_anchor,
        )

    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisExecutionTrustAnchor,
        execution_anchor.model_dump(mode="json", by_alias=True),
        _EXECUTION_ANCHOR_FALSE_MARKERS,
    )


@pytest.mark.parametrize(
    "extra_field",
    (
        "rawSource",
        "rawResult",
        "rawProvenance",
        "sourcePath",
        "identityMaterial",
        "secretMaterial",
        "credentialMaterial",
    ),
)
def test_result_receipt_rejects_raw_path_identity_secret_and_credential_fields(
    sample_campaign: CampaignManifest,
    extra_field: str,
) -> None:
    receipt = _result_receipt(_prepare(sample_campaign))
    payload = receipt.model_dump(mode="json", by_alias=True)
    payload[extra_field] = "forbidden"
    with pytest.raises(ValidationError):
        ForensicEvidenceAnalysisResultReceipt.model_validate(payload)

    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisResultReceipt,
        receipt.model_dump(mode="json", by_alias=True),
        _RESULT_FALSE_MARKERS,
        identity_fields=("receiptId", "receiptDigest"),
    )


def test_runtime_receipt_binds_exact_profile_and_zero_byte_ratio(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    runtime = _runtime_receipt(preparation)
    sandbox = preparation.sandbox

    assert runtime.worker_profile == sandbox.worker_profile
    assert runtime.surface == preparation.surface.reference()
    assert runtime.rule_set == sandbox.rule_set
    assert runtime.parser_configuration_sha256 == PARSER_CONFIGURATION_DIGEST
    assert runtime.parser_executable_sha256 == PARSER_EXECUTABLE_DIGEST
    assert runtime.sandbox_image_sha256 == SANDBOX_IMAGE_DIGEST
    assert runtime.run_as_identity == FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY
    assert runtime.evidence_mount_target == FORENSIC_EVIDENCE_MOUNT_TARGET
    assert runtime.output_schema == FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA
    assert runtime.parser_work_unit == FORENSIC_PARSER_WORK_UNIT
    assert runtime.pre_state == runtime.post_state == _source_state(preparation)

    zero_preparation = _prepare(sample_campaign, surface=_surface(artifact_bytes=0))
    zero_runtime = _runtime_receipt(zero_preparation)
    assert zero_runtime.artifact_bytes == 0
    assert zero_runtime.observed_artifact_bytes == 0
    assert zero_runtime.observed_decompressed_bytes == 0
    assert zero_runtime.observed_decompression_ratio == 0
    assert zero_runtime.observed_parser_work_units == 1


@pytest.mark.parametrize(
    "field",
    (
        "observedArtifactBytes",
        "observedOutputBytes",
        "observedRuntimeSeconds",
        "observedPeakMemoryMiB",
        "observedPeakProcessCount",
        "observedParserWorkUnits",
        "observedRecursionDepth",
        "observedDecompressionRatio",
        "observedDecompressedBytes",
    ),
)
def test_runtime_observed_values_cannot_exceed_exact_b_ceiling(
    sample_campaign: CampaignManifest,
    field: str,
) -> None:
    preparation = _prepare(sample_campaign)
    sandbox = preparation.sandbox
    ceiling = {
        "observedArtifactBytes": preparation.artifact_custody.artifact_bytes,
        "observedOutputBytes": sandbox.max_output_bytes,
        "observedRuntimeSeconds": sandbox.max_runtime_seconds,
        "observedPeakMemoryMiB": sandbox.max_memory_mib,
        "observedPeakProcessCount": sandbox.max_process_count,
        "observedParserWorkUnits": sandbox.max_parser_work_units,
        "observedRecursionDepth": sandbox.max_recursion_depth,
        "observedDecompressionRatio": sandbox.max_decompression_ratio,
        "observedDecompressedBytes": sandbox.max_decompressed_bytes,
    }[field]

    with pytest.raises(ValidationError, match="observed ceilings"):
        _runtime_receipt(preparation, update={field: ceiling + 1})


def test_runtime_markers_and_counters_reject_authority_and_coercion(
    sample_campaign: CampaignManifest,
) -> None:
    runtime = _runtime_receipt(_prepare(sample_campaign))
    payload = runtime.model_dump(mode="json", by_alias=True)
    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisSandboxRuntimeReceipt,
        payload,
        _RUNTIME_FALSE_MARKERS,
        identity_fields=("receiptId", "receiptDigest"),
    )

    for value in _INVALID_TRUE_MARKER_VALUES:
        changed = deepcopy(payload)
        changed.update(dict.fromkeys(_RUNTIME_TRUE_MARKERS, value))
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError) as caught:
            ForensicEvidenceAnalysisSandboxRuntimeReceipt.model_validate(changed)
        rejected_aliases = {str(error["loc"][0]) for error in caught.value.errors()}
        assert set(_RUNTIME_TRUE_MARKERS).issubset(rejected_aliases)

    for invalid in (1, False, 0.0, "0"):
        changed = deepcopy(payload)
        changed.update(dict.fromkeys(_RUNTIME_ZERO_COUNTERS, invalid))
        changed["receiptId"] = ""
        changed["receiptDigest"] = ""
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisSandboxRuntimeReceipt.model_validate(changed)


@pytest.mark.asyncio
@pytest.mark.parametrize("surface_class", tuple(ForensicSurfaceClass))
async def test_sealed_source_admits_fixed_neutral_graph_and_open_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: ForensicSurfaceClass,
) -> None:
    context = await _context(tmp_path, sample_campaign, surface_class=surface_class)
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
    admission = context.gate.admit(context.source_inputs, candidate)
    observation_event = admission.observation_graph_event
    hypothesis_event = admission.hypothesis_graph_event

    assert candidate.review_signal is _SIGNAL_BY_CLASS[surface_class]
    assert candidate.oracle_verdict.review_signal is _SIGNAL_BY_CLASS[surface_class]
    assert candidate.hypothesis_proposal is not None
    assert candidate.hypothesis_proposal.hypothesis.confidence == 0.5
    assert (
        candidate.hypothesis_proposal.hypothesis.hypothesis_type == "forensics.forensic-proposition"
    )
    assert (
        candidate.observation_proposal.observation.observation_type
        == "forensics.analysis-observation"
    )
    assert candidate.observation_proposal.observation.confidence == 1.0
    assert len(candidate.observation_proposal.evidence_nodes) == 2
    assert {item.reference for item in candidate.observation_proposal.evidence_nodes} == {
        context.attestation_path.relative_to(_context_source_root(context)).as_posix(),
        context.result_path.relative_to(_context_source_root(context)).as_posix(),
    }
    assert (
        candidate.observation_proposal.lineage.capability_grant_digest
        == capability_grant_digest(context.source_inputs.job.grant)
    )
    assert observation_event.decision is GraphAdmissionDecision.ADMITTED
    assert hypothesis_event is not None
    assert hypothesis_event.decision is GraphAdmissionDecision.ADMITTED
    kinds = [item.kind for item in observation_event.admitted_nodes]
    assert kinds.count(GraphNodeKind.ACTION.value) == 1
    assert kinds.count(GraphNodeKind.OBSERVATION.value) == 1
    assert kinds.count(GraphNodeKind.EVIDENCE.value) == 2
    assert len(kinds) == 4
    assert {item.relation for item in observation_event.admitted_edges} == {
        GraphRelation.PRODUCES,
        GraphRelation.SUPPORTED_BY,
    }
    assert hypothesis_event.admitted_edges[0].relation is GraphRelation.ENABLES
    candidate_payload = candidate.model_dump(mode="json", by_alias=True)
    assert all(candidate_payload[alias] is False for alias in _CANDIDATE_FALSE_MARKERS)

    graph_text = json.dumps(
        {
            "observation": observation_event.model_dump(mode="json", by_alias=True),
            "hypothesis": hypothesis_event.model_dump(mode="json", by_alias=True),
        },
        sort_keys=True,
    )
    assert "external-forensic-analysis-result" not in graph_text
    assert "sourcePath" not in graph_text
    assert "credentialMaterial" not in graph_text
    assert "secretMaterial" not in graph_text


@pytest.mark.asyncio
async def test_no_signal_admits_observation_without_hypothesis_or_negative_claim(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        result_disposition=ForensicEvidenceAnalysisResultDisposition.NO_SIGNAL,
    )
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
    admission = context.gate.admit(context.source_inputs, candidate)

    assert candidate.review_signal is None
    assert candidate.oracle_verdict.negative_security_claim is False
    assert candidate.hypothesis_proposal is None
    assert admission.hypothesis_graph_event is None
    assert admission.bounded_hypothesis_admitted is False
    assert len(context.graph_store.event_log.events()) == 2


@pytest.mark.asyncio
async def test_zero_byte_source_admits_without_ratio_or_parser_budget_bypass(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        artifact_bytes=0,
        result_size=2,
        result_body=b"{}",
    )
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
    runtime = json.loads(context.attestation_path.read_text(encoding="utf-8"))["statement"][
        "sandboxRuntime"
    ]
    admission = context.gate.admit(context.source_inputs, candidate)

    assert runtime["observedArtifactBytes"] == 0
    assert runtime["observedDecompressedBytes"] == 0
    assert runtime["observedDecompressionRatio"] == 0
    assert runtime["observedParserWorkUnits"] == 1
    assert candidate.artifact_bytes == 0
    assert admission.observation_graph_event.decision is GraphAdmissionDecision.ADMITTED


@pytest.mark.asyncio
async def test_execution_trust_rejects_tamper_foreign_expired_and_revoked_keys(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    original = context.attestation_path.read_bytes()
    original_result = context.result_path.read_bytes()
    payload = json.loads(original)
    signature = payload["signatureBase64url"]
    payload["signatureBase64url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    _install_source_bytes(
        context,
        attestation_content=json.dumps(payload).encode("utf-8"),
        result_content=original_result,
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="signature",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    _install_source_bytes(
        context,
        attestation_content=original,
        result_content=original_result,
    )

    foreign_anchor, _ = _execution_trust_anchor(
        context.preparation,
        signing_seed="foreign-execution",
        key_id="forensic-analysis.foreign",
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="signing key",
    ):
        load_verified_forensic_evidence_analysis_observation_source(
            context.source_inputs,
            source_root=_context_source_root(context),
            graph_store=context.graph_store,
            execution_trust_anchor=foreign_anchor,
            source_membership_trust_anchor=context.source_trust_anchor,
        )

    key_payload = context.execution_trust_anchor.keys[0].model_dump(
        mode="json",
        by_alias=True,
    )
    key_payload["notAfter"] = (NOW + timedelta(seconds=8)).isoformat()
    expired_key = ForensicEvidenceAnalysisExecutionVerificationKey.model_validate(key_payload)
    anchor_payload = context.execution_trust_anchor.model_dump(
        mode="json",
        by_alias=True,
    )
    anchor_payload["keys"] = [expired_key.model_dump(mode="json", by_alias=True)]
    expired_anchor = ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(anchor_payload)
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="validity window",
    ):
        load_verified_forensic_evidence_analysis_observation_source(
            context.source_inputs,
            source_root=_context_source_root(context),
            graph_store=context.graph_store,
            execution_trust_anchor=expired_anchor,
            source_membership_trust_anchor=context.source_trust_anchor,
        )

    revoked_payload = context.execution_trust_anchor.keys[0].model_dump(
        mode="json",
        by_alias=True,
    )
    revoked_payload.update(
        {
            "state": ForensicEvidenceAnalysisExecutionKeyState.REVOKED.value,
            "revokedAt": NOW.isoformat(),
        }
    )
    revoked_key = ForensicEvidenceAnalysisExecutionVerificationKey.model_validate(revoked_payload)
    revoked_anchor_payload = context.execution_trust_anchor.model_dump(
        mode="json",
        by_alias=True,
    )
    revoked_anchor_payload["keys"] = [
        item.model_dump(mode="json", by_alias=True)
        for item in sorted(
            (revoked_key, foreign_anchor.keys[0]),
            key=lambda item: item.key_id,
        )
    ]
    revoked_anchor = ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(
        revoked_anchor_payload
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="revoked",
    ):
        load_verified_forensic_evidence_analysis_observation_source(
            context.source_inputs,
            source_root=_context_source_root(context),
            graph_store=context.graph_store,
            execution_trust_anchor=revoked_anchor,
            source_membership_trust_anchor=context.source_trust_anchor,
        )
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_detached_result_strict_json_and_reference_traversal_fail_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    original = context.result_path.read_bytes()
    payload = json.loads(original)
    payload["resultBodySha256"] = "0" * 64
    payload["receiptId"] = ""
    payload["receiptDigest"] = ""
    context.result_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)

    context.result_path.write_bytes(b'{"resultBytes":2,"resultBytes":3}')
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    context.result_path.write_bytes(original)

    traversal_inputs = replace(
        context.source_inputs,
        attestation_reference="../forensic-analysis-attestation.json",
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="reference",
    ):
        context.gate.prepare_candidate(traversal_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_content_addressed_aliases_and_candidate_reference_drift_fail_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    source_root = _context_source_root(context)
    alias_attestation_path = source_root / ATTESTATION_ALIAS_REFERENCE
    alias_result_path = source_root / RESULT_ALIAS_REFERENCE
    alias_attestation_path.write_bytes(context.attestation_path.read_bytes())
    alias_result_path.write_bytes(context.result_path.read_bytes())
    alias_inputs = replace(
        context.source_inputs,
        attestation_reference=ATTESTATION_ALIAS_REFERENCE,
    )

    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="content-addressed",
    ):
        context.gate.prepare_candidate(alias_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1

    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
    candidate_payload = candidate.model_dump(mode="json", by_alias=True)
    for update in (
        {"attestationReference": ATTESTATION_ALIAS_REFERENCE},
        {"attestationSha256": "0" * 64},
        {"resultReceiptReference": RESULT_ALIAS_REFERENCE},
        {"resultReceiptSha256": "0" * 64},
    ):
        changed = deepcopy(candidate_payload)
        changed.update(update)
        changed["candidateId"] = ""
        changed["candidateDigest"] = ""
        with pytest.raises(ValidationError, match="sealed semantics"):
            ForensicEvidenceAnalysisKnowledgeCandidate.model_validate(changed)

    _resign_source(
        context,
        statement_update={"resultReceiptReference": RESULT_ALIAS_REFERENCE},
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="content-addressed",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_gate_owns_absolute_existing_root_and_inputs_cannot_override_it(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    root_file = tmp_path / "not-a-source-root.json"
    root_file.write_bytes(b"{}")
    missing_root = (tmp_path / "missing-source-root").absolute()
    invalid_roots = (Path("relative-source-root"), missing_root, root_file.absolute())

    for source_root in invalid_roots:
        with pytest.raises(
            ForensicEvidenceAnalysisKnowledgeAdmissionError,
            match="absolute existing non-symlink directory",
        ):
            ForensicEvidenceAnalysisKnowledgeAdmissionGate(
                graph_store=context.graph_store,
                graph_admission=context.graph_admission,
                trusted_lineages=context.graph_lineages,
                source_root=source_root,
                execution_trust_anchor=context.execution_trust_anchor,
                source_membership_trust_anchor=context.source_trust_anchor,
            )

    assert "source_root" not in {field.name for field in fields(context.source_inputs)}
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="absolute existing non-symlink directory",
    ):
        load_verified_forensic_evidence_analysis_observation_source(
            context.source_inputs,
            source_root=Path("relative-source-root"),
            graph_store=context.graph_store,
            execution_trust_anchor=context.execution_trust_anchor,
            source_membership_trust_anchor=context.source_trust_anchor,
        )
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_symlink_source_root_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    symlink_root = tmp_path / "source-root-link"
    try:
        os.symlink(
            _context_source_root(context),
            symlink_root,
            target_is_directory=True,
        )
    except OSError:
        pytest.skip("directory symlink creation is unavailable in this Windows environment")

    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="absolute existing non-symlink directory",
    ):
        ForensicEvidenceAnalysisKnowledgeAdmissionGate(
            graph_store=context.graph_store,
            graph_admission=context.graph_admission,
            trusted_lineages=context.graph_lineages,
            source_root=symlink_root.absolute(),
            execution_trust_anchor=context.execution_trust_anchor,
            source_membership_trust_anchor=context.source_trust_anchor,
        )
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_hardlinked_and_symlinked_evidence_are_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    hardlink_context = await _context(tmp_path / "hardlink", sample_campaign)
    hardlink_source = hardlink_context.result_path.with_name("hardlink-source.json")
    hardlink_source.write_bytes(hardlink_context.result_path.read_bytes())
    hardlink_context.result_path.unlink()
    os.link(hardlink_source, hardlink_context.result_path)
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        hardlink_context.gate.prepare_candidate(
            hardlink_context.source_inputs,
            hardlink_context.graph_binding,
        )

    symlink_context = await _context(tmp_path / "symlink", sample_campaign)
    symlink_target = symlink_context.result_path.with_name("symlink-target.json")
    symlink_target.write_bytes(symlink_context.result_path.read_bytes())
    symlink_context.result_path.unlink()
    try:
        os.symlink(symlink_target, symlink_context.result_path)
    except OSError:
        pytest.skip("symlink creation is unavailable in this Windows environment")
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        symlink_context.gate.prepare_candidate(
            symlink_context.source_inputs,
            symlink_context.graph_binding,
        )


@pytest.mark.asyncio
async def test_signed_runtime_cannot_substitute_exact_b_sandbox_binding(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    original_attestation = context.attestation_path.read_bytes()
    original_result = context.result_path.read_bytes()
    sandbox = context.preparation.sandbox
    substitutions: tuple[dict[str, object], ...] = (
        {"parserExecutableSHA256": "0" * 64},
        {"parserConfigurationSHA256": "0" * 64},
        {"sandboxImageSHA256": "0" * 64},
        {"runAsIdentity": "sandbox:foreign-nonroot"},
        {"evidenceMountTarget": "/foreign-evidence"},
        {"maxArtifactBytes": sandbox.max_artifact_bytes + 1},
        {"maxOutputBytes": sandbox.max_output_bytes + 1},
        {"maxRuntimeSeconds": sandbox.max_runtime_seconds + 1},
        {"maxMemoryMiB": sandbox.max_memory_mib + 1},
        {"maxProcessCount": sandbox.max_process_count + 1},
        {"maxParserWorkUnits": sandbox.max_parser_work_units + 1},
        {"maxRecursionDepth": sandbox.max_recursion_depth + 1},
        {"maxDecompressionRatio": sandbox.max_decompression_ratio + 1},
        {"maxDecompressedBytes": sandbox.max_decompressed_bytes + 1},
    )

    for update in substitutions:
        _install_source_bytes(
            context,
            attestation_content=original_attestation,
            result_content=original_result,
        )
        _resign_source(context, runtime_update=update)
        with pytest.raises(
            ForensicEvidenceAnalysisKnowledgeAdmissionError,
            match="differs",
        ):
            context.gate.prepare_candidate(
                context.source_inputs,
                context.graph_binding,
            )
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_consumed_permit_durable_approval_and_gateway_are_recomputed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    verified = load_verified_forensic_evidence_analysis_observation_source(
        context.source_inputs,
        source_root=_context_source_root(context),
        graph_store=context.graph_store,
        execution_trust_anchor=context.execution_trust_anchor,
        source_membership_trust_anchor=context.source_trust_anchor,
    )
    assert verified.bundle.statement.action_permit == verified.permit
    assert verified.bundle.statement.approval_receipt == verified.approval_receipt
    assert verified.approval_receipt.action_permit == verified.permit

    foreign_run_inputs = replace(
        context.source_inputs,
        expected_run_id="run_20260827T120000Z_foreign",
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="ActionPermit",
    ):
        context.gate.prepare_candidate(foreign_run_inputs, context.graph_binding)

    missing_approval_job = context.source_inputs.job.model_copy(
        update={"approval": None},
        deep=True,
    )
    missing_approval_inputs = replace(
        context.source_inputs,
        job=missing_approval_job,
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="approved execution inputs",
    ):
        context.gate.prepare_candidate(missing_approval_inputs, context.graph_binding)

    statement_payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))[
        "statement"
    ]
    forged_decision = PolicyDecision(
        allowed=True,
        reason="forged policy explanation",
        policy="allow",
    )
    permit = verified.permit
    runtime = ForensicEvidenceAnalysisSandboxRuntimeReceipt.model_validate(
        statement_payload["sandboxRuntime"]
    )
    forged_gateway_digest = forensic_evidence_analysis_gateway_outcome_digest(
        policy_decision=forged_decision,
        request_digest=permit.request_digest,
        permit_digest=permit.permit_digest,
        approval_receipt_digest=verified.approval_receipt.receipt_digest,
        capability_grant_digest=capability_grant_digest(context.source_inputs.job.grant),
        source_membership_verification_digest=(
            verified.verification.source_membership_verification.verification_digest
        ),
        sandbox_runtime_receipt_digest=runtime.receipt_digest,
        result_receipt_digest=verified.result_receipt.receipt_digest,
    )
    _resign_source(
        context,
        statement_update={
            "gatewayPolicyDecision": forged_decision,
            "gatewayOutcomeDigest": forged_gateway_digest,
        },
    )
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="differs",
    ):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_caller_and_signed_capability_grant_drift_fail_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    grant = context.source_inputs.job.grant
    substitutions = (
        grant.model_copy(update={"grant_id": "grant_foreign_compatible"}),
        grant.model_copy(update={"expires_at": grant.expires_at - timedelta(seconds=1)}),
    )

    for substitution in substitutions:
        substituted_job = context.source_inputs.job.model_copy(
            update={"grant": substitution},
        )
        substituted_inputs = replace(
            context.source_inputs,
            job=substituted_job,
        )
        with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
            context.gate.prepare_candidate(substituted_inputs, context.graph_binding)
        assert len(context.graph_store.event_log.events()) == 1

    _resign_source(
        context,
        statement_update={
            "capabilityGrantId": "grant_foreign_compatible",
            "capabilityGrantDigest": "0" * 64,
        },
    )
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    assert len(context.graph_store.event_log.events()) == 1


@pytest.mark.asyncio
async def test_candidate_rejects_authority_escalation_mutation_and_hidden_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
    payload = candidate.model_dump(mode="json", by_alias=True)
    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisKnowledgeCandidate,
        payload,
        _CANDIDATE_FALSE_MARKERS,
        identity_fields=("candidateId", "candidateDigest"),
    )
    _assert_true_markers_reject_values(
        ForensicEvidenceAnalysisKnowledgeCandidate,
        payload,
        _CANDIDATE_TRUE_MARKERS,
        identity_fields=("candidateId", "candidateDigest"),
    )

    mutated = candidate.model_copy(
        update={"oracle_verdict_digest": "0" * 64},
        deep=True,
    )
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        context.gate.admit(context.source_inputs, mutated)

    hidden = candidate.model_copy(update={"unmodeledAuthority": True})
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        context.gate.admit(context.source_inputs, hidden)

    admission = context.gate.admit(context.source_inputs, candidate)
    admission_payload = admission.model_dump(mode="json", by_alias=True)
    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisKnowledgeAdmission,
        admission_payload,
        _ADMISSION_FALSE_MARKERS,
        identity_fields=("admissionId", "admissionDigest"),
    )
    _assert_true_markers_reject_values(
        ForensicEvidenceAnalysisKnowledgeAdmission,
        admission_payload,
        _ADMISSION_TRUE_MARKERS,
        identity_fields=("admissionId", "admissionDigest"),
    )
    assert len(context.graph_store.event_log.events()) == 3


@pytest.mark.asyncio
async def test_graph_exact_retry_is_idempotent_and_source_mutation_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
    first = context.gate.admit(context.source_inputs, candidate)
    second = context.gate.admit(context.source_inputs, candidate)

    assert first == second
    assert len(context.graph_store.event_log.events()) == 3
    with pytest.raises(
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
        match="current canonical head",
    ):
        context.gate.prepare_candidate(
            context.source_inputs,
            context.graph_binding,
        )

    context.result_path.write_bytes(context.result_path.read_bytes() + b" ")
    with pytest.raises(ForensicEvidenceAnalysisKnowledgeAdmissionError):
        context.gate.admit(context.source_inputs, candidate)
    assert len(context.graph_store.event_log.events()) == 3


@pytest.mark.asyncio
async def test_retry_after_observation_only_reuses_it_and_completes_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
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
    assert len(context.graph_store.event_log.events()) == 2

    admission = context.gate.admit(context.source_inputs, candidate)

    assert admission.observation_graph_event == observation_result.event
    assert admission.hypothesis_graph_event is not None
    assert admission.hypothesis_graph_event.sequence == observation_result.event.sequence + 1
    assert (
        admission.hypothesis_graph_event.previous_event_digest
        == observation_result.event.event_digest
    )
    assert len(context.graph_store.event_log.events()) == 3


@pytest.mark.asyncio
async def test_intervening_graph_head_preserves_observation_and_blocks_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )
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
        proposalId="proposal:surface:forensic-analysis-intervening",
        producerId="pajin.graph.forensic-analysis-admission-test",
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
        ForensicEvidenceAnalysisKnowledgeAdmissionError,
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
async def test_graph_store_subclass_is_rejected_at_gate_and_loader(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    subclass_store = _SQLiteGraphStoreSubclass(
        tmp_path / "subclass-graph.sqlite3",
        campaign_id=context.graph_store.campaign_id,
    )
    with pytest.raises(TypeError, match="exact SQLite Graph Store"):
        ForensicEvidenceAnalysisKnowledgeAdmissionGate(
            graph_store=subclass_store,
            graph_admission=context.graph_admission,
            trusted_lineages=context.graph_lineages,
            source_root=_context_source_root(context),
            execution_trust_anchor=context.execution_trust_anchor,
            source_membership_trust_anchor=context.source_trust_anchor,
        )
    with pytest.raises(TypeError, match="exact SQLite Graph Store"):
        load_verified_forensic_evidence_analysis_observation_source(
            context.source_inputs,
            source_root=_context_source_root(context),
            graph_store=subclass_store,
            execution_trust_anchor=context.execution_trust_anchor,
            source_membership_trust_anchor=context.source_trust_anchor,
        )


@pytest.mark.asyncio
async def test_resolver_parser_worker_tool_and_result_body_are_not_invoked(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pajin.capabilities.forensic_evidence_analysis as forensic_capability

    context = await _context(tmp_path, sample_campaign)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("forbidden FORENSICS runtime path was invoked")

    monkeypatch.setattr(
        forensic_capability,
        "resolve_forensic_evidence_analysis_binding",
        forbidden,
    )
    monkeypatch.setattr(
        forensic_capability,
        "resolve_registered_forensic_evidence_rule_set",
        forbidden,
    )
    monkeypatch.setattr(ForensicEvidenceAnalysisTool, "prepare", forbidden)
    monkeypatch.setattr(ForensicEvidenceAnalysisTool, "interpret", forbidden)
    monkeypatch.setattr(forensic_capability, "WorkerJob", forbidden)
    monkeypatch.setattr(forensic_capability, "WorkerResult", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    candidate = context.gate.prepare_candidate(
        context.source_inputs,
        context.graph_binding,
    )

    assert candidate.oracle_verdict.source_read_performed is False
    assert candidate.oracle_verdict.result_body_read_performed is False
    assert candidate.oracle_verdict.key_material_read_performed is False
    assert candidate.oracle_verdict.cryptographic_validation_performed is False
    assert sorted(path.name for path in context.result_path.parent.iterdir()) == sorted(
        (context.attestation_path.name, context.result_path.name)
    )


@pytest.mark.asyncio
async def test_statement_requires_exact_counters_and_negative_authority_markers(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(tmp_path, sample_campaign)
    payload = json.loads(context.attestation_path.read_text(encoding="utf-8"))["statement"]
    _assert_false_markers_reject_values(
        ForensicEvidenceAnalysisExecutionStatement,
        payload,
        _STATEMENT_FALSE_MARKERS,
    )

    for value in _INVALID_TRUE_MARKER_VALUES:
        changed = deepcopy(payload)
        changed.update(dict.fromkeys(_STATEMENT_TRUE_MARKERS, value))
        with pytest.raises(ValidationError) as caught:
            ForensicEvidenceAnalysisExecutionStatement.model_validate(changed)
        rejected_aliases = {str(error["loc"][0]) for error in caught.value.errors()}
        assert set(_STATEMENT_TRUE_MARKERS).issubset(rejected_aliases)

    for alias in _STATEMENT_ZERO_COUNTERS:
        for invalid in (1, False, 0.0, "0"):
            changed = deepcopy(payload)
            changed[alias] = invalid
            with pytest.raises(ValidationError):
                ForensicEvidenceAnalysisExecutionStatement.model_validate(changed)
    for alias in ("requestCount", "artifactReads"):
        for invalid in (True, 1.0, "1"):
            changed = deepcopy(payload)
            changed[alias] = invalid
            with pytest.raises(ValidationError):
                ForensicEvidenceAnalysisExecutionStatement.model_validate(changed)


def test_producer_registration_allows_only_observation_and_hypothesis() -> None:
    registration = forensic_evidence_analysis_knowledge_producer_registration()

    assert registration.allowed_proposal_kinds == (
        GraphProposalKind.HYPOTHESIS,
        GraphProposalKind.OBSERVATION,
    )
    assert GraphProposalKind.SURFACE not in registration.allowed_proposal_kinds
    assert GraphProposalKind.CAMPAIGN_FACT not in registration.allowed_proposal_kinds


def test_output_schema_constant_remains_exact() -> None:
    assert (
        FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA
        == "pajin.forensics.read-only-evidence-analysis-result.v1"
    )
