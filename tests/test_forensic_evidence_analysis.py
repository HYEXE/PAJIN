from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import cache
from hashlib import sha256
from inspect import signature

import pytest
from pydantic import BaseModel, ValidationError

from pajin.capabilities.authorities import CapabilityAuthorityRole, CapabilityOracleDecision
from pajin.capabilities.forensic_evidence_analysis import (
    FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ID,
    FORENSIC_EVIDENCE_ANALYSIS_DEPLOYMENT_ID,
    FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
    FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY,
    FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID,
    FORENSIC_EVIDENCE_CUSTODY_AUTHORITY_ID,
    FORENSIC_EVIDENCE_MOUNT_TARGET,
    FORENSIC_PARSER_WORK_UNIT,
    FORENSIC_SURFACE_SCOPE_ORIGIN,
    BoundedForensicEvidenceParserAdapter,
    ForensicEvidenceAnalysisBinding,
    ForensicEvidenceAnalysisBudget,
    ForensicEvidenceAnalysisCapabilityActivation,
    ForensicEvidenceAnalysisCapabilityError,
    ForensicEvidenceAnalysisOperation,
    ForensicEvidenceAnalysisPreparation,
    ForensicEvidenceAnalysisRequest,
    ForensicEvidenceAnalysisSandboxBinding,
    ForensicEvidenceAnalysisSandboxRef,
    ForensicEvidenceAnalysisTool,
    ForensicEvidenceCustodyBinding,
    ForensicEvidenceCustodyRef,
    ForensicEvidenceDigestSource,
    ForensicEvidenceInputKind,
    ForensicEvidenceParser,
    ForensicEvidenceSignalKind,
    ForensicSurfaceAnalysisMapping,
    activate_forensic_evidence_analysis_capability,
    bind_forensic_evidence_analysis_sandbox,
    bind_forensic_evidence_custody,
    forensic_evidence_analysis_capability_bundle,
    forensic_surface_scope_target,
    prepare_forensic_evidence_analysis,
    registered_forensic_evidence_analysis_binding,
    registered_forensic_evidence_analysis_capability_definition,
    registered_forensic_evidence_analysis_capability_domain_classification,
    registered_forensic_evidence_rule_set,
    resolve_forensic_evidence_analysis_binding,
    resolve_forensic_evidence_analysis_capability_domain_classification,
    resolve_registered_forensic_evidence_rule_set,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity, CapabilitySideEffectClass
from pajin.control_plane.domain_worker_boundaries import (
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    registered_domain_worker_boundary_profiles,
)
from pajin.discovery import (
    ForensicImmutableArtifactSurface,
    ForensicImmutableArtifactSurfaceLocator,
    ForensicSourceRootKind,
    ForensicSurfaceClass,
    ForensicSurfaceRegistryError,
    bind_forensic_immutable_artifact_surface_reference,
    forensic_artifact_surface_locator,
    forensic_disk_surface_locator,
    forensic_log_surface_locator,
    forensic_memory_surface_locator,
    forensic_source_provenance_coordinate,
    registered_forensic_immutable_artifact_locator_registry,
    typed_forensic_immutable_artifact_surface,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
AUTHORIZATION_DIGEST = sha256(b"forensic-evidence-custody-authorization").hexdigest()
PARSER_EXECUTABLE_DIGEST = sha256(b"forensic-evidence-parser").hexdigest()
PARSER_CONFIGURATION_DIGEST = sha256(b"forensic-evidence-parser-configuration").hexdigest()
SANDBOX_IMAGE_DIGEST = sha256(b"forensic-evidence-sandbox-image").hexdigest()

_OPERATION_BY_CLASS = {
    ForensicSurfaceClass.DISK: ForensicEvidenceAnalysisOperation.DISK_EVIDENCE,
    ForensicSurfaceClass.MEMORY: ForensicEvidenceAnalysisOperation.MEMORY_EVIDENCE,
    ForensicSurfaceClass.LOG: ForensicEvidenceAnalysisOperation.LOG_EVIDENCE,
    ForensicSurfaceClass.ARTIFACT: ForensicEvidenceAnalysisOperation.ARTIFACT_EVIDENCE,
}
_PARSER_BY_CLASS = {
    ForensicSurfaceClass.DISK: ForensicEvidenceParser.DISK_EVIDENCE,
    ForensicSurfaceClass.MEMORY: ForensicEvidenceParser.MEMORY_EVIDENCE,
    ForensicSurfaceClass.LOG: ForensicEvidenceParser.LOG_EVIDENCE,
    ForensicSurfaceClass.ARTIFACT: ForensicEvidenceParser.ARTIFACT_EVIDENCE,
}
_INPUT_KIND_BY_CLASS = {
    ForensicSurfaceClass.DISK: ForensicEvidenceInputKind.DISK_EVIDENCE,
    ForensicSurfaceClass.MEMORY: ForensicEvidenceInputKind.MEMORY_EVIDENCE,
    ForensicSurfaceClass.LOG: ForensicEvidenceInputKind.LOG_EVIDENCE,
    ForensicSurfaceClass.ARTIFACT: ForensicEvidenceInputKind.ARTIFACT_EVIDENCE,
}
_LOCATOR_KIND_BY_CLASS = {
    ForensicSurfaceClass.DISK: "forensics-disk",
    ForensicSurfaceClass.MEMORY: "forensics-memory",
    ForensicSurfaceClass.LOG: "forensics-log",
    ForensicSurfaceClass.ARTIFACT: "forensics-artifact",
}

_BINDING_FALSE_MARKERS = (
    "custodyRuntimeVerified",
    "authorizationVerified",
    "provenanceSanitizationVerified",
    "provenancePreserved",
    "provenancePreservationVerified",
    "parserResultAvailable",
    "sourceResolved",
    "sourceReadAuthorized",
    "sourceMountAuthorized",
    "sourceCopyAuthorized",
    "analysisAuthorized",
    "parserInvocationAuthorized",
    "sandboxSelected",
    "workerSelectionAuthorized",
    "workerJobMaterializationAvailable",
    "evidenceMountMaterialized",
    "credentialAccessAuthorized",
    "credentialUseAuthorized",
    "secretMaterialAccessAuthorized",
    "lateralMovementAuthorized",
    "sourceMutationAuthorized",
    "evidenceMutationAuthorized",
    "targetExecutionAuthorized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "observationProductionAuthorized",
    "evidenceSealingAuthorized",
    "graphAdmissionAuthorized",
    "hypothesisAuthority",
    "findingAuthority",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "runtimeSupportAssertedByBinding",
    "executionAuthorized",
)
_CUSTODY_FALSE_MARKERS = (
    "rawSourceBytesEmbedded",
    "rawDiskContentEmbedded",
    "rawMemoryContentEmbedded",
    "rawLogContentEmbedded",
    "rawArtifactContentEmbedded",
    "rawProvenanceRecordEmbedded",
    "mutablePathEmbedded",
    "sourceURIEmbedded",
    "objectKeyEmbedded",
    "filenameEmbedded",
    "secretMaterialEmbedded",
    "credentialMaterialEmbedded",
    "credentialReferenceEmbedded",
    "authorizationVerifiedByPreparation",
    "sourceRootVerified",
    "sourceArtifactRecordVerified",
    "provenanceRecordVerified",
    "sourceSealVerified",
    "sourceAuthenticityVerified",
    "sourceImmutabilityVerified",
    "sourceArtifactMembershipVerified",
    "chainOfCustodyVerified",
    "custodyRuntimeVerified",
    "artifactDigestVerified",
    "artifactBytesVerified",
    "evidenceClassVerified",
    "sourceFormatVerified",
    "provenanceSanitizationVerified",
    "provenancePreserved",
    "provenancePreservationVerified",
    "parserResultAvailable",
    "sourceResolved",
    "sourceReadAuthorized",
    "sourceMountAuthorized",
    "sourceCopyAuthorized",
    "evidenceMutationAuthorized",
    "mountMaterialized",
    "noMutationVerified",
    "executionAuthorized",
)
_SANDBOX_FALSE_MARKERS = (
    "hostFilesystemAccessAllowed",
    "credentialInjectionAllowed",
    "secretMaterialInjectionAllowed",
    "environmentInheritanceAllowed",
    "symlinkTraversalAllowed",
    "deviceAccessAllowed",
    "pluginLoadingAllowed",
    "shellCommandAllowed",
    "runtimeAttested",
    "sandboxSelected",
    "evidenceMountMaterialized",
    "sourceReadAuthorized",
    "sourceMountAuthorized",
    "sourceCopyAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "secretMaterialAccessAuthorized",
    "credentialUseAuthorized",
    "lateralMovementAuthorized",
    "sourceMutationAuthorized",
    "evidenceMutationAuthorized",
    "parserConformanceVerified",
    "provenancePreserved",
    "provenancePreservationVerified",
    "parserResultAvailable",
    "noMutationVerified",
    "workerJobMaterialized",
    "parserInvocationAuthorized",
    "targetExecutionAuthorized",
    "rawResultEchoAllowed",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_REQUEST_FALSE_MARKERS = (
    "rawSourceBytesEmbedded",
    "rawDiskContentEmbedded",
    "rawMemoryContentEmbedded",
    "rawLogContentEmbedded",
    "rawArtifactContentEmbedded",
    "rawProvenanceRecordEmbedded",
    "mutablePathEmbedded",
    "sourceURIEmbedded",
    "objectKeyEmbedded",
    "filenameEmbedded",
    "secretMaterialEmbedded",
    "credentialMaterialEmbedded",
    "credentialReferenceEmbedded",
    "callerParserOrPluginEmbedded",
    "sourceResolutionPerformed",
    "sourceResolutionAuthorized",
    "sourceReadPerformed",
    "sourceReadAuthorized",
    "sourceMountAuthorized",
    "sourceCopyAuthorized",
    "evidenceMountMaterialized",
    "sandboxInvocationAuthorized",
    "workerJobMaterializationAvailable",
    "parserInvocationAuthorized",
    "credentialAccessAuthorized",
    "credentialUseAuthorized",
    "secretMaterialAccessAuthorized",
    "lateralMovementAuthorized",
    "sourceMutationAuthorized",
    "evidenceMutationAuthorized",
    "targetExecutionAuthorized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "provenancePreserved",
    "provenancePreservationVerified",
    "parserResultAvailable",
    "analysisExecuted",
)
_PREPARATION_FALSE_MARKERS = (
    "custodyRuntimeVerified",
    "authorizationVerifiedByPreparation",
    "sourceRootVerified",
    "sourceArtifactRecordVerified",
    "provenanceRecordVerified",
    "sourceSealVerified",
    "sourceAuthenticityVerified",
    "sourceImmutabilityVerified",
    "sourceArtifactMembershipVerified",
    "chainOfCustodyVerified",
    "artifactDigestVerified",
    "artifactBytesVerified",
    "evidenceClassVerified",
    "sourceFormatVerified",
    "provenanceSanitizationVerified",
    "provenancePreserved",
    "provenancePreservationVerified",
    "parserResultAvailable",
    "noMutationVerified",
    "sourceResolved",
    "sourceReadPerformed",
    "sandboxRuntimeAvailable",
    "sandboxRuntimeAttested",
    "sandboxSelected",
    "evidenceMountMaterialized",
    "budgetReserved",
    "workerJobMaterialized",
    "credentialAccessed",
    "credentialUsed",
    "secretMaterialAccessed",
    "sourceCopyPerformed",
    "targetExecutionPerformed",
    "lateralMovementPerformed",
    "networkRequestPerformed",
    "dnsRequestPerformed",
    "analysisExecuted",
    "sourceMutated",
    "evidenceMutationPerformed",
    "observationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "hypothesisProduced",
    "findingProduced",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "gatewayDispatchAuthorized",
    "workerSelectionAuthorized",
    "executionAuthorized",
)
_BUDGET_ZERO_FIELDS = (
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


def _seed(label: str) -> bytes:
    return sha256(f"forensic-evidence-analysis:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"forensic-evidence-analysis.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


@cache
def _activation() -> tuple[ForensicEvidenceAnalysisCapabilityActivation, CapabilityReleaseRef]:
    tools = ToolRegistry()
    tools.register(ForensicEvidenceAnalysisTool())
    bundle = forensic_evidence_analysis_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="forensic-evidence-analysis.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="forensic-evidence-analysis.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_seed("reviewer"),
    )
    review = CapabilityReviewStatement(
        capability=bundle.capability(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"forensic-evidence-analysis-review").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(days=2),
        expiresAt=NOW + timedelta(days=5),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=bundle.capability(),
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=NOW - timedelta(days=1),
    )
    signed_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(signed_bundle,),
        clock=lambda: NOW,
    )
    release_ref = signed_bundle.release.statement.reference()
    return (
        activate_forensic_evidence_analysis_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_ref,
        ),
        release_ref,
    )


def _surface(
    surface_class: ForensicSurfaceClass = ForensicSurfaceClass.DISK,
    *,
    source_root_sha256: str = "1" * 64,
    source_artifact_record_sha256: str = "2" * 64,
    provenance_record_sha256: str = "3" * 64,
    artifact_sha256: str = "4" * 64,
    artifact_bytes: int = 4_096,
) -> ForensicImmutableArtifactSurface:
    provenance = forensic_source_provenance_coordinate(
        source_root_kind=ForensicSourceRootKind.PAJIN_RUN_INTEGRITY_V1,
        source_root_sha256=source_root_sha256,
        source_artifact_record_sha256=source_artifact_record_sha256,
        provenance_record_sha256=provenance_record_sha256,
        artifact_sha256=artifact_sha256,
        artifact_bytes=artifact_bytes,
    )
    locator: ForensicImmutableArtifactSurfaceLocator
    if surface_class is ForensicSurfaceClass.DISK:
        locator = forensic_disk_surface_locator(provenance=provenance)
    elif surface_class is ForensicSurfaceClass.MEMORY:
        locator = forensic_memory_surface_locator(provenance=provenance)
    elif surface_class is ForensicSurfaceClass.LOG:
        locator = forensic_log_surface_locator(provenance=provenance)
    else:
        locator = forensic_artifact_surface_locator(provenance=provenance)
    return typed_forensic_immutable_artifact_surface(locator=locator)


def _custody(surface: ForensicImmutableArtifactSurface) -> ForensicEvidenceCustodyBinding:
    return bind_forensic_evidence_custody(
        surface=surface,
        authorization_digest=AUTHORIZATION_DIGEST,
    )


def _sandbox(
    surface: ForensicImmutableArtifactSurface,
    *,
    max_artifact_bytes: int = 65_536,
    parser_executable_sha256: str = PARSER_EXECUTABLE_DIGEST,
    parser_configuration_sha256: str = PARSER_CONFIGURATION_DIGEST,
    sandbox_image_sha256: str = SANDBOX_IMAGE_DIGEST,
    max_output_bytes: int = 131_072,
    max_runtime_seconds: int = 30,
    max_memory_mib: int = 256,
    max_process_count: int = 4,
    max_parser_work_units: int = 100_000,
    max_recursion_depth: int = 16,
    max_decompression_ratio: int = 50,
    max_decompressed_bytes: int = 262_144,
) -> ForensicEvidenceAnalysisSandboxBinding:
    return bind_forensic_evidence_analysis_sandbox(
        surface=surface,
        parser_executable_sha256=parser_executable_sha256,
        parser_configuration_sha256=parser_configuration_sha256,
        sandbox_image_sha256=sandbox_image_sha256,
        max_artifact_bytes=max_artifact_bytes,
        max_output_bytes=max_output_bytes,
        max_runtime_seconds=max_runtime_seconds,
        max_memory_mib=max_memory_mib,
        max_process_count=max_process_count,
        max_parser_work_units=max_parser_work_units,
        max_recursion_depth=max_recursion_depth,
        max_decompression_ratio=max_decompression_ratio,
        max_decompressed_bytes=max_decompressed_bytes,
    )


def _adapter(
    surface: ForensicImmutableArtifactSurface,
    *,
    max_artifact_bytes: int = 65_536,
    parser_executable_sha256: str = PARSER_EXECUTABLE_DIGEST,
    parser_configuration_sha256: str = PARSER_CONFIGURATION_DIGEST,
    sandbox_image_sha256: str = SANDBOX_IMAGE_DIGEST,
    max_output_bytes: int = 131_072,
    max_runtime_seconds: int = 30,
    max_memory_mib: int = 256,
    max_process_count: int = 4,
    max_parser_work_units: int = 100_000,
    max_recursion_depth: int = 16,
    max_decompression_ratio: int = 50,
    max_decompressed_bytes: int = 262_144,
) -> BoundedForensicEvidenceParserAdapter:
    return BoundedForensicEvidenceParserAdapter(
        _custody(surface),
        _sandbox(
            surface,
            max_artifact_bytes=max_artifact_bytes,
            parser_executable_sha256=parser_executable_sha256,
            parser_configuration_sha256=parser_configuration_sha256,
            sandbox_image_sha256=sandbox_image_sha256,
            max_output_bytes=max_output_bytes,
            max_runtime_seconds=max_runtime_seconds,
            max_memory_mib=max_memory_mib,
            max_process_count=max_process_count,
            max_parser_work_units=max_parser_work_units,
            max_recursion_depth=max_recursion_depth,
            max_decompression_ratio=max_decompression_ratio,
            max_decompressed_bytes=max_decompressed_bytes,
        ),
    )


def _campaign(
    sample_campaign: CampaignManifest,
    *,
    surface: ForensicImmutableArtifactSurface,
    include_surface: bool = True,
    allow_get: bool = True,
    allow_private: bool = False,
    deny: list[str] | None = None,
    wildcard_only: bool = False,
) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    if wildcard_only:
        allow = [f"{FORENSIC_SURFACE_SCOPE_ORIGIN}/surfaces/*"]
    elif include_surface:
        allow = [forensic_surface_scope_target(surface)]
    else:
        allow = ["https://unrelated.example.test/"]
    payload["spec"]["scope"] = {"allow": allow, "deny": deny or []}
    methods = set(payload["spec"]["rulesOfEngagement"]["allowedMethods"])
    if allow_get:
        methods.add("GET")
    else:
        methods.discard("GET")
    payload["spec"]["rulesOfEngagement"]["allowedMethods"] = sorted(methods)
    payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"] = allow_private
    return CampaignManifest.model_validate(payload)


def _prepare(
    sample_campaign: CampaignManifest,
    *,
    surface: ForensicImmutableArtifactSurface | None = None,
) -> ForensicEvidenceAnalysisPreparation:
    if surface is None:
        cached = _cached_default_preparation(sample_campaign.model_dump_json(by_alias=True))
        return cached.model_copy(deep=True)
    return _prepare_uncached(sample_campaign, surface=surface)


@cache
def _cached_default_preparation(campaign_json: str) -> ForensicEvidenceAnalysisPreparation:
    return _prepare_uncached(
        CampaignManifest.model_validate_json(campaign_json),
        surface=_surface(),
    )


def _prepare_uncached(
    sample_campaign: CampaignManifest,
    *,
    surface: ForensicImmutableArtifactSurface,
) -> ForensicEvidenceAnalysisPreparation:
    selected = surface
    activation, release = _activation()
    return prepare_forensic_evidence_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign, surface=selected),
        surface=selected,
        operation=_OPERATION_BY_CLASS[selected.surface_class],
        parser=_adapter(selected),
        request_id="tool_forensic_evidence_analysis_prepare",
        agent_id="agent:forensic-evidence-analysis",
    )


def test_capability_binding_pins_forensic_surface_cap_002_and_worker_profile() -> None:
    definition = registered_forensic_evidence_analysis_capability_definition()
    binding = registered_forensic_evidence_analysis_binding()
    tools = ToolRegistry()
    tools.register(ForensicEvidenceAnalysisTool())
    bundle = forensic_evidence_analysis_capability_bundle(tools)
    worker = next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.FORENSICS
    )

    assert definition.capability_id == FORENSIC_EVIDENCE_ANALYSIS_CAPABILITY_ID
    assert definition.supported_surface_types == (
        "forensics-artifact",
        "forensics-disk",
        "forensics-log",
        "forensics-memory",
    )
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.network_access is False
    assert definition.approval_required is True
    assert {item.role for item in bundle.authorities.capabilities()[0].authorities} == set(
        CapabilityAuthorityRole
    )
    assert binding.capability == bundle.capability()
    assert binding.worker_profile == worker.reference()
    assert worker.network_boundary is WorkerNetworkBoundary.DISABLED_BY_DEFAULT
    assert worker.filesystem_boundary is WorkerFilesystemBoundary.IMMUTABLE_EVIDENCE
    assert worker.credential_boundary is WorkerCredentialBoundary.NONE
    assert worker.runtime_boundary is WorkerRuntimeBoundary.PROVENANCE_PRESERVING_PARSER
    assert worker.required_identity_dimensions == ("evidence-source", "parser")
    assert worker.required_budget_dimensions == ("artifact-bytes", "runtime")
    assert worker.provenance_preservation_required is True
    assert all(
        binding.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _BINDING_FALSE_MARKERS
    )
    assert resolve_forensic_evidence_analysis_binding(binding.reference()) == binding

    classification = registered_forensic_evidence_analysis_capability_domain_classification()
    assert classification.domain_classification.domain is SecurityDomain.FORENSICS
    assert classification.global_domain_inventory_changed is False
    assert classification.existing_capability_reused is False
    assert (
        resolve_forensic_evidence_analysis_capability_domain_classification(
            classification.reference()
        )
        == classification
    )


def test_code_owned_rule_set_is_exact_bounded_and_non_executable() -> None:
    rule_set = registered_forensic_evidence_rule_set()
    payload = rule_set.model_dump(mode="json", by_alias=True)

    assert rule_set.rule_set_id == "pajin.forensics.parser-rules.baseline"
    assert rule_set.signal_vocabulary == tuple(
        sorted(ForensicEvidenceSignalKind, key=lambda item: item.value)
    )
    assert tuple(item.surface_class for item in rule_set.surface_analysis_mapping) == tuple(
        sorted(ForensicSurfaceClass, key=lambda item: item.value)
    )
    for item in rule_set.surface_analysis_mapping:
        assert isinstance(item, ForensicSurfaceAnalysisMapping)
        assert item.locator_kind == _LOCATOR_KIND_BY_CLASS[item.surface_class]
        assert item.input_kind is _INPUT_KIND_BY_CLASS[item.surface_class]
        assert item.digest_source is ForensicEvidenceDigestSource.ARTIFACT_SHA256
        assert item.operation is _OPERATION_BY_CLASS[item.surface_class]
        assert item.parser is _PARSER_BY_CLASS[item.surface_class]
    assert payload["ruleSetOnly"] is True
    for alias in (
        "callerRuleSelectionAllowed",
        "pluginLoadingAllowed",
        "parserRuntimeAvailable",
        "analysisTruthConfirmed",
        "findingAuthority",
        "executionAuthorized",
    ):
        assert payload[alias] is False
    assert resolve_registered_forensic_evidence_rule_set(rule_set.reference()) == rule_set


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("toolId", "attacker.substituted-forensic-tool"),
        ("toolVersion", "9.9.9"),
        ("toolDigest", "0" * 64),
        ("riskTier", 0),
    ),
)
def test_activation_rejects_recomputed_action_metadata_substitution(
    field: str,
    replacement: str | int,
) -> None:
    activation, _ = _activation()
    original = activation.activation_set
    payload = original.model_dump(mode="json", by_alias=True)
    expected_action = original.binding.action_capability
    payload["binding"]["actionCapability"][field] = replacement
    payload["binding"]["actionCapability"]["capabilityDigest"] = ""
    tampered = type(expected_action).model_validate(payload["binding"]["actionCapability"])
    payload["binding"]["actionCapability"] = tampered.model_dump(mode="json", by_alias=True)
    payload["activationSetId"] = ""
    payload["activationSetDigest"] = ""
    with pytest.raises(ValidationError, match="activation references another Capability"):
        type(original).model_validate(payload)


def test_activation_rejects_authority_set_identity_substitution() -> None:
    original = _activation()[0].activation_set
    payload = original.model_dump(mode="json", by_alias=True)
    payload["binding"]["capability"]["authoritySetId"] = f"capability-authority-set_{'0' * 64}"
    payload["binding"]["capability"]["authoritySetDigest"] = "0" * 64
    payload["activationSetId"] = ""
    payload["activationSetDigest"] = ""
    with pytest.raises(ValidationError, match="activation references another Capability"):
        type(original).model_validate(payload)


@pytest.mark.parametrize("surface_class", tuple(ForensicSurfaceClass))
def test_all_surface_classes_bind_complete_custody_parser_sandbox_and_request(
    surface_class: ForensicSurfaceClass,
) -> None:
    surface = _surface(surface_class)
    custody = _custody(surface)
    sandbox = _sandbox(surface)
    request = BoundedForensicEvidenceParserAdapter(custody, sandbox).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface_class],
    )

    assert custody.surface == surface
    assert custody.surface is not surface
    assert custody.surface.locator.provenance == surface.locator.provenance
    assert custody.input_kind is _INPUT_KIND_BY_CLASS[surface_class]
    assert custody.artifact_sha256 == surface.locator.provenance.artifact_sha256
    assert custody.artifact_bytes == surface.locator.provenance.artifact_bytes
    assert custody.custody_authority_id == FORENSIC_EVIDENCE_CUSTODY_AUTHORITY_ID
    assert custody.custody_object_id == f"forensic-evidence_{surface.surface_digest}"
    assert custody.authorization_id == f"forensic-analysis-authorization_{AUTHORIZATION_DIGEST}"
    assert sandbox.surface == surface
    assert sandbox.operation is _OPERATION_BY_CLASS[surface_class]
    assert sandbox.parser is _PARSER_BY_CLASS[surface_class]
    assert request.surface == surface
    assert request.custody.surface == surface.reference()
    assert request.sandbox.surface == surface.reference()
    assert request.input_kind is _INPUT_KIND_BY_CLASS[surface_class]
    assert request.operation is _OPERATION_BY_CLASS[surface_class]
    assert request.parser is _PARSER_BY_CLASS[surface_class]
    assert request.target == forensic_surface_scope_target(surface)
    assert request.method == "GET"
    assert request.output_schema == FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA
    assert request.budget.request_count == 1
    assert request.budget.artifact_bytes == 4_096
    assert request.budget.parser_work_unit == FORENSIC_PARSER_WORK_UNIT
    assert request.budget.max_parser_work_units == 100_000
    assert request.budget.max_recursion_depth == 16
    assert request.budget.max_decompression_ratio == 50
    assert all(
        request.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _REQUEST_FALSE_MARKERS
    )


@pytest.mark.parametrize("surface_class", tuple(ForensicSurfaceClass))
def test_zero_byte_artifact_is_preserved_without_false_read_or_verification_claims(
    surface_class: ForensicSurfaceClass,
) -> None:
    surface = _surface(surface_class, artifact_bytes=0)
    custody = _custody(surface)
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface_class],
    )
    assert custody.artifact_bytes == 0
    assert request.budget.artifact_bytes == 0
    assert request.source_read_performed is False
    assert custody.artifact_bytes_verified is False


def test_sandbox_pins_profile_digests_mount_and_parser_ceilings_without_runtime() -> None:
    surface = _surface(ForensicSurfaceClass.MEMORY)
    sandbox = _sandbox(surface)
    payload = sandbox.model_dump(mode="json", by_alias=True)
    worker = next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.FORENSICS
    )

    assert sandbox.deployment_id == FORENSIC_EVIDENCE_ANALYSIS_DEPLOYMENT_ID
    assert sandbox.worker_profile == worker.reference()
    assert sandbox.parser is ForensicEvidenceParser.MEMORY_EVIDENCE
    assert sandbox.parser_executable_sha256 == PARSER_EXECUTABLE_DIGEST
    assert sandbox.parser_configuration_sha256 == PARSER_CONFIGURATION_DIGEST
    assert sandbox.sandbox_image_sha256 == SANDBOX_IMAGE_DIGEST
    assert sandbox.run_as_identity == FORENSIC_EVIDENCE_ANALYSIS_RUN_AS_IDENTITY
    assert sandbox.evidence_mount_target == FORENSIC_EVIDENCE_MOUNT_TARGET
    assert sandbox.output_schema == FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA
    assert sandbox.max_artifact_bytes == 65_536
    assert sandbox.max_output_bytes == 131_072
    assert sandbox.max_runtime_seconds == 30
    assert sandbox.max_memory_mib == 256
    assert sandbox.max_process_count == 4
    assert sandbox.parser_work_unit == FORENSIC_PARSER_WORK_UNIT
    assert sandbox.max_parser_work_units == 100_000
    assert sandbox.max_recursion_depth == 16
    assert sandbox.max_decompression_ratio == 50
    assert sandbox.max_decompressed_bytes == 262_144
    for alias in (
        "configurationOnly",
        "networkDisabledRequired",
        "dnsDisabledRequired",
        "readOnlyRootFilesystemRequired",
        "immutableReadOnlyEvidenceMountRequired",
        "evidenceMountNoexecRequired",
        "noNewPrivilegesRequired",
        "nonRootRuntimeRequired",
        "exactParserExecutableDigestRequired",
        "exactParserConfigurationDigestRequired",
        "exactSandboxImageDigestRequired",
        "exactRuleSetRequired",
        "coreDumpDisabledRequired",
        "provenancePreservationRequired",
        "noSourceMutationRequired",
        "prePostNoMutationEvidenceRequired",
    ):
        assert payload[alias] is True
    assert all(payload[alias] is False for alias in _SANDBOX_FALSE_MARKERS)
    assert ForensicEvidenceAnalysisSandboxBinding.model_validate(payload) == sandbox

    reference_payload = sandbox.reference().model_dump(mode="json", by_alias=True)
    reference_payload["sandboxBindingId"] = f"forensic-analysis-sandbox_{'0' * 64}"
    with pytest.raises(ValidationError, match="reference differs"):
        ForensicEvidenceAnalysisSandboxRef.model_validate(reference_payload)


def test_signed_preparation_stops_at_prepared_action_without_execution_or_admission(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    request = preparation.prepared_action.request
    payload = preparation.model_dump(mode="json", by_alias=True)

    assert preparation.state == "prepared-not-authorized"
    assert preparation.current_campaign_bound is True
    assert preparation.exact_surface_parser_scope_bound is True
    assert preparation.custody_authorization_reference_bound is True
    assert preparation.exact_rule_set_bound is True
    assert preparation.network_disabled_sandbox_bound is True
    assert preparation.zero_live_channels_bound is True
    assert preparation.provenance_preservation_requirements_bound is True
    assert preparation.analysis_request_adapted is True
    assert preparation.capability_prepared is True
    assert preparation.matched_surface_allow_rule == forensic_surface_scope_target(
        preparation.surface
    )
    assert preparation.prepared_action.release == preparation.release
    assert request.method == "GET"
    assert request.target == forensic_surface_scope_target(preparation.surface)
    assert request.arguments == preparation.analysis_request.model_dump(mode="json", by_alias=True)
    assert all(payload[alias] is False for alias in _PREPARATION_FALSE_MARKERS)
    assert preparation.preparation_id == (
        f"forensic-evidence-analysis-preparation_{preparation.preparation_digest}"
    )
    assert ForensicEvidenceAnalysisPreparation.model_validate(payload) == preparation


@pytest.mark.parametrize(
    ("include_surface", "allow_get", "wildcard_only", "match"),
    (
        (False, True, False, "lacks an exact"),
        (True, False, False, "Scope binding failed closed"),
        (True, True, True, "lacks an exact"),
    ),
)
def test_preparation_requires_exact_parser_bound_surface_scope_and_get(
    sample_campaign: CampaignManifest,
    include_surface: bool,
    allow_get: bool,
    wildcard_only: bool,
    match: str,
) -> None:
    surface = _surface()
    activation, release = _activation()
    with pytest.raises(
        (ForensicEvidenceAnalysisCapabilityError, ValidationError),
        match=match,
    ):
        prepare_forensic_evidence_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(
                sample_campaign,
                surface=surface,
                include_surface=include_surface,
                allow_get=allow_get,
                wildcard_only=wildcard_only,
            ),
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
            parser=_adapter(surface),
            request_id="tool_forensic_scope_rejected",
            agent_id="agent:forensic-evidence-analysis",
        )


def test_campaign_deny_overrides_exact_parser_bound_surface_allow(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(ForensicSurfaceClass.LOG)
    activation, release = _activation()
    target = forensic_surface_scope_target(surface)
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="deny rule"):
        prepare_forensic_evidence_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign, surface=surface, deny=[target]),
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
            parser=_adapter(surface),
            request_id="tool_forensic_scope_denied",
            agent_id="agent:forensic-evidence-analysis",
        )


def test_private_network_scope_flag_cannot_open_network_or_dns(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(ForensicSurfaceClass.ARTIFACT)
    activation, release = _activation()
    preparation = prepare_forensic_evidence_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign, surface=surface, allow_private=True),
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
        parser=_adapter(surface),
        request_id="tool_forensic_private_scope",
        agent_id="agent:forensic-evidence-analysis",
    )
    assert preparation.campaign_scope.allow_private_networks is True
    assert preparation.analysis_request.budget.network_requests == 0
    assert preparation.analysis_request.budget.dns_queries == 0
    assert preparation.analysis_request.network_access_authorized is False
    assert preparation.analysis_request.dns_access_authorized is False


def test_scope_target_binds_both_surface_identity_and_code_owned_parser() -> None:
    disk = _surface(ForensicSurfaceClass.DISK)
    memory = _surface(ForensicSurfaceClass.MEMORY)
    assert forensic_surface_scope_target(disk) == (
        f"{FORENSIC_SURFACE_SCOPE_ORIGIN}/surfaces/{disk.surface_id}/parsers/disk-evidence-parser"
    )
    assert forensic_surface_scope_target(disk) != forensic_surface_scope_target(memory)


def test_complete_surface_and_reference_binding_rejects_structurally_valid_substitution() -> None:
    surface = _surface(ForensicSurfaceClass.ARTIFACT)
    reference = surface.reference()
    payload = reference.model_dump(mode="json", by_alias=True)
    payload["surfaceDigest"] = "0" * 64
    payload["surfaceId"] = f"forensics-immutable-artifact-surface_{'0' * 64}"
    structurally_valid = type(reference).model_validate(payload)

    with pytest.raises(ForensicSurfaceRegistryError):
        bind_forensic_immutable_artifact_surface_reference(
            reference=structurally_valid,
            surface=surface,
        )

    custody_payload = _custody(surface).reference().model_dump(mode="json", by_alias=True)
    custody_payload["surface"] = structurally_valid.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError):
        ForensicEvidenceCustodyRef.model_validate(custody_payload)


def test_provenance_root_record_digest_bytes_and_class_drift_fail_closed() -> None:
    baseline = _surface(ForensicSurfaceClass.DISK)
    alternatives = (
        _surface(ForensicSurfaceClass.DISK, source_root_sha256="5" * 64),
        _surface(ForensicSurfaceClass.DISK, source_artifact_record_sha256="5" * 64),
        _surface(ForensicSurfaceClass.DISK, provenance_record_sha256="5" * 64),
        _surface(ForensicSurfaceClass.DISK, artifact_sha256="5" * 64),
        _surface(ForensicSurfaceClass.DISK, artifact_bytes=4_097),
        _surface(ForensicSurfaceClass.MEMORY),
    )
    baseline_custody = _custody(baseline)
    baseline_sandbox = _sandbox(baseline)

    for alternative in alternatives:
        assert alternative.surface_digest != baseline.surface_digest
        with pytest.raises(
            ForensicEvidenceAnalysisCapabilityError,
            match="different Surfaces",
        ):
            BoundedForensicEvidenceParserAdapter(
                baseline_custody,
                _sandbox(alternative),
            )
        with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="custody differs"):
            BoundedForensicEvidenceParserAdapter(
                baseline_custody,
                baseline_sandbox,
            ).prepare_request(
                surface=alternative,
                operation=_OPERATION_BY_CLASS[alternative.surface_class],
            )


def test_surface_operation_parser_custody_and_sandbox_substitution_fail_closed() -> None:
    disk = _surface(ForensicSurfaceClass.DISK)
    memory = _surface(ForensicSurfaceClass.MEMORY)
    adapter = _adapter(disk)

    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="Surface class"):
        adapter.prepare_request(
            surface=disk,
            operation=ForensicEvidenceAnalysisOperation.MEMORY_EVIDENCE,
        )
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="custody differs"):
        adapter.prepare_request(
            surface=memory,
            operation=ForensicEvidenceAnalysisOperation.MEMORY_EVIDENCE,
        )

    request = adapter.prepare_request(
        surface=disk,
        operation=ForensicEvidenceAnalysisOperation.DISK_EVIDENCE,
    )
    payload = request.model_dump(mode="json", by_alias=True)
    payload["parser"] = ForensicEvidenceParser.MEMORY_EVIDENCE.value
    with pytest.raises(ValidationError, match="exact bindings"):
        ForensicEvidenceAnalysisRequest.model_validate(payload)

    payload = request.model_dump(mode="json", by_alias=True)
    payload["custody"]["artifactSHA256"] = "0" * 64
    with pytest.raises(ValidationError):
        ForensicEvidenceAnalysisRequest.model_validate(payload)


def test_artifact_must_fit_exact_sandbox_ceiling() -> None:
    surface = _surface(artifact_bytes=65_537)
    adapter = _adapter(surface, max_artifact_bytes=65_536)
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="byte ceiling"):
        adapter.prepare_request(
            surface=surface,
            operation=ForensicEvidenceAnalysisOperation.DISK_EVIDENCE,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("maxArtifactBytes", 0),
        ("maxArtifactBytes", 536_870_913),
        ("maxArtifactBytes", True),
        ("maxOutputBytes", 1_023),
        ("maxOutputBytes", 16_777_217),
        ("maxRuntimeSeconds", 0),
        ("maxRuntimeSeconds", 301),
        ("maxMemoryMiB", 63),
        ("maxMemoryMiB", 4_097),
        ("maxProcessCount", 0),
        ("maxProcessCount", 65),
        ("maxParserWorkUnits", 0),
        ("maxParserWorkUnits", 8_589_934_593),
        ("maxRecursionDepth", 0),
        ("maxRecursionDepth", 129),
        ("maxDecompressionRatio", 0),
        ("maxDecompressionRatio", 1_001),
        ("maxDecompressedBytes", 0),
        ("maxDecompressedBytes", 4_294_967_297),
    ),
)
def test_sandbox_resource_and_parser_ceiling_bounds_fail_closed(
    field: str,
    value: object,
) -> None:
    payload = _sandbox(_surface()).model_dump(mode="json", by_alias=True)
    payload[field] = value
    payload["sandboxBindingDigest"] = ""
    payload["sandboxBindingId"] = ""
    with pytest.raises(ValidationError):
        ForensicEvidenceAnalysisSandboxBinding.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "increment"),
    (
        ("requestCount", 1),
        ("artifactBytes", 1),
        ("maxOutputBytes", 1),
        ("runtimeSeconds", 1),
        ("memoryMiB", 1),
        ("processCount", 1),
        ("maxParserWorkUnits", 1),
        ("maxRecursionDepth", 1),
        ("maxDecompressionRatio", 1),
        ("maxDecompressedBytes", 1),
    ),
)
def test_request_cannot_drift_from_surface_custody_or_sandbox_ceilings(
    field: str,
    increment: int,
) -> None:
    surface = _surface()
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    payload = request.model_dump(mode="json", by_alias=True)
    payload["budget"][field] += increment
    with pytest.raises(ValidationError):
        ForensicEvidenceAnalysisRequest.model_validate(payload)


@pytest.mark.parametrize("field", _BUDGET_ZERO_FIELDS)
def test_request_cannot_expand_live_secret_mutation_or_execution_budget(field: str) -> None:
    surface = _surface()
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    payload = request.model_dump(mode="json", by_alias=True)
    payload["budget"][field] = 1
    with pytest.raises(ValidationError):
        ForensicEvidenceAnalysisRequest.model_validate(payload)

    payload["budget"][field] = True
    with pytest.raises(ValidationError, match="must be integers"):
        ForensicEvidenceAnalysisRequest.model_validate(payload)


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
def test_binding_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    original = registered_forensic_evidence_analysis_binding().model_dump(
        mode="json", by_alias=True
    )
    for value in (True, 0):
        payload = deepcopy(original)
        payload[alias] = value
        payload["bindingDigest"] = ""
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _CUSTODY_FALSE_MARKERS)
def test_custody_rejects_verification_or_authority_escalation(alias: str) -> None:
    original = _custody(_surface()).model_dump(mode="json", by_alias=True)
    for value in (True, 0):
        payload = deepcopy(original)
        payload[alias] = value
        payload["custodyBindingDigest"] = ""
        payload["custodyBindingId"] = ""
        with pytest.raises(ValidationError):
            ForensicEvidenceCustodyBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _SANDBOX_FALSE_MARKERS)
def test_sandbox_rejects_runtime_or_mutation_authority_escalation(alias: str) -> None:
    original = _sandbox(_surface()).model_dump(mode="json", by_alias=True)
    for value in (True, 0):
        payload = deepcopy(original)
        payload[alias] = value
        payload["sandboxBindingDigest"] = ""
        payload["sandboxBindingId"] = ""
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisSandboxBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _REQUEST_FALSE_MARKERS)
def test_request_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    surface = _surface()
    original = (
        _adapter(surface)
        .prepare_request(
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
        )
        .model_dump(mode="json", by_alias=True)
    )
    for value in (True, 0):
        payload = deepcopy(original)
        payload[alias] = value
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisRequest.model_validate(payload)


@pytest.mark.parametrize("alias", _PREPARATION_FALSE_MARKERS)
def test_preparation_rejects_verification_admission_or_execution_escalation(
    alias: str,
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    for value in (True, 0):
        payload = deepcopy(original)
        payload[alias] = value
        payload["preparationDigest"] = ""
        payload["preparationId"] = ""
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisPreparation.model_validate(payload)


@pytest.mark.parametrize(
    ("model", "marker_aliases"),
    (
        (ForensicEvidenceAnalysisBinding, _BINDING_FALSE_MARKERS),
        (ForensicEvidenceCustodyBinding, _CUSTODY_FALSE_MARKERS),
        (ForensicEvidenceAnalysisSandboxBinding, _SANDBOX_FALSE_MARKERS),
        (ForensicEvidenceAnalysisRequest, _REQUEST_FALSE_MARKERS),
        (ForensicEvidenceAnalysisPreparation, _PREPARATION_FALSE_MARKERS),
    ),
)
def test_false_marker_catalog_covers_every_false_default(
    model: type[BaseModel],
    marker_aliases: tuple[str, ...],
) -> None:
    assert {field.alias for field in model.model_fields.values() if field.default is False} == set(
        marker_aliases
    )


def test_custody_sandbox_and_request_reject_paths_secrets_commands_and_raw_evidence() -> None:
    surface = _surface(ForensicSurfaceClass.MEMORY)
    custody_payload = _custody(surface).model_dump(mode="json", by_alias=True)
    custody_injections: tuple[tuple[str, object], ...] = (
        ("sourcePath", r"C:\\cases\\memory.raw"),
        ("sourceURI", "s3://private-bucket/memory.raw"),
        ("objectKey", "cases/incident/memory.raw"),
        ("caseId", "incident-123"),
        ("operatorId", "analyst@example.test"),
        ("bearerToken", "secret-token"),
        ("credential", {"token": "secret"}),
        ("rawEvidence", "base64-data"),
        ("rawProvenance", {"path": "private"}),
    )
    for field, value in custody_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ForensicEvidenceCustodyBinding.model_validate({**custody_payload, field: value})

    sandbox_payload = _sandbox(surface).model_dump(mode="json", by_alias=True)
    sandbox_injections: tuple[tuple[str, object], ...] = (
        ("endpoint", "https://parser.example.test"),
        ("command", ["parser", "--unsafe"]),
        ("plugin", "caller-forensic-plugin"),
        ("environment", {"TOKEN": "secret"}),
        ("hostPath", r"C:\\cases"),
        ("credential", {"token": "secret"}),
        ("workerJob", {"executionAuthorized": True}),
    )
    for field, value in sandbox_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ForensicEvidenceAnalysisSandboxBinding.model_validate({**sandbox_payload, field: value})

    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    request_payload = request.model_dump(mode="json", by_alias=True)
    request_injections: tuple[tuple[str, object], ...] = (
        ("rawEvidence", "base64-data"),
        ("parserOutput", {"credential": "secret"}),
        ("credential", "secret-token"),
        ("shell", ["powershell.exe"]),
        ("plugin", "caller-plugin"),
        ("permit", {"executionAuthorized": True}),
        ("observation", {"kind": "Observation"}),
        ("evidence", {"kind": "Evidence"}),
        ("finding", {"kind": "Finding"}),
    )
    for field, value in request_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ForensicEvidenceAnalysisRequest.model_validate({**request_payload, field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("custodyAuthorityId", "kms:production"),
        ("custodyAuthorityId", "pkcs11:production"),
        ("custodyObjectId", "case-production-incident"),
        ("custodyObjectId", f"forensic-evidence_{'0' * 64}"),
        ("authorizationId", "eyJhbGciOiJIUzI1NiJ9.payload.signature"),
        ("authorizationId", f"forensic-analysis-authorization_{'0' * 64}"),
    ),
)
def test_custody_identifiers_cannot_smuggle_case_key_or_credential_references(
    field: str,
    value: str,
) -> None:
    payload = _custody(_surface()).model_dump(mode="json", by_alias=True)
    payload[field] = value
    payload["custodyBindingId"] = ""
    payload["custodyBindingDigest"] = ""
    with pytest.raises(ValidationError):
        ForensicEvidenceCustodyBinding.model_validate(payload)


def test_forged_model_copy_and_hidden_nested_state_fail_at_public_boundaries(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(ForensicSurfaceClass.LOG)
    forged_surface = surface.model_copy(update={"credential": "secret"})
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        bind_forensic_evidence_custody(
            surface=forged_surface,
            authorization_digest=AUTHORIZATION_DIGEST,
        )

    hidden_surface = _surface(ForensicSurfaceClass.LOG)
    object.__setattr__(
        hidden_surface.locator.provenance,
        "hidden_credential_reference",
        "secret",
    )
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        bind_forensic_evidence_custody(
            surface=hidden_surface,
            authorization_digest=AUTHORIZATION_DIGEST,
        )

    custody = _custody(surface)
    forged_custody = custody.model_copy(update={"bearerToken": "secret"})
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        BoundedForensicEvidenceParserAdapter(forged_custody, _sandbox(surface))

    forged_nested_custody = custody.model_copy(
        update={"surface": surface.model_copy(update={"caseId": "incident-1"})}
    )
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        BoundedForensicEvidenceParserAdapter(
            forged_nested_custody,
            _sandbox(surface),
        )

    sandbox = _sandbox(surface)
    forged_sandbox = sandbox.model_copy(update={"command": ["parser"]})
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        BoundedForensicEvidenceParserAdapter(custody, forged_sandbox)

    binding_ref = registered_forensic_evidence_analysis_binding().reference()
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        resolve_forensic_evidence_analysis_binding(
            binding_ref.model_copy(update={"secret": "token"})
        )

    classification = registered_forensic_evidence_analysis_capability_domain_classification()
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        resolve_forensic_evidence_analysis_capability_domain_classification(
            classification.reference().model_copy(update={"caseId": "incident-1"})
        )

    request = _prepare(sample_campaign).prepared_action.request
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="unmodeled"):
        ForensicEvidenceAnalysisTool().prepare(request.model_copy(update={"credential": "secret"}))


def test_reference_digests_profile_and_parser_configuration_reject_drift() -> None:
    surface = _surface(ForensicSurfaceClass.ARTIFACT)
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )

    custody_ref = request.custody.model_dump(mode="json", by_alias=True)
    custody_ref["custodyObjectId"] = "forensic-evidence_" + "0" * 64
    with pytest.raises(ValidationError):
        ForensicEvidenceCustodyRef.model_validate(custody_ref)

    for field, value in (
        ("parserExecutableSHA256", "0" * 64),
        ("parserConfigurationSHA256", "0" * 64),
        ("sandboxImageSHA256", "0" * 64),
        ("maxParserWorkUnits", request.sandbox.max_parser_work_units + 1),
        ("maxRecursionDepth", request.sandbox.max_recursion_depth + 1),
        ("maxDecompressionRatio", request.sandbox.max_decompression_ratio + 1),
        ("maxDecompressedBytes", request.sandbox.max_decompressed_bytes + 1),
    ):
        sandbox_ref = request.sandbox.model_dump(mode="json", by_alias=True)
        sandbox_ref[field] = value
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisSandboxRef.model_validate(sandbox_ref)

    application_profile = next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.APPLICATION
    )
    sandbox_payload = _sandbox(surface).model_dump(mode="json", by_alias=True)
    sandbox_payload["workerProfile"] = application_profile.reference().model_dump(
        mode="json", by_alias=True
    )
    sandbox_payload["sandboxBindingId"] = ""
    sandbox_payload["sandboxBindingDigest"] = ""
    with pytest.raises(ValidationError, match="code authority"):
        ForensicEvidenceAnalysisSandboxBinding.model_validate(sandbox_payload)


def test_sandbox_rejects_caller_controlled_identity_and_secret_smuggling() -> None:
    sandbox = _sandbox(_surface())
    for field, value in (
        ("deploymentId", "kms:production-signing-key"),
        ("deploymentId", "sk_live_supersecret"),
        ("runAsIdentity", "root"),
        ("runAsIdentity", "administrator"),
        ("runAsIdentity", "SYSTEM"),
        ("runAsIdentity", "uid:0"),
        ("runAsIdentity", "0:1000"),
        ("runAsIdentity", "S-1-5-18"),
        ("runAsIdentity", "kms:production-signing-key"),
    ):
        binding_payload = sandbox.model_dump(mode="json", by_alias=True)
        binding_payload[field] = value
        binding_payload["sandboxBindingDigest"] = ""
        binding_payload["sandboxBindingId"] = ""
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisSandboxBinding.model_validate(binding_payload)

        reference_payload = sandbox.reference().model_dump(mode="json", by_alias=True)
        reference_payload[field] = value
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisSandboxRef.model_validate(reference_payload)


def test_preparation_rejects_surface_custody_sandbox_scope_release_and_digest_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    mutations = (
        ("artifactCustody", "authorizationDigest", "0" * 64),
        ("artifactCustody", "artifactSHA256", "0" * 64),
        ("sandbox", "parserExecutableSHA256", "0" * 64),
        ("sandbox", "parserConfigurationSHA256", "0" * 64),
        ("sandbox", "sandboxImageSHA256", "0" * 64),
        ("campaignScope", "campaignDigest", "0" * 64),
        (
            "analysisRequest",
            "target",
            forensic_surface_scope_target(_surface(ForensicSurfaceClass.MEMORY)),
        ),
        ("analysisRequest", "outputSchema", "attacker.output.v1"),
        ("preparedAction", "requestDigest", "0" * 64),
        ("preparedAction", "normalizedParametersDigest", "0" * 64),
        (None, "preparationDigest", "0" * 64),
    )
    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            ForensicEvidenceAnalysisPreparation.model_validate(payload)


def test_stale_release_and_tool_request_substitution_fail_closed(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    activation, release = _activation()
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError):
        prepare_forensic_evidence_analysis(
            activation=activation,
            release=release.model_copy(update={"release_digest": "0" * 64}),
            campaign=_campaign(sample_campaign, surface=surface),
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
            parser=_adapter(surface),
            request_id="tool_forensic_stale_release",
            agent_id="agent:forensic-evidence-analysis",
        )

    request = _prepare(sample_campaign).prepared_action.request
    tool = ForensicEvidenceAnalysisTool()
    for changed in (
        request.model_copy(update={"target": "https://other.example.test/v1/analyze"}),
        request.model_copy(update={"method": "POST"}),
        request.model_copy(update={"tool_id": "forensics.other-parser"}),
    ):
        with pytest.raises(ForensicEvidenceAnalysisCapabilityError):
            tool.prepare(changed)


def test_capability_materializer_rejects_mutated_reference_summary() -> None:
    surface = _surface(ForensicSurfaceClass.MEMORY)
    analysis = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    parameters = analysis.model_dump(mode="json", by_alias=True)
    parameters["custody"]["authorizationDigest"] = "0" * 64
    activation, release = _activation()
    request = ToolRequest(
        request_id="tool_forensic_mutated_reference",
        agent_id="agent:forensic-evidence-analysis",
        tool_id=FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID,
        target=analysis.target,
        method="GET",
        arguments={},
    )
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError):
        activation.prepare_action(
            release=release,
            request=request,
            parameters=parameters,
        )


def test_runtime_executor_normalizer_oracle_replay_and_cleanup_remain_unavailable(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    tool = ForensicEvidenceAnalysisTool()
    activation = _activation()[0]
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    normalizer = activation.authority(CapabilityAuthorityRole.RESULT_NORMALIZER)
    oracle = activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE)
    replay = activation.authority(CapabilityAuthorityRole.REPLAY_STRATEGY)
    cleanup = activation.authority(CapabilityAuthorityRole.CLEANUP_HANDLER)
    result = ToolResult(
        request_id=preparation.prepared_action.request.request_id,
        tool_id=FORENSIC_EVIDENCE_ANALYSIS_TOOL_ID,
        success=True,
        started_at=NOW,
        finished_at=NOW,
    )
    worker_result = WorkerResult(
        execution_id="forensic-evidence-analysis-execution",
        backend="unavailable-forensic-evidence-parser",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        started_at=NOW,
        finished_at=NOW,
    )

    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="does not materialize"):
        tool.prepare(preparation.prepared_action.request)
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="does not materialize"):
        executor.prepare(preparation.prepared_action.request)
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="no sandbox result"):
        tool.interpret(preparation.prepared_action.request, worker_result)
    with pytest.raises(ForensicEvidenceAnalysisCapabilityError, match="no sandbox result"):
        normalizer.normalize(preparation.prepared_action.request, worker_result)
    assert (
        oracle.evaluate(preparation.prepared_action.request, result)
        is CapabilityOracleDecision.INCONCLUSIVE
    )
    assert replay.plan_replay(preparation.prepared_action.request, result) is None
    assert cleanup.plan_cleanup(preparation.prepared_action.request, result) is None


def test_public_registered_values_and_resolvers_are_detached() -> None:
    first_rule_set = registered_forensic_evidence_rule_set()
    second_rule_set = registered_forensic_evidence_rule_set()
    assert first_rule_set == second_rule_set
    assert first_rule_set is not second_rule_set
    assert (
        first_rule_set.surface_analysis_mapping[0]
        is not (second_rule_set.surface_analysis_mapping[0])
    )

    first_binding = registered_forensic_evidence_analysis_binding()
    second_binding = registered_forensic_evidence_analysis_binding()
    assert first_binding == second_binding
    assert first_binding is not second_binding
    assert (
        resolve_forensic_evidence_analysis_binding(first_binding.reference()) is not first_binding
    )


def test_b_builders_do_not_accept_paths_identity_or_deployment_selection() -> None:
    custody_parameters = set(signature(bind_forensic_evidence_custody).parameters)
    sandbox_parameters = set(signature(bind_forensic_evidence_analysis_sandbox).parameters)
    assert custody_parameters == {"surface", "authorization_digest"}
    assert {
        "path",
        "source_uri",
        "object_key",
        "case_id",
        "operator_id",
        "credential",
        "deployment_id",
        "run_as_identity",
        "parser",
        "operation",
    }.isdisjoint(custody_parameters | sandbox_parameters)


def test_a_surface_registry_and_false_state_remain_unchanged_by_b_preparation(
    sample_campaign: CampaignManifest,
) -> None:
    registry_before = registered_forensic_immutable_artifact_locator_registry()
    surface = _surface(ForensicSurfaceClass.ARTIFACT)
    surface_before = surface.model_dump(mode="json", by_alias=True)

    preparation = _prepare(sample_campaign, surface=surface)

    assert registered_forensic_immutable_artifact_locator_registry() == registry_before
    assert preparation.surface.model_dump(mode="json", by_alias=True) == surface_before
    for alias in (
        "sourceResolved",
        "sourceSealVerified",
        "sourceAuthenticityVerified",
        "sourceImmutabilityVerified",
        "sourceArtifactMembershipVerified",
        "chainOfCustodyVerified",
        "artifactDigestVerified",
        "artifactBytesVerified",
        "evidenceClassVerified",
        "provenancePreserved",
        "sourceFormatVerified",
        "parserResultAvailable",
        "forensicHypothesisCreated",
        "evidenceSealed",
        "graphAdmitted",
        "sourceReadAuthorized",
        "evidenceMutationAuthorized",
        "executionAuthorized",
    ):
        assert surface_before[alias] is False


def test_budget_request_and_preparation_exclude_runtime_graph_and_evidence_objects() -> None:
    forbidden = {
        "source_path",
        "source_uri",
        "object_key",
        "case_id",
        "operator_id",
        "credential",
        "token",
        "command",
        "plugin",
        "worker_job",
        "permit",
        "observation",
        "evidence",
        "hypothesis",
        "finding",
    }
    assert forbidden.isdisjoint(ForensicEvidenceAnalysisBudget.model_fields)
    assert forbidden.isdisjoint(ForensicEvidenceAnalysisRequest.model_fields)
    assert forbidden.isdisjoint(ForensicEvidenceAnalysisPreparation.model_fields)

    context = ForensicEvidenceAnalysisTool().stable_execution_context()
    assert context["sourceResolutionRuntimeAvailable"] is False
    assert context["evidenceCustodyRuntimeAvailable"] is False
    assert context["offlineParserRuntimeAvailable"] is False
    assert context["workerJobMaterializationAvailable"] is False
