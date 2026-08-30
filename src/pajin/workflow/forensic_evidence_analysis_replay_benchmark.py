"""FORENSICS-001D deterministic re-parse and independent parser comparison."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.forensic_evidence_analysis import (
    ForensicEvidenceAnalysisOperation,
    ForensicEvidenceAnalysisPreparation,
    ForensicEvidenceAnalysisRequest,
    ForensicEvidenceAnalysisSandboxBinding,
    ForensicEvidenceInputKind,
    ForensicEvidenceParser,
    ForensicEvidenceRuleSetRef,
    ForensicEvidenceSignalKind,
    ForensicSurfaceAnalysisMapping,
    registered_forensic_evidence_rule_set,
)
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    registered_domain_worker_boundary_profiles,
)
from pajin.discovery.forensics_surfaces import ForensicSurfaceClass
from pajin.domain.models import CapabilityGrant, StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow.forensic_evidence_analysis_admission import (
    ForensicEvidenceAnalysisAdmissionOracleVerdict,
    ForensicEvidenceAnalysisExecutionBundle,
    ForensicEvidenceAnalysisExecutionKeyState,
    ForensicEvidenceAnalysisExecutionStatement,
    ForensicEvidenceAnalysisExecutionTrustAnchor,
    ForensicEvidenceAnalysisExecutionVerification,
    ForensicEvidenceAnalysisExecutionVerificationKey,
    ForensicEvidenceAnalysisKnowledgeAdmission,
    ForensicEvidenceAnalysisObservationSourceInputs,
    ForensicEvidenceAnalysisOracleDisposition,
    ForensicEvidenceAnalysisResultDisposition,
    ForensicEvidenceAnalysisResultReceipt,
    ForensicEvidenceAnalysisSandboxRuntimeReceipt,
    ForensicEvidenceSourceMembershipKeyState,
    ForensicEvidenceSourceMembershipTrustAnchor,
    ForensicEvidenceSourceMembershipVerificationKey,
    VerifiedForensicEvidenceAnalysisObservationSource,
    forensic_evidence_analysis_execution_bundle_reference,
    forensic_evidence_analysis_result_receipt_reference,
    forensic_evidence_analysis_source_root_digest,
    load_verified_forensic_evidence_analysis_observation_source,
    registered_forensic_evidence_analysis_oracle_policy,
    verify_forensic_evidence_analysis_execution_bundle,
)

FORENSIC_EVIDENCE_ANALYSIS_REPLAY_VALIDATION_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-replay-validation/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-replay-validation/v1alpha1"
FORENSIC_EVIDENCE_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-benchmark-fixture-profile/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-benchmark-fixture-profile/v1alpha1"

_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_ArtifactPath = Annotated[
    str,
    Field(pattern=r"^evidence/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$"),
]
_ReplayState = Literal[
    "deterministic-reparse-match",
    "deterministic-reparse-changed",
    "deterministic-reparse-unresolved",
    "independent-parser-comparison-match",
    "independent-parser-comparison-changed",
    "independent-parser-comparison-unresolved",
]
_EvidenceRequirement = Literal[
    "private-ground-truth-attestation",
    "field-level-ground-truth-manifest-attestation",
    "fixture-materialization-and-control-attestation",
    "source-membership-attestation",
    "source-execution-attestation",
    "source-provenance-preserving-runtime-receipt",
    "source-result-receipt",
    "comparison-source-membership-attestation",
    "comparison-execution-attestation",
    "comparison-provenance-preserving-runtime-receipt",
    "comparison-result-receipt",
    "source-bounded-parser-rejection-receipt",
    "comparison-bounded-parser-rejection-receipt",
    "cleanup-receipt",
]


class ForensicEvidenceAnalysisReplayBenchmarkError(RuntimeError):
    """Raised when FORENSICS-001D comparison or benchmark authority differs."""


class ForensicEvidenceAnalysisReplayMode(StrEnum):
    """Code-derived modes for two already-completed parser executions."""

    DETERMINISTIC_REPARSE = "deterministic-reparse"
    INDEPENDENT_PARSER_COMPARISON = "independent-parser-comparison"


class ForensicEvidenceAnalysisReplayComparison(StrEnum):
    """Neutral comparisons that never establish forensic semantic truth."""

    MATCHED = "forensic-analysis-result-match"
    CHANGED = "forensic-analysis-result-changed"
    UNRESOLVED = "forensic-analysis-result-unresolved"


class ForensicEvidenceBenchmarkGroundTruthClass(StrEnum):
    """Closed seeded-evidence classes for future Forensics measurement."""

    KNOWN_POSITIVE = "known-positive"
    NEGATIVE_CONTROL = "negative-control"
    CORRUPTED_INPUT_CONTROL = "corrupted-input-control"


class ForensicEvidenceBenchmarkExpectedOutcome(StrEnum):
    """Expected bounded routing or corruption-handling requirement."""

    REVIEW_SIGNAL = "review-signal"
    NO_REVIEW_SIGNAL = "no-review-signal"
    BOUNDED_CORRUPTION_HANDLING = "bounded-corruption-handling"


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    """Reject unchecked nested state introduced through model_copy(update=...)."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        unknown = set(value.__dict__) - set(type(value).model_fields)
        if unknown:
            raise ValueError(f"{label} contains unmodeled instance state")
        for field_name in type(value).model_fields:
            _require_known_instance_fields(
                getattr(value, field_name),
                label=label,
                _seen=seen,
            )
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


class ForensicEvidenceAnalysisReplayExecution(_FrozenStrictModel):
    """Digest-only projection whose trusted use requires the C loader context."""

    preparation: ForensicEvidenceAnalysisPreparation
    capability_grant: CapabilityGrant = Field(alias="capabilityGrant")
    action_permit: ActionPermit = Field(alias="actionPermit")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor = Field(
        alias="sourceMembershipTrustAnchor"
    )
    execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor = Field(
        alias="executionTrustAnchor"
    )
    verification: ForensicEvidenceAnalysisExecutionVerification
    execution_bundle: ForensicEvidenceAnalysisExecutionBundle = Field(alias="executionBundle")
    result_receipt: ForensicEvidenceAnalysisResultReceipt = Field(alias="resultReceipt")
    oracle_verdict: ForensicEvidenceAnalysisAdmissionOracleVerdict = Field(alias="oracleVerdict")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    attestation_reference: _ArtifactPath = Field(alias="attestationReference")
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")

    @field_serializer("capability_grant", when_used="json")
    def serialize_capability_grant(self, value: CapabilityGrant) -> dict[str, object]:
        return _canonical_capability_grant_payload(value)

    @model_validator(mode="after")
    def bind_execution_projection(self) -> Self:
        verified = verify_forensic_evidence_analysis_execution_bundle(
            self.execution_bundle,
            trust_anchor=self.execution_trust_anchor,
            source_membership_trust_anchor=self.source_membership_trust_anchor,
        )
        statement = self.execution_bundle.statement
        result = self.result_receipt
        verdict = self.oracle_verdict
        expected_root = forensic_evidence_analysis_source_root_digest(
            attestation_reference=self.attestation_reference,
            attestation_sha256=self.attestation_sha256,
            result_receipt_reference=self.result_receipt_reference,
            result_receipt_sha256=self.result_receipt_sha256,
            source_membership_trust_anchor_digest=self.source_membership_trust_anchor.digest,
            execution_trust_anchor_digest=verified.trust_anchor_digest,
            source_membership_attestation_sha256=(
                verified.source_membership_verification.attestation_sha256
            ),
            statement_sha256=verified.statement_sha256,
            oracle_verdict_digest=verdict.verdict_digest,
        )
        if (
            verified != self.verification
            or verified.key_state is not ForensicEvidenceAnalysisExecutionKeyState.ACTIVE
            or verified.source_membership_verification.key_state
            is not ForensicEvidenceSourceMembershipKeyState.ACTIVE
            or verified.key_id != _active_execution_signer(self.execution_trust_anchor).key_id
            or verified.source_membership_verification.key_id
            != _active_source_signer(self.source_membership_trust_anchor).key_id
            or self.source_root_digest != expected_root
            or self.attestation_reference == self.result_receipt_reference
            or self.attestation_reference
            != forensic_evidence_analysis_execution_bundle_reference(self.attestation_sha256)
            or self.result_receipt_reference
            != forensic_evidence_analysis_result_receipt_reference(self.result_receipt_sha256)
            or self.source_membership_trust_anchor.surface != self.preparation.surface
            or self.source_membership_trust_anchor.artifact_custody
            != self.preparation.artifact_custody
            or self.execution_trust_anchor.sandbox != self.preparation.sandbox
            or self.execution_trust_anchor.capability != self.preparation.binding.capability
            or self.execution_trust_anchor.capability_release != self.preparation.release
            or statement.preparation != self.preparation
            or statement.action_permit != self.action_permit
            or statement.approval_receipt != self.approval_receipt
            or statement.capability_grant_id != self.capability_grant.grant_id
            or statement.capability_grant_digest != capability_grant_digest(self.capability_grant)
            or statement.result_receipt_reference != self.result_receipt_reference
            or statement.result_receipt_sha256 != self.result_receipt_sha256
            or statement.result_receipt_id != result.receipt_id
            or statement.result_receipt_digest != result.receipt_digest
            or result.execution_id != statement.execution_id
            or result.request_id != self.action_permit.request_id
            or result.request_digest != self.action_permit.request_digest
            or result.preparation_id != self.preparation.preparation_id
            or result.preparation_digest != self.preparation.preparation_digest
            or result.surface != self.preparation.surface.reference()
            or result.input_kind is not self.preparation.input_kind
            or result.operation is not self.preparation.operation
            or result.parser is not self.preparation.analysis_request.parser
            or result.rule_set != self.preparation.analysis_request.rule_set
            or verdict.surface != result.surface
            or verdict.input_kind is not result.input_kind
            or verdict.rule_set != result.rule_set
            or verdict.artifact_sha256 != result.artifact_sha256
            or verdict.artifact_bytes != result.artifact_bytes
            or verdict.output_schema != result.output_schema
            or verdict.result_receipt_id != result.receipt_id
            or verdict.result_receipt_digest != result.receipt_digest
            or verdict.result_body_sha256 != result.result_body_sha256
            or verdict.result_bytes != result.result_bytes
            or verdict.result_disposition is not result.disposition
        ):
            raise ValueError("FORENSICS-001D execution projection differs from sealed C evidence")
        return self


_VALIDATION_TRUE_FIELDS = (
    "sealed_source_reverified",
    "sealed_replay_reverified",
    "stored_source_admission_verified",
    "common_source_membership_authority_verified",
    "same_immutable_source_and_custody_verified",
    "separate_action_authority_verified",
    "separate_evidence_provenance_verified",
    "signed_timestamp_order_verified",
    "exact_surface_verified",
    "exact_input_kind_verified",
    "exact_operation_verified",
    "exact_logical_parser_verified",
    "exact_rule_set_verified",
    "exact_artifact_digest_and_bytes_verified",
    "exact_campaign_scope_verified",
    "exact_release_and_activation_verified",
    "exact_request_semantics_verified",
    "exact_output_schema_verified",
    "exact_resource_limits_verified",
    "exact_confinement_verified",
    "zero_live_channels_verified",
    "mode_derived_from_code_coordinates",
    "bounded_structural_comparison_verified",
    "graph_read_only_verified",
    "deployment_context_reverification_required",
)
_VALIDATION_FALSE_FIELDS = (
    "raw_source_embedded",
    "raw_result_body_embedded",
    "raw_provenance_embedded",
    "raw_custody_embedded",
    "personal_information_embedded",
    "source_path_embedded",
    "caller_prose_embedded",
    "credential_material_embedded",
    "secret_material_embedded",
    "self_authenticating_projection",
    "source_bound_replay_authorization_verified",
    "cross_signer_clock_synchronization_verified",
    "source_code_independence_verified",
    "algorithm_independence_verified",
    "organization_independence_verified",
    "supply_chain_independence_verified",
    "host_independence_verified",
    "worker_independence_verified",
    "common_mode_failure_excluded",
    "source_truth_established",
    "legal_custody_established",
    "acquisition_completeness_established",
    "global_immutability_established",
    "evidence_class_verified",
    "source_format_verified",
    "parser_correctness_established",
    "result_truth_established",
    "negative_security_claim_established",
    "hypothesis_confirmed",
    "finding_authority",
    "ground_truth_verified",
    "benchmark_measurement_observed",
    "artifact_coverage_measured",
    "parsing_accuracy_measured",
    "provenance_preservation_rate_measured",
    "corrupted_input_handling_rate_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "source_access_authorized",
    "result_body_read_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "worker_job_materialization_authorized",
    "network_access_authorized",
    "dns_access_authorized",
    "host_filesystem_access_authorized",
    "device_access_authorized",
    "plugin_loading_authorized",
    "credential_use_authorized",
    "secret_material_access_authorized",
    "lateral_movement_authorized",
    "target_execution_authorized",
    "shell_command_authorized",
    "debugger_attach_authorized",
    "source_mutation_authorized",
    "evidence_mutation_authorized",
    "graph_admission_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class ForensicEvidenceAnalysisReplayValidation(_FrozenStrictModel):
    """Non-authorizing projection for one source and one later parser execution."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-replay-validation/v1alpha1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_REPLAY_VALIDATION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["ForensicEvidenceAnalysisReplayValidation"] = (
        "ForensicEvidenceAnalysisReplayValidation"
    )
    validation_id: str = Field(default="", alias="validationId", max_length=118)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    source_admission: ForensicEvidenceAnalysisKnowledgeAdmission = Field(alias="sourceAdmission")
    source_execution: ForensicEvidenceAnalysisReplayExecution = Field(alias="sourceExecution")
    replay_execution: ForensicEvidenceAnalysisReplayExecution = Field(alias="replayExecution")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    replay_mode: ForensicEvidenceAnalysisReplayMode = Field(alias="replayMode")
    comparison: ForensicEvidenceAnalysisReplayComparison
    result_body_digest_matched: bool = Field(alias="resultBodyDigestMatched")
    result_bytes_matched: bool = Field(alias="resultBytesMatched")
    result_disposition_matched: bool = Field(alias="resultDispositionMatched")
    oracle_disposition_matched: bool = Field(alias="oracleDispositionMatched")
    review_signal_matched: bool = Field(alias="reviewSignalMatched")
    domain_validation_strategy_satisfied: bool = Field(alias="domainValidationStrategySatisfied")
    state: _ReplayState
    sealed_source_reverified: Literal[True] = Field(default=True, alias="sealedSourceReverified")
    sealed_replay_reverified: Literal[True] = Field(default=True, alias="sealedReplayReverified")
    stored_source_admission_verified: Literal[True] = Field(
        default=True, alias="storedSourceAdmissionVerified"
    )
    common_source_membership_authority_verified: Literal[True] = Field(
        default=True, alias="commonSourceMembershipAuthorityVerified"
    )
    same_immutable_source_and_custody_verified: Literal[True] = Field(
        default=True, alias="sameImmutableSourceAndCustodyVerified"
    )
    separate_action_authority_verified: Literal[True] = Field(
        default=True, alias="separateActionAuthorityVerified"
    )
    separate_evidence_provenance_verified: Literal[True] = Field(
        default=True, alias="separateEvidenceProvenanceVerified"
    )
    signed_timestamp_order_verified: Literal[True] = Field(
        default=True, alias="signedTimestampOrderVerified"
    )
    exact_surface_verified: Literal[True] = Field(default=True, alias="exactSurfaceVerified")
    exact_input_kind_verified: Literal[True] = Field(default=True, alias="exactInputKindVerified")
    exact_operation_verified: Literal[True] = Field(default=True, alias="exactOperationVerified")
    exact_logical_parser_verified: Literal[True] = Field(
        default=True, alias="exactLogicalParserVerified"
    )
    exact_rule_set_verified: Literal[True] = Field(default=True, alias="exactRuleSetVerified")
    exact_artifact_digest_and_bytes_verified: Literal[True] = Field(
        default=True, alias="exactArtifactDigestAndBytesVerified"
    )
    exact_campaign_scope_verified: Literal[True] = Field(
        default=True, alias="exactCampaignScopeVerified"
    )
    exact_release_and_activation_verified: Literal[True] = Field(
        default=True, alias="exactReleaseAndActivationVerified"
    )
    exact_request_semantics_verified: Literal[True] = Field(
        default=True, alias="exactRequestSemanticsVerified"
    )
    exact_output_schema_verified: Literal[True] = Field(
        default=True, alias="exactOutputSchemaVerified"
    )
    exact_resource_limits_verified: Literal[True] = Field(
        default=True, alias="exactResourceLimitsVerified"
    )
    exact_confinement_verified: Literal[True] = Field(
        default=True, alias="exactConfinementVerified"
    )
    zero_live_channels_verified: Literal[True] = Field(
        default=True, alias="zeroLiveChannelsVerified"
    )
    mode_derived_from_code_coordinates: Literal[True] = Field(
        default=True, alias="modeDerivedFromCodeCoordinates"
    )
    bounded_structural_comparison_verified: Literal[True] = Field(
        default=True, alias="boundedStructuralComparisonVerified"
    )
    graph_read_only_verified: Literal[True] = Field(default=True, alias="graphReadOnlyVerified")
    deployment_context_reverification_required: Literal[True] = Field(
        default=True, alias="deploymentContextReverificationRequired"
    )
    deterministic_parser_coordinates_reused: bool = Field(
        alias="deterministicParserCoordinatesReused"
    )
    distinct_parser_implementation_coordinates_verified: bool = Field(
        alias="distinctParserImplementationCoordinatesVerified"
    )
    raw_source_embedded: Literal[False] = Field(default=False, alias="rawSourceEmbedded")
    raw_result_body_embedded: Literal[False] = Field(default=False, alias="rawResultBodyEmbedded")
    raw_provenance_embedded: Literal[False] = Field(default=False, alias="rawProvenanceEmbedded")
    raw_custody_embedded: Literal[False] = Field(default=False, alias="rawCustodyEmbedded")
    personal_information_embedded: Literal[False] = Field(
        default=False, alias="personalInformationEmbedded"
    )
    source_path_embedded: Literal[False] = Field(default=False, alias="sourcePathEmbedded")
    caller_prose_embedded: Literal[False] = Field(default=False, alias="callerProseEmbedded")
    credential_material_embedded: Literal[False] = Field(
        default=False, alias="credentialMaterialEmbedded"
    )
    secret_material_embedded: Literal[False] = Field(default=False, alias="secretMaterialEmbedded")
    self_authenticating_projection: Literal[False] = Field(
        default=False, alias="selfAuthenticatingProjection"
    )
    source_bound_replay_authorization_verified: Literal[False] = Field(
        default=False, alias="sourceBoundReplayAuthorizationVerified"
    )
    cross_signer_clock_synchronization_verified: Literal[False] = Field(
        default=False, alias="crossSignerClockSynchronizationVerified"
    )
    source_code_independence_verified: Literal[False] = Field(
        default=False, alias="sourceCodeIndependenceVerified"
    )
    algorithm_independence_verified: Literal[False] = Field(
        default=False, alias="algorithmIndependenceVerified"
    )
    organization_independence_verified: Literal[False] = Field(
        default=False, alias="organizationIndependenceVerified"
    )
    supply_chain_independence_verified: Literal[False] = Field(
        default=False, alias="supplyChainIndependenceVerified"
    )
    host_independence_verified: Literal[False] = Field(
        default=False, alias="hostIndependenceVerified"
    )
    worker_independence_verified: Literal[False] = Field(
        default=False, alias="workerIndependenceVerified"
    )
    common_mode_failure_excluded: Literal[False] = Field(
        default=False, alias="commonModeFailureExcluded"
    )
    source_truth_established: Literal[False] = Field(default=False, alias="sourceTruthEstablished")
    legal_custody_established: Literal[False] = Field(
        default=False, alias="legalCustodyEstablished"
    )
    acquisition_completeness_established: Literal[False] = Field(
        default=False, alias="acquisitionCompletenessEstablished"
    )
    global_immutability_established: Literal[False] = Field(
        default=False, alias="globalImmutabilityEstablished"
    )
    evidence_class_verified: Literal[False] = Field(default=False, alias="evidenceClassVerified")
    source_format_verified: Literal[False] = Field(default=False, alias="sourceFormatVerified")
    parser_correctness_established: Literal[False] = Field(
        default=False, alias="parserCorrectnessEstablished"
    )
    result_truth_established: Literal[False] = Field(default=False, alias="resultTruthEstablished")
    negative_security_claim_established: Literal[False] = Field(
        default=False, alias="negativeSecurityClaimEstablished"
    )
    hypothesis_confirmed: Literal[False] = Field(default=False, alias="hypothesisConfirmed")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    ground_truth_verified: Literal[False] = Field(default=False, alias="groundTruthVerified")
    benchmark_measurement_observed: Literal[False] = Field(
        default=False, alias="benchmarkMeasurementObserved"
    )
    artifact_coverage_measured: Literal[False] = Field(
        default=False, alias="artifactCoverageMeasured"
    )
    parsing_accuracy_measured: Literal[False] = Field(
        default=False, alias="parsingAccuracyMeasured"
    )
    provenance_preservation_rate_measured: Literal[False] = Field(
        default=False, alias="provenancePreservationRateMeasured"
    )
    corrupted_input_handling_rate_measured: Literal[False] = Field(
        default=False, alias="corruptedInputHandlingRateMeasured"
    )
    detection_quality_established: Literal[False] = Field(
        default=False, alias="detectionQualityEstablished"
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="profileValidationFloorSatisfied"
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False, alias="capabilityActivationAuthorized"
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    source_access_authorized: Literal[False] = Field(default=False, alias="sourceAccessAuthorized")
    result_body_read_authorized: Literal[False] = Field(
        default=False, alias="resultBodyReadAuthorized"
    )
    custody_authorization_authority: Literal[False] = Field(
        default=False, alias="custodyAuthorizationAuthority"
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False, alias="sandboxInvocationAuthorized"
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False, alias="workerSelectionAuthorized"
    )
    worker_job_materialization_authorized: Literal[False] = Field(
        default=False, alias="workerJobMaterializationAuthorized"
    )
    network_access_authorized: Literal[False] = Field(
        default=False, alias="networkAccessAuthorized"
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    host_filesystem_access_authorized: Literal[False] = Field(
        default=False, alias="hostFilesystemAccessAuthorized"
    )
    device_access_authorized: Literal[False] = Field(default=False, alias="deviceAccessAuthorized")
    plugin_loading_authorized: Literal[False] = Field(
        default=False, alias="pluginLoadingAuthorized"
    )
    credential_use_authorized: Literal[False] = Field(
        default=False, alias="credentialUseAuthorized"
    )
    secret_material_access_authorized: Literal[False] = Field(
        default=False, alias="secretMaterialAccessAuthorized"
    )
    lateral_movement_authorized: Literal[False] = Field(
        default=False, alias="lateralMovementAuthorized"
    )
    target_execution_authorized: Literal[False] = Field(
        default=False, alias="targetExecutionAuthorized"
    )
    shell_command_authorized: Literal[False] = Field(default=False, alias="shellCommandAuthorized")
    debugger_attach_authorized: Literal[False] = Field(
        default=False, alias="debuggerAttachAuthorized"
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False, alias="sourceMutationAuthorized"
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False, alias="evidenceMutationAuthorized"
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False, alias="graphAdmissionAuthorized"
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False, alias="findingConfirmationAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_VALIDATION_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("FORENSICS-001D verification markers must be boolean true")
        return value

    @field_validator(
        "result_body_digest_matched",
        "result_bytes_matched",
        "result_disposition_matched",
        "oracle_disposition_matched",
        "review_signal_matched",
        "domain_validation_strategy_satisfied",
        "deterministic_parser_coordinates_reused",
        "distinct_parser_implementation_coordinates_verified",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("FORENSICS-001D derived markers must be booleans")
        return value

    @field_validator(*_VALIDATION_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("FORENSICS-001D validation cannot grant authority or truth")
        return value

    @model_validator(mode="after")
    def bind_replay_validation(self) -> Self:
        _require_forensics_domain_plan(self.domain_benchmark_plan)
        _require_admission_projection(self.source_admission, self.source_execution)
        _require_equivalent_replay_semantics(self.source_execution, self.replay_execution)
        _require_distinct_replay_provenance(self.source_execution, self.replay_execution)
        mode = _replay_mode(self.source_execution, self.replay_execution)
        source_result = self.source_execution.result_receipt
        replay_result = self.replay_execution.result_receipt
        source_oracle = self.source_execution.oracle_verdict
        replay_oracle = self.replay_execution.oracle_verdict
        comparison = _comparison(
            source_result=source_result,
            source_oracle=source_oracle,
            replay_result=replay_result,
            replay_oracle=replay_oracle,
        )
        deterministic = mode is ForensicEvidenceAnalysisReplayMode.DETERMINISTIC_REPARSE
        independent = mode is ForensicEvidenceAnalysisReplayMode.INDEPENDENT_PARSER_COMPARISON
        if (
            self.replay_mode is not mode
            or self.result_body_digest_matched
            is not (source_result.result_body_sha256 == replay_result.result_body_sha256)
            or self.result_bytes_matched
            is not (source_result.result_bytes == replay_result.result_bytes)
            or self.result_disposition_matched
            is not (source_result.disposition is replay_result.disposition)
            or self.oracle_disposition_matched
            is not (source_oracle.disposition is replay_oracle.disposition)
            or self.review_signal_matched
            is not (source_oracle.review_signal is replay_oracle.review_signal)
            or self.domain_validation_strategy_satisfied is not independent
            or self.deterministic_parser_coordinates_reused is not deterministic
            or self.distinct_parser_implementation_coordinates_verified is not independent
            or self.comparison is not comparison
            or self.state != _replay_state(mode, comparison)
        ):
            raise ValueError("FORENSICS-001D neutral replay comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.forensic-evidence-analysis-replay-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"forensic-evidence-analysis-replay_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("FORENSICS-001D validation digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("FORENSICS-001D validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


_FIXTURE_CASE_FALSE_FIELDS = (
    "raw_source_content_embedded",
    "raw_result_body_embedded",
    "raw_provenance_embedded",
    "raw_custody_embedded",
    "mutable_path_embedded",
    "filename_embedded",
    "case_identity_embedded",
    "operator_identity_embedded",
    "custodian_identity_embedded",
    "credential_material_embedded",
    "secret_material_embedded",
)
_FIXTURE_CASE_ZERO_FIELDS = (
    "source_write_operations",
    "source_copy_operations",
    "evidence_mutation_operations",
    "network_requests",
    "dns_queries",
    "host_filesystem_reads",
    "device_sessions",
    "plugin_loads",
    "credential_reads",
    "credential_uses",
    "lateral_movement_attempts",
    "target_process_executions",
    "shell_commands",
    "debugger_attaches",
)


class ForensicEvidenceAnalysisBenchmarkFixtureCase(_FrozenStrictModel):
    """One sanitized seeded-evidence requirement without source bytes or identities."""

    fixture_id: _Identifier = Field(alias="fixtureId")
    ground_truth_class: ForensicEvidenceBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    surface_class: ForensicSurfaceClass = Field(alias="surfaceClass")
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    domain_worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="domainWorkerProfile")
    expected_outcome: ForensicEvidenceBenchmarkExpectedOutcome = Field(alias="expectedOutcome")
    expected_result_disposition: ForensicEvidenceAnalysisResultDisposition | None = Field(
        default=None,
        alias="expectedResultDisposition",
    )
    expected_oracle_disposition: ForensicEvidenceAnalysisOracleDisposition | None = Field(
        default=None,
        alias="expectedOracleDisposition",
    )
    expected_review_signal: ForensicEvidenceSignalKind | None = Field(
        default=None,
        alias="expectedReviewSignal",
    )
    required_evidence: tuple[_EvidenceRequirement, ...] = Field(
        min_length=12,
        max_length=12,
        alias="requiredEvidence",
    )
    fixture_materialization: Literal["seeded-sanitized-immutable-forensic-evidence"] = Field(
        default="seeded-sanitized-immutable-forensic-evidence",
        alias="fixtureMaterialization",
    )
    isolation_requirement: Literal[
        "disposable-network-dns-disabled-non-root-parser-sandbox-per-case"
    ] = Field(
        default="disposable-network-dns-disabled-non-root-parser-sandbox-per-case",
        alias="isolationRequirement",
    )
    evidence_mount_requirement: Literal[
        "immutable-read-only-noexec-exact-artifact-and-provenance"
    ] = Field(
        default="immutable-read-only-noexec-exact-artifact-and-provenance",
        alias="evidenceMountRequirement",
    )
    synthetic_test_only_required: Literal[True] = Field(
        default=True,
        alias="syntheticTestOnlyRequired",
    )
    raw_source_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawSourceContentEmbedded",
    )
    raw_result_body_embedded: Literal[False] = Field(
        default=False,
        alias="rawResultBodyEmbedded",
    )
    raw_provenance_embedded: Literal[False] = Field(
        default=False,
        alias="rawProvenanceEmbedded",
    )
    raw_custody_embedded: Literal[False] = Field(default=False, alias="rawCustodyEmbedded")
    mutable_path_embedded: Literal[False] = Field(default=False, alias="mutablePathEmbedded")
    filename_embedded: Literal[False] = Field(default=False, alias="filenameEmbedded")
    case_identity_embedded: Literal[False] = Field(default=False, alias="caseIdentityEmbedded")
    operator_identity_embedded: Literal[False] = Field(
        default=False,
        alias="operatorIdentityEmbedded",
    )
    custodian_identity_embedded: Literal[False] = Field(
        default=False,
        alias="custodianIdentityEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    source_write_operations: Literal[0] = Field(default=0, alias="sourceWriteOperations")
    source_copy_operations: Literal[0] = Field(default=0, alias="sourceCopyOperations")
    evidence_mutation_operations: Literal[0] = Field(
        default=0,
        alias="evidenceMutationOperations",
    )
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_queries: Literal[0] = Field(default=0, alias="dnsQueries")
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    device_sessions: Literal[0] = Field(default=0, alias="deviceSessions")
    plugin_loads: Literal[0] = Field(default=0, alias="pluginLoads")
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    credential_uses: Literal[0] = Field(default=0, alias="credentialUses")
    lateral_movement_attempts: Literal[0] = Field(
        default=0,
        alias="lateralMovementAttempts",
    )
    target_process_executions: Literal[0] = Field(
        default=0,
        alias="targetProcessExecutions",
    )
    shell_commands: Literal[0] = Field(default=0, alias="shellCommands")
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")

    @field_validator("synthetic_test_only_required", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("FORENSICS-001D fixtures must remain synthetic test requirements")
        return value

    @field_validator(*_FIXTURE_CASE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("FORENSICS-001D fixtures cannot embed source or identity content")
        return value

    @field_validator(*_FIXTURE_CASE_ZERO_FIELDS, mode="before")
    @classmethod
    def require_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("FORENSICS-001D fixture channel counters must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_fixture_case(self) -> Self:
        mapping = _surface_mapping(self.surface_class)
        expected_signal = _surface_review_signal(self.surface_class)
        successful_evidence: tuple[_EvidenceRequirement, ...] = (
            "private-ground-truth-attestation",
            "field-level-ground-truth-manifest-attestation",
            "fixture-materialization-and-control-attestation",
            "source-membership-attestation",
            "source-execution-attestation",
            "source-provenance-preserving-runtime-receipt",
            "source-result-receipt",
            "comparison-source-membership-attestation",
            "comparison-execution-attestation",
            "comparison-provenance-preserving-runtime-receipt",
            "comparison-result-receipt",
            "cleanup-receipt",
        )
        corrupted_evidence: tuple[_EvidenceRequirement, ...] = (
            "private-ground-truth-attestation",
            "field-level-ground-truth-manifest-attestation",
            "fixture-materialization-and-control-attestation",
            "source-membership-attestation",
            "source-execution-attestation",
            "source-provenance-preserving-runtime-receipt",
            "source-bounded-parser-rejection-receipt",
            "comparison-source-membership-attestation",
            "comparison-execution-attestation",
            "comparison-provenance-preserving-runtime-receipt",
            "comparison-bounded-parser-rejection-receipt",
            "cleanup-receipt",
        )
        if self.ground_truth_class is ForensicEvidenceBenchmarkGroundTruthClass.KNOWN_POSITIVE:
            valid_outcome = (
                self.expected_outcome is ForensicEvidenceBenchmarkExpectedOutcome.REVIEW_SIGNAL
                and self.expected_result_disposition
                is ForensicEvidenceAnalysisResultDisposition.REVIEW
                and self.expected_oracle_disposition
                is ForensicEvidenceAnalysisOracleDisposition.REVIEW
                and self.expected_review_signal is expected_signal
                and self.required_evidence == successful_evidence
            )
        elif self.ground_truth_class is ForensicEvidenceBenchmarkGroundTruthClass.NEGATIVE_CONTROL:
            valid_outcome = (
                self.expected_outcome is ForensicEvidenceBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
                and self.expected_result_disposition
                is ForensicEvidenceAnalysisResultDisposition.NO_SIGNAL
                and self.expected_oracle_disposition
                is ForensicEvidenceAnalysisOracleDisposition.NO_SIGNAL
                and self.expected_review_signal is None
                and self.required_evidence == successful_evidence
            )
        else:
            valid_outcome = (
                self.expected_outcome
                is ForensicEvidenceBenchmarkExpectedOutcome.BOUNDED_CORRUPTION_HANDLING
                and self.expected_result_disposition is None
                and self.expected_oracle_disposition is None
                and self.expected_review_signal is None
                and self.required_evidence == corrupted_evidence
            )
        if (
            self.input_kind is not mapping.input_kind
            or self.operation is not mapping.operation
            or self.parser is not mapping.parser
            or self.rule_set != registered_forensic_evidence_rule_set().reference()
            or self.domain_worker_profile != _forensics_worker_profile_ref()
            or not valid_outcome
        ):
            raise ValueError("FORENSICS-001D seeded fixture shape differs")
        return self


_ForensicsMetricId = Literal[
    "forensics.artifact-coverage",
    "forensics.parsing-accuracy",
    "forensics.provenance-preservation-rate",
    "forensics.corrupted-input-handling-rate",
]
_REQUIRED_FORENSICS_METRIC_IDS: tuple[_ForensicsMetricId, ...] = (
    "forensics.artifact-coverage",
    "forensics.parsing-accuracy",
    "forensics.provenance-preservation-rate",
    "forensics.corrupted-input-handling-rate",
)
_FIXTURE_PROFILE_TRUE_FIELDS = (
    "seeded_evidence_requirements_registered",
    "private_ground_truth_requirements_registered",
    "sanitized_immutable_evidence_required",
    "disposable_parser_sandbox_required",
    "network_and_dns_disabled_required",
    "non_root_runtime_required",
    "read_only_noexec_evidence_mount_required",
    "positive_controls_registered",
    "negative_controls_registered",
    "corrupted_input_controls_registered",
    "bounded_parser_rejection_evidence_required",
    "two_separately_authorized_executions_required",
    "source_membership_and_provenance_evidence_required",
    "field_level_ground_truth_manifest_required",
    "cleanup_evidence_required",
    "domain_metrics_required",
)
_FIXTURE_PROFILE_FALSE_FIELDS = (
    "target_profile_selected",
    "fixture_materialized",
    "sandbox_provisioned",
    "private_ground_truth_verified",
    "ground_truth_case_observed",
    "positive_control_observed",
    "negative_control_observed",
    "corrupted_input_control_observed",
    "bounded_parser_rejection_observed",
    "fixture_execution_authorized",
    "cleanup_observed",
    "parser_comparison_evidence_bound",
    "benchmark_measurement_observed",
    "artifact_coverage_measured",
    "parsing_accuracy_measured",
    "provenance_preservation_rate_measured",
    "corrupted_input_handling_rate_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "source_truth_established",
    "parser_correctness_established",
    "negative_security_claim_established",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "source_access_authorized",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "dns_access_authorized",
    "credential_use_authorized",
    "source_mutation_authorized",
    "evidence_mutation_authorized",
    "graph_admission_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
    "debugger_attach_authorized",
)


class ForensicEvidenceAnalysisBenchmarkFixtureProfile(_FrozenStrictModel):
    """Registered seeded-evidence requirements, never materialization or measurement."""

    api_version: Literal[
        "pajin.dev/forensic-evidence-analysis-benchmark-fixture-profile/v1alpha1"
    ] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisBenchmarkFixtureProfile"] = (
        "ForensicEvidenceAnalysisBenchmarkFixtureProfile"
    )
    profile_id: str = Field(default="", alias="profileId", max_length=118)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    domain_worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="domainWorkerProfile")
    required_domain_metric_ids: tuple[_ForensicsMetricId, ...] = Field(
        min_length=4,
        max_length=4,
        alias="requiredDomainMetricIds",
    )
    covered_surface_classes: tuple[ForensicSurfaceClass, ...] = Field(
        min_length=4,
        max_length=4,
        alias="coveredSurfaceClasses",
    )
    cases: tuple[ForensicEvidenceAnalysisBenchmarkFixtureCase, ...] = Field(
        min_length=12,
        max_length=12,
    )
    state: Literal["registered-seeded-evidence-requirements-not-materialized-or-measured"] = (
        "registered-seeded-evidence-requirements-not-materialized-or-measured"
    )
    seeded_evidence_requirements_registered: Literal[True] = Field(
        default=True,
        alias="seededEvidenceRequirementsRegistered",
    )
    private_ground_truth_requirements_registered: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthRequirementsRegistered",
    )
    sanitized_immutable_evidence_required: Literal[True] = Field(
        default=True,
        alias="sanitizedImmutableEvidenceRequired",
    )
    disposable_parser_sandbox_required: Literal[True] = Field(
        default=True,
        alias="disposableParserSandboxRequired",
    )
    network_and_dns_disabled_required: Literal[True] = Field(
        default=True,
        alias="networkAndDnsDisabledRequired",
    )
    non_root_runtime_required: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeRequired",
    )
    read_only_noexec_evidence_mount_required: Literal[True] = Field(
        default=True,
        alias="readOnlyNoexecEvidenceMountRequired",
    )
    positive_controls_registered: Literal[True] = Field(
        default=True,
        alias="positiveControlsRegistered",
    )
    negative_controls_registered: Literal[True] = Field(
        default=True,
        alias="negativeControlsRegistered",
    )
    corrupted_input_controls_registered: Literal[True] = Field(
        default=True,
        alias="corruptedInputControlsRegistered",
    )
    bounded_parser_rejection_evidence_required: Literal[True] = Field(
        default=True,
        alias="boundedParserRejectionEvidenceRequired",
    )
    two_separately_authorized_executions_required: Literal[True] = Field(
        default=True,
        alias="twoSeparatelyAuthorizedExecutionsRequired",
    )
    source_membership_and_provenance_evidence_required: Literal[True] = Field(
        default=True,
        alias="sourceMembershipAndProvenanceEvidenceRequired",
    )
    field_level_ground_truth_manifest_required: Literal[True] = Field(
        default=True,
        alias="fieldLevelGroundTruthManifestRequired",
    )
    cleanup_evidence_required: Literal[True] = Field(default=True, alias="cleanupEvidenceRequired")
    domain_metrics_required: Literal[True] = Field(default=True, alias="domainMetricsRequired")
    target_profile_selected: Literal[False] = Field(default=False, alias="targetProfileSelected")
    fixture_materialized: Literal[False] = Field(default=False, alias="fixtureMaterialized")
    sandbox_provisioned: Literal[False] = Field(default=False, alias="sandboxProvisioned")
    private_ground_truth_verified: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthVerified",
    )
    ground_truth_case_observed: Literal[False] = Field(
        default=False,
        alias="groundTruthCaseObserved",
    )
    positive_control_observed: Literal[False] = Field(
        default=False,
        alias="positiveControlObserved",
    )
    negative_control_observed: Literal[False] = Field(
        default=False,
        alias="negativeControlObserved",
    )
    corrupted_input_control_observed: Literal[False] = Field(
        default=False,
        alias="corruptedInputControlObserved",
    )
    bounded_parser_rejection_observed: Literal[False] = Field(
        default=False,
        alias="boundedParserRejectionObserved",
    )
    fixture_execution_authorized: Literal[False] = Field(
        default=False,
        alias="fixtureExecutionAuthorized",
    )
    cleanup_observed: Literal[False] = Field(default=False, alias="cleanupObserved")
    parser_comparison_evidence_bound: Literal[False] = Field(
        default=False,
        alias="parserComparisonEvidenceBound",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    artifact_coverage_measured: Literal[False] = Field(
        default=False,
        alias="artifactCoverageMeasured",
    )
    parsing_accuracy_measured: Literal[False] = Field(
        default=False,
        alias="parsingAccuracyMeasured",
    )
    provenance_preservation_rate_measured: Literal[False] = Field(
        default=False,
        alias="provenancePreservationRateMeasured",
    )
    corrupted_input_handling_rate_measured: Literal[False] = Field(
        default=False,
        alias="corruptedInputHandlingRateMeasured",
    )
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    source_truth_established: Literal[False] = Field(default=False, alias="sourceTruthEstablished")
    parser_correctness_established: Literal[False] = Field(
        default=False,
        alias="parserCorrectnessEstablished",
    )
    negative_security_claim_established: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaimEstablished",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    source_access_authorized: Literal[False] = Field(default=False, alias="sourceAccessAuthorized")
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceMutationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    debugger_attach_authorized: Literal[False] = Field(
        default=False, alias="debuggerAttachAuthorized"
    )

    @field_validator(*_FIXTURE_PROFILE_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("FORENSICS-001D fixture requirements must be boolean true")
        return value

    @field_validator(*_FIXTURE_PROFILE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("FORENSICS-001D fixture profile cannot claim authority or measurement")
        return value

    @model_validator(mode="after")
    def bind_fixture_profile(self) -> Self:
        _require_forensics_domain_plan(self.domain_benchmark_plan)
        if (
            self.domain_worker_profile != _forensics_worker_profile_ref()
            or self.required_domain_metric_ids != _REQUIRED_FORENSICS_METRIC_IDS
            or self.covered_surface_classes != tuple(ForensicSurfaceClass)
            or self.cases != _registered_fixture_cases()
        ):
            raise ValueError("FORENSICS-001D fixture profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.forensic-evidence-analysis-benchmark-fixture-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"forensic-evidence-analysis-fixtures_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("FORENSICS-001D fixture profile digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("FORENSICS-001D fixture profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


class ForensicEvidenceAnalysisReplayBenchmarkGate:
    """Reopen two sealed C executions without reading source or result bodies."""

    def __init__(
        self,
        *,
        source_root: Path,
        replay_root: Path,
        source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
        source_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
        replay_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
    ) -> None:
        if type(source_membership_trust_anchor) is not ForensicEvidenceSourceMembershipTrustAnchor:
            raise TypeError("FORENSICS-001D requires an exact source-membership trust anchor")
        if type(source_execution_trust_anchor) is not ForensicEvidenceAnalysisExecutionTrustAnchor:
            raise TypeError("FORENSICS-001D requires an exact source execution trust anchor")
        if type(replay_execution_trust_anchor) is not ForensicEvidenceAnalysisExecutionTrustAnchor:
            raise TypeError("FORENSICS-001D requires an exact replay execution trust anchor")
        _require_known_instance_fields(
            source_membership_trust_anchor,
            label="FORENSICS-001D source-membership anchor",
        )
        _require_known_instance_fields(
            source_execution_trust_anchor,
            label="FORENSICS-001D source execution anchor",
        )
        _require_known_instance_fields(
            replay_execution_trust_anchor,
            label="FORENSICS-001D replay execution anchor",
        )
        self._source_root = _canonical_source_root(source_root, label="source")
        self._replay_root = _canonical_source_root(replay_root, label="replay")
        if self._source_root == self._replay_root or self._source_root.samefile(self._replay_root):
            raise ValueError("FORENSICS-001D requires distinct Gate-owned evidence roots")
        self._source_membership_trust_anchor = (
            ForensicEvidenceSourceMembershipTrustAnchor.model_validate(
                source_membership_trust_anchor.model_dump(mode="json", by_alias=True)
            )
        )
        self._source_execution_trust_anchor = (
            ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(
                source_execution_trust_anchor.model_dump(mode="json", by_alias=True)
            )
        )
        self._replay_execution_trust_anchor = (
            ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(
                replay_execution_trust_anchor.model_dump(mode="json", by_alias=True)
            )
        )

    def bind_replay(
        self,
        source_inputs: ForensicEvidenceAnalysisObservationSourceInputs,
        source_admission: ForensicEvidenceAnalysisKnowledgeAdmission,
        replay_inputs: ForensicEvidenceAnalysisObservationSourceInputs,
        *,
        source_graph_store: SQLiteGraphStore,
        replay_graph_store: SQLiteGraphStore,
    ) -> ForensicEvidenceAnalysisReplayValidation:
        """Return a read-only neutral comparison of two separately authorized executions."""

        try:
            if type(source_graph_store) is not SQLiteGraphStore:
                raise TypeError("FORENSICS-001D requires an exact source SQLite Graph Store")
            if type(replay_graph_store) is not SQLiteGraphStore:
                raise TypeError("FORENSICS-001D requires an exact replay SQLite Graph Store")
            if (
                source_graph_store.path == replay_graph_store.path
                or source_graph_store.path.samefile(replay_graph_store.path)
            ):
                raise ValueError("FORENSICS-001D requires separate SQLite Graph authority stores")
            _require_known_instance_fields(
                source_admission,
                label="FORENSICS-001D source admission",
            )
            canonical_admission = ForensicEvidenceAnalysisKnowledgeAdmission.model_validate(
                source_admission.model_dump(mode="json", by_alias=True)
            )
            source_event_count = len(source_graph_store.event_log.events())
            replay_event_count = len(replay_graph_store.event_log.events())
            source = load_verified_forensic_evidence_analysis_observation_source(
                source_inputs,
                graph_store=source_graph_store,
                source_root=self._source_root,
                execution_trust_anchor=self._source_execution_trust_anchor,
                source_membership_trust_anchor=self._source_membership_trust_anchor,
            )
            replay = load_verified_forensic_evidence_analysis_observation_source(
                replay_inputs,
                graph_store=replay_graph_store,
                source_root=self._replay_root,
                execution_trust_anchor=self._replay_execution_trust_anchor,
                source_membership_trust_anchor=self._source_membership_trust_anchor,
            )
            _require_stored_source_admission(canonical_admission, source_graph_store)
            source_projection = _execution_projection(source)
            replay_projection = _execution_projection(replay)
            _require_admission_projection(canonical_admission, source_projection)
            mode = _replay_mode(source_projection, replay_projection)
            comparison = _comparison(
                source_result=source_projection.result_receipt,
                source_oracle=source_projection.oracle_verdict,
                replay_result=replay_projection.result_receipt,
                replay_oracle=replay_projection.oracle_verdict,
            )
            validation = ForensicEvidenceAnalysisReplayValidation(
                sourceAdmission=canonical_admission,
                sourceExecution=source_projection,
                replayExecution=replay_projection,
                domainBenchmarkPlan=_forensics_domain_benchmark_plan_ref(),
                replayMode=mode,
                comparison=comparison,
                resultBodyDigestMatched=(
                    source_projection.result_receipt.result_body_sha256
                    == replay_projection.result_receipt.result_body_sha256
                ),
                resultBytesMatched=(
                    source_projection.result_receipt.result_bytes
                    == replay_projection.result_receipt.result_bytes
                ),
                resultDispositionMatched=(
                    source_projection.result_receipt.disposition
                    is replay_projection.result_receipt.disposition
                ),
                oracleDispositionMatched=(
                    source_projection.oracle_verdict.disposition
                    is replay_projection.oracle_verdict.disposition
                ),
                reviewSignalMatched=(
                    source_projection.oracle_verdict.review_signal
                    is replay_projection.oracle_verdict.review_signal
                ),
                domainValidationStrategySatisfied=(
                    mode is ForensicEvidenceAnalysisReplayMode.INDEPENDENT_PARSER_COMPARISON
                ),
                deterministicParserCoordinatesReused=(
                    mode is ForensicEvidenceAnalysisReplayMode.DETERMINISTIC_REPARSE
                ),
                distinctParserImplementationCoordinatesVerified=(
                    mode is ForensicEvidenceAnalysisReplayMode.INDEPENDENT_PARSER_COMPARISON
                ),
                state=_replay_state(mode, comparison),
            )
            if (
                len(source_graph_store.event_log.events()) != source_event_count
                or len(replay_graph_store.event_log.events()) != replay_event_count
            ):
                raise ValueError("FORENSICS-001D comparison mutated Graph authority")
            return validation
        except ForensicEvidenceAnalysisReplayBenchmarkError:
            raise
        except (
            AttributeError,
            KeyError,
            OSError,
            RuntimeError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise ForensicEvidenceAnalysisReplayBenchmarkError(
                "FORENSICS-001D forensic analysis replay failed closed"
            ) from exc


def bind_forensic_evidence_analysis_replay(
    source_inputs: ForensicEvidenceAnalysisObservationSourceInputs,
    source_admission: ForensicEvidenceAnalysisKnowledgeAdmission,
    replay_inputs: ForensicEvidenceAnalysisObservationSourceInputs,
    *,
    source_root: Path,
    replay_root: Path,
    source_graph_store: SQLiteGraphStore,
    replay_graph_store: SQLiteGraphStore,
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    source_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
    replay_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
) -> ForensicEvidenceAnalysisReplayValidation:
    """Functional entry point for the deployment-configured FORENSICS-001D Gate."""

    try:
        gate = ForensicEvidenceAnalysisReplayBenchmarkGate(
            source_root=source_root,
            replay_root=replay_root,
            source_membership_trust_anchor=source_membership_trust_anchor,
            source_execution_trust_anchor=source_execution_trust_anchor,
            replay_execution_trust_anchor=replay_execution_trust_anchor,
        )
        return gate.bind_replay(
            source_inputs,
            source_admission,
            replay_inputs,
            source_graph_store=source_graph_store,
            replay_graph_store=replay_graph_store,
        )
    except ForensicEvidenceAnalysisReplayBenchmarkError:
        raise
    except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
        raise ForensicEvidenceAnalysisReplayBenchmarkError(
            "FORENSICS-001D forensic analysis replay failed closed"
        ) from exc


def load_verified_forensic_evidence_analysis_replay_validation(
    validation: object,
    source_inputs: ForensicEvidenceAnalysisObservationSourceInputs,
    replay_inputs: ForensicEvidenceAnalysisObservationSourceInputs,
    *,
    source_root: Path,
    replay_root: Path,
    source_graph_store: SQLiteGraphStore,
    replay_graph_store: SQLiteGraphStore,
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    source_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
    replay_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
) -> ForensicEvidenceAnalysisReplayValidation:
    """Reverify a wire projection against both C contexts and Graph authority."""

    try:
        _require_known_instance_fields(
            validation,
            label="FORENSICS-001D replay validation",
        )
        payload: object = (
            validation.model_dump(mode="json", by_alias=True)
            if isinstance(validation, ForensicEvidenceAnalysisReplayValidation)
            else validation
        )
        canonical = ForensicEvidenceAnalysisReplayValidation.model_validate(payload)
        expected = bind_forensic_evidence_analysis_replay(
            source_inputs,
            canonical.source_admission,
            replay_inputs,
            source_root=source_root,
            replay_root=replay_root,
            source_graph_store=source_graph_store,
            replay_graph_store=replay_graph_store,
            source_membership_trust_anchor=source_membership_trust_anchor,
            source_execution_trust_anchor=source_execution_trust_anchor,
            replay_execution_trust_anchor=replay_execution_trust_anchor,
        )
        if canonical != expected:
            raise ValueError(
                "FORENSICS-001D wire projection differs from deployment evidence "
                "and Graph authority"
            )
        return expected
    except ForensicEvidenceAnalysisReplayBenchmarkError:
        raise
    except (
        AttributeError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise ForensicEvidenceAnalysisReplayBenchmarkError(
            "FORENSICS-001D wire re-verification failed closed"
        ) from exc


def registered_forensic_evidence_analysis_benchmark_fixture_profile() -> (
    ForensicEvidenceAnalysisBenchmarkFixtureProfile
):
    """Return exact seeded-evidence requirements without materializing or measuring them."""

    try:
        return ForensicEvidenceAnalysisBenchmarkFixtureProfile(
            domainBenchmarkPlan=_forensics_domain_benchmark_plan_ref(),
            domainWorkerProfile=_forensics_worker_profile_ref(),
            requiredDomainMetricIds=_REQUIRED_FORENSICS_METRIC_IDS,
            coveredSurfaceClasses=tuple(ForensicSurfaceClass),
            cases=_registered_fixture_cases(),
        )
    except (RuntimeError, ValidationError, ValueError) as exc:
        raise ForensicEvidenceAnalysisReplayBenchmarkError(
            "FORENSICS-001D seeded evidence registration failed closed"
        ) from exc


def _canonical_source_root(value: Path, *, label: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"FORENSICS-001D {label} evidence root must be a Path")
    if not value.is_absolute() or not value.exists() or not value.is_dir() or value.is_symlink():
        raise ValueError(f"FORENSICS-001D {label} evidence root is not canonical")
    canonical = value.resolve(strict=True)
    if canonical != value:
        raise ValueError(f"FORENSICS-001D {label} evidence root must be pre-resolved")
    return canonical


def _execution_projection(
    source: VerifiedForensicEvidenceAnalysisObservationSource,
) -> ForensicEvidenceAnalysisReplayExecution:
    return ForensicEvidenceAnalysisReplayExecution(
        preparation=source.preparation,
        capabilityGrant=source.job.grant,
        actionPermit=source.permit,
        approvalReceipt=source.approval_receipt,
        sourceMembershipTrustAnchor=source.source_membership_trust_anchor,
        executionTrustAnchor=source.execution_trust_anchor,
        verification=source.verification,
        executionBundle=source.bundle,
        resultReceipt=source.result_receipt,
        oracleVerdict=source.oracle_verdict,
        sourceRootDigest=source.source_root_digest,
        attestationReference=source.attestation_reference,
        attestationSha256=source.attestation_sha256,
        resultReceiptReference=source.result_receipt_reference,
        resultReceiptSha256=source.result_receipt_sha256,
    )


def _require_stored_source_admission(
    admission: ForensicEvidenceAnalysisKnowledgeAdmission,
    graph_store: SQLiteGraphStore,
) -> None:
    observation = admission.candidate.observation_proposal
    stored_observation = graph_store.event_log.event_for_attempt(
        observation.proposal_id,
        observation.digest(),
    )
    if stored_observation != admission.observation_graph_event:
        raise ValueError("FORENSICS-001D source Observation admission is not stored exactly")
    hypothesis = admission.candidate.hypothesis_proposal
    if hypothesis is None:
        if admission.hypothesis_graph_event is not None:
            raise ValueError("FORENSICS-001D source Hypothesis admission differs")
        return
    stored_hypothesis = graph_store.event_log.event_for_attempt(
        hypothesis.proposal_id,
        hypothesis.digest(),
    )
    if stored_hypothesis != admission.hypothesis_graph_event:
        raise ValueError("FORENSICS-001D source Hypothesis admission is not stored exactly")


def _require_admission_projection(
    admission: ForensicEvidenceAnalysisKnowledgeAdmission,
    execution: ForensicEvidenceAnalysisReplayExecution,
) -> None:
    candidate = admission.candidate
    receipt = execution.result_receipt
    verdict = execution.oracle_verdict
    source_verification = execution.verification.source_membership_verification
    if (
        candidate.preparation != execution.preparation
        or candidate.surface != execution.preparation.surface.reference()
        or candidate.source_execution_snapshot != execution.action_permit.snapshot
        or candidate.source_run_id != execution.action_permit.run_id
        or candidate.source_root_digest != execution.source_root_digest
        or candidate.caller_source_root_sha256
        != execution.preparation.surface.locator.provenance.source_root_sha256
        or candidate.source_membership_trust_anchor_digest
        != execution.source_membership_trust_anchor.digest
        or candidate.execution_trust_anchor_digest != execution.verification.trust_anchor_digest
        or candidate.source_membership_verification_digest
        != source_verification.verification_digest
        or candidate.statement_sha256 != execution.verification.statement_sha256
        or candidate.approval_receipt_id != execution.approval_receipt.receipt_id
        or candidate.approval_receipt_digest != execution.approval_receipt.receipt_digest
        or candidate.attestation_reference != execution.attestation_reference
        or candidate.attestation_sha256 != execution.attestation_sha256
        or candidate.result_receipt_reference != execution.result_receipt_reference
        or candidate.result_receipt_sha256 != execution.result_receipt_sha256
        or candidate.result_receipt_digest != receipt.receipt_digest
        or candidate.result_body_sha256 != receipt.result_body_sha256
        or candidate.result_bytes != receipt.result_bytes
        or candidate.result_disposition is not receipt.disposition
        or candidate.review_signal is not verdict.review_signal
        or candidate.artifact_sha256 != receipt.artifact_sha256
        or candidate.artifact_bytes != receipt.artifact_bytes
        or candidate.output_schema != receipt.output_schema
        or candidate.operation is not receipt.operation
        or candidate.parser is not receipt.parser
        or candidate.input_kind is not receipt.input_kind
        or candidate.rule_set != receipt.rule_set
        or candidate.oracle_verdict != verdict
        or candidate.oracle_policy_digest != verdict.policy.policy_digest
        or candidate.oracle_verdict_digest != verdict.verdict_digest
    ):
        raise ValueError("FORENSICS-001D source admission differs from sealed C evidence")


def _require_equivalent_replay_semantics(
    source: ForensicEvidenceAnalysisReplayExecution,
    replay: ForensicEvidenceAnalysisReplayExecution,
) -> None:
    left = source.preparation
    right = replay.preparation
    left_prepared = left.prepared_action
    right_prepared = right.prepared_action
    left_statement = source.execution_bundle.statement
    right_statement = replay.execution_bundle.statement
    if (
        source.source_membership_trust_anchor != replay.source_membership_trust_anchor
        or left.binding != right.binding
        or left.surface != right.surface
        or left.input_kind is not right.input_kind
        or left.operation is not right.operation
        or left.artifact_custody != right.artifact_custody
        or _sandbox_semantic_projection(left.sandbox) != _sandbox_semantic_projection(right.sandbox)
        or _analysis_request_semantic_projection(left.analysis_request)
        != _analysis_request_semantic_projection(right.analysis_request)
        or left.campaign_scope != right.campaign_scope
        or left.matched_surface_allow_rule != right.matched_surface_allow_rule
        or left.release != right.release
        or left_prepared.activation_set_digest != right_prepared.activation_set_digest
        or left_prepared.capability != right_prepared.capability
        or left_statement.campaign_id != right_statement.campaign_id
        or left_statement.campaign_digest != right_statement.campaign_digest
        or _capability_grant_semantic_projection(source.capability_grant)
        != _capability_grant_semantic_projection(replay.capability_grant)
        or left_statement.gateway_policy_decision != right_statement.gateway_policy_decision
        or _source_membership_semantic_projection(left_statement)
        != _source_membership_semantic_projection(right_statement)
        or _runtime_semantic_projection(left_statement.sandbox_runtime)
        != _runtime_semantic_projection(right_statement.sandbox_runtime)
        or _result_semantic_projection(source.result_receipt)
        != _result_semantic_projection(replay.result_receipt)
        or _oracle_semantic_projection(source.oracle_verdict)
        != _oracle_semantic_projection(replay.oracle_verdict)
    ):
        raise ValueError("FORENSICS-001D replay differs from exact source semantics")
    if (
        source.result_receipt.result_body_sha256 == replay.result_receipt.result_body_sha256
        and source.result_receipt.result_bytes != replay.result_receipt.result_bytes
    ):
        raise ValueError("FORENSICS-001D equal result digest has inconsistent byte count")


def _sandbox_semantic_projection(
    sandbox: ForensicEvidenceAnalysisSandboxBinding,
) -> dict[str, object]:
    projection = sandbox.model_dump(mode="json", by_alias=True)
    for key in (
        "sandboxBindingId",
        "sandboxBindingDigest",
        "parserExecutableSHA256",
        "parserConfigurationSHA256",
        "sandboxImageSHA256",
    ):
        projection.pop(key)
    return projection


def _analysis_request_semantic_projection(
    request: ForensicEvidenceAnalysisRequest,
) -> dict[str, object]:
    projection = request.model_dump(mode="json", by_alias=True)
    sandbox = projection.get("sandbox")
    if not isinstance(sandbox, dict):
        raise ValueError("FORENSICS-001D analysis request lacks canonical sandbox semantics")
    for key in (
        "sandboxBindingId",
        "sandboxBindingDigest",
        "parserExecutableSHA256",
        "parserConfigurationSHA256",
        "sandboxImageSHA256",
    ):
        sandbox.pop(key)
    return projection


def _capability_grant_semantic_projection(grant: CapabilityGrant) -> dict[str, object]:
    projection = _canonical_capability_grant_payload(grant)
    for key in ("grant_id", "issued_at", "expires_at"):
        projection.pop(key)
    return projection


def _canonical_capability_grant_payload(grant: CapabilityGrant) -> dict[str, object]:
    projection = grant.model_dump(mode="json", by_alias=True)
    projection["tools"] = sorted(grant.tools)
    projection["targets"] = sorted(grant.targets)
    return projection


def _source_membership_semantic_projection(
    statement: ForensicEvidenceAnalysisExecutionStatement,
) -> dict[str, object]:
    attestation = statement.source_membership.attestation
    projection = attestation.model_dump(mode="json", by_alias=True)
    for key in (
        "attestationId",
        "attestationDigest",
        "validFrom",
        "validUntil",
        "attestedAt",
    ):
        projection.pop(key)
    return projection


def _runtime_semantic_projection(
    runtime: ForensicEvidenceAnalysisSandboxRuntimeReceipt,
) -> dict[str, object]:
    projection = runtime.model_dump(mode="json", by_alias=True)
    for key in (
        "receiptId",
        "receiptDigest",
        "sandboxBindingId",
        "sandboxBindingDigest",
        "parserExecutableSHA256",
        "parserConfigurationSHA256",
        "sandboxImageSHA256",
        "observedArtifactBytes",
        "observedOutputBytes",
        "observedRuntimeSeconds",
        "observedPeakMemoryMiB",
        "observedPeakProcessCount",
        "observedParserWorkUnits",
        "observedRecursionDepth",
        "observedDecompressionRatio",
        "observedDecompressedBytes",
        "runtimeIdentityDigest",
        "confinementDigest",
        "attestedAt",
    ):
        projection.pop(key)
    return projection


def _result_semantic_projection(
    receipt: ForensicEvidenceAnalysisResultReceipt,
) -> dict[str, object]:
    projection = receipt.model_dump(mode="json", by_alias=True)
    for key in (
        "receiptId",
        "receiptDigest",
        "executionId",
        "requestId",
        "requestDigest",
        "preparationId",
        "preparationDigest",
        "resultBodySha256",
        "resultBytes",
        "disposition",
        "receivedAt",
    ):
        projection.pop(key)
    return projection


def _oracle_semantic_projection(
    verdict: ForensicEvidenceAnalysisAdmissionOracleVerdict,
) -> dict[str, object]:
    projection = verdict.model_dump(mode="json", by_alias=True)
    for key in (
        "verdictId",
        "verdictDigest",
        "disposition",
        "resultDisposition",
        "reviewSignal",
        "resultReceiptId",
        "resultReceiptDigest",
        "resultBodySha256",
        "resultBytes",
    ):
        projection.pop(key)
    return projection


def _require_distinct_replay_provenance(
    source: ForensicEvidenceAnalysisReplayExecution,
    replay: ForensicEvidenceAnalysisReplayExecution,
) -> None:
    left = _execution_identity_coordinates(source)
    right = _execution_identity_coordinates(replay)
    reused = tuple(name for name in left if left[name] == right[name])
    if reused:
        raise ValueError(
            "FORENSICS-001D replay reused source action or evidence provenance: "
            + ", ".join(reused)
        )
    if (
        replay.execution_bundle.statement.started_at
        <= source.execution_bundle.statement.finished_at
    ):
        raise ValueError("FORENSICS-001D signed replay timestamp is not after the source")


def _execution_identity_coordinates(
    execution: ForensicEvidenceAnalysisReplayExecution,
) -> dict[str, str]:
    preparation = execution.preparation
    permit = execution.action_permit
    approval_receipt = execution.approval_receipt
    approval = approval_receipt.approval
    statement = execution.execution_bundle.statement
    runtime = statement.sandbox_runtime
    source_verification = execution.verification.source_membership_verification
    result = execution.result_receipt
    oracle = execution.oracle_verdict
    return {
        "preparationId": preparation.preparation_id,
        "preparationDigest": preparation.preparation_digest,
        "runId": permit.run_id,
        "sourceRootDigest": execution.source_root_digest,
        "requestId": permit.request_id,
        "requestDigest": permit.request_digest,
        "envelopeId": permit.envelope_id,
        "envelopeDigest": permit.envelope_digest,
        "proposalId": permit.proposal_id,
        "proposalDigest": permit.proposal_digest,
        "decisionId": permit.decision_id,
        "decisionDigest": permit.decision_digest,
        "permitId": permit.permit_id,
        "permitDigest": permit.permit_digest,
        "dispatchId": permit.dispatch_id,
        "approvalId": approval.approval_id,
        "approvalDigest": approval.approval_digest,
        "approvalReceiptId": approval_receipt.receipt_id,
        "approvalReceiptDigest": approval_receipt.receipt_digest,
        "executionId": statement.execution_id,
        "gatewayOutcomeDigest": statement.gateway_outcome_digest,
        "statementSha256": execution.verification.statement_sha256,
        "sourceMembershipAttestationSha256": source_verification.attestation_sha256,
        "sourceMembershipVerificationId": source_verification.verification_id,
        "sourceMembershipVerificationDigest": source_verification.verification_digest,
        "sandboxRuntimeReceiptId": runtime.receipt_id,
        "sandboxRuntimeReceiptDigest": runtime.receipt_digest,
        "attestationSha256": execution.attestation_sha256,
        "resultReceiptId": result.receipt_id,
        "resultReceiptDigest": result.receipt_digest,
        "resultReceiptSha256": execution.result_receipt_sha256,
        "oracleVerdictId": oracle.verdict_id,
        "oracleVerdictDigest": oracle.verdict_digest,
    }


def _parser_implementation_coordinates(
    execution: ForensicEvidenceAnalysisReplayExecution,
) -> dict[str, str]:
    sandbox = execution.preparation.sandbox
    signer = _active_execution_signer(execution.execution_trust_anchor)
    return {
        "executionTrustAnchorDigest": execution.verification.trust_anchor_digest,
        "activeSignerKeyId": signer.key_id,
        "activeSignerPublicKey": signer.public_key_base64url,
        "sandboxBindingId": sandbox.sandbox_binding_id,
        "sandboxBindingDigest": sandbox.sandbox_binding_digest,
        "parserExecutableSHA256": sandbox.parser_executable_sha256,
        "parserConfigurationSHA256": sandbox.parser_configuration_sha256,
        "sandboxImageSHA256": sandbox.sandbox_image_sha256,
    }


def _replay_mode(
    source: ForensicEvidenceAnalysisReplayExecution,
    replay: ForensicEvidenceAnalysisReplayExecution,
) -> ForensicEvidenceAnalysisReplayMode:
    left = _parser_implementation_coordinates(source)
    right = _parser_implementation_coordinates(replay)
    equal = tuple(name for name in left if left[name] == right[name])
    if len(equal) == len(left):
        return ForensicEvidenceAnalysisReplayMode.DETERMINISTIC_REPARSE
    if not equal:
        return ForensicEvidenceAnalysisReplayMode.INDEPENDENT_PARSER_COMPARISON
    raise ValueError(
        "FORENSICS-001D parser implementation coordinates are only partially independent: "
        + ", ".join(equal)
    )


def _active_execution_signer(
    trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
) -> ForensicEvidenceAnalysisExecutionVerificationKey:
    active = tuple(
        key
        for key in trust_anchor.keys
        if key.state is ForensicEvidenceAnalysisExecutionKeyState.ACTIVE
    )
    if len(active) != 1:
        raise ValueError("FORENSICS-001D execution anchor lacks one exact active signer")
    return active[0]


def _active_source_signer(
    trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
) -> ForensicEvidenceSourceMembershipVerificationKey:
    active = tuple(
        key
        for key in trust_anchor.keys
        if key.state is ForensicEvidenceSourceMembershipKeyState.ACTIVE
    )
    if len(active) != 1:
        raise ValueError("FORENSICS-001D source anchor lacks one exact active signer")
    return active[0]


def _comparison(
    *,
    source_result: ForensicEvidenceAnalysisResultReceipt,
    source_oracle: ForensicEvidenceAnalysisAdmissionOracleVerdict,
    replay_result: ForensicEvidenceAnalysisResultReceipt,
    replay_oracle: ForensicEvidenceAnalysisAdmissionOracleVerdict,
) -> ForensicEvidenceAnalysisReplayComparison:
    body_matched = source_result.result_body_sha256 == replay_result.result_body_sha256
    bytes_matched = source_result.result_bytes == replay_result.result_bytes
    if body_matched and not bytes_matched:
        raise ValueError("FORENSICS-001D equal result digest has inconsistent byte count")
    bounded_matched = (
        source_result.disposition is replay_result.disposition
        and source_oracle.disposition is replay_oracle.disposition
        and source_oracle.review_signal is replay_oracle.review_signal
    )
    if body_matched and bytes_matched and bounded_matched:
        return ForensicEvidenceAnalysisReplayComparison.MATCHED
    if not bounded_matched:
        return ForensicEvidenceAnalysisReplayComparison.CHANGED
    return ForensicEvidenceAnalysisReplayComparison.UNRESOLVED


def _replay_state(
    mode: ForensicEvidenceAnalysisReplayMode,
    comparison: ForensicEvidenceAnalysisReplayComparison,
) -> _ReplayState:
    suffix = {
        ForensicEvidenceAnalysisReplayComparison.MATCHED: "match",
        ForensicEvidenceAnalysisReplayComparison.CHANGED: "changed",
        ForensicEvidenceAnalysisReplayComparison.UNRESOLVED: "unresolved",
    }[comparison]
    states: dict[
        ForensicEvidenceAnalysisReplayMode,
        tuple[_ReplayState, _ReplayState, _ReplayState],
    ] = {
        ForensicEvidenceAnalysisReplayMode.DETERMINISTIC_REPARSE: (
            "deterministic-reparse-match",
            "deterministic-reparse-changed",
            "deterministic-reparse-unresolved",
        ),
        ForensicEvidenceAnalysisReplayMode.INDEPENDENT_PARSER_COMPARISON: (
            "independent-parser-comparison-match",
            "independent-parser-comparison-changed",
            "independent-parser-comparison-unresolved",
        ),
    }
    index = ("match", "changed", "unresolved").index(suffix)
    return states[mode][index]


def _surface_mapping(
    surface_class: ForensicSurfaceClass,
) -> ForensicSurfaceAnalysisMapping:
    rows = tuple(
        row
        for row in registered_forensic_evidence_rule_set().surface_analysis_mapping
        if row.surface_class is surface_class
    )
    if len(rows) != 1:
        raise ValueError("FORENSICS-001D Surface mapping is not registered exactly")
    return rows[0]


def _surface_review_signal(
    surface_class: ForensicSurfaceClass,
) -> ForensicEvidenceSignalKind:
    rows = tuple(
        row
        for row in registered_forensic_evidence_analysis_oracle_policy().surface_signal_mapping
        if row.surface_class is surface_class
    )
    if len(rows) != 1:
        raise ValueError("FORENSICS-001D Oracle Surface signal is not registered exactly")
    return rows[0].review_signal


def _fixture_evidence_requirements(
    ground_truth_class: ForensicEvidenceBenchmarkGroundTruthClass,
) -> tuple[_EvidenceRequirement, ...]:
    shared: tuple[_EvidenceRequirement, ...] = (
        "private-ground-truth-attestation",
        "field-level-ground-truth-manifest-attestation",
        "fixture-materialization-and-control-attestation",
        "source-membership-attestation",
        "source-execution-attestation",
        "source-provenance-preserving-runtime-receipt",
    )
    comparison: tuple[_EvidenceRequirement, ...] = (
        "comparison-source-membership-attestation",
        "comparison-execution-attestation",
        "comparison-provenance-preserving-runtime-receipt",
    )
    if ground_truth_class is ForensicEvidenceBenchmarkGroundTruthClass.CORRUPTED_INPUT_CONTROL:
        return (
            *shared,
            "source-bounded-parser-rejection-receipt",
            *comparison,
            "comparison-bounded-parser-rejection-receipt",
            "cleanup-receipt",
        )
    return (
        *shared,
        "source-result-receipt",
        *comparison,
        "comparison-result-receipt",
        "cleanup-receipt",
    )


def _fixture_case(
    *,
    fixture_id: str,
    ground_truth_class: ForensicEvidenceBenchmarkGroundTruthClass,
    surface_class: ForensicSurfaceClass,
) -> ForensicEvidenceAnalysisBenchmarkFixtureCase:
    mapping = _surface_mapping(surface_class)
    expected_outcome: ForensicEvidenceBenchmarkExpectedOutcome
    expected_result: ForensicEvidenceAnalysisResultDisposition | None
    expected_oracle: ForensicEvidenceAnalysisOracleDisposition | None
    expected_signal: ForensicEvidenceSignalKind | None
    if ground_truth_class is ForensicEvidenceBenchmarkGroundTruthClass.KNOWN_POSITIVE:
        expected_outcome = ForensicEvidenceBenchmarkExpectedOutcome.REVIEW_SIGNAL
        expected_result = ForensicEvidenceAnalysisResultDisposition.REVIEW
        expected_oracle = ForensicEvidenceAnalysisOracleDisposition.REVIEW
        expected_signal = _surface_review_signal(surface_class)
    elif ground_truth_class is ForensicEvidenceBenchmarkGroundTruthClass.NEGATIVE_CONTROL:
        expected_outcome = ForensicEvidenceBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
        expected_result = ForensicEvidenceAnalysisResultDisposition.NO_SIGNAL
        expected_oracle = ForensicEvidenceAnalysisOracleDisposition.NO_SIGNAL
        expected_signal = None
    else:
        expected_outcome = ForensicEvidenceBenchmarkExpectedOutcome.BOUNDED_CORRUPTION_HANDLING
        expected_result = None
        expected_oracle = None
        expected_signal = None
    return ForensicEvidenceAnalysisBenchmarkFixtureCase(
        fixtureId=fixture_id,
        groundTruthClass=ground_truth_class,
        surfaceClass=surface_class,
        inputKind=mapping.input_kind,
        operation=mapping.operation,
        parser=mapping.parser,
        ruleSet=registered_forensic_evidence_rule_set().reference(),
        domainWorkerProfile=_forensics_worker_profile_ref(),
        expectedOutcome=expected_outcome,
        expectedResultDisposition=expected_result,
        expectedOracleDisposition=expected_oracle,
        expectedReviewSignal=expected_signal,
        requiredEvidence=_fixture_evidence_requirements(ground_truth_class),
    )


def _registered_fixture_cases() -> tuple[
    ForensicEvidenceAnalysisBenchmarkFixtureCase,
    ...,
]:
    cases: list[ForensicEvidenceAnalysisBenchmarkFixtureCase] = []
    for surface_class in ForensicSurfaceClass:
        base = f"forensic-evidence-fixture:{surface_class.value}"
        for ground_truth_class in ForensicEvidenceBenchmarkGroundTruthClass:
            cases.append(
                _fixture_case(
                    fixture_id=f"{base}-{ground_truth_class.value}",
                    ground_truth_class=ground_truth_class,
                    surface_class=surface_class,
                )
            )
    return tuple(sorted(cases, key=lambda item: item.fixture_id))


def _require_forensics_domain_plan(reference: DomainBenchmarkPlanRef) -> None:
    try:
        plan = resolve_registered_domain_benchmark_plan(reference)
    except Exception as exc:
        raise ValueError("FORENSICS-001D Domain benchmark plan is not registered exactly") from exc
    forensics_requirements = tuple(
        requirement
        for requirement in plan.metric_requirements
        if requirement.metric.metric_id.startswith("forensics.")
    )
    if (
        plan.domain_classification.domain is not SecurityDomain.FORENSICS
        or plan.validation_strategy is not DomainValidationStrategy.INDEPENDENT_PARSER_COMPARISON
        or tuple(item.metric.metric_id for item in forensics_requirements)
        != _REQUIRED_FORENSICS_METRIC_IDS
        or any(
            item.applicability is not DomainBenchmarkMetricApplicability.REQUIRED
            for item in forensics_requirements
        )
    ):
        raise ValueError("FORENSICS-001D Domain benchmark strategy or metrics differ")


def _forensics_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    plans = tuple(
        plan.reference()
        for plan in registered_domain_benchmark_registry().plans
        if plan.domain_classification.domain is SecurityDomain.FORENSICS
    )
    if len(plans) != 1:
        raise ForensicEvidenceAnalysisReplayBenchmarkError(
            "DOMAIN-006 Forensics benchmark plan is missing or ambiguous"
        )
    return plans[0]


def _forensics_worker_profile_ref() -> DomainWorkerBoundaryProfileRef:
    profiles = tuple(
        profile.reference()
        for profile in registered_domain_worker_boundary_profiles().profiles
        if profile.domain_classification.domain is SecurityDomain.FORENSICS
    )
    if len(profiles) != 1:
        raise ForensicEvidenceAnalysisReplayBenchmarkError(
            "DOMAIN-004 Forensics Worker profile is missing or ambiguous"
        )
    return profiles[0]


__all__ = [
    "FORENSIC_EVIDENCE_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_REPLAY_VALIDATION_API_VERSION",
    "ForensicEvidenceAnalysisBenchmarkFixtureCase",
    "ForensicEvidenceAnalysisBenchmarkFixtureProfile",
    "ForensicEvidenceAnalysisReplayBenchmarkError",
    "ForensicEvidenceAnalysisReplayBenchmarkGate",
    "ForensicEvidenceAnalysisReplayComparison",
    "ForensicEvidenceAnalysisReplayExecution",
    "ForensicEvidenceAnalysisReplayMode",
    "ForensicEvidenceAnalysisReplayValidation",
    "ForensicEvidenceBenchmarkExpectedOutcome",
    "ForensicEvidenceBenchmarkGroundTruthClass",
    "bind_forensic_evidence_analysis_replay",
    "load_verified_forensic_evidence_analysis_replay_validation",
    "registered_forensic_evidence_analysis_benchmark_fixture_profile",
]
