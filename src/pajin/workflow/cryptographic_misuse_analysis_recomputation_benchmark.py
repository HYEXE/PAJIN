"""CRYPTO-001D independent recomputation and seeded vector contract."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.capabilities.cryptographic_misuse_analysis import (
    CryptographicAnalysisInputKind,
    CryptographicMisuseAnalysisOperation,
    CryptographicMisuseAnalysisPreparation,
    CryptographicMisuseAnalysisRequest,
    CryptographicMisuseAnalysisSandboxBinding,
    CryptographicMisuseAnalyzer,
    CryptographicMisuseRuleSetRef,
    CryptographicMisuseSignalKind,
    CryptographicSurfaceAnalysisMapping,
    registered_cryptographic_misuse_rule_set,
)
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    registered_domain_worker_boundary_profiles,
)
from pajin.discovery.cryptography_surfaces import CryptographySurfaceClass
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow.cryptographic_misuse_analysis_admission import (
    CryptographicMisuseAnalysisExecutionBundle,
    CryptographicMisuseAnalysisExecutionKeyState,
    CryptographicMisuseAnalysisExecutionTrustAnchor,
    CryptographicMisuseAnalysisExecutionVerification,
    CryptographicMisuseAnalysisExecutionVerificationKey,
    CryptographicMisuseAnalysisKnowledgeAdmission,
    CryptographicMisuseAnalysisObservationSourceInputs,
    CryptographicMisuseAnalysisOracleVerdict,
    CryptographicMisuseAnalysisResultDisposition,
    CryptographicMisuseAnalysisResultReceipt,
    CryptographicMisuseAnalysisSandboxRuntimeReceipt,
    CryptographicMisuseOracleDisposition,
    VerifiedCryptographicMisuseAnalysisObservationSource,
    cryptographic_misuse_analysis_source_root_digest,
    load_verified_cryptographic_misuse_analysis_observation_source,
    registered_cryptographic_misuse_analysis_oracle_policy,
    verify_cryptographic_misuse_analysis_execution_bundle,
)

CRYPTOGRAPHIC_MISUSE_ANALYSIS_RECOMPUTATION_VALIDATION_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-recomputation-validation/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-recomputation-validation/v1alpha1"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_BENCHMARK_VECTOR_PROFILE_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-benchmark-vector-profile/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-benchmark-vector-profile/v1alpha1"

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
_EvidenceRequirement = Literal[
    "private-ground-truth-attestation",
    "vector-materialization-attestation",
    "source-execution-attestation",
    "source-non-root-offline-runtime-receipt",
    "source-result-receipt",
    "recomputation-execution-attestation",
    "recomputation-non-root-offline-runtime-receipt",
    "recomputation-result-receipt",
    "cleanup-receipt",
]
_RecomputationState = Literal[
    "independent-recomputation-match",
    "independent-recomputation-changed",
    "independent-recomputation-unresolved",
]


class CryptographicMisuseAnalysisRecomputationBenchmarkError(RuntimeError):
    """Raised when CRYPTO-001D evidence or benchmark authority differs."""


class CryptographicMisuseAnalysisRecomputationComparison(StrEnum):
    """Neutral comparisons that never confirm cryptographic semantic truth."""

    MATCHED = "cryptographic-analysis-independent-recomputation-match"
    CHANGED = "cryptographic-analysis-independent-recomputation-changed"
    UNRESOLVED = "cryptographic-analysis-independent-recomputation-unresolved"


class CryptographicBenchmarkGroundTruthClass(StrEnum):
    """Closed seeded-vector classes for future Cryptography measurement."""

    KNOWN_POSITIVE = "known-positive"
    NEGATIVE_CONTROL = "negative-control"


class CryptographicBenchmarkExpectedOutcome(StrEnum):
    """Expected bounded routing outcome without semantic security authority."""

    REVIEW_SIGNAL = "review-signal"
    NO_REVIEW_SIGNAL = "no-review-signal"


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


class CryptographicMisuseAnalysisRecomputationExecution(_FrozenStrictModel):
    """Digest-only execution projection whose trusted use requires both C loaders."""

    preparation: CryptographicMisuseAnalysisPreparation
    action_permit: ActionPermit = Field(alias="actionPermit")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor = Field(alias="trustAnchor")
    verification: CryptographicMisuseAnalysisExecutionVerification
    execution_bundle: CryptographicMisuseAnalysisExecutionBundle = Field(alias="executionBundle")
    result_receipt: CryptographicMisuseAnalysisResultReceipt = Field(alias="resultReceipt")
    oracle_verdict: CryptographicMisuseAnalysisOracleVerdict = Field(alias="oracleVerdict")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    attestation_reference: _ArtifactPath = Field(alias="attestationReference")
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")

    @model_validator(mode="after")
    def bind_execution_projection(self) -> Self:
        verified = verify_cryptographic_misuse_analysis_execution_bundle(
            self.execution_bundle,
            trust_anchor=self.trust_anchor,
        )
        active_signer = _active_signer(self.trust_anchor)
        verdict = self.oracle_verdict
        result = self.result_receipt
        expected_root = cryptographic_misuse_analysis_source_root_digest(
            attestation_reference=self.attestation_reference,
            attestation_sha256=self.attestation_sha256,
            result_receipt_reference=self.result_receipt_reference,
            result_receipt_sha256=self.result_receipt_sha256,
            trust_anchor_digest=verified.trust_anchor_digest,
            statement_sha256=verified.statement_sha256,
            oracle_policy_digest=verdict.oracle_policy.oracle_digest,
            oracle_verdict_digest=verdict.verdict_digest,
        )
        if (
            verified != self.verification
            or verified.key_state is not CryptographicMisuseAnalysisExecutionKeyState.ACTIVE
            or verified.key_id != active_signer.key_id
            or self.execution_bundle.key_id != active_signer.key_id
            or self.source_root_digest != expected_root
            or self.attestation_reference == self.result_receipt_reference
            or self.trust_anchor.sandbox != self.preparation.sandbox
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
            or verdict.result_disposition is not result.result_disposition
        ):
            raise ValueError("CRYPTO-001D execution projection differs from sealed C evidence")
        return self


_VALIDATION_TRUE_FIELDS = (
    "sealed_source_reverified",
    "sealed_recomputation_reverified",
    "stored_source_admission_verified",
    "separate_action_authority_verified",
    "signed_timestamp_order_verified",
    "exact_surface_verified",
    "exact_input_kind_verified",
    "exact_operation_verified",
    "exact_logical_analyzer_verified",
    "exact_rule_set_verified",
    "exact_artifact_digest_and_bytes_verified",
    "exact_custody_verified",
    "exact_campaign_scope_verified",
    "exact_allow_rule_verified",
    "exact_release_and_activation_verified",
    "exact_request_semantics_verified",
    "exact_output_schema_verified",
    "exact_resource_limits_verified",
    "exact_confinement_verified",
    "zero_live_channels_verified",
    "distinct_preparation_verified",
    "distinct_analyzer_executable_verified",
    "distinct_sandbox_image_verified",
    "distinct_sandbox_binding_verified",
    "distinct_trust_anchor_verified",
    "distinct_active_signer_verified",
    "distinct_execution_provenance_verified",
    "distinct_implementation_coordinates_verified",
    "bounded_oracle_comparison_verified",
    "domain_validation_strategy_satisfied",
    "graph_read_only_verified",
    "deployment_context_reverification_required",
)
_VALIDATION_FALSE_FIELDS = (
    "raw_artifact_embedded",
    "raw_result_body_embedded",
    "raw_key_material_embedded",
    "key_reference_embedded",
    "raw_ciphertext_embedded",
    "raw_plaintext_embedded",
    "raw_configuration_embedded",
    "raw_parameter_material_embedded",
    "credential_material_embedded",
    "source_bound_recomputation_authorization_verified",
    "cross_signer_clock_synchronization_verified",
    "self_authenticating_projection",
    "source_code_independence_verified",
    "algorithm_independence_verified",
    "organization_independence_verified",
    "host_independence_verified",
    "common_mode_failure_excluded",
    "semantic_misuse_truth_established",
    "negative_security_claim_established",
    "hypothesis_confirmed",
    "finding_authority",
    "benchmark_measurement_observed",
    "test_vector_coverage_measured",
    "independent_recomputation_success_rate_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "artifact_access_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "worker_job_materialization_authorized",
    "network_access_authorized",
    "dns_access_authorized",
    "key_material_access_authorized",
    "credential_use_authorized",
    "cryptographic_operation_authorized",
    "key_search_authorized",
    "protocol_negotiation_authorized",
    "oracle_invocation_authorized",
    "plaintext_output_authorized",
    "key_material_output_authorized",
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "artifact_mutation_authorized",
    "graph_admission_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class CryptographicMisuseAnalysisRecomputationValidation(_FrozenStrictModel):
    """Non-authorizing wire projection for one independent recomputation pair."""

    api_version: Literal[
        "pajin.dev/cryptographic-misuse-analysis-recomputation-validation/v1alpha1"
    ] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_RECOMPUTATION_VALIDATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisRecomputationValidation"] = (
        "CryptographicMisuseAnalysisRecomputationValidation"
    )
    validation_id: str = Field(default="", alias="validationId", max_length=118)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    source_admission: CryptographicMisuseAnalysisKnowledgeAdmission = Field(alias="sourceAdmission")
    source_execution: CryptographicMisuseAnalysisRecomputationExecution = Field(
        alias="sourceExecution"
    )
    recomputation_execution: CryptographicMisuseAnalysisRecomputationExecution = Field(
        alias="recomputationExecution"
    )
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    comparison: CryptographicMisuseAnalysisRecomputationComparison
    result_body_digest_matched: bool = Field(alias="resultBodyDigestMatched")
    result_bytes_matched: bool = Field(alias="resultBytesMatched")
    result_disposition_matched: bool = Field(alias="resultDispositionMatched")
    oracle_disposition_matched: bool = Field(alias="oracleDispositionMatched")
    review_signal_matched: bool = Field(alias="reviewSignalMatched")
    state: _RecomputationState
    sealed_source_reverified: Literal[True] = Field(default=True, alias="sealedSourceReverified")
    sealed_recomputation_reverified: Literal[True] = Field(
        default=True, alias="sealedRecomputationReverified"
    )
    stored_source_admission_verified: Literal[True] = Field(
        default=True, alias="storedSourceAdmissionVerified"
    )
    separate_action_authority_verified: Literal[True] = Field(
        default=True, alias="separateActionAuthorityVerified"
    )
    signed_timestamp_order_verified: Literal[True] = Field(
        default=True, alias="signedTimestampOrderVerified"
    )
    exact_surface_verified: Literal[True] = Field(default=True, alias="exactSurfaceVerified")
    exact_input_kind_verified: Literal[True] = Field(default=True, alias="exactInputKindVerified")
    exact_operation_verified: Literal[True] = Field(default=True, alias="exactOperationVerified")
    exact_logical_analyzer_verified: Literal[True] = Field(
        default=True, alias="exactLogicalAnalyzerVerified"
    )
    exact_rule_set_verified: Literal[True] = Field(default=True, alias="exactRuleSetVerified")
    exact_artifact_digest_and_bytes_verified: Literal[True] = Field(
        default=True, alias="exactArtifactDigestAndBytesVerified"
    )
    exact_custody_verified: Literal[True] = Field(default=True, alias="exactCustodyVerified")
    exact_campaign_scope_verified: Literal[True] = Field(
        default=True, alias="exactCampaignScopeVerified"
    )
    exact_allow_rule_verified: Literal[True] = Field(default=True, alias="exactAllowRuleVerified")
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
    distinct_preparation_verified: Literal[True] = Field(
        default=True, alias="distinctPreparationVerified"
    )
    distinct_analyzer_executable_verified: Literal[True] = Field(
        default=True, alias="distinctAnalyzerExecutableVerified"
    )
    distinct_sandbox_image_verified: Literal[True] = Field(
        default=True, alias="distinctSandboxImageVerified"
    )
    distinct_sandbox_binding_verified: Literal[True] = Field(
        default=True, alias="distinctSandboxBindingVerified"
    )
    distinct_trust_anchor_verified: Literal[True] = Field(
        default=True, alias="distinctTrustAnchorVerified"
    )
    distinct_active_signer_verified: Literal[True] = Field(
        default=True, alias="distinctActiveSignerVerified"
    )
    distinct_execution_provenance_verified: Literal[True] = Field(
        default=True, alias="distinctExecutionProvenanceVerified"
    )
    distinct_implementation_coordinates_verified: Literal[True] = Field(
        default=True, alias="distinctImplementationCoordinatesVerified"
    )
    bounded_oracle_comparison_verified: Literal[True] = Field(
        default=True, alias="boundedOracleComparisonVerified"
    )
    domain_validation_strategy_satisfied: Literal[True] = Field(
        default=True, alias="domainValidationStrategySatisfied"
    )
    graph_read_only_verified: Literal[True] = Field(default=True, alias="graphReadOnlyVerified")
    deployment_context_reverification_required: Literal[True] = Field(
        default=True, alias="deploymentContextReverificationRequired"
    )
    raw_artifact_embedded: Literal[False] = Field(default=False, alias="rawArtifactEmbedded")
    raw_result_body_embedded: Literal[False] = Field(default=False, alias="rawResultBodyEmbedded")
    raw_key_material_embedded: Literal[False] = Field(default=False, alias="rawKeyMaterialEmbedded")
    key_reference_embedded: Literal[False] = Field(default=False, alias="keyReferenceEmbedded")
    raw_ciphertext_embedded: Literal[False] = Field(default=False, alias="rawCiphertextEmbedded")
    raw_plaintext_embedded: Literal[False] = Field(default=False, alias="rawPlaintextEmbedded")
    raw_configuration_embedded: Literal[False] = Field(
        default=False, alias="rawConfigurationEmbedded"
    )
    raw_parameter_material_embedded: Literal[False] = Field(
        default=False, alias="rawParameterMaterialEmbedded"
    )
    credential_material_embedded: Literal[False] = Field(
        default=False, alias="credentialMaterialEmbedded"
    )
    source_bound_recomputation_authorization_verified: Literal[False] = Field(
        default=False, alias="sourceBoundRecomputationAuthorizationVerified"
    )
    cross_signer_clock_synchronization_verified: Literal[False] = Field(
        default=False, alias="crossSignerClockSynchronizationVerified"
    )
    self_authenticating_projection: Literal[False] = Field(
        default=False, alias="selfAuthenticatingProjection"
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
    host_independence_verified: Literal[False] = Field(
        default=False, alias="hostIndependenceVerified"
    )
    common_mode_failure_excluded: Literal[False] = Field(
        default=False, alias="commonModeFailureExcluded"
    )
    semantic_misuse_truth_established: Literal[False] = Field(
        default=False, alias="semanticMisuseTruthEstablished"
    )
    negative_security_claim_established: Literal[False] = Field(
        default=False, alias="negativeSecurityClaimEstablished"
    )
    hypothesis_confirmed: Literal[False] = Field(default=False, alias="hypothesisConfirmed")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    benchmark_measurement_observed: Literal[False] = Field(
        default=False, alias="benchmarkMeasurementObserved"
    )
    test_vector_coverage_measured: Literal[False] = Field(
        default=False, alias="testVectorCoverageMeasured"
    )
    independent_recomputation_success_rate_measured: Literal[False] = Field(
        default=False, alias="independentRecomputationSuccessRateMeasured"
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
    artifact_access_authorized: Literal[False] = Field(
        default=False, alias="artifactAccessAuthorized"
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
    key_material_access_authorized: Literal[False] = Field(
        default=False, alias="keyMaterialAccessAuthorized"
    )
    credential_use_authorized: Literal[False] = Field(
        default=False, alias="credentialUseAuthorized"
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False, alias="cryptographicOperationAuthorized"
    )
    key_search_authorized: Literal[False] = Field(default=False, alias="keySearchAuthorized")
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False, alias="protocolNegotiationAuthorized"
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False, alias="oracleInvocationAuthorized"
    )
    plaintext_output_authorized: Literal[False] = Field(
        default=False, alias="plaintextOutputAuthorized"
    )
    key_material_output_authorized: Literal[False] = Field(
        default=False, alias="keyMaterialOutputAuthorized"
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False, alias="dynamicTargetExecutionAuthorized"
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False, alias="debuggerAttachAuthorized"
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False, alias="artifactMutationAuthorized"
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
            raise ValueError("CRYPTO-001D verification markers must be boolean true")
        return value

    @field_validator(
        "result_body_digest_matched",
        "result_bytes_matched",
        "result_disposition_matched",
        "oracle_disposition_matched",
        "review_signal_matched",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("CRYPTO-001D comparison markers must be booleans")
        return value

    @field_validator(*_VALIDATION_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CRYPTO-001D validation cannot grant authority or truth")
        return value

    @model_validator(mode="after")
    def bind_recomputation_validation(self) -> Self:
        _require_cryptography_domain_plan(self.domain_benchmark_plan)
        _require_admission_projection(self.source_admission, self.source_execution)
        _require_equivalent_recomputation_semantics(
            self.source_execution,
            self.recomputation_execution,
        )
        _require_distinct_recomputation_provenance(
            self.source_execution,
            self.recomputation_execution,
        )
        source_result = self.source_execution.result_receipt
        recomputation_result = self.recomputation_execution.result_receipt
        source_oracle = self.source_execution.oracle_verdict
        recomputation_oracle = self.recomputation_execution.oracle_verdict
        body_matched = source_result.result_body_sha256 == recomputation_result.result_body_sha256
        bytes_matched = source_result.result_bytes == recomputation_result.result_bytes
        result_disposition_matched = (
            source_result.result_disposition is recomputation_result.result_disposition
        )
        oracle_disposition_matched = source_oracle.disposition is recomputation_oracle.disposition
        signal_matched = source_oracle.review_signal is recomputation_oracle.review_signal
        comparison = _comparison(
            source_result=source_result,
            source_oracle=source_oracle,
            recomputation_result=recomputation_result,
            recomputation_oracle=recomputation_oracle,
        )
        if (
            self.result_body_digest_matched is not body_matched
            or self.result_bytes_matched is not bytes_matched
            or self.result_disposition_matched is not result_disposition_matched
            or self.oracle_disposition_matched is not oracle_disposition_matched
            or self.review_signal_matched is not signal_matched
            or self.comparison is not comparison
            or self.state != _recomputation_state(comparison)
        ):
            raise ValueError("CRYPTO-001D neutral recomputation comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.cryptographic-misuse-analysis-recomputation-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"cryptographic-misuse-analysis-recomputation_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("CRYPTO-001D validation digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("CRYPTO-001D validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


_VECTOR_TRUE_FIELDS = (
    "seeded_vector_requirements_registered",
    "private_ground_truth_requirements_registered",
    "seeded_vectors_required",
    "sanitized_immutable_vectors_required",
    "disposable_offline_sandbox_required",
    "network_and_dns_disabled_required",
    "non_root_runtime_required",
    "read_only_noexec_artifact_mount_required",
    "positive_controls_registered",
    "negative_controls_registered",
    "evidence_completeness_required",
    "independent_implementation_recomputation_required",
    "domain_worker_profile_required",
)
_VECTOR_FALSE_FIELDS = (
    "target_profile_selected",
    "vector_materialized",
    "sandbox_provisioned",
    "private_ground_truth_verified",
    "ground_truth_verified",
    "ground_truth_case_observed",
    "negative_control_observed",
    "provider_execution_authorized",
    "fixture_execution_authorized",
    "cleanup_observed",
    "recomputation_evidence_bound",
    "benchmark_measurement_observed",
    "test_vector_coverage_measured",
    "independent_recomputation_success_rate_measured",
    "evidence_completeness_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "semantic_misuse_truth_established",
    "negative_security_claim_established",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "artifact_access_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "dns_access_authorized",
    "key_material_access_authorized",
    "credential_use_authorized",
    "cryptographic_operation_authorized",
    "key_search_authorized",
    "protocol_negotiation_authorized",
    "oracle_invocation_authorized",
    "dynamic_target_execution_authorized",
    "artifact_mutation_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)
_VECTOR_CASE_EMBEDDED_FALSE_FIELDS = (
    "raw_artifact_content_embedded",
    "raw_result_body_embedded",
    "raw_key_material_embedded",
    "key_reference_embedded",
    "raw_ciphertext_embedded",
    "raw_plaintext_embedded",
    "raw_configuration_embedded",
    "raw_parameter_material_embedded",
    "credential_material_embedded",
)
_VECTOR_CASE_TRUE_FIELDS = ("synthetic_test_only_required",)
_VECTOR_CASE_ZERO_FIELDS = (
    "artifact_write_operations",
    "network_requests",
    "dns_queries",
    "key_material_reads",
    "key_reference_reads",
    "key_store_sessions",
    "credential_reads",
    "cryptographic_operations",
    "key_search_attempts",
    "protocol_negotiations",
    "oracle_invocations",
    "plaintext_outputs",
    "key_material_outputs",
    "target_process_executions",
    "shell_commands",
    "debugger_attaches",
    "host_filesystem_reads",
)


class CryptographicMisuseAnalysisBenchmarkVectorCase(_FrozenStrictModel):
    """One sanitized seeded outcome requirement without embedded vector content."""

    vector_id: _Identifier = Field(alias="vectorId")
    ground_truth_class: CryptographicBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    surface_class: CryptographySurfaceClass = Field(alias="surfaceClass")
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    domain_worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="domainWorkerProfile")
    expected_outcome: CryptographicBenchmarkExpectedOutcome = Field(alias="expectedOutcome")
    expected_result_disposition: CryptographicMisuseAnalysisResultDisposition = Field(
        alias="expectedResultDisposition"
    )
    expected_oracle_disposition: CryptographicMisuseOracleDisposition = Field(
        alias="expectedOracleDisposition"
    )
    expected_review_signal: CryptographicMisuseSignalKind | None = Field(
        default=None,
        alias="expectedReviewSignal",
    )
    required_evidence: tuple[_EvidenceRequirement, ...] = Field(
        min_length=9,
        max_length=9,
        alias="requiredEvidence",
    )
    vector_materialization: Literal["seeded-sanitized-immutable-cryptographic-vector"] = Field(
        default="seeded-sanitized-immutable-cryptographic-vector",
        alias="vectorMaterialization",
    )
    isolation_requirement: Literal[
        "disposable-network-dns-disabled-non-root-offline-sandbox-per-case"
    ] = Field(
        default="disposable-network-dns-disabled-non-root-offline-sandbox-per-case",
        alias="isolationRequirement",
    )
    artifact_mount_requirement: Literal["read-only-noexec-exact-artifact-digest"] = Field(
        default="read-only-noexec-exact-artifact-digest",
        alias="artifactMountRequirement",
    )
    synthetic_test_only_required: Literal[True] = Field(
        default=True,
        alias="syntheticTestOnlyRequired",
    )
    raw_artifact_content_embedded: Literal[False] = Field(
        default=False, alias="rawArtifactContentEmbedded"
    )
    raw_result_body_embedded: Literal[False] = Field(default=False, alias="rawResultBodyEmbedded")
    raw_key_material_embedded: Literal[False] = Field(default=False, alias="rawKeyMaterialEmbedded")
    key_reference_embedded: Literal[False] = Field(default=False, alias="keyReferenceEmbedded")
    raw_ciphertext_embedded: Literal[False] = Field(default=False, alias="rawCiphertextEmbedded")
    raw_plaintext_embedded: Literal[False] = Field(default=False, alias="rawPlaintextEmbedded")
    raw_configuration_embedded: Literal[False] = Field(
        default=False, alias="rawConfigurationEmbedded"
    )
    raw_parameter_material_embedded: Literal[False] = Field(
        default=False, alias="rawParameterMaterialEmbedded"
    )
    credential_material_embedded: Literal[False] = Field(
        default=False, alias="credentialMaterialEmbedded"
    )
    artifact_write_operations: Literal[0] = Field(default=0, alias="artifactWriteOperations")
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_queries: Literal[0] = Field(default=0, alias="dnsQueries")
    key_material_reads: Literal[0] = Field(default=0, alias="keyMaterialReads")
    key_reference_reads: Literal[0] = Field(default=0, alias="keyReferenceReads")
    key_store_sessions: Literal[0] = Field(default=0, alias="keyStoreSessions")
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    cryptographic_operations: Literal[0] = Field(default=0, alias="cryptographicOperations")
    key_search_attempts: Literal[0] = Field(default=0, alias="keySearchAttempts")
    protocol_negotiations: Literal[0] = Field(default=0, alias="protocolNegotiations")
    oracle_invocations: Literal[0] = Field(default=0, alias="oracleInvocations")
    plaintext_outputs: Literal[0] = Field(default=0, alias="plaintextOutputs")
    key_material_outputs: Literal[0] = Field(default=0, alias="keyMaterialOutputs")
    target_process_executions: Literal[0] = Field(default=0, alias="targetProcessExecutions")
    shell_commands: Literal[0] = Field(default=0, alias="shellCommands")
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")

    @field_validator(*_VECTOR_CASE_EMBEDDED_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CRYPTO-001D vectors cannot embed artifact or secret content")
        return value

    @field_validator(*_VECTOR_CASE_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CRYPTO-001D vectors must remain synthetic test-only requirements")
        return value

    @field_validator(*_VECTOR_CASE_ZERO_FIELDS, mode="before")
    @classmethod
    def require_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("CRYPTO-001D vector channel counters must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_vector_case(self) -> Self:
        mapping = _surface_mapping(self.surface_class)
        expected_signal = _surface_review_signal(self.surface_class)
        expected_evidence: tuple[_EvidenceRequirement, ...] = (
            "private-ground-truth-attestation",
            "vector-materialization-attestation",
            "source-execution-attestation",
            "source-non-root-offline-runtime-receipt",
            "source-result-receipt",
            "recomputation-execution-attestation",
            "recomputation-non-root-offline-runtime-receipt",
            "recomputation-result-receipt",
            "cleanup-receipt",
        )
        if self.ground_truth_class is CryptographicBenchmarkGroundTruthClass.KNOWN_POSITIVE:
            valid_outcome = (
                self.expected_outcome is CryptographicBenchmarkExpectedOutcome.REVIEW_SIGNAL
                and self.expected_result_disposition
                is CryptographicMisuseAnalysisResultDisposition.REVIEW
                and self.expected_oracle_disposition
                is CryptographicMisuseOracleDisposition.STRUCTURALLY_CONSISTENT_REVIEW
                and self.expected_review_signal is expected_signal
            )
        else:
            valid_outcome = (
                self.expected_outcome is CryptographicBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
                and self.expected_result_disposition
                is CryptographicMisuseAnalysisResultDisposition.NO_SIGNAL
                and self.expected_oracle_disposition
                is CryptographicMisuseOracleDisposition.INCONCLUSIVE_NO_SIGNAL
                and self.expected_review_signal is None
            )
        if (
            self.input_kind is not mapping.input_kind
            or self.operation is not mapping.operation
            or self.analyzer is not mapping.analyzer
            or self.rule_set != registered_cryptographic_misuse_rule_set().reference()
            or self.domain_worker_profile != _cryptography_worker_profile_ref()
            or self.required_evidence != expected_evidence
            or not valid_outcome
        ):
            raise ValueError("CRYPTO-001D seeded vector shape differs")
        return self


class CryptographicMisuseAnalysisBenchmarkVectorProfile(_FrozenStrictModel):
    """Registered seeded-vector requirements, never a benchmark measurement."""

    api_version: Literal[
        "pajin.dev/cryptographic-misuse-analysis-benchmark-vector-profile/v1alpha1"
    ] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_BENCHMARK_VECTOR_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisBenchmarkVectorProfile"] = (
        "CryptographicMisuseAnalysisBenchmarkVectorProfile"
    )
    profile_id: str = Field(default="", alias="profileId", max_length=118)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    domain_worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="domainWorkerProfile")
    covered_surface_classes: tuple[CryptographySurfaceClass, ...] = Field(
        min_length=4,
        max_length=4,
        alias="coveredSurfaceClasses",
    )
    cases: tuple[CryptographicMisuseAnalysisBenchmarkVectorCase, ...] = Field(
        min_length=8,
        max_length=8,
    )
    state: Literal["registered-seeded-vector-requirements-not-materialized-or-measured"] = (
        "registered-seeded-vector-requirements-not-materialized-or-measured"
    )
    seeded_vector_requirements_registered: Literal[True] = Field(
        default=True, alias="seededVectorRequirementsRegistered"
    )
    private_ground_truth_requirements_registered: Literal[True] = Field(
        default=True, alias="privateGroundTruthRequirementsRegistered"
    )
    seeded_vectors_required: Literal[True] = Field(default=True, alias="seededVectorsRequired")
    sanitized_immutable_vectors_required: Literal[True] = Field(
        default=True, alias="sanitizedImmutableVectorsRequired"
    )
    disposable_offline_sandbox_required: Literal[True] = Field(
        default=True, alias="disposableOfflineSandboxRequired"
    )
    network_and_dns_disabled_required: Literal[True] = Field(
        default=True, alias="networkAndDnsDisabledRequired"
    )
    non_root_runtime_required: Literal[True] = Field(default=True, alias="nonRootRuntimeRequired")
    read_only_noexec_artifact_mount_required: Literal[True] = Field(
        default=True, alias="readOnlyNoexecArtifactMountRequired"
    )
    positive_controls_registered: Literal[True] = Field(
        default=True, alias="positiveControlsRegistered"
    )
    negative_controls_registered: Literal[True] = Field(
        default=True, alias="negativeControlsRegistered"
    )
    evidence_completeness_required: Literal[True] = Field(
        default=True, alias="evidenceCompletenessRequired"
    )
    independent_implementation_recomputation_required: Literal[True] = Field(
        default=True, alias="independentImplementationRecomputationRequired"
    )
    domain_worker_profile_required: Literal[True] = Field(
        default=True, alias="domainWorkerProfileRequired"
    )
    target_profile_selected: Literal[False] = Field(default=False, alias="targetProfileSelected")
    vector_materialized: Literal[False] = Field(default=False, alias="vectorMaterialized")
    sandbox_provisioned: Literal[False] = Field(default=False, alias="sandboxProvisioned")
    private_ground_truth_verified: Literal[False] = Field(
        default=False, alias="privateGroundTruthVerified"
    )
    ground_truth_verified: Literal[False] = Field(default=False, alias="groundTruthVerified")
    ground_truth_case_observed: Literal[False] = Field(
        default=False, alias="groundTruthCaseObserved"
    )
    negative_control_observed: Literal[False] = Field(
        default=False, alias="negativeControlObserved"
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False, alias="providerExecutionAuthorized"
    )
    fixture_execution_authorized: Literal[False] = Field(
        default=False, alias="fixtureExecutionAuthorized"
    )
    cleanup_observed: Literal[False] = Field(default=False, alias="cleanupObserved")
    recomputation_evidence_bound: Literal[False] = Field(
        default=False, alias="recomputationEvidenceBound"
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False, alias="benchmarkMeasurementObserved"
    )
    test_vector_coverage_measured: Literal[False] = Field(
        default=False, alias="testVectorCoverageMeasured"
    )
    independent_recomputation_success_rate_measured: Literal[False] = Field(
        default=False, alias="independentRecomputationSuccessRateMeasured"
    )
    evidence_completeness_measured: Literal[False] = Field(
        default=False, alias="evidenceCompletenessMeasured"
    )
    detection_quality_established: Literal[False] = Field(
        default=False, alias="detectionQualityEstablished"
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="profileValidationFloorSatisfied"
    )
    semantic_misuse_truth_established: Literal[False] = Field(
        default=False, alias="semanticMisuseTruthEstablished"
    )
    negative_security_claim_established: Literal[False] = Field(
        default=False, alias="negativeSecurityClaimEstablished"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
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
    artifact_access_authorized: Literal[False] = Field(
        default=False, alias="artifactAccessAuthorized"
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
    network_access_authorized: Literal[False] = Field(
        default=False, alias="networkAccessAuthorized"
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    key_material_access_authorized: Literal[False] = Field(
        default=False, alias="keyMaterialAccessAuthorized"
    )
    credential_use_authorized: Literal[False] = Field(
        default=False, alias="credentialUseAuthorized"
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False, alias="cryptographicOperationAuthorized"
    )
    key_search_authorized: Literal[False] = Field(default=False, alias="keySearchAuthorized")
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False, alias="protocolNegotiationAuthorized"
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False, alias="oracleInvocationAuthorized"
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False, alias="dynamicTargetExecutionAuthorized"
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False, alias="artifactMutationAuthorized"
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False, alias="findingConfirmationAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_VECTOR_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CRYPTO-001D vector requirements must be boolean true")
        return value

    @field_validator(*_VECTOR_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CRYPTO-001D vector profile cannot claim authority or measurement")
        return value

    @model_validator(mode="after")
    def bind_vector_profile(self) -> Self:
        _require_cryptography_domain_plan(self.domain_benchmark_plan)
        if (
            self.domain_worker_profile != _cryptography_worker_profile_ref()
            or self.covered_surface_classes != tuple(CryptographySurfaceClass)
            or self.cases != _registered_vector_cases()
        ):
            raise ValueError("CRYPTO-001D seeded vector profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.cryptographic-misuse-analysis-benchmark-vector-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"cryptographic-misuse-analysis-vectors_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("CRYPTO-001D vector profile digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("CRYPTO-001D vector profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


class CryptographicMisuseAnalysisRecomputationBenchmarkGate:
    """Reopen two sealed C executions without reading an artifact or invoking a Worker."""

    def __init__(
        self,
        *,
        source_trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
        recomputation_trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
    ) -> None:
        if type(source_trust_anchor) is not CryptographicMisuseAnalysisExecutionTrustAnchor:
            raise TypeError("CRYPTO-001D requires an exact source trust anchor")
        if type(recomputation_trust_anchor) is not CryptographicMisuseAnalysisExecutionTrustAnchor:
            raise TypeError("CRYPTO-001D requires an exact recomputation trust anchor")
        _require_known_instance_fields(source_trust_anchor, label="CRYPTO-001D source anchor")
        _require_known_instance_fields(
            recomputation_trust_anchor,
            label="CRYPTO-001D recomputation anchor",
        )
        self._source_trust_anchor = CryptographicMisuseAnalysisExecutionTrustAnchor.model_validate(
            source_trust_anchor.model_dump(mode="json", by_alias=True)
        )
        self._recomputation_trust_anchor = (
            CryptographicMisuseAnalysisExecutionTrustAnchor.model_validate(
                recomputation_trust_anchor.model_dump(mode="json", by_alias=True)
            )
        )

    def bind_recomputation(
        self,
        source_inputs: CryptographicMisuseAnalysisObservationSourceInputs,
        source_admission: CryptographicMisuseAnalysisKnowledgeAdmission,
        recomputation_inputs: CryptographicMisuseAnalysisObservationSourceInputs,
        *,
        source_graph_store: SQLiteGraphStore,
        recomputation_graph_store: SQLiteGraphStore,
    ) -> CryptographicMisuseAnalysisRecomputationValidation:
        """Return one neutral comparison of separately authorized sealed executions."""

        try:
            if type(source_graph_store) is not SQLiteGraphStore:
                raise TypeError("CRYPTO-001D requires an exact source SQLite Graph Store")
            if type(recomputation_graph_store) is not SQLiteGraphStore:
                raise TypeError("CRYPTO-001D requires an exact recomputation SQLite Graph Store")
            if (
                source_graph_store.path == recomputation_graph_store.path
                or source_graph_store.path.samefile(recomputation_graph_store.path)
            ):
                raise ValueError("CRYPTO-001D requires separate SQLite Graph authority stores")
            _require_known_instance_fields(
                source_admission,
                label="CRYPTO-001D source admission",
            )
            canonical_admission = CryptographicMisuseAnalysisKnowledgeAdmission.model_validate(
                source_admission.model_dump(mode="json", by_alias=True)
            )
            source = load_verified_cryptographic_misuse_analysis_observation_source(
                source_inputs,
                graph_store=source_graph_store,
                trust_anchor=self._source_trust_anchor,
            )
            recomputation = load_verified_cryptographic_misuse_analysis_observation_source(
                recomputation_inputs,
                graph_store=recomputation_graph_store,
                trust_anchor=self._recomputation_trust_anchor,
            )
            _require_stored_source_admission(canonical_admission, source_graph_store)
            source_projection = _execution_projection(source)
            recomputation_projection = _execution_projection(recomputation)
            _require_admission_projection(canonical_admission, source_projection)
            comparison = _comparison(
                source_result=source_projection.result_receipt,
                source_oracle=source_projection.oracle_verdict,
                recomputation_result=recomputation_projection.result_receipt,
                recomputation_oracle=recomputation_projection.oracle_verdict,
            )
            return CryptographicMisuseAnalysisRecomputationValidation(
                sourceAdmission=canonical_admission,
                sourceExecution=source_projection,
                recomputationExecution=recomputation_projection,
                domainBenchmarkPlan=_cryptography_domain_benchmark_plan_ref(),
                comparison=comparison,
                resultBodyDigestMatched=(
                    source_projection.result_receipt.result_body_sha256
                    == recomputation_projection.result_receipt.result_body_sha256
                ),
                resultBytesMatched=(
                    source_projection.result_receipt.result_bytes
                    == recomputation_projection.result_receipt.result_bytes
                ),
                resultDispositionMatched=(
                    source_projection.result_receipt.result_disposition
                    is recomputation_projection.result_receipt.result_disposition
                ),
                oracleDispositionMatched=(
                    source_projection.oracle_verdict.disposition
                    is recomputation_projection.oracle_verdict.disposition
                ),
                reviewSignalMatched=(
                    source_projection.oracle_verdict.review_signal
                    is recomputation_projection.oracle_verdict.review_signal
                ),
                state=_recomputation_state(comparison),
            )
        except CryptographicMisuseAnalysisRecomputationBenchmarkError:
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
            raise CryptographicMisuseAnalysisRecomputationBenchmarkError(
                "CRYPTO-001D independent recomputation failed closed"
            ) from exc


def bind_cryptographic_misuse_analysis_independent_recomputation(
    source_inputs: CryptographicMisuseAnalysisObservationSourceInputs,
    source_admission: CryptographicMisuseAnalysisKnowledgeAdmission,
    recomputation_inputs: CryptographicMisuseAnalysisObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    recomputation_graph_store: SQLiteGraphStore,
    source_trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
    recomputation_trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
) -> CryptographicMisuseAnalysisRecomputationValidation:
    """Functional entry point for the deployment-configured CRYPTO-001D gate."""

    gate = CryptographicMisuseAnalysisRecomputationBenchmarkGate(
        source_trust_anchor=source_trust_anchor,
        recomputation_trust_anchor=recomputation_trust_anchor,
    )
    return gate.bind_recomputation(
        source_inputs,
        source_admission,
        recomputation_inputs,
        source_graph_store=source_graph_store,
        recomputation_graph_store=recomputation_graph_store,
    )


def load_verified_cryptographic_misuse_analysis_recomputation_validation(
    validation: object,
    source_inputs: CryptographicMisuseAnalysisObservationSourceInputs,
    recomputation_inputs: CryptographicMisuseAnalysisObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    recomputation_graph_store: SQLiteGraphStore,
    source_trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
    recomputation_trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
) -> CryptographicMisuseAnalysisRecomputationValidation:
    """Reverify a wire projection against both evidence roots and Graph authority."""

    try:
        _require_known_instance_fields(validation, label="CRYPTO-001D validation")
        if isinstance(validation, CryptographicMisuseAnalysisRecomputationValidation):
            payload: object = validation.model_dump(mode="json", by_alias=True)
        else:
            payload = validation
        canonical = CryptographicMisuseAnalysisRecomputationValidation.model_validate(payload)
        expected = bind_cryptographic_misuse_analysis_independent_recomputation(
            source_inputs,
            canonical.source_admission,
            recomputation_inputs,
            source_graph_store=source_graph_store,
            recomputation_graph_store=recomputation_graph_store,
            source_trust_anchor=source_trust_anchor,
            recomputation_trust_anchor=recomputation_trust_anchor,
        )
        if canonical != expected:
            raise ValueError(
                "CRYPTO-001D wire projection differs from deployment evidence and Graph authority"
            )
        return expected
    except CryptographicMisuseAnalysisRecomputationBenchmarkError:
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
        raise CryptographicMisuseAnalysisRecomputationBenchmarkError(
            "CRYPTO-001D wire re-verification failed closed"
        ) from exc


def registered_cryptographic_misuse_analysis_benchmark_vector_profile() -> (
    CryptographicMisuseAnalysisBenchmarkVectorProfile
):
    """Return exact seeded-vector requirements without materializing or measuring them."""

    try:
        return CryptographicMisuseAnalysisBenchmarkVectorProfile(
            domainBenchmarkPlan=_cryptography_domain_benchmark_plan_ref(),
            domainWorkerProfile=_cryptography_worker_profile_ref(),
            coveredSurfaceClasses=tuple(CryptographySurfaceClass),
            cases=_registered_vector_cases(),
        )
    except (RuntimeError, ValidationError, ValueError) as exc:
        raise CryptographicMisuseAnalysisRecomputationBenchmarkError(
            "CRYPTO-001D seeded vector registration failed closed"
        ) from exc


def _execution_projection(
    source: VerifiedCryptographicMisuseAnalysisObservationSource,
) -> CryptographicMisuseAnalysisRecomputationExecution:
    return CryptographicMisuseAnalysisRecomputationExecution(
        preparation=source.preparation,
        actionPermit=source.permit,
        approvalReceipt=source.approval_receipt,
        trustAnchor=source.trust_anchor,
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
    admission: CryptographicMisuseAnalysisKnowledgeAdmission,
    graph_store: SQLiteGraphStore,
) -> None:
    observation = admission.candidate.observation_proposal
    stored_observation = graph_store.event_log.event_for_attempt(
        observation.proposal_id,
        observation.digest(),
    )
    if stored_observation != admission.observation_graph_event:
        raise ValueError("CRYPTO-001D source Observation admission is not stored exactly")
    hypothesis = admission.candidate.hypothesis_proposal
    if hypothesis is None:
        if admission.hypothesis_graph_event is not None:
            raise ValueError("CRYPTO-001D source Hypothesis admission differs")
        return
    stored_hypothesis = graph_store.event_log.event_for_attempt(
        hypothesis.proposal_id,
        hypothesis.digest(),
    )
    if stored_hypothesis != admission.hypothesis_graph_event:
        raise ValueError("CRYPTO-001D source Hypothesis admission is not stored exactly")


def _require_admission_projection(
    admission: CryptographicMisuseAnalysisKnowledgeAdmission,
    execution: CryptographicMisuseAnalysisRecomputationExecution,
) -> None:
    candidate = admission.candidate
    receipt = execution.result_receipt
    verdict = execution.oracle_verdict
    if (
        candidate.preparation != execution.preparation
        or candidate.surface != execution.preparation.surface.reference()
        or candidate.source_execution_snapshot != execution.action_permit.snapshot
        or candidate.source_run_id != execution.action_permit.run_id
        or candidate.source_root_digest != execution.source_root_digest
        or candidate.trust_anchor_digest != execution.verification.trust_anchor_digest
        or candidate.statement_sha256 != execution.verification.statement_sha256
        or candidate.approval_receipt_id != execution.approval_receipt.receipt_id
        or candidate.approval_receipt_digest != execution.approval_receipt.receipt_digest
        or candidate.attestation_reference != execution.attestation_reference
        or candidate.attestation_sha256 != execution.attestation_sha256
        or candidate.result_receipt_reference != execution.result_receipt_reference
        or candidate.result_receipt_sha256 != execution.result_receipt_sha256
        or candidate.result_receipt_digest != receipt.receipt_digest
        or candidate.result_body_sha256 != receipt.result_body_sha256
        or candidate.artifact_sha256 != receipt.artifact_sha256
        or candidate.artifact_bytes != receipt.artifact_bytes
        or candidate.output_schema != receipt.output_schema
        or candidate.operation is not receipt.operation
        or candidate.analyzer is not receipt.analyzer
        or candidate.input_kind is not receipt.input_kind
        or candidate.rule_set != receipt.rule_set
        or candidate.oracle_verdict != verdict
        or candidate.oracle_policy_digest != verdict.oracle_policy.oracle_digest
        or candidate.oracle_verdict_digest != verdict.verdict_digest
        or candidate.result_disposition is not verdict.result_disposition
        or candidate.review_signal is not verdict.review_signal
    ):
        raise ValueError("CRYPTO-001D source admission differs from its sealed execution")


def _require_equivalent_recomputation_semantics(
    source: CryptographicMisuseAnalysisRecomputationExecution,
    recomputation: CryptographicMisuseAnalysisRecomputationExecution,
) -> None:
    left = source.preparation
    right = recomputation.preparation
    left_prepared = left.prepared_action
    right_prepared = right.prepared_action
    left_statement = source.execution_bundle.statement
    right_statement = recomputation.execution_bundle.statement
    if (
        left.binding != right.binding
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
        or left_statement.gateway_policy_decision != right_statement.gateway_policy_decision
        or _runtime_semantic_projection(left_statement.sandbox_runtime)
        != _runtime_semantic_projection(right_statement.sandbox_runtime)
        or _result_semantic_projection(source.result_receipt)
        != _result_semantic_projection(recomputation.result_receipt)
        or _oracle_semantic_projection(source.oracle_verdict)
        != _oracle_semantic_projection(recomputation.oracle_verdict)
    ):
        raise ValueError("CRYPTO-001D recomputation differs from source Cryptographic semantics")
    if (
        source.result_receipt.result_body_sha256 == recomputation.result_receipt.result_body_sha256
        and source.result_receipt.result_bytes != recomputation.result_receipt.result_bytes
    ):
        raise ValueError("CRYPTO-001D equal result digest has inconsistent byte count")


def _sandbox_semantic_projection(
    sandbox: CryptographicMisuseAnalysisSandboxBinding,
) -> dict[str, object]:
    projection = sandbox.model_dump(mode="json", by_alias=True)
    for key in (
        "sandboxBindingId",
        "sandboxBindingDigest",
        "analyzerExecutableSHA256",
        "sandboxImageSHA256",
    ):
        projection.pop(key)
    return projection


def _analysis_request_semantic_projection(
    request: CryptographicMisuseAnalysisRequest,
) -> dict[str, object]:
    projection = request.model_dump(mode="json", by_alias=True)
    sandbox = projection.get("sandbox")
    if not isinstance(sandbox, dict):
        raise ValueError("CRYPTO-001D analysis request lacks a canonical sandbox projection")
    for key in (
        "sandboxBindingId",
        "sandboxBindingDigest",
        "analyzerExecutableSHA256",
        "sandboxImageSHA256",
    ):
        sandbox.pop(key)
    return projection


def _runtime_semantic_projection(
    runtime: CryptographicMisuseAnalysisSandboxRuntimeReceipt,
) -> dict[str, object]:
    projection = runtime.model_dump(mode="json", by_alias=True)
    for key in (
        "receiptId",
        "receiptDigest",
        "sandboxBindingId",
        "sandboxBindingDigest",
        "analyzerExecutableSHA256",
        "sandboxImageSHA256",
        "attestedAt",
    ):
        projection.pop(key)
    return projection


def _result_semantic_projection(
    receipt: CryptographicMisuseAnalysisResultReceipt,
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
        "resultDisposition",
        "receivedAt",
    ):
        projection.pop(key)
    return projection


def _oracle_semantic_projection(
    verdict: CryptographicMisuseAnalysisOracleVerdict,
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


def _require_distinct_recomputation_provenance(
    source: CryptographicMisuseAnalysisRecomputationExecution,
    recomputation: CryptographicMisuseAnalysisRecomputationExecution,
) -> None:
    left = _execution_identity_coordinates(source)
    right = _execution_identity_coordinates(recomputation)
    reused = tuple(name for name in left if left[name] == right[name])
    if reused:
        raise ValueError(
            "CRYPTO-001D recomputation reused source execution provenance: " + ", ".join(reused)
        )
    if (
        recomputation.execution_bundle.statement.started_at
        <= source.execution_bundle.statement.finished_at
    ):
        raise ValueError("CRYPTO-001D signed recomputation timestamp is not after the source")


def _execution_identity_coordinates(
    execution: CryptographicMisuseAnalysisRecomputationExecution,
) -> dict[str, str]:
    preparation = execution.preparation
    permit = execution.action_permit
    approval_receipt = execution.approval_receipt
    approval = approval_receipt.approval
    statement = execution.execution_bundle.statement
    runtime = statement.sandbox_runtime
    result = execution.result_receipt
    oracle = execution.oracle_verdict
    active_key = _active_signer(execution.trust_anchor)
    return {
        "preparationId": preparation.preparation_id,
        "preparationDigest": preparation.preparation_digest,
        "runId": permit.run_id,
        "sourceRootDigest": execution.source_root_digest,
        "requestId": permit.request_id,
        "requestDigest": permit.request_digest,
        "normalizedParametersDigest": permit.normalized_parameters_digest,
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
        "trustAnchorDigest": execution.verification.trust_anchor_digest,
        "activeSignerKeyId": active_key.key_id,
        "activeSignerPublicKey": active_key.public_key_base64url,
        "sandboxBindingId": preparation.sandbox.sandbox_binding_id,
        "sandboxBindingDigest": preparation.sandbox.sandbox_binding_digest,
        "analyzerExecutableSHA256": preparation.sandbox.analyzer_executable_sha256,
        "sandboxImageSHA256": preparation.sandbox.sandbox_image_sha256,
        "executionId": statement.execution_id,
        "gatewayOutcomeDigest": statement.gateway_outcome_digest,
        "statementSha256": execution.verification.statement_sha256,
        "sandboxRuntimeReceiptId": runtime.receipt_id,
        "sandboxRuntimeReceiptDigest": runtime.receipt_digest,
        "attestationSha256": execution.attestation_sha256,
        "resultReceiptId": result.receipt_id,
        "resultReceiptDigest": result.receipt_digest,
        "resultReceiptSha256": execution.result_receipt_sha256,
        "oracleVerdictId": oracle.verdict_id,
        "oracleVerdictDigest": oracle.verdict_digest,
    }


def _active_signer(
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
) -> CryptographicMisuseAnalysisExecutionVerificationKey:
    active = tuple(
        key
        for key in trust_anchor.keys
        if key.state is CryptographicMisuseAnalysisExecutionKeyState.ACTIVE
    )
    if len(active) != 1:
        raise ValueError("CRYPTO-001D trust anchor lacks one exact active signer")
    return active[0]


def _comparison(
    *,
    source_result: CryptographicMisuseAnalysisResultReceipt,
    source_oracle: CryptographicMisuseAnalysisOracleVerdict,
    recomputation_result: CryptographicMisuseAnalysisResultReceipt,
    recomputation_oracle: CryptographicMisuseAnalysisOracleVerdict,
) -> CryptographicMisuseAnalysisRecomputationComparison:
    body_matched = source_result.result_body_sha256 == recomputation_result.result_body_sha256
    bytes_matched = source_result.result_bytes == recomputation_result.result_bytes
    if body_matched and not bytes_matched:
        raise ValueError("CRYPTO-001D equal result digest has inconsistent byte count")
    bounded_matched = (
        source_result.result_disposition is recomputation_result.result_disposition
        and source_oracle.disposition is recomputation_oracle.disposition
        and source_oracle.review_signal is recomputation_oracle.review_signal
    )
    if body_matched and bytes_matched and bounded_matched:
        return CryptographicMisuseAnalysisRecomputationComparison.MATCHED
    if not bounded_matched:
        return CryptographicMisuseAnalysisRecomputationComparison.CHANGED
    return CryptographicMisuseAnalysisRecomputationComparison.UNRESOLVED


def _recomputation_state(
    comparison: CryptographicMisuseAnalysisRecomputationComparison,
) -> _RecomputationState:
    states: dict[
        CryptographicMisuseAnalysisRecomputationComparison,
        _RecomputationState,
    ] = {
        CryptographicMisuseAnalysisRecomputationComparison.MATCHED: (
            "independent-recomputation-match"
        ),
        CryptographicMisuseAnalysisRecomputationComparison.CHANGED: (
            "independent-recomputation-changed"
        ),
        CryptographicMisuseAnalysisRecomputationComparison.UNRESOLVED: (
            "independent-recomputation-unresolved"
        ),
    }
    return states[comparison]


def _surface_mapping(
    surface_class: CryptographySurfaceClass,
) -> CryptographicSurfaceAnalysisMapping:
    rows = tuple(
        row
        for row in registered_cryptographic_misuse_rule_set().surface_analysis_mapping
        if row.surface_class is surface_class
    )
    if len(rows) != 1:
        raise ValueError("CRYPTO-001D Surface mapping is not registered exactly")
    return rows[0]


def _surface_review_signal(
    surface_class: CryptographySurfaceClass,
) -> CryptographicMisuseSignalKind:
    rows = tuple(
        row
        for row in registered_cryptographic_misuse_analysis_oracle_policy().surface_signal_mapping
        if row.surface_class is surface_class
    )
    if len(rows) != 1:
        raise ValueError("CRYPTO-001D Oracle Surface signal is not registered exactly")
    return rows[0].review_signal


def _vector_case(
    *,
    vector_id: str,
    ground_truth_class: CryptographicBenchmarkGroundTruthClass,
    surface_class: CryptographySurfaceClass,
    expected_outcome: CryptographicBenchmarkExpectedOutcome,
    expected_result_disposition: CryptographicMisuseAnalysisResultDisposition,
    expected_oracle_disposition: CryptographicMisuseOracleDisposition,
    expected_review_signal: CryptographicMisuseSignalKind | None = None,
) -> CryptographicMisuseAnalysisBenchmarkVectorCase:
    mapping = _surface_mapping(surface_class)
    return CryptographicMisuseAnalysisBenchmarkVectorCase(
        vectorId=vector_id,
        groundTruthClass=ground_truth_class,
        surfaceClass=surface_class,
        inputKind=mapping.input_kind,
        operation=mapping.operation,
        analyzer=mapping.analyzer,
        ruleSet=registered_cryptographic_misuse_rule_set().reference(),
        domainWorkerProfile=_cryptography_worker_profile_ref(),
        expectedOutcome=expected_outcome,
        expectedResultDisposition=expected_result_disposition,
        expectedOracleDisposition=expected_oracle_disposition,
        expectedReviewSignal=expected_review_signal,
        requiredEvidence=(
            "private-ground-truth-attestation",
            "vector-materialization-attestation",
            "source-execution-attestation",
            "source-non-root-offline-runtime-receipt",
            "source-result-receipt",
            "recomputation-execution-attestation",
            "recomputation-non-root-offline-runtime-receipt",
            "recomputation-result-receipt",
            "cleanup-receipt",
        ),
    )


def _registered_vector_cases() -> tuple[
    CryptographicMisuseAnalysisBenchmarkVectorCase,
    ...,
]:
    cases: list[CryptographicMisuseAnalysisBenchmarkVectorCase] = []
    for surface_class in CryptographySurfaceClass:
        base = f"cryptographic-vector:{surface_class.value}"
        cases.extend(
            (
                _vector_case(
                    vector_id=f"{base}-known-positive",
                    ground_truth_class=CryptographicBenchmarkGroundTruthClass.KNOWN_POSITIVE,
                    surface_class=surface_class,
                    expected_outcome=CryptographicBenchmarkExpectedOutcome.REVIEW_SIGNAL,
                    expected_result_disposition=(
                        CryptographicMisuseAnalysisResultDisposition.REVIEW
                    ),
                    expected_oracle_disposition=(
                        CryptographicMisuseOracleDisposition.STRUCTURALLY_CONSISTENT_REVIEW
                    ),
                    expected_review_signal=_surface_review_signal(surface_class),
                ),
                _vector_case(
                    vector_id=f"{base}-negative-control",
                    ground_truth_class=CryptographicBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
                    surface_class=surface_class,
                    expected_outcome=CryptographicBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL,
                    expected_result_disposition=(
                        CryptographicMisuseAnalysisResultDisposition.NO_SIGNAL
                    ),
                    expected_oracle_disposition=(
                        CryptographicMisuseOracleDisposition.INCONCLUSIVE_NO_SIGNAL
                    ),
                ),
            )
        )
    return tuple(sorted(cases, key=lambda item: item.vector_id))


def _require_cryptography_domain_plan(reference: DomainBenchmarkPlanRef) -> None:
    try:
        plan = resolve_registered_domain_benchmark_plan(reference)
    except Exception as exc:
        raise ValueError("CRYPTO-001D Domain benchmark plan is not registered exactly") from exc
    if (
        plan.domain_classification.domain is not SecurityDomain.CRYPTOGRAPHY
        or plan.validation_strategy is not DomainValidationStrategy.INDEPENDENT_RECOMPUTATION
    ):
        raise ValueError("CRYPTO-001D Domain benchmark strategy differs")


def _cryptography_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY:
            return plan.reference()
    raise CryptographicMisuseAnalysisRecomputationBenchmarkError(
        "DOMAIN-006 Cryptography benchmark plan is missing"
    )


def _cryptography_worker_profile_ref() -> DomainWorkerBoundaryProfileRef:
    profiles = tuple(
        profile.reference()
        for profile in registered_domain_worker_boundary_profiles().profiles
        if profile.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    )
    if len(profiles) != 1:
        raise CryptographicMisuseAnalysisRecomputationBenchmarkError(
            "DOMAIN-004 Cryptography Worker profile is missing or ambiguous"
        )
    return profiles[0]


__all__ = [
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_BENCHMARK_VECTOR_PROFILE_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_RECOMPUTATION_VALIDATION_API_VERSION",
    "CryptographicBenchmarkExpectedOutcome",
    "CryptographicBenchmarkGroundTruthClass",
    "CryptographicMisuseAnalysisBenchmarkVectorCase",
    "CryptographicMisuseAnalysisBenchmarkVectorProfile",
    "CryptographicMisuseAnalysisRecomputationBenchmarkError",
    "CryptographicMisuseAnalysisRecomputationBenchmarkGate",
    "CryptographicMisuseAnalysisRecomputationComparison",
    "CryptographicMisuseAnalysisRecomputationExecution",
    "CryptographicMisuseAnalysisRecomputationValidation",
    "bind_cryptographic_misuse_analysis_independent_recomputation",
    "load_verified_cryptographic_misuse_analysis_recomputation_validation",
    "registered_cryptographic_misuse_analysis_benchmark_vector_profile",
]
