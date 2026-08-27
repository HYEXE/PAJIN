"""APP-001D deterministic Application re-analysis and seeded fixture contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.capabilities.application_static_analysis import (
    ApplicationStaticAnalysisPreparation,
)
from pajin.discovery.application_surfaces import ApplicationSurfaceClass
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow.application_static_analysis_admission import (
    ApplicationStaticAnalysisExecutionBundle,
    ApplicationStaticAnalysisExecutionTrustAnchor,
    ApplicationStaticAnalysisExecutionVerification,
    ApplicationStaticAnalysisKnowledgeAdmission,
    ApplicationStaticAnalysisObservationSourceInputs,
    ApplicationStaticAnalysisResultReceipt,
    ApplicationStaticAnalysisReviewSignal,
    VerifiedApplicationStaticAnalysisObservationSource,
    application_static_analysis_source_root_digest,
    load_verified_application_static_analysis_observation_source,
    verify_application_static_analysis_execution_bundle,
)

APPLICATION_STATIC_ANALYSIS_REANALYSIS_VALIDATION_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-reanalysis-validation/v1alpha1"
] = "pajin.dev/application-static-analysis-reanalysis-validation/v1alpha1"
APPLICATION_STATIC_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION: Literal[
    "pajin.dev/application-benchmark-fixture-profile/v1alpha1"
] = "pajin.dev/application-benchmark-fixture-profile/v1alpha1"

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
    "execution-attestation",
    "non-root-offline-runtime-receipt",
    "result-receipt",
    "cleanup-receipt",
]
_ReanalysisState = Literal[
    "deterministic-artifact-reanalysis-match",
    "deterministic-artifact-reanalysis-changed",
    "deterministic-artifact-reanalysis-unresolved",
]

_REANALYSIS_TRUE_FIELDS = (
    "sealed_source_reverified",
    "sealed_reanalysis_reverified",
    "stored_source_admission_verified",
    "separate_action_authority_verified",
    "causal_reanalysis_order_verified",
    "exact_surface_semantics_verified",
    "exact_artifact_digest_verified",
    "exact_parser_executable_verified",
    "exact_sandbox_image_verified",
    "exact_output_schema_verified",
    "exact_budget_verified",
    "offline_sandbox_verified",
    "domain_validation_strategy_satisfied",
    "deployment_context_reverification_required",
)
_REANALYSIS_FALSE_FIELDS = (
    "artifact_format_confirmed",
    "configuration_value_confirmed",
    "runtime_support_confirmed",
    "dependency_relationship_confirmed",
    "vulnerability_confirmed",
    "hypothesis_confirmed",
    "ground_truth_case_bound",
    "negative_control_observed",
    "artifact_analysis_coverage_measured",
    "evidence_completeness_measured",
    "benchmark_measurement_observed",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "self_authenticating_projection",
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
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "artifact_mutation_authorized",
    "replay_authorized",
    "execution_authorized",
)
_FIXTURE_TRUE_FIELDS = (
    "private_ground_truth_requirements_registered",
    "seeded_artifacts_required",
    "disposable_sandbox_required",
    "network_disabled_required",
    "non_root_runtime_required",
    "read_only_noexec_artifact_mount_required",
    "positive_controls_registered",
    "negative_controls_registered",
    "evidence_completeness_required",
    "deterministic_artifact_reanalysis_required",
)
_FIXTURE_FALSE_FIELDS = (
    "private_ground_truth_verified",
    "target_profile_selected",
    "target_factory_authority",
    "artifact_fixture_materialized",
    "sandbox_provisioned",
    "provider_execution_authorized",
    "fixture_execution_authorized",
    "cleanup_observed",
    "reanalysis_evidence_bound",
    "benchmark_measurement_observed",
    "artifact_analysis_coverage_measured",
    "evidence_completeness_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "artifact_format_confirmed",
    "configuration_value_confirmed",
    "runtime_support_confirmed",
    "dependency_relationship_confirmed",
    "vulnerability_confirmed",
    "hypothesis_confirmed",
    "ground_truth_case_observed",
    "negative_control_observed",
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
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "artifact_mutation_authorized",
    "replay_authorized",
    "execution_authorized",
)


class ApplicationStaticAnalysisReanalysisBenchmarkError(RuntimeError):
    """Raised when APP-001D provenance or benchmark authority differs."""


class ApplicationStaticAnalysisReanalysisComparison(StrEnum):
    """Neutral comparisons that never confirm artifact or vulnerability truth."""

    MATCHED = "analysis-result-match"
    CHANGED = "analysis-result-changed"
    UNRESOLVED = "analysis-result-unresolved"


class ApplicationBenchmarkGroundTruthClass(StrEnum):
    """Closed seeded-fixture classes for future Application measurement."""

    KNOWN_POSITIVE = "known-positive"
    NEGATIVE_CONTROL = "negative-control"


class ApplicationBenchmarkExpectedOutcome(StrEnum):
    """Private expected outcomes without raw parser output or truth claims."""

    REVIEW_SIGNAL = "review-signal"
    NO_REVIEW_SIGNAL = "no-review-signal"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class ApplicationStaticAnalysisReanalysisExecution(_FrozenStrictModel):
    """Digest-only projection whose trusted use requires the contextful loader."""

    preparation: ApplicationStaticAnalysisPreparation
    action_permit: ActionPermit = Field(alias="actionPermit")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor = Field(alias="trustAnchor")
    verification: ApplicationStaticAnalysisExecutionVerification
    execution_bundle: ApplicationStaticAnalysisExecutionBundle = Field(alias="executionBundle")
    result_receipt: ApplicationStaticAnalysisResultReceipt = Field(alias="resultReceipt")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    attestation_reference: _ArtifactPath = Field(alias="attestationReference")
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")

    @model_validator(mode="after")
    def bind_execution_projection(self) -> Self:
        preparation = self.preparation
        prepared = preparation.prepared_action
        permit = self.action_permit
        statement = self.execution_bundle.statement
        runtime = statement.sandbox_runtime
        receipt = self.result_receipt
        verified = verify_application_static_analysis_execution_bundle(
            self.execution_bundle,
            trust_anchor=self.trust_anchor,
        )
        expected_source_root_digest = application_static_analysis_source_root_digest(
            attestation_sha256=self.attestation_sha256,
            result_receipt_sha256=self.result_receipt_sha256,
            trust_anchor_digest=verified.trust_anchor_digest,
            statement_sha256=verified.statement_sha256,
        )
        if (
            verified != self.verification
            or self.source_root_digest != expected_source_root_digest
            or self.attestation_reference == self.result_receipt_reference
            or self.trust_anchor.sandbox != preparation.sandbox
            or self.trust_anchor.capability != preparation.binding.capability
            or self.trust_anchor.capability_release != preparation.release
            or permit.capability != prepared.capability
            or permit.request_id != prepared.request.request_id
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
            or self.approval_receipt.action_permit != permit
            or statement.run_id != permit.run_id
            or statement.preparation_id != preparation.preparation_id
            or statement.preparation_digest != preparation.preparation_digest
            or statement.analysis_request != preparation.analysis_request
            or statement.request_id != permit.request_id
            or statement.request_digest != permit.request_digest
            or statement.normalized_parameters_digest != permit.normalized_parameters_digest
            or statement.action_permit_id != permit.permit_id
            or statement.action_permit_digest != permit.permit_digest
            or statement.approval_receipt_id != self.approval_receipt.receipt_id
            or statement.approval_receipt_digest != self.approval_receipt.receipt_digest
            or runtime.sandbox_binding_id != preparation.sandbox.sandbox_binding_id
            or runtime.sandbox_binding_digest != preparation.sandbox.sandbox_binding_digest
            or runtime.deployment_id != preparation.sandbox.deployment_id
            or runtime.operation is not preparation.operation
            or runtime.parser is not preparation.sandbox.parser
            or runtime.parser_executable_sha256 != preparation.sandbox.parser_executable_sha256
            or runtime.sandbox_image_sha256 != preparation.sandbox.sandbox_image_sha256
            or runtime.artifact_sha256 != preparation.artifact_custody.artifact_sha256
            or receipt.execution_id != statement.execution_id
            or receipt.request_id != permit.request_id
            or receipt.request_digest != permit.request_digest
            or receipt.preparation_id != preparation.preparation_id
            or receipt.preparation_digest != preparation.preparation_digest
            or receipt.operation is not preparation.operation
            or receipt.surface != preparation.surface.reference()
            or receipt.artifact_sha256 != preparation.artifact_custody.artifact_sha256
            or receipt.output_schema != preparation.analysis_request.output_schema
            or statement.result_receipt_reference != self.result_receipt_reference
            or statement.result_receipt_sha256 != self.result_receipt_sha256
            or statement.result_receipt_id != receipt.receipt_id
            or statement.result_receipt_digest != receipt.receipt_digest
        ):
            raise ValueError("APP-001D execution projection differs from sealed authority")
        return self


class ApplicationStaticAnalysisReanalysisValidation(_FrozenStrictModel):
    """Non-authorizing wire projection; bare model parsing is not verification."""

    api_version: Literal["pajin.dev/application-static-analysis-reanalysis-validation/v1alpha1"] = (
        Field(
            default=APPLICATION_STATIC_ANALYSIS_REANALYSIS_VALIDATION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["ApplicationStaticAnalysisReanalysisValidation"] = (
        "ApplicationStaticAnalysisReanalysisValidation"
    )
    validation_id: str = Field(default="", alias="validationId", max_length=118)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    source_admission: ApplicationStaticAnalysisKnowledgeAdmission = Field(alias="sourceAdmission")
    source_execution: ApplicationStaticAnalysisReanalysisExecution = Field(alias="sourceExecution")
    reanalysis_execution: ApplicationStaticAnalysisReanalysisExecution = Field(
        alias="reanalysisExecution"
    )
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    comparison: ApplicationStaticAnalysisReanalysisComparison
    result_body_digest_matched: bool = Field(alias="resultBodyDigestMatched")
    result_bytes_matched: bool = Field(alias="resultBytesMatched")
    review_signal_matched: bool = Field(alias="reviewSignalMatched")
    state: _ReanalysisState
    sealed_source_reverified: Literal[True] = Field(
        default=True,
        alias="sealedSourceReverified",
    )
    sealed_reanalysis_reverified: Literal[True] = Field(
        default=True,
        alias="sealedReanalysisReverified",
    )
    stored_source_admission_verified: Literal[True] = Field(
        default=True,
        alias="storedSourceAdmissionVerified",
    )
    separate_action_authority_verified: Literal[True] = Field(
        default=True,
        alias="separateActionAuthorityVerified",
    )
    causal_reanalysis_order_verified: Literal[True] = Field(
        default=True,
        alias="causalReanalysisOrderVerified",
    )
    exact_surface_semantics_verified: Literal[True] = Field(
        default=True,
        alias="exactSurfaceSemanticsVerified",
    )
    exact_artifact_digest_verified: Literal[True] = Field(
        default=True,
        alias="exactArtifactDigestVerified",
    )
    exact_parser_executable_verified: Literal[True] = Field(
        default=True,
        alias="exactParserExecutableVerified",
    )
    exact_sandbox_image_verified: Literal[True] = Field(
        default=True,
        alias="exactSandboxImageVerified",
    )
    exact_output_schema_verified: Literal[True] = Field(
        default=True,
        alias="exactOutputSchemaVerified",
    )
    exact_budget_verified: Literal[True] = Field(default=True, alias="exactBudgetVerified")
    offline_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="offlineSandboxVerified",
    )
    domain_validation_strategy_satisfied: Literal[True] = Field(
        default=True,
        alias="domainValidationStrategySatisfied",
    )
    deployment_context_reverification_required: Literal[True] = Field(
        default=True,
        alias="deploymentContextReverificationRequired",
    )
    artifact_format_confirmed: Literal[False] = Field(
        default=False,
        alias="artifactFormatConfirmed",
    )
    configuration_value_confirmed: Literal[False] = Field(
        default=False,
        alias="configurationValueConfirmed",
    )
    runtime_support_confirmed: Literal[False] = Field(
        default=False,
        alias="runtimeSupportConfirmed",
    )
    dependency_relationship_confirmed: Literal[False] = Field(
        default=False,
        alias="dependencyRelationshipConfirmed",
    )
    vulnerability_confirmed: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmed",
    )
    hypothesis_confirmed: Literal[False] = Field(
        default=False,
        alias="hypothesisConfirmed",
    )
    ground_truth_case_bound: Literal[False] = Field(
        default=False,
        alias="groundTruthCaseBound",
    )
    negative_control_observed: Literal[False] = Field(
        default=False,
        alias="negativeControlObserved",
    )
    artifact_analysis_coverage_measured: Literal[False] = Field(
        default=False,
        alias="artifactAnalysisCoverageMeasured",
    )
    evidence_completeness_measured: Literal[False] = Field(
        default=False,
        alias="evidenceCompletenessMeasured",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    self_authenticating_projection: Literal[False] = Field(
        default=False,
        alias="selfAuthenticatingProjection",
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
    artifact_access_authorized: Literal[False] = Field(
        default=False,
        alias="artifactAccessAuthorized",
    )
    custody_authorization_authority: Literal[False] = Field(
        default=False,
        alias="custodyAuthorizationAuthority",
    )
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
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_REANALYSIS_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("APP-001D verified markers must be boolean true")
        return value

    @field_validator(
        "result_body_digest_matched",
        "result_bytes_matched",
        "review_signal_matched",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("APP-001D comparison markers must be booleans")
        return value

    @field_validator(*_REANALYSIS_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("APP-001D re-analysis authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_reanalysis_validation(self) -> Self:
        _require_application_domain_plan(self.domain_benchmark_plan)
        _require_admission_projection(self.source_admission, self.source_execution)
        _require_equivalent_reanalysis_semantics(
            self.source_execution,
            self.reanalysis_execution,
        )
        _require_distinct_reanalysis_authority(
            self.source_execution,
            self.reanalysis_execution,
        )
        source_result = self.source_execution.result_receipt
        reanalysis_result = self.reanalysis_execution.result_receipt
        body_matched = source_result.result_body_sha256 == reanalysis_result.result_body_sha256
        bytes_matched = source_result.result_bytes == reanalysis_result.result_bytes
        signal_matched = source_result.review_signal is reanalysis_result.review_signal
        comparison = _comparison(
            source=source_result,
            reanalysis=reanalysis_result,
        )
        if (
            self.result_body_digest_matched is not body_matched
            or self.result_bytes_matched is not bytes_matched
            or self.review_signal_matched is not signal_matched
            or self.comparison is not comparison
            or self.state != _reanalysis_state(comparison)
        ):
            raise ValueError("APP-001D neutral re-analysis comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.application-static-analysis-reanalysis-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"application-static-analysis-reanalysis_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("APP-001D re-analysis validation digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("APP-001D re-analysis validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


class ApplicationStaticAnalysisBenchmarkFixtureCase(_FrozenStrictModel):
    """One seeded expected outcome without embedded artifact or parser content."""

    fixture_id: _Identifier = Field(alias="fixtureId")
    ground_truth_class: ApplicationBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    surface_class: ApplicationSurfaceClass = Field(alias="surfaceClass")
    expected_outcome: ApplicationBenchmarkExpectedOutcome = Field(alias="expectedOutcome")
    expected_review_signal: ApplicationStaticAnalysisReviewSignal | None = Field(
        default=None,
        alias="expectedReviewSignal",
    )
    required_evidence: tuple[_EvidenceRequirement, ...] = Field(
        min_length=4,
        max_length=4,
        alias="requiredEvidence",
    )
    fixture_materialization: Literal["seeded-immutable-application-artifact"] = Field(
        default="seeded-immutable-application-artifact",
        alias="fixtureMaterialization",
    )
    isolation_requirement: Literal["disposable-network-disabled-non-root-sandbox-per-case"] = Field(
        default="disposable-network-disabled-non-root-sandbox-per-case",
        alias="isolationRequirement",
    )
    artifact_mount_requirement: Literal["read-only-noexec-exact-digest"] = Field(
        default="read-only-noexec-exact-digest",
        alias="artifactMountRequirement",
    )
    raw_artifact_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentEmbedded",
    )
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    artifact_write_operations: Literal[0] = Field(
        default=0,
        alias="artifactWriteOperations",
    )
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dynamic_target_executions: Literal[0] = Field(
        default=0,
        alias="dynamicTargetExecutions",
    )
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")

    @field_validator(
        "raw_artifact_content_embedded",
        "raw_parser_output_embedded",
        "secret_material_embedded",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("APP-001D fixture cases cannot embed artifact or secret content")
        return value

    @field_validator(
        "artifact_write_operations",
        "network_requests",
        "dynamic_target_executions",
        "debugger_attaches",
        mode="before",
    )
    @classmethod
    def require_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("APP-001D fixture operation counters must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_fixture_case(self) -> Self:
        expected_evidence: tuple[_EvidenceRequirement, ...] = (
            "execution-attestation",
            "non-root-offline-runtime-receipt",
            "result-receipt",
            "cleanup-receipt",
        )
        if self.ground_truth_class is ApplicationBenchmarkGroundTruthClass.KNOWN_POSITIVE:
            valid = (
                self.expected_outcome is ApplicationBenchmarkExpectedOutcome.REVIEW_SIGNAL
                and self.expected_review_signal is not None
            )
        else:
            valid = (
                self.expected_outcome is ApplicationBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
                and self.expected_review_signal is None
            )
        signal_surface = {
            ApplicationStaticAnalysisReviewSignal.BINARY_SECURITY_METADATA_REVIEW: (
                ApplicationSurfaceClass.BINARY
            ),
            ApplicationStaticAnalysisReviewSignal.CONFIGURATION_STRUCTURE_REVIEW: (
                ApplicationSurfaceClass.CONFIGURATION
            ),
            ApplicationStaticAnalysisReviewSignal.RUNTIME_METADATA_REVIEW: (
                ApplicationSurfaceClass.RUNTIME
            ),
            ApplicationStaticAnalysisReviewSignal.LIBRARY_METADATA_REVIEW: (
                ApplicationSurfaceClass.LIBRARY
            ),
        }
        if (
            not valid
            or self.required_evidence != expected_evidence
            or (
                self.expected_review_signal is not None
                and signal_surface[self.expected_review_signal] is not self.surface_class
            )
        ):
            raise ValueError("APP-001D fixture Ground Truth shape differs")
        return self


class ApplicationStaticAnalysisBenchmarkFixtureProfile(_FrozenStrictModel):
    """Registered seeded-artifact requirements, never a benchmark measurement."""

    api_version: Literal["pajin.dev/application-benchmark-fixture-profile/v1alpha1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisBenchmarkFixtureProfile"] = (
        "ApplicationStaticAnalysisBenchmarkFixtureProfile"
    )
    profile_id: str = Field(default="", alias="profileId", max_length=110)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    covered_surface_classes: tuple[ApplicationSurfaceClass, ...] = Field(
        min_length=4,
        max_length=4,
        alias="coveredSurfaceClasses",
    )
    cases: tuple[ApplicationStaticAnalysisBenchmarkFixtureCase, ...] = Field(
        min_length=8,
        max_length=8,
    )
    state: Literal["registered-seeded-ground-truth-not-measured"] = (
        "registered-seeded-ground-truth-not-measured"
    )
    private_ground_truth_requirements_registered: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthRequirementsRegistered",
    )
    seeded_artifacts_required: Literal[True] = Field(
        default=True,
        alias="seededArtifactsRequired",
    )
    disposable_sandbox_required: Literal[True] = Field(
        default=True,
        alias="disposableSandboxRequired",
    )
    network_disabled_required: Literal[True] = Field(
        default=True,
        alias="networkDisabledRequired",
    )
    non_root_runtime_required: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeRequired",
    )
    read_only_noexec_artifact_mount_required: Literal[True] = Field(
        default=True,
        alias="readOnlyNoexecArtifactMountRequired",
    )
    positive_controls_registered: Literal[True] = Field(
        default=True,
        alias="positiveControlsRegistered",
    )
    negative_controls_registered: Literal[True] = Field(
        default=True,
        alias="negativeControlsRegistered",
    )
    evidence_completeness_required: Literal[True] = Field(
        default=True,
        alias="evidenceCompletenessRequired",
    )
    deterministic_artifact_reanalysis_required: Literal[True] = Field(
        default=True,
        alias="deterministicArtifactReanalysisRequired",
    )
    target_profile_selected: Literal[False] = Field(
        default=False,
        alias="targetProfileSelected",
    )
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    artifact_fixture_materialized: Literal[False] = Field(
        default=False,
        alias="artifactFixtureMaterialized",
    )
    sandbox_provisioned: Literal[False] = Field(
        default=False,
        alias="sandboxProvisioned",
    )
    private_ground_truth_verified: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthVerified",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )
    fixture_execution_authorized: Literal[False] = Field(
        default=False,
        alias="fixtureExecutionAuthorized",
    )
    cleanup_observed: Literal[False] = Field(default=False, alias="cleanupObserved")
    reanalysis_evidence_bound: Literal[False] = Field(
        default=False,
        alias="reanalysisEvidenceBound",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    artifact_analysis_coverage_measured: Literal[False] = Field(
        default=False,
        alias="artifactAnalysisCoverageMeasured",
    )
    evidence_completeness_measured: Literal[False] = Field(
        default=False,
        alias="evidenceCompletenessMeasured",
    )
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    artifact_format_confirmed: Literal[False] = Field(
        default=False,
        alias="artifactFormatConfirmed",
    )
    configuration_value_confirmed: Literal[False] = Field(
        default=False,
        alias="configurationValueConfirmed",
    )
    runtime_support_confirmed: Literal[False] = Field(
        default=False,
        alias="runtimeSupportConfirmed",
    )
    dependency_relationship_confirmed: Literal[False] = Field(
        default=False,
        alias="dependencyRelationshipConfirmed",
    )
    vulnerability_confirmed: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmed",
    )
    hypothesis_confirmed: Literal[False] = Field(
        default=False,
        alias="hypothesisConfirmed",
    )
    ground_truth_case_observed: Literal[False] = Field(
        default=False,
        alias="groundTruthCaseObserved",
    )
    negative_control_observed: Literal[False] = Field(
        default=False,
        alias="negativeControlObserved",
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
    artifact_access_authorized: Literal[False] = Field(
        default=False,
        alias="artifactAccessAuthorized",
    )
    custody_authorization_authority: Literal[False] = Field(
        default=False,
        alias="custodyAuthorizationAuthority",
    )
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
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_FIXTURE_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("APP-001D fixture requirement markers must be boolean true")
        return value

    @field_validator(*_FIXTURE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("APP-001D fixture authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_fixture_profile(self) -> Self:
        _require_application_domain_plan(self.domain_benchmark_plan)
        if (
            self.covered_surface_classes != tuple(ApplicationSurfaceClass)
            or self.cases != _registered_fixture_cases()
        ):
            raise ValueError("APP-001D seeded fixture profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.application-benchmark-fixture-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"application-analysis-fixtures_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("APP-001D fixture profile digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("APP-001D fixture profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


class ApplicationStaticAnalysisReanalysisBenchmarkGate:
    """Reopen sealed C evidence without reading an artifact or invoking a sandbox."""

    def __init__(
        self,
        *,
        trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
    ) -> None:
        if not isinstance(trust_anchor, ApplicationStaticAnalysisExecutionTrustAnchor):
            raise TypeError("APP-001D requires a deployment Application trust anchor")
        self._trust_anchor = ApplicationStaticAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )

    def bind_reanalysis(
        self,
        source_inputs: ApplicationStaticAnalysisObservationSourceInputs,
        source_admission: ApplicationStaticAnalysisKnowledgeAdmission,
        reanalysis_inputs: ApplicationStaticAnalysisObservationSourceInputs,
        *,
        source_graph_store: SQLiteGraphStore,
        reanalysis_graph_store: SQLiteGraphStore,
    ) -> ApplicationStaticAnalysisReanalysisValidation:
        """Return one neutral comparison of separately authorized sealed executions."""

        try:
            canonical_admission = ApplicationStaticAnalysisKnowledgeAdmission.model_validate(
                source_admission.model_dump(mode="json", by_alias=True)
            )
            source = load_verified_application_static_analysis_observation_source(
                source_inputs,
                graph_store=source_graph_store,
                trust_anchor=self._trust_anchor,
            )
            reanalysis = load_verified_application_static_analysis_observation_source(
                reanalysis_inputs,
                graph_store=reanalysis_graph_store,
                trust_anchor=self._trust_anchor,
            )
            _require_stored_source_admission(canonical_admission, source_graph_store)
            source_projection = _execution_projection(source)
            reanalysis_projection = _execution_projection(reanalysis)
            _require_admission_projection(canonical_admission, source_projection)
            comparison = _comparison(
                source=source_projection.result_receipt,
                reanalysis=reanalysis_projection.result_receipt,
            )
            return ApplicationStaticAnalysisReanalysisValidation(
                sourceAdmission=canonical_admission,
                sourceExecution=source_projection,
                reanalysisExecution=reanalysis_projection,
                domainBenchmarkPlan=_application_domain_benchmark_plan_ref(),
                comparison=comparison,
                resultBodyDigestMatched=(
                    source_projection.result_receipt.result_body_sha256
                    == reanalysis_projection.result_receipt.result_body_sha256
                ),
                resultBytesMatched=(
                    source_projection.result_receipt.result_bytes
                    == reanalysis_projection.result_receipt.result_bytes
                ),
                reviewSignalMatched=(
                    source_projection.result_receipt.review_signal
                    is reanalysis_projection.result_receipt.review_signal
                ),
                state=_reanalysis_state(comparison),
            )
        except ApplicationStaticAnalysisReanalysisBenchmarkError:
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
            raise ApplicationStaticAnalysisReanalysisBenchmarkError(
                "APP-001D deterministic Application re-analysis failed closed"
            ) from exc


def bind_application_static_analysis_reanalysis(
    source_inputs: ApplicationStaticAnalysisObservationSourceInputs,
    source_admission: ApplicationStaticAnalysisKnowledgeAdmission,
    reanalysis_inputs: ApplicationStaticAnalysisObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    reanalysis_graph_store: SQLiteGraphStore,
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
) -> ApplicationStaticAnalysisReanalysisValidation:
    """Functional entry point for the deployment-configured APP-001D gate."""

    return ApplicationStaticAnalysisReanalysisBenchmarkGate(
        trust_anchor=trust_anchor
    ).bind_reanalysis(
        source_inputs,
        source_admission,
        reanalysis_inputs,
        source_graph_store=source_graph_store,
        reanalysis_graph_store=reanalysis_graph_store,
    )


def load_verified_application_static_analysis_reanalysis_validation(
    validation: object,
    source_inputs: ApplicationStaticAnalysisObservationSourceInputs,
    reanalysis_inputs: ApplicationStaticAnalysisObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    reanalysis_graph_store: SQLiteGraphStore,
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
) -> ApplicationStaticAnalysisReanalysisValidation:
    """Reverify one wire projection against deployment evidence and Graph authority."""

    try:
        if isinstance(validation, ApplicationStaticAnalysisReanalysisValidation):
            payload: object = validation.model_dump(mode="json", by_alias=True)
        else:
            payload = validation
        canonical = ApplicationStaticAnalysisReanalysisValidation.model_validate(payload)
        expected = bind_application_static_analysis_reanalysis(
            source_inputs,
            canonical.source_admission,
            reanalysis_inputs,
            source_graph_store=source_graph_store,
            reanalysis_graph_store=reanalysis_graph_store,
            trust_anchor=trust_anchor,
        )
        if canonical != expected:
            raise ValueError(
                "APP-001D wire projection differs from deployment evidence and Graph authority"
            )
        return expected
    except ApplicationStaticAnalysisReanalysisBenchmarkError:
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
        raise ApplicationStaticAnalysisReanalysisBenchmarkError(
            "APP-001D wire re-verification failed closed"
        ) from exc


def registered_application_static_analysis_benchmark_fixture_profile() -> (
    ApplicationStaticAnalysisBenchmarkFixtureProfile
):
    """Return exact seeded-artifact requirements without materializing or measuring them."""

    try:
        return ApplicationStaticAnalysisBenchmarkFixtureProfile(
            domainBenchmarkPlan=_application_domain_benchmark_plan_ref(),
            coveredSurfaceClasses=tuple(ApplicationSurfaceClass),
            cases=_registered_fixture_cases(),
        )
    except (RuntimeError, ValidationError, ValueError) as exc:
        raise ApplicationStaticAnalysisReanalysisBenchmarkError(
            "APP-001D seeded fixture registration failed closed"
        ) from exc


def _execution_projection(
    source: VerifiedApplicationStaticAnalysisObservationSource,
) -> ApplicationStaticAnalysisReanalysisExecution:
    return ApplicationStaticAnalysisReanalysisExecution(
        preparation=source.preparation,
        actionPermit=source.permit,
        approvalReceipt=source.approval_receipt,
        trustAnchor=source.trust_anchor,
        verification=source.verification,
        executionBundle=source.bundle,
        resultReceipt=source.result_receipt,
        sourceRootDigest=source.source_root_digest,
        attestationReference=source.attestation_reference,
        attestationSha256=source.attestation_sha256,
        resultReceiptReference=source.result_receipt_reference,
        resultReceiptSha256=source.result_receipt_sha256,
    )


def _require_stored_source_admission(
    admission: ApplicationStaticAnalysisKnowledgeAdmission,
    graph_store: SQLiteGraphStore,
) -> None:
    observation = admission.candidate.observation_proposal
    stored_observation = graph_store.event_log.event_for_attempt(
        observation.proposal_id,
        observation.digest(),
    )
    if stored_observation != admission.observation_graph_event:
        raise ValueError("APP-001D source Observation admission is not stored exactly")
    hypothesis = admission.candidate.hypothesis_proposal
    if hypothesis is None:
        if admission.hypothesis_graph_event is not None:
            raise ValueError("APP-001D source Hypothesis admission differs")
        return
    stored_hypothesis = graph_store.event_log.event_for_attempt(
        hypothesis.proposal_id,
        hypothesis.digest(),
    )
    if stored_hypothesis != admission.hypothesis_graph_event:
        raise ValueError("APP-001D source Hypothesis admission is not stored exactly")


def _require_admission_projection(
    admission: ApplicationStaticAnalysisKnowledgeAdmission,
    execution: ApplicationStaticAnalysisReanalysisExecution,
) -> None:
    candidate = admission.candidate
    receipt = execution.result_receipt
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
        or candidate.output_schema != receipt.output_schema
        or candidate.operation is not receipt.operation
        or candidate.review_signal is not receipt.review_signal
    ):
        raise ValueError("APP-001D source admission differs from its sealed execution")


def _require_equivalent_reanalysis_semantics(
    source: ApplicationStaticAnalysisReanalysisExecution,
    reanalysis: ApplicationStaticAnalysisReanalysisExecution,
) -> None:
    source_preparation = source.preparation
    reanalysis_preparation = reanalysis.preparation
    source_prepared = source_preparation.prepared_action
    reanalysis_prepared = reanalysis_preparation.prepared_action
    source_request = source_prepared.request
    reanalysis_request = reanalysis_prepared.request
    source_runtime = source.execution_bundle.statement.sandbox_runtime
    reanalysis_runtime = reanalysis.execution_bundle.statement.sandbox_runtime
    if (
        source.trust_anchor != reanalysis.trust_anchor
        or source_preparation.binding != reanalysis_preparation.binding
        or source_preparation.surface != reanalysis_preparation.surface
        or source_preparation.operation is not reanalysis_preparation.operation
        or source_preparation.artifact_custody != reanalysis_preparation.artifact_custody
        or source_preparation.sandbox != reanalysis_preparation.sandbox
        or source_preparation.analysis_request != reanalysis_preparation.analysis_request
        or source_preparation.campaign_scope != reanalysis_preparation.campaign_scope
        or source_preparation.matched_surface_allow_rule
        != reanalysis_preparation.matched_surface_allow_rule
        or source_preparation.release != reanalysis_preparation.release
        or source_prepared.activation_set_digest != reanalysis_prepared.activation_set_digest
        or source_prepared.capability != reanalysis_prepared.capability
        or source_prepared.normalized_parameters_digest
        != reanalysis_prepared.normalized_parameters_digest
        or source_request.model_dump(mode="json", exclude={"request_id"})
        != reanalysis_request.model_dump(mode="json", exclude={"request_id"})
        or source.result_receipt.surface != reanalysis.result_receipt.surface
        or source.result_receipt.artifact_sha256 != reanalysis.result_receipt.artifact_sha256
        or source.result_receipt.output_schema != reanalysis.result_receipt.output_schema
        or source_runtime.parser is not reanalysis_runtime.parser
        or source_runtime.parser_executable_sha256 != reanalysis_runtime.parser_executable_sha256
        or source_runtime.sandbox_image_sha256 != reanalysis_runtime.sandbox_image_sha256
    ):
        raise ValueError("APP-001D re-analysis differs from source Application semantics")
    if (
        source.result_receipt.result_body_sha256 == reanalysis.result_receipt.result_body_sha256
        and source.result_receipt.result_bytes != reanalysis.result_receipt.result_bytes
    ):
        raise ValueError("APP-001D equal result digest has inconsistent result byte count")


def _require_distinct_reanalysis_authority(
    source: ApplicationStaticAnalysisReanalysisExecution,
    reanalysis: ApplicationStaticAnalysisReanalysisExecution,
) -> None:
    left = _execution_identity_coordinates(source)
    right = _execution_identity_coordinates(reanalysis)
    reused = tuple(name for name in left if left[name] == right[name])
    if reused:
        raise ValueError(
            "APP-001D re-analysis reused source execution authority: " + ", ".join(reused)
        )
    if (
        reanalysis.execution_bundle.statement.started_at
        <= source.execution_bundle.statement.finished_at
    ):
        raise ValueError("APP-001D re-analysis is not causally after the source")


def _execution_identity_coordinates(
    execution: ApplicationStaticAnalysisReanalysisExecution,
) -> dict[str, str]:
    permit = execution.action_permit
    receipt = execution.approval_receipt
    approval = receipt.approval
    statement = execution.execution_bundle.statement
    runtime = statement.sandbox_runtime
    result = execution.result_receipt
    return {
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
        "approvalReceiptId": receipt.receipt_id,
        "approvalReceiptDigest": receipt.receipt_digest,
        "executionId": statement.execution_id,
        "statementSha256": execution.verification.statement_sha256,
        "sandboxRuntimeReceiptId": runtime.receipt_id,
        "sandboxRuntimeReceiptDigest": runtime.receipt_digest,
        "attestationSha256": execution.attestation_sha256,
        "resultReceiptId": result.receipt_id,
        "resultReceiptDigest": result.receipt_digest,
        "resultReceiptSha256": execution.result_receipt_sha256,
    }


def _comparison(
    *,
    source: ApplicationStaticAnalysisResultReceipt,
    reanalysis: ApplicationStaticAnalysisResultReceipt,
) -> ApplicationStaticAnalysisReanalysisComparison:
    body_matched = source.result_body_sha256 == reanalysis.result_body_sha256
    bytes_matched = source.result_bytes == reanalysis.result_bytes
    signal_matched = source.review_signal is reanalysis.review_signal
    if body_matched and not bytes_matched:
        raise ValueError("APP-001D equal result digest has inconsistent result byte count")
    if body_matched and bytes_matched and signal_matched:
        return ApplicationStaticAnalysisReanalysisComparison.MATCHED
    if source.review_signal is None and reanalysis.review_signal is None:
        return ApplicationStaticAnalysisReanalysisComparison.UNRESOLVED
    return ApplicationStaticAnalysisReanalysisComparison.CHANGED


def _reanalysis_state(
    comparison: ApplicationStaticAnalysisReanalysisComparison,
) -> _ReanalysisState:
    states: dict[ApplicationStaticAnalysisReanalysisComparison, _ReanalysisState] = {
        ApplicationStaticAnalysisReanalysisComparison.MATCHED: (
            "deterministic-artifact-reanalysis-match"
        ),
        ApplicationStaticAnalysisReanalysisComparison.CHANGED: (
            "deterministic-artifact-reanalysis-changed"
        ),
        ApplicationStaticAnalysisReanalysisComparison.UNRESOLVED: (
            "deterministic-artifact-reanalysis-unresolved"
        ),
    }
    return states[comparison]


def _fixture_case(
    *,
    fixture_id: str,
    ground_truth_class: ApplicationBenchmarkGroundTruthClass,
    surface_class: ApplicationSurfaceClass,
    expected_outcome: ApplicationBenchmarkExpectedOutcome,
    expected_review_signal: ApplicationStaticAnalysisReviewSignal | None = None,
) -> ApplicationStaticAnalysisBenchmarkFixtureCase:
    return ApplicationStaticAnalysisBenchmarkFixtureCase(
        fixtureId=fixture_id,
        groundTruthClass=ground_truth_class,
        surfaceClass=surface_class,
        expectedOutcome=expected_outcome,
        expectedReviewSignal=expected_review_signal,
        requiredEvidence=(
            "execution-attestation",
            "non-root-offline-runtime-receipt",
            "result-receipt",
            "cleanup-receipt",
        ),
    )


def _registered_fixture_cases() -> tuple[ApplicationStaticAnalysisBenchmarkFixtureCase, ...]:
    signals = {
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
    }
    cases: list[ApplicationStaticAnalysisBenchmarkFixtureCase] = []
    for surface_class in ApplicationSurfaceClass:
        cases.extend(
            (
                _fixture_case(
                    fixture_id=(f"application-fixture:{surface_class.value}-known-positive"),
                    ground_truth_class=ApplicationBenchmarkGroundTruthClass.KNOWN_POSITIVE,
                    surface_class=surface_class,
                    expected_outcome=ApplicationBenchmarkExpectedOutcome.REVIEW_SIGNAL,
                    expected_review_signal=signals[surface_class],
                ),
                _fixture_case(
                    fixture_id=(f"application-fixture:{surface_class.value}-negative-control"),
                    ground_truth_class=ApplicationBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
                    surface_class=surface_class,
                    expected_outcome=ApplicationBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL,
                ),
            )
        )
    return tuple(sorted(cases, key=lambda item: item.fixture_id))


def _require_application_domain_plan(reference: DomainBenchmarkPlanRef) -> None:
    try:
        plan = resolve_registered_domain_benchmark_plan(reference)
    except Exception as exc:
        raise ValueError("APP-001D Domain benchmark plan is not registered exactly") from exc
    if (
        plan.domain_classification.domain is not SecurityDomain.APPLICATION
        or plan.validation_strategy
        is not DomainValidationStrategy.DETERMINISTIC_ARTIFACT_REANALYSIS
    ):
        raise ValueError("APP-001D Domain benchmark strategy differs")


def _application_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.APPLICATION:
            return plan.reference()
    raise ApplicationStaticAnalysisReanalysisBenchmarkError(
        "DOMAIN-006 Application benchmark plan is missing"
    )


__all__ = [
    "APPLICATION_STATIC_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_REANALYSIS_VALIDATION_API_VERSION",
    "ApplicationBenchmarkExpectedOutcome",
    "ApplicationBenchmarkGroundTruthClass",
    "ApplicationStaticAnalysisBenchmarkFixtureCase",
    "ApplicationStaticAnalysisBenchmarkFixtureProfile",
    "ApplicationStaticAnalysisReanalysisBenchmarkError",
    "ApplicationStaticAnalysisReanalysisBenchmarkGate",
    "ApplicationStaticAnalysisReanalysisComparison",
    "ApplicationStaticAnalysisReanalysisExecution",
    "ApplicationStaticAnalysisReanalysisValidation",
    "bind_application_static_analysis_reanalysis",
    "load_verified_application_static_analysis_reanalysis_validation",
    "registered_application_static_analysis_benchmark_fixture_profile",
]
