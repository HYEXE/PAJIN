"""MOBILE-001D deterministic package re-analysis and seeded fixture contract."""

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
from pajin.capabilities.mobile_package_analysis import (
    MobilePackageAnalysisOperation,
    MobilePackageAnalysisPreparation,
)
from pajin.discovery.mobile_surfaces import MobilePlatform, MobileSurfaceClass
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow.mobile_package_analysis_admission import (
    MobilePackageAnalysisExecutionBundle,
    MobilePackageAnalysisExecutionTrustAnchor,
    MobilePackageAnalysisExecutionVerification,
    MobilePackageAnalysisKnowledgeAdmission,
    MobilePackageAnalysisObservationSourceInputs,
    MobilePackageAnalysisResultReceipt,
    MobilePackageAnalysisReviewSignal,
    MobilePackageSandboxRuntimeReceipt,
    VerifiedMobilePackageAnalysisObservationSource,
    load_verified_mobile_package_analysis_observation_source,
    mobile_package_analysis_source_root_digest,
    verify_mobile_package_analysis_execution_bundle,
)

MOBILE_PACKAGE_ANALYSIS_REANALYSIS_VALIDATION_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-reanalysis-validation/v1alpha1"
] = "pajin.dev/mobile-package-analysis-reanalysis-validation/v1alpha1"
MOBILE_PACKAGE_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-benchmark-fixture-profile/v1alpha1"
] = "pajin.dev/mobile-package-analysis-benchmark-fixture-profile/v1alpha1"

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
    "deterministic-package-reanalysis-match",
    "deterministic-package-reanalysis-changed",
    "deterministic-package-reanalysis-unresolved",
]


class MobilePackageAnalysisReanalysisBenchmarkError(RuntimeError):
    """Raised when MOBILE-001D provenance or benchmark authority differs."""


class MobilePackageAnalysisReanalysisComparison(StrEnum):
    """Neutral comparisons that never confirm package or security truth."""

    MATCHED = "package-analysis-result-match"
    CHANGED = "package-analysis-result-changed"
    UNRESOLVED = "package-analysis-result-unresolved"


class MobileBenchmarkGroundTruthClass(StrEnum):
    """Closed seeded-fixture classes for future Mobile measurement."""

    KNOWN_POSITIVE = "known-positive"
    NEGATIVE_CONTROL = "negative-control"


class MobileBenchmarkExpectedOutcome(StrEnum):
    """Private expected outcomes without raw package or parser content."""

    REVIEW_SIGNAL = "review-signal"
    NO_REVIEW_SIGNAL = "no-review-signal"


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    """Reject state that Pydantic ``model_copy(update=...)`` did not validate."""

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


class MobilePackageAnalysisReanalysisExecution(_FrozenStrictModel):
    """Digest-only projection whose trusted use requires the contextful loader."""

    preparation: MobilePackageAnalysisPreparation
    action_permit: ActionPermit = Field(alias="actionPermit")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor = Field(alias="trustAnchor")
    verification: MobilePackageAnalysisExecutionVerification
    execution_bundle: MobilePackageAnalysisExecutionBundle = Field(alias="executionBundle")
    result_receipt: MobilePackageAnalysisResultReceipt = Field(alias="resultReceipt")
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
        custody = preparation.package_custody
        sandbox = preparation.sandbox
        verified = verify_mobile_package_analysis_execution_bundle(
            self.execution_bundle,
            trust_anchor=self.trust_anchor,
        )
        expected_source_root_digest = mobile_package_analysis_source_root_digest(
            attestation_sha256=self.attestation_sha256,
            result_receipt_sha256=self.result_receipt_sha256,
            trust_anchor_digest=verified.trust_anchor_digest,
            statement_sha256=verified.statement_sha256,
        )
        expected_platform = (
            MobilePlatform.ANDROID
            if preparation.package_surface.surface_class is MobileSurfaceClass.APK
            else MobilePlatform.IOS
        )
        if (
            verified != self.verification
            or self.source_root_digest != expected_source_root_digest
            or self.attestation_reference == self.result_receipt_reference
            or self.trust_anchor.sandbox != sandbox
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
            or runtime.sandbox_binding_id != sandbox.sandbox_binding_id
            or runtime.sandbox_binding_digest != sandbox.sandbox_binding_digest
            or runtime.deployment_id != sandbox.deployment_id
            or runtime.surface != preparation.surface.reference()
            or runtime.package_surface != preparation.package_surface.reference()
            or runtime.operation is not preparation.operation
            or runtime.platform is not expected_platform
            or runtime.parser is not sandbox.parser
            or runtime.parser_executable_sha256 != sandbox.parser_executable_sha256
            or runtime.sandbox_image_sha256 != sandbox.sandbox_image_sha256
            or runtime.run_as_identity != sandbox.run_as_identity
            or runtime.output_schema != sandbox.output_schema
            or runtime.artifact_sha256 != custody.artifact_sha256
            or runtime.artifact_bytes != custody.artifact_bytes
            or runtime.custody_binding_id != custody.custody_binding_id
            or runtime.custody_binding_digest != custody.custody_binding_digest
            or runtime.custody_authority_id != custody.custody_authority_id
            or runtime.custody_object_id != custody.custody_object_id
            or runtime.authorization_id != custody.authorization_id
            or runtime.authorization_digest != custody.authorization_digest
            or runtime.max_artifact_bytes != sandbox.max_artifact_bytes
            or runtime.max_output_bytes != sandbox.max_output_bytes
            or runtime.max_runtime_seconds != sandbox.max_runtime_seconds
            or runtime.max_memory_mib != sandbox.max_memory_mib
            or runtime.max_process_count != sandbox.max_process_count
            or runtime.max_archive_entries != sandbox.max_archive_entries
            or runtime.max_total_uncompressed_bytes != sandbox.max_total_uncompressed_bytes
            or runtime.max_single_uncompressed_bytes != sandbox.max_single_uncompressed_bytes
            or runtime.max_archive_path_bytes != sandbox.max_archive_path_bytes
            or runtime.max_archive_nesting_depth != sandbox.max_archive_nesting_depth
            or runtime.max_compression_ratio != sandbox.max_compression_ratio
            or receipt.execution_id != statement.execution_id
            or receipt.request_id != permit.request_id
            or receipt.request_digest != permit.request_digest
            or receipt.preparation_id != preparation.preparation_id
            or receipt.preparation_digest != preparation.preparation_digest
            or receipt.operation is not preparation.operation
            or receipt.platform is not expected_platform
            or receipt.parser is not sandbox.parser
            or receipt.surface != preparation.surface.reference()
            or receipt.package_surface != preparation.package_surface.reference()
            or receipt.artifact_sha256 != custody.artifact_sha256
            or receipt.output_schema != preparation.analysis_request.output_schema
            or statement.result_receipt_reference != self.result_receipt_reference
            or statement.result_receipt_sha256 != self.result_receipt_sha256
            or statement.result_receipt_id != receipt.receipt_id
            or statement.result_receipt_digest != receipt.receipt_digest
        ):
            raise ValueError("MOBILE-001D execution projection differs from sealed authority")
        return self


_REANALYSIS_TRUE_FIELDS = (
    "sealed_source_reverified",
    "sealed_reanalysis_reverified",
    "stored_source_admission_verified",
    "separate_action_authority_verified",
    "causal_reanalysis_order_verified",
    "exact_selected_surface_verified",
    "exact_package_surface_verified",
    "exact_platform_verified",
    "exact_package_digest_verified",
    "exact_custody_verified",
    "exact_parser_executable_verified",
    "exact_sandbox_image_verified",
    "exact_output_schema_verified",
    "exact_budget_verified",
    "exact_archive_limits_verified",
    "exact_archive_observations_verified",
    "offline_static_sandbox_verified",
    "domain_worker_profile_binding_deferred",
    "domain_validation_strategy_satisfied",
    "deployment_context_reverification_required",
)
_REANALYSIS_FALSE_FIELDS = (
    "raw_package_embedded",
    "raw_parser_output_embedded",
    "raw_manifest_embedded",
    "signing_material_embedded",
    "raw_security_configuration_embedded",
    "device_state_embedded",
    "credential_material_embedded",
    "package_path_embedded",
    "package_format_confirmed",
    "manifest_truth_confirmed",
    "signing_identity_confirmed",
    "application_declaration_confirmed",
    "runtime_declaration_confirmed",
    "runtime_support_confirmed",
    "storage_value_confirmed",
    "deeplink_reachability_confirmed",
    "tls_enforcement_confirmed",
    "authentication_safety_confirmed",
    "vulnerability_confirmed",
    "hypothesis_confirmed",
    "ground_truth_case_bound",
    "negative_control_observed",
    "manifest_component_coverage_measured",
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
    "package_access_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "worker_job_materialization_authorized",
    "worker_job_materialized",
    "domain_worker_profile_bound",
    "device_bound_runtime_profile_applied",
    "network_access_authorized",
    "dns_access_authorized",
    "emulator_or_device_access_authorized",
    "package_installation_authorized",
    "application_launch_authorized",
    "instrumentation_authorized",
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "storage_read_authorized",
    "tls_invocation_authorized",
    "authentication_invocation_authorized",
    "credential_access_authorized",
    "artifact_mutation_authorized",
    "package_mutation_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class MobilePackageAnalysisReanalysisValidation(_FrozenStrictModel):
    """Non-authorizing wire projection; bare model parsing is not verification."""

    api_version: Literal["pajin.dev/mobile-package-analysis-reanalysis-validation/v1alpha1"] = (
        Field(
            default=MOBILE_PACKAGE_ANALYSIS_REANALYSIS_VALIDATION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["MobilePackageAnalysisReanalysisValidation"] = (
        "MobilePackageAnalysisReanalysisValidation"
    )
    validation_id: str = Field(default="", alias="validationId", max_length=118)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    source_admission: MobilePackageAnalysisKnowledgeAdmission = Field(alias="sourceAdmission")
    source_execution: MobilePackageAnalysisReanalysisExecution = Field(alias="sourceExecution")
    reanalysis_execution: MobilePackageAnalysisReanalysisExecution = Field(
        alias="reanalysisExecution"
    )
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    comparison: MobilePackageAnalysisReanalysisComparison
    result_body_digest_matched: bool = Field(alias="resultBodyDigestMatched")
    result_bytes_matched: bool = Field(alias="resultBytesMatched")
    review_signal_matched: bool = Field(alias="reviewSignalMatched")
    state: _ReanalysisState
    sealed_source_reverified: Literal[True] = Field(default=True, alias="sealedSourceReverified")
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
    exact_selected_surface_verified: Literal[True] = Field(
        default=True,
        alias="exactSelectedSurfaceVerified",
    )
    exact_package_surface_verified: Literal[True] = Field(
        default=True,
        alias="exactPackageSurfaceVerified",
    )
    exact_platform_verified: Literal[True] = Field(default=True, alias="exactPlatformVerified")
    exact_package_digest_verified: Literal[True] = Field(
        default=True,
        alias="exactPackageDigestVerified",
    )
    exact_custody_verified: Literal[True] = Field(default=True, alias="exactCustodyVerified")
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
    exact_archive_limits_verified: Literal[True] = Field(
        default=True,
        alias="exactArchiveLimitsVerified",
    )
    exact_archive_observations_verified: Literal[True] = Field(
        default=True,
        alias="exactArchiveObservationsVerified",
    )
    offline_static_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="offlineStaticSandboxVerified",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    domain_validation_strategy_satisfied: Literal[True] = Field(
        default=True,
        alias="domainValidationStrategySatisfied",
    )
    deployment_context_reverification_required: Literal[True] = Field(
        default=True,
        alias="deploymentContextReverificationRequired",
    )
    raw_package_embedded: Literal[False] = Field(default=False, alias="rawPackageEmbedded")
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    raw_manifest_embedded: Literal[False] = Field(default=False, alias="rawManifestEmbedded")
    signing_material_embedded: Literal[False] = Field(
        default=False,
        alias="signingMaterialEmbedded",
    )
    raw_security_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawSecurityConfigurationEmbedded",
    )
    device_state_embedded: Literal[False] = Field(default=False, alias="deviceStateEmbedded")
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    package_path_embedded: Literal[False] = Field(default=False, alias="packagePathEmbedded")
    package_format_confirmed: Literal[False] = Field(default=False, alias="packageFormatConfirmed")
    manifest_truth_confirmed: Literal[False] = Field(default=False, alias="manifestTruthConfirmed")
    signing_identity_confirmed: Literal[False] = Field(
        default=False,
        alias="signingIdentityConfirmed",
    )
    application_declaration_confirmed: Literal[False] = Field(
        default=False,
        alias="applicationDeclarationConfirmed",
    )
    runtime_declaration_confirmed: Literal[False] = Field(
        default=False,
        alias="runtimeDeclarationConfirmed",
    )
    runtime_support_confirmed: Literal[False] = Field(
        default=False,
        alias="runtimeSupportConfirmed",
    )
    storage_value_confirmed: Literal[False] = Field(default=False, alias="storageValueConfirmed")
    deeplink_reachability_confirmed: Literal[False] = Field(
        default=False,
        alias="deeplinkReachabilityConfirmed",
    )
    tls_enforcement_confirmed: Literal[False] = Field(
        default=False,
        alias="tlsEnforcementConfirmed",
    )
    authentication_safety_confirmed: Literal[False] = Field(
        default=False,
        alias="authenticationSafetyConfirmed",
    )
    vulnerability_confirmed: Literal[False] = Field(default=False, alias="vulnerabilityConfirmed")
    hypothesis_confirmed: Literal[False] = Field(default=False, alias="hypothesisConfirmed")
    ground_truth_case_bound: Literal[False] = Field(default=False, alias="groundTruthCaseBound")
    negative_control_observed: Literal[False] = Field(
        default=False,
        alias="negativeControlObserved",
    )
    manifest_component_coverage_measured: Literal[False] = Field(
        default=False,
        alias="manifestComponentCoverageMeasured",
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
    package_access_authorized: Literal[False] = Field(
        default=False,
        alias="packageAccessAuthorized",
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
    worker_job_materialization_authorized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAuthorized",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    emulator_or_device_access_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorOrDeviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(default=False, alias="storageReadAuthorized")
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_REANALYSIS_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("MOBILE-001D verified markers must be boolean true")
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
            raise ValueError("MOBILE-001D comparison markers must be booleans")
        return value

    @field_validator(*_REANALYSIS_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("MOBILE-001D re-analysis authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_reanalysis_validation(self) -> Self:
        _require_mobile_domain_plan(self.domain_benchmark_plan)
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
        comparison = _comparison(source=source_result, reanalysis=reanalysis_result)
        if (
            self.result_body_digest_matched is not body_matched
            or self.result_bytes_matched is not bytes_matched
            or self.review_signal_matched is not signal_matched
            or self.comparison is not comparison
            or self.state != _reanalysis_state(comparison)
        ):
            raise ValueError("MOBILE-001D neutral re-analysis comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.mobile-package-analysis-reanalysis-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"mobile-package-analysis-reanalysis_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("MOBILE-001D re-analysis validation digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("MOBILE-001D re-analysis validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


_FIXTURE_TRUE_FIELDS = (
    "private_ground_truth_requirements_registered",
    "seeded_packages_required",
    "disposable_static_sandbox_required",
    "network_and_dns_disabled_required",
    "non_root_runtime_required",
    "read_only_noexec_package_mount_required",
    "archive_limits_required",
    "archive_rejection_rules_required",
    "positive_controls_registered",
    "negative_controls_registered",
    "evidence_completeness_required",
    "deterministic_package_reanalysis_required",
    "domain_worker_profile_binding_deferred",
)
_FIXTURE_FALSE_FIELDS = (
    "target_profile_selected",
    "target_factory_authority",
    "package_fixture_materialized",
    "sandbox_provisioned",
    "private_ground_truth_verified",
    "provider_execution_authorized",
    "fixture_execution_authorized",
    "cleanup_observed",
    "reanalysis_evidence_bound",
    "benchmark_measurement_observed",
    "manifest_component_coverage_measured",
    "evidence_completeness_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "package_format_confirmed",
    "manifest_truth_confirmed",
    "signing_identity_confirmed",
    "application_declaration_confirmed",
    "runtime_declaration_confirmed",
    "runtime_support_confirmed",
    "storage_value_confirmed",
    "deeplink_reachability_confirmed",
    "tls_enforcement_confirmed",
    "authentication_safety_confirmed",
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
    "package_access_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "worker_job_materialization_authorized",
    "worker_job_materialized",
    "domain_worker_profile_bound",
    "device_bound_runtime_profile_applied",
    "network_access_authorized",
    "dns_access_authorized",
    "emulator_or_device_access_authorized",
    "package_installation_authorized",
    "application_launch_authorized",
    "instrumentation_authorized",
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "storage_read_authorized",
    "tls_invocation_authorized",
    "authentication_invocation_authorized",
    "credential_access_authorized",
    "artifact_mutation_authorized",
    "package_mutation_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)

_FIXTURE_ZERO_FIELDS = (
    "package_write_operations",
    "network_requests",
    "dns_requests",
    "emulator_sessions",
    "device_sessions",
    "package_installations",
    "application_launches",
    "instrumentation_sessions",
    "dynamic_target_executions",
    "debugger_attaches",
    "storage_reads",
    "tls_connections",
    "authentication_invocations",
    "credential_reads",
    "host_filesystem_reads",
)


class MobilePackageAnalysisBenchmarkFixtureCase(_FrozenStrictModel):
    """One package-lineage expected outcome without embedded package content."""

    fixture_id: _Identifier = Field(alias="fixtureId")
    ground_truth_class: MobileBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    selected_surface_class: MobileSurfaceClass = Field(alias="selectedSurfaceClass")
    platform: MobilePlatform
    package_surface_class: MobileSurfaceClass = Field(alias="packageSurfaceClass")
    operation: MobilePackageAnalysisOperation
    expected_outcome: MobileBenchmarkExpectedOutcome = Field(alias="expectedOutcome")
    expected_review_signal: MobilePackageAnalysisReviewSignal | None = Field(
        default=None,
        alias="expectedReviewSignal",
    )
    required_evidence: tuple[_EvidenceRequirement, ...] = Field(
        min_length=4,
        max_length=4,
        alias="requiredEvidence",
    )
    fixture_materialization: Literal["seeded-immutable-mobile-package"] = Field(
        default="seeded-immutable-mobile-package",
        alias="fixtureMaterialization",
    )
    isolation_requirement: Literal[
        "disposable-network-dns-disabled-non-root-static-sandbox-per-case"
    ] = Field(
        default="disposable-network-dns-disabled-non-root-static-sandbox-per-case",
        alias="isolationRequirement",
    )
    package_mount_requirement: Literal["read-only-noexec-exact-package-digest"] = Field(
        default="read-only-noexec-exact-package-digest",
        alias="packageMountRequirement",
    )
    archive_requirement: Literal["bounded-reject-traversal-symlink-duplicate"] = Field(
        default="bounded-reject-traversal-symlink-duplicate",
        alias="archiveRequirement",
    )
    raw_package_content_embedded: Literal[False] = Field(
        default=False,
        alias="rawPackageContentEmbedded",
    )
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    raw_manifest_embedded: Literal[False] = Field(default=False, alias="rawManifestEmbedded")
    signing_material_embedded: Literal[False] = Field(
        default=False,
        alias="signingMaterialEmbedded",
    )
    raw_security_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawSecurityConfigurationEmbedded",
    )
    device_state_embedded: Literal[False] = Field(default=False, alias="deviceStateEmbedded")
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    package_path_embedded: Literal[False] = Field(default=False, alias="packagePathEmbedded")
    package_write_operations: Literal[0] = Field(default=0, alias="packageWriteOperations")
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_requests: Literal[0] = Field(default=0, alias="dnsRequests")
    emulator_sessions: Literal[0] = Field(default=0, alias="emulatorSessions")
    device_sessions: Literal[0] = Field(default=0, alias="deviceSessions")
    package_installations: Literal[0] = Field(default=0, alias="packageInstallations")
    application_launches: Literal[0] = Field(default=0, alias="applicationLaunches")
    instrumentation_sessions: Literal[0] = Field(default=0, alias="instrumentationSessions")
    dynamic_target_executions: Literal[0] = Field(
        default=0,
        alias="dynamicTargetExecutions",
    )
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")
    storage_reads: Literal[0] = Field(default=0, alias="storageReads")
    tls_connections: Literal[0] = Field(default=0, alias="tlsConnections")
    authentication_invocations: Literal[0] = Field(
        default=0,
        alias="authenticationInvocations",
    )
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")

    @field_validator(
        "raw_package_content_embedded",
        "raw_parser_output_embedded",
        "raw_manifest_embedded",
        "signing_material_embedded",
        "raw_security_configuration_embedded",
        "device_state_embedded",
        "credential_material_embedded",
        "package_path_embedded",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("MOBILE-001D fixture cases cannot embed package or secret content")
        return value

    @field_validator(*_FIXTURE_ZERO_FIELDS, mode="before")
    @classmethod
    def require_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("MOBILE-001D fixture operation counters must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_fixture_case(self) -> Self:
        expected_evidence: tuple[_EvidenceRequirement, ...] = (
            "execution-attestation",
            "non-root-offline-runtime-receipt",
            "result-receipt",
            "cleanup-receipt",
        )
        expected_operation = _surface_operation(self.selected_surface_class)
        expected_signal = _surface_review_signal(self.selected_surface_class)
        expected_package_class = (
            MobileSurfaceClass.APK
            if self.platform is MobilePlatform.ANDROID
            else MobileSurfaceClass.IPA
        )
        valid_lineage = (
            self.package_surface_class is expected_package_class
            and not (
                self.selected_surface_class is MobileSurfaceClass.APK
                and self.platform is not MobilePlatform.ANDROID
            )
            and not (
                self.selected_surface_class is MobileSurfaceClass.IPA
                and self.platform is not MobilePlatform.IOS
            )
        )
        if self.ground_truth_class is MobileBenchmarkGroundTruthClass.KNOWN_POSITIVE:
            valid_outcome = (
                self.expected_outcome is MobileBenchmarkExpectedOutcome.REVIEW_SIGNAL
                and self.expected_review_signal is expected_signal
            )
        else:
            valid_outcome = (
                self.expected_outcome is MobileBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
                and self.expected_review_signal is None
            )
        if (
            not valid_lineage
            or not valid_outcome
            or self.operation is not expected_operation
            or self.required_evidence != expected_evidence
        ):
            raise ValueError("MOBILE-001D fixture Ground Truth shape differs")
        return self


class MobilePackageAnalysisBenchmarkFixtureProfile(_FrozenStrictModel):
    """Registered package-lineage requirements, never a benchmark measurement."""

    api_version: Literal["pajin.dev/mobile-package-analysis-benchmark-fixture-profile/v1alpha1"] = (
        Field(
            default=MOBILE_PACKAGE_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["MobilePackageAnalysisBenchmarkFixtureProfile"] = (
        "MobilePackageAnalysisBenchmarkFixtureProfile"
    )
    profile_id: str = Field(default="", alias="profileId", max_length=118)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    covered_surface_classes: tuple[MobileSurfaceClass, ...] = Field(
        min_length=8,
        max_length=8,
        alias="coveredSurfaceClasses",
    )
    covered_platforms: tuple[MobilePlatform, ...] = Field(
        min_length=2,
        max_length=2,
        alias="coveredPlatforms",
    )
    cases: tuple[MobilePackageAnalysisBenchmarkFixtureCase, ...] = Field(
        min_length=28,
        max_length=28,
    )
    state: Literal["registered-seeded-ground-truth-not-measured"] = (
        "registered-seeded-ground-truth-not-measured"
    )
    private_ground_truth_requirements_registered: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthRequirementsRegistered",
    )
    seeded_packages_required: Literal[True] = Field(default=True, alias="seededPackagesRequired")
    disposable_static_sandbox_required: Literal[True] = Field(
        default=True,
        alias="disposableStaticSandboxRequired",
    )
    network_and_dns_disabled_required: Literal[True] = Field(
        default=True,
        alias="networkAndDnsDisabledRequired",
    )
    non_root_runtime_required: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeRequired",
    )
    read_only_noexec_package_mount_required: Literal[True] = Field(
        default=True,
        alias="readOnlyNoexecPackageMountRequired",
    )
    archive_limits_required: Literal[True] = Field(default=True, alias="archiveLimitsRequired")
    archive_rejection_rules_required: Literal[True] = Field(
        default=True,
        alias="archiveRejectionRulesRequired",
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
    deterministic_package_reanalysis_required: Literal[True] = Field(
        default=True,
        alias="deterministicPackageReanalysisRequired",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    target_profile_selected: Literal[False] = Field(default=False, alias="targetProfileSelected")
    target_factory_authority: Literal[False] = Field(default=False, alias="targetFactoryAuthority")
    package_fixture_materialized: Literal[False] = Field(
        default=False,
        alias="packageFixtureMaterialized",
    )
    sandbox_provisioned: Literal[False] = Field(default=False, alias="sandboxProvisioned")
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
    manifest_component_coverage_measured: Literal[False] = Field(
        default=False,
        alias="manifestComponentCoverageMeasured",
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
    package_format_confirmed: Literal[False] = Field(default=False, alias="packageFormatConfirmed")
    manifest_truth_confirmed: Literal[False] = Field(default=False, alias="manifestTruthConfirmed")
    signing_identity_confirmed: Literal[False] = Field(
        default=False,
        alias="signingIdentityConfirmed",
    )
    application_declaration_confirmed: Literal[False] = Field(
        default=False,
        alias="applicationDeclarationConfirmed",
    )
    runtime_declaration_confirmed: Literal[False] = Field(
        default=False,
        alias="runtimeDeclarationConfirmed",
    )
    runtime_support_confirmed: Literal[False] = Field(
        default=False,
        alias="runtimeSupportConfirmed",
    )
    storage_value_confirmed: Literal[False] = Field(default=False, alias="storageValueConfirmed")
    deeplink_reachability_confirmed: Literal[False] = Field(
        default=False,
        alias="deeplinkReachabilityConfirmed",
    )
    tls_enforcement_confirmed: Literal[False] = Field(
        default=False,
        alias="tlsEnforcementConfirmed",
    )
    authentication_safety_confirmed: Literal[False] = Field(
        default=False,
        alias="authenticationSafetyConfirmed",
    )
    vulnerability_confirmed: Literal[False] = Field(default=False, alias="vulnerabilityConfirmed")
    hypothesis_confirmed: Literal[False] = Field(default=False, alias="hypothesisConfirmed")
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
    package_access_authorized: Literal[False] = Field(
        default=False,
        alias="packageAccessAuthorized",
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
    worker_job_materialization_authorized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAuthorized",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    emulator_or_device_access_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorOrDeviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(default=False, alias="storageReadAuthorized")
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_FIXTURE_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("MOBILE-001D fixture requirement markers must be boolean true")
        return value

    @field_validator(*_FIXTURE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("MOBILE-001D fixture authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_fixture_profile(self) -> Self:
        _require_mobile_domain_plan(self.domain_benchmark_plan)
        if (
            self.covered_surface_classes != tuple(MobileSurfaceClass)
            or self.covered_platforms != tuple(MobilePlatform)
            or self.cases != _registered_fixture_cases()
        ):
            raise ValueError("MOBILE-001D seeded fixture profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.mobile-package-analysis-benchmark-fixture-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"mobile-package-analysis-fixtures_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("MOBILE-001D fixture profile digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("MOBILE-001D fixture profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


class MobilePackageAnalysisReanalysisBenchmarkGate:
    """Reopen sealed C evidence without reading a package or invoking a sandbox."""

    def __init__(
        self,
        *,
        trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
    ) -> None:
        if not isinstance(trust_anchor, MobilePackageAnalysisExecutionTrustAnchor):
            raise TypeError("MOBILE-001D requires a deployment Mobile trust anchor")
        _require_known_instance_fields(trust_anchor, label="MOBILE-001D trust anchor")
        self._trust_anchor = MobilePackageAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )

    def bind_reanalysis(
        self,
        source_inputs: MobilePackageAnalysisObservationSourceInputs,
        source_admission: MobilePackageAnalysisKnowledgeAdmission,
        reanalysis_inputs: MobilePackageAnalysisObservationSourceInputs,
        *,
        source_graph_store: SQLiteGraphStore,
        reanalysis_graph_store: SQLiteGraphStore,
    ) -> MobilePackageAnalysisReanalysisValidation:
        """Return one neutral comparison of separately authorized sealed executions."""

        try:
            _require_known_instance_fields(source_inputs, label="MOBILE-001D source inputs")
            _require_known_instance_fields(source_admission, label="MOBILE-001D source admission")
            _require_known_instance_fields(
                reanalysis_inputs, label="MOBILE-001D re-analysis inputs"
            )
            canonical_admission = MobilePackageAnalysisKnowledgeAdmission.model_validate(
                source_admission.model_dump(mode="json", by_alias=True)
            )
            source = load_verified_mobile_package_analysis_observation_source(
                source_inputs,
                graph_store=source_graph_store,
                trust_anchor=self._trust_anchor,
            )
            reanalysis = load_verified_mobile_package_analysis_observation_source(
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
            return MobilePackageAnalysisReanalysisValidation(
                sourceAdmission=canonical_admission,
                sourceExecution=source_projection,
                reanalysisExecution=reanalysis_projection,
                domainBenchmarkPlan=_mobile_domain_benchmark_plan_ref(),
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
        except MobilePackageAnalysisReanalysisBenchmarkError:
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
            raise MobilePackageAnalysisReanalysisBenchmarkError(
                "MOBILE-001D deterministic package re-analysis failed closed"
            ) from exc


def bind_mobile_package_analysis_reanalysis(
    source_inputs: MobilePackageAnalysisObservationSourceInputs,
    source_admission: MobilePackageAnalysisKnowledgeAdmission,
    reanalysis_inputs: MobilePackageAnalysisObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    reanalysis_graph_store: SQLiteGraphStore,
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
) -> MobilePackageAnalysisReanalysisValidation:
    """Functional entry point for the deployment-configured MOBILE-001D gate."""

    return MobilePackageAnalysisReanalysisBenchmarkGate(trust_anchor=trust_anchor).bind_reanalysis(
        source_inputs,
        source_admission,
        reanalysis_inputs,
        source_graph_store=source_graph_store,
        reanalysis_graph_store=reanalysis_graph_store,
    )


def load_verified_mobile_package_analysis_reanalysis_validation(
    validation: object,
    source_inputs: MobilePackageAnalysisObservationSourceInputs,
    reanalysis_inputs: MobilePackageAnalysisObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    reanalysis_graph_store: SQLiteGraphStore,
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
) -> MobilePackageAnalysisReanalysisValidation:
    """Reverify one wire projection against deployment evidence and Graph authority."""

    try:
        _require_known_instance_fields(validation, label="MOBILE-001D validation")
        if isinstance(validation, MobilePackageAnalysisReanalysisValidation):
            payload: object = validation.model_dump(mode="json", by_alias=True)
        else:
            payload = validation
        canonical = MobilePackageAnalysisReanalysisValidation.model_validate(payload)
        expected = bind_mobile_package_analysis_reanalysis(
            source_inputs,
            canonical.source_admission,
            reanalysis_inputs,
            source_graph_store=source_graph_store,
            reanalysis_graph_store=reanalysis_graph_store,
            trust_anchor=trust_anchor,
        )
        if canonical != expected:
            raise ValueError(
                "MOBILE-001D wire projection differs from deployment evidence and Graph authority"
            )
        return expected
    except MobilePackageAnalysisReanalysisBenchmarkError:
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
        raise MobilePackageAnalysisReanalysisBenchmarkError(
            "MOBILE-001D wire re-verification failed closed"
        ) from exc


def registered_mobile_package_analysis_benchmark_fixture_profile() -> (
    MobilePackageAnalysisBenchmarkFixtureProfile
):
    """Return exact seeded-package requirements without materializing or measuring them."""

    try:
        return MobilePackageAnalysisBenchmarkFixtureProfile(
            domainBenchmarkPlan=_mobile_domain_benchmark_plan_ref(),
            coveredSurfaceClasses=tuple(MobileSurfaceClass),
            coveredPlatforms=tuple(MobilePlatform),
            cases=_registered_fixture_cases(),
        )
    except (RuntimeError, ValidationError, ValueError) as exc:
        raise MobilePackageAnalysisReanalysisBenchmarkError(
            "MOBILE-001D seeded fixture registration failed closed"
        ) from exc


def _execution_projection(
    source: VerifiedMobilePackageAnalysisObservationSource,
) -> MobilePackageAnalysisReanalysisExecution:
    return MobilePackageAnalysisReanalysisExecution(
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
    admission: MobilePackageAnalysisKnowledgeAdmission,
    graph_store: SQLiteGraphStore,
) -> None:
    observation = admission.candidate.observation_proposal
    stored_observation = graph_store.event_log.event_for_attempt(
        observation.proposal_id,
        observation.digest(),
    )
    if stored_observation != admission.observation_graph_event:
        raise ValueError("MOBILE-001D source Observation admission is not stored exactly")
    hypothesis = admission.candidate.hypothesis_proposal
    if hypothesis is None:
        if admission.hypothesis_graph_event is not None:
            raise ValueError("MOBILE-001D source Hypothesis admission differs")
        return
    stored_hypothesis = graph_store.event_log.event_for_attempt(
        hypothesis.proposal_id,
        hypothesis.digest(),
    )
    if stored_hypothesis != admission.hypothesis_graph_event:
        raise ValueError("MOBILE-001D source Hypothesis admission is not stored exactly")


def _require_admission_projection(
    admission: MobilePackageAnalysisKnowledgeAdmission,
    execution: MobilePackageAnalysisReanalysisExecution,
) -> None:
    candidate = admission.candidate
    receipt = execution.result_receipt
    if (
        candidate.preparation != execution.preparation
        or candidate.surface != execution.preparation.surface.reference()
        or candidate.package_surface != execution.preparation.package_surface.reference()
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
        or candidate.platform is not receipt.platform
        or candidate.parser is not receipt.parser
        or candidate.review_signal is not receipt.review_signal
    ):
        raise ValueError("MOBILE-001D source admission differs from its sealed execution")


def _require_equivalent_reanalysis_semantics(
    source: MobilePackageAnalysisReanalysisExecution,
    reanalysis: MobilePackageAnalysisReanalysisExecution,
) -> None:
    source_preparation = source.preparation
    reanalysis_preparation = reanalysis.preparation
    source_prepared = source_preparation.prepared_action
    reanalysis_prepared = reanalysis_preparation.prepared_action
    source_request = source_prepared.request
    reanalysis_request = reanalysis_prepared.request
    source_runtime = source.execution_bundle.statement.sandbox_runtime
    reanalysis_runtime = reanalysis.execution_bundle.statement.sandbox_runtime
    source_result = source.result_receipt
    reanalysis_result = reanalysis.result_receipt
    if (
        source.trust_anchor != reanalysis.trust_anchor
        or source_preparation.binding != reanalysis_preparation.binding
        or source_preparation.surface != reanalysis_preparation.surface
        or source_preparation.package_surface != reanalysis_preparation.package_surface
        or source_preparation.operation is not reanalysis_preparation.operation
        or source_preparation.package_custody != reanalysis_preparation.package_custody
        or source_preparation.sandbox != reanalysis_preparation.sandbox
        or source_preparation.analysis_request != reanalysis_preparation.analysis_request
        or source_preparation.campaign_scope != reanalysis_preparation.campaign_scope
        or source_preparation.matched_surface_allow_rule
        != reanalysis_preparation.matched_surface_allow_rule
        or source_preparation.matched_package_allow_rule
        != reanalysis_preparation.matched_package_allow_rule
        or source_preparation.release != reanalysis_preparation.release
        or source_prepared.activation_set_digest != reanalysis_prepared.activation_set_digest
        or source_prepared.capability != reanalysis_prepared.capability
        or source_prepared.normalized_parameters_digest
        != reanalysis_prepared.normalized_parameters_digest
        or source_request.model_dump(mode="json", exclude={"request_id"})
        != reanalysis_request.model_dump(mode="json", exclude={"request_id"})
        or source_result.surface != reanalysis_result.surface
        or source_result.package_surface != reanalysis_result.package_surface
        or source_result.platform is not reanalysis_result.platform
        or source_result.parser is not reanalysis_result.parser
        or source_result.artifact_sha256 != reanalysis_result.artifact_sha256
        or source_result.output_schema != reanalysis_result.output_schema
        or source_runtime.surface != reanalysis_runtime.surface
        or source_runtime.package_surface != reanalysis_runtime.package_surface
        or source_runtime.operation is not reanalysis_runtime.operation
        or source_runtime.platform is not reanalysis_runtime.platform
        or source_runtime.parser is not reanalysis_runtime.parser
        or source_runtime.parser_executable_sha256 != reanalysis_runtime.parser_executable_sha256
        or source_runtime.sandbox_image_sha256 != reanalysis_runtime.sandbox_image_sha256
        or source_runtime.artifact_sha256 != reanalysis_runtime.artifact_sha256
        or source_runtime.artifact_bytes != reanalysis_runtime.artifact_bytes
        or source_runtime.custody_binding_id != reanalysis_runtime.custody_binding_id
        or source_runtime.custody_binding_digest != reanalysis_runtime.custody_binding_digest
        or source_runtime.custody_authority_id != reanalysis_runtime.custody_authority_id
        or source_runtime.custody_object_id != reanalysis_runtime.custody_object_id
        or source_runtime.authorization_id != reanalysis_runtime.authorization_id
        or source_runtime.authorization_digest != reanalysis_runtime.authorization_digest
        or _resource_and_archive_limits(source_runtime)
        != _resource_and_archive_limits(reanalysis_runtime)
        or _archive_observations(source_runtime) != _archive_observations(reanalysis_runtime)
    ):
        raise ValueError("MOBILE-001D re-analysis differs from source Mobile package semantics")
    if (
        source_result.result_body_sha256 == reanalysis_result.result_body_sha256
        and source_result.result_bytes != reanalysis_result.result_bytes
    ):
        raise ValueError("MOBILE-001D equal result digest has inconsistent result byte count")


def _resource_and_archive_limits(
    runtime: MobilePackageSandboxRuntimeReceipt,
) -> tuple[int, ...]:
    return (
        runtime.max_artifact_bytes,
        runtime.max_output_bytes,
        runtime.max_runtime_seconds,
        runtime.max_memory_mib,
        runtime.max_process_count,
        runtime.max_archive_entries,
        runtime.max_total_uncompressed_bytes,
        runtime.max_single_uncompressed_bytes,
        runtime.max_archive_path_bytes,
        runtime.max_archive_nesting_depth,
        runtime.max_compression_ratio,
    )


def _archive_observations(runtime: MobilePackageSandboxRuntimeReceipt) -> tuple[int, ...]:
    return (
        runtime.observed_archive_entries,
        runtime.observed_total_uncompressed_bytes,
        runtime.observed_largest_uncompressed_bytes,
        runtime.observed_max_archive_path_bytes,
        runtime.observed_archive_nesting_depth,
        runtime.observed_max_compression_ratio,
    )


def _require_distinct_reanalysis_authority(
    source: MobilePackageAnalysisReanalysisExecution,
    reanalysis: MobilePackageAnalysisReanalysisExecution,
) -> None:
    left = _execution_identity_coordinates(source)
    right = _execution_identity_coordinates(reanalysis)
    reused = tuple(name for name in left if left[name] == right[name])
    if reused:
        raise ValueError(
            "MOBILE-001D re-analysis reused source execution authority: " + ", ".join(reused)
        )
    if (
        reanalysis.execution_bundle.statement.started_at
        <= source.execution_bundle.statement.finished_at
    ):
        raise ValueError("MOBILE-001D re-analysis is not causally after the source")


def _execution_identity_coordinates(
    execution: MobilePackageAnalysisReanalysisExecution,
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
    source: MobilePackageAnalysisResultReceipt,
    reanalysis: MobilePackageAnalysisResultReceipt,
) -> MobilePackageAnalysisReanalysisComparison:
    body_matched = source.result_body_sha256 == reanalysis.result_body_sha256
    bytes_matched = source.result_bytes == reanalysis.result_bytes
    signal_matched = source.review_signal is reanalysis.review_signal
    if body_matched and not bytes_matched:
        raise ValueError("MOBILE-001D equal result digest has inconsistent result byte count")
    if body_matched and bytes_matched and signal_matched:
        return MobilePackageAnalysisReanalysisComparison.MATCHED
    if source.review_signal is None and reanalysis.review_signal is None:
        return MobilePackageAnalysisReanalysisComparison.UNRESOLVED
    return MobilePackageAnalysisReanalysisComparison.CHANGED


def _reanalysis_state(
    comparison: MobilePackageAnalysisReanalysisComparison,
) -> _ReanalysisState:
    states: dict[MobilePackageAnalysisReanalysisComparison, _ReanalysisState] = {
        MobilePackageAnalysisReanalysisComparison.MATCHED: (
            "deterministic-package-reanalysis-match"
        ),
        MobilePackageAnalysisReanalysisComparison.CHANGED: (
            "deterministic-package-reanalysis-changed"
        ),
        MobilePackageAnalysisReanalysisComparison.UNRESOLVED: (
            "deterministic-package-reanalysis-unresolved"
        ),
    }
    return states[comparison]


def _surface_operation(surface_class: MobileSurfaceClass) -> MobilePackageAnalysisOperation:
    return {
        MobileSurfaceClass.APK: MobilePackageAnalysisOperation.APK_PACKAGE_STRUCTURE,
        MobileSurfaceClass.IPA: MobilePackageAnalysisOperation.IPA_PACKAGE_STRUCTURE,
        MobileSurfaceClass.APPLICATION: MobilePackageAnalysisOperation.APPLICATION_DECLARATION,
        MobileSurfaceClass.RUNTIME: MobilePackageAnalysisOperation.RUNTIME_DECLARATION,
        MobileSurfaceClass.STORAGE: MobilePackageAnalysisOperation.STORAGE_DECLARATION,
        MobileSurfaceClass.DEEPLINK: MobilePackageAnalysisOperation.DEEP_LINK_DECLARATION,
        MobileSurfaceClass.TLS: MobilePackageAnalysisOperation.TLS_POLICY_DECLARATION,
        MobileSurfaceClass.AUTH: MobilePackageAnalysisOperation.AUTHENTICATION_FLOW_DECLARATION,
    }[surface_class]


def _surface_review_signal(surface_class: MobileSurfaceClass) -> MobilePackageAnalysisReviewSignal:
    return {
        MobileSurfaceClass.APK: MobilePackageAnalysisReviewSignal.APK_PACKAGE_STRUCTURE_REVIEW,
        MobileSurfaceClass.IPA: MobilePackageAnalysisReviewSignal.IPA_PACKAGE_STRUCTURE_REVIEW,
        MobileSurfaceClass.APPLICATION: (
            MobilePackageAnalysisReviewSignal.APPLICATION_DECLARATION_REVIEW
        ),
        MobileSurfaceClass.RUNTIME: MobilePackageAnalysisReviewSignal.RUNTIME_DECLARATION_REVIEW,
        MobileSurfaceClass.STORAGE: MobilePackageAnalysisReviewSignal.STORAGE_DECLARATION_REVIEW,
        MobileSurfaceClass.DEEPLINK: MobilePackageAnalysisReviewSignal.DEEP_LINK_DECLARATION_REVIEW,
        MobileSurfaceClass.TLS: MobilePackageAnalysisReviewSignal.TLS_POLICY_DECLARATION_REVIEW,
        MobileSurfaceClass.AUTH: (
            MobilePackageAnalysisReviewSignal.AUTHENTICATION_FLOW_DECLARATION_REVIEW
        ),
    }[surface_class]


def _valid_surface_platform_lineages() -> tuple[
    tuple[MobileSurfaceClass, MobilePlatform, MobileSurfaceClass], ...
]:
    lineages: list[tuple[MobileSurfaceClass, MobilePlatform, MobileSurfaceClass]] = [
        (MobileSurfaceClass.APK, MobilePlatform.ANDROID, MobileSurfaceClass.APK),
        (MobileSurfaceClass.IPA, MobilePlatform.IOS, MobileSurfaceClass.IPA),
    ]
    for surface_class in (
        MobileSurfaceClass.APPLICATION,
        MobileSurfaceClass.RUNTIME,
        MobileSurfaceClass.STORAGE,
        MobileSurfaceClass.DEEPLINK,
        MobileSurfaceClass.TLS,
        MobileSurfaceClass.AUTH,
    ):
        lineages.extend(
            (
                (surface_class, MobilePlatform.ANDROID, MobileSurfaceClass.APK),
                (surface_class, MobilePlatform.IOS, MobileSurfaceClass.IPA),
            )
        )
    return tuple(lineages)


def _fixture_case(
    *,
    fixture_id: str,
    ground_truth_class: MobileBenchmarkGroundTruthClass,
    selected_surface_class: MobileSurfaceClass,
    platform: MobilePlatform,
    package_surface_class: MobileSurfaceClass,
    expected_outcome: MobileBenchmarkExpectedOutcome,
    expected_review_signal: MobilePackageAnalysisReviewSignal | None = None,
) -> MobilePackageAnalysisBenchmarkFixtureCase:
    return MobilePackageAnalysisBenchmarkFixtureCase(
        fixtureId=fixture_id,
        groundTruthClass=ground_truth_class,
        selectedSurfaceClass=selected_surface_class,
        platform=platform,
        packageSurfaceClass=package_surface_class,
        operation=_surface_operation(selected_surface_class),
        expectedOutcome=expected_outcome,
        expectedReviewSignal=expected_review_signal,
        requiredEvidence=(
            "execution-attestation",
            "non-root-offline-runtime-receipt",
            "result-receipt",
            "cleanup-receipt",
        ),
    )


def _registered_fixture_cases() -> tuple[MobilePackageAnalysisBenchmarkFixtureCase, ...]:
    cases: list[MobilePackageAnalysisBenchmarkFixtureCase] = []
    for (
        selected_surface_class,
        platform,
        package_surface_class,
    ) in _valid_surface_platform_lineages():
        base = f"mobile-fixture:{selected_surface_class.value}-{platform.value}"
        cases.extend(
            (
                _fixture_case(
                    fixture_id=f"{base}-known-positive",
                    ground_truth_class=MobileBenchmarkGroundTruthClass.KNOWN_POSITIVE,
                    selected_surface_class=selected_surface_class,
                    platform=platform,
                    package_surface_class=package_surface_class,
                    expected_outcome=MobileBenchmarkExpectedOutcome.REVIEW_SIGNAL,
                    expected_review_signal=_surface_review_signal(selected_surface_class),
                ),
                _fixture_case(
                    fixture_id=f"{base}-negative-control",
                    ground_truth_class=MobileBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
                    selected_surface_class=selected_surface_class,
                    platform=platform,
                    package_surface_class=package_surface_class,
                    expected_outcome=MobileBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL,
                ),
            )
        )
    return tuple(sorted(cases, key=lambda item: item.fixture_id))


def _require_mobile_domain_plan(reference: DomainBenchmarkPlanRef) -> None:
    try:
        plan = resolve_registered_domain_benchmark_plan(reference)
    except Exception as exc:
        raise ValueError("MOBILE-001D Domain benchmark plan is not registered exactly") from exc
    if (
        plan.domain_classification.domain is not SecurityDomain.MOBILE
        or plan.validation_strategy is not DomainValidationStrategy.DETERMINISTIC_PACKAGE_REANALYSIS
    ):
        raise ValueError("MOBILE-001D Domain benchmark strategy differs")


def _mobile_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.MOBILE:
            return plan.reference()
    raise MobilePackageAnalysisReanalysisBenchmarkError(
        "DOMAIN-006 Mobile benchmark plan is missing"
    )


__all__ = [
    "MOBILE_PACKAGE_ANALYSIS_BENCHMARK_FIXTURE_PROFILE_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_REANALYSIS_VALIDATION_API_VERSION",
    "MobileBenchmarkExpectedOutcome",
    "MobileBenchmarkGroundTruthClass",
    "MobilePackageAnalysisBenchmarkFixtureCase",
    "MobilePackageAnalysisBenchmarkFixtureProfile",
    "MobilePackageAnalysisReanalysisBenchmarkError",
    "MobilePackageAnalysisReanalysisBenchmarkGate",
    "MobilePackageAnalysisReanalysisComparison",
    "MobilePackageAnalysisReanalysisExecution",
    "MobilePackageAnalysisReanalysisValidation",
    "bind_mobile_package_analysis_reanalysis",
    "load_verified_mobile_package_analysis_reanalysis_validation",
    "registered_mobile_package_analysis_benchmark_fixture_profile",
]
