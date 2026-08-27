"""SYS-001D System inspection Replay and disposable-host fixture contract."""

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
from pajin.capabilities.system_inspection import SystemReadOnlyInspectionPreparation
from pajin.discovery.system_surfaces import SystemSurfaceClass
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow.system_inspection_admission import (
    SystemInspectionExecutionBundle,
    SystemInspectionExecutionTrustAnchor,
    SystemInspectionExecutionVerification,
    SystemInspectionKnowledgeAdmission,
    SystemInspectionObservationSourceInputs,
    SystemInspectionResultReceipt,
    SystemInspectionReviewSignal,
    SystemInspectionSourceKind,
    VerifiedSystemInspectionObservationSource,
    load_verified_system_inspection_observation_source,
    system_inspection_source_root_digest,
    verify_system_inspection_execution_bundle,
)

SYSTEM_INSPECTION_REPLAY_VALIDATION_API_VERSION: Literal[
    "pajin.dev/system-inspection-replay-validation/v1alpha1"
] = "pajin.dev/system-inspection-replay-validation/v1alpha1"
SYSTEM_INSPECTION_BENCHMARK_FIXTURE_PROFILE_API_VERSION: Literal[
    "pajin.dev/system-inspection-benchmark-fixture-profile/v1alpha1"
] = "pajin.dev/system-inspection-benchmark-fixture-profile/v1alpha1"

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
    "non-root-runtime-receipt",
    "result-receipt",
    "privilege-denial-receipt",
    "cleanup-receipt",
]
_ReplayState = Literal[
    "immutable-snapshot-reanalysis-match",
    "immutable-snapshot-reanalysis-changed",
    "immutable-snapshot-reanalysis-unresolved",
    "fresh-authenticated-inspection-match",
    "fresh-authenticated-inspection-changed",
    "fresh-authenticated-inspection-unresolved",
]

_REPLAY_TRUE_FIELDS = (
    "sealed_source_reverified",
    "sealed_replay_reverified",
    "stored_source_admission_verified",
    "separate_authorization_verified",
    "causal_replay_order_verified",
    "exact_surface_semantics_verified",
    "input_provenance_verified",
    "non_root_runtime_verified",
    "deployment_context_reverification_required",
)
_REPLAY_FALSE_FIELDS = (
    "host_state_confirmed",
    "process_state_confirmed",
    "filesystem_state_confirmed",
    "service_state_confirmed",
    "configuration_state_confirmed",
    "ground_truth_case_bound",
    "negative_control_observed",
    "privilege_denial_observed",
    "evidence_completeness_measured",
    "benchmark_measurement_observed",
    "configuration_control_coverage_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "self_authenticating_projection",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "agent_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "root_authority_asserted",
    "privilege_escalation_authorized",
    "service_control_authorized",
    "host_mutation_authorized",
    "replay_authorized",
    "execution_authorized",
)
_FIXTURE_TRUE_FIELDS = (
    "private_ground_truth_requirements_registered",
    "disposable_host_required",
    "non_root_runtime_required",
    "negative_control_registered",
    "privilege_denial_control_registered",
    "evidence_completeness_required",
    "immutable_snapshot_reanalysis_required",
)
_FIXTURE_FALSE_FIELDS = (
    "private_ground_truth_verified",
    "target_profile_selected",
    "target_factory_authority",
    "host_agent_provisioned",
    "provider_execution_authorized",
    "fixture_execution_authorized",
    "cleanup_observed",
    "replay_evidence_bound",
    "benchmark_measurement_observed",
    "configuration_control_coverage_measured",
    "privilege_denial_measured",
    "evidence_completeness_measured",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "host_state_confirmed",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "agent_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "root_authority_asserted",
    "privilege_escalation_authorized",
    "service_control_authorized",
    "host_mutation_authorized",
    "replay_authorized",
    "execution_authorized",
)


class SystemInspectionReplayBenchmarkError(RuntimeError):
    """Raised when SYS-001D predecessor or benchmark authority differs."""


class SystemInspectionReplayMode(StrEnum):
    """Two explicitly distinguished, already-completed inspection replay modes."""

    IMMUTABLE_SNAPSHOT_REANALYSIS = "immutable-snapshot-reanalysis"
    FRESH_AUTHENTICATED_INSPECTION = "fresh-authenticated-inspection"


class SystemInspectionReplayComparison(StrEnum):
    """Neutral comparison outcomes that never confirm host security state."""

    MATCHED = "inspection-result-match"
    CHANGED = "inspection-result-changed"
    UNRESOLVED = "inspection-result-unresolved"


class SystemBenchmarkGroundTruthClass(StrEnum):
    """Closed fixture classes for future disposable-host measurement."""

    KNOWN_POSITIVE = "known-positive"
    NEGATIVE_CONTROL = "negative-control"
    PRIVILEGE_DENIAL_CONTROL = "privilege-denial-control"


class SystemBenchmarkExpectedOutcome(StrEnum):
    """Private expected outcome vocabulary without raw host values."""

    REVIEW_SIGNAL = "review-signal"
    NO_REVIEW_SIGNAL = "no-review-signal"
    PRIVILEGE_DENIED = "privilege-denied"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class SystemInspectionReplayExecution(_FrozenStrictModel):
    """Self-contained safe projection of one reverified SYS-001C execution."""

    preparation: SystemReadOnlyInspectionPreparation
    action_permit: ActionPermit = Field(alias="actionPermit")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    trust_anchor: SystemInspectionExecutionTrustAnchor = Field(alias="trustAnchor")
    verification: SystemInspectionExecutionVerification
    execution_bundle: SystemInspectionExecutionBundle = Field(alias="executionBundle")
    result_receipt: SystemInspectionResultReceipt = Field(alias="resultReceipt")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    attestation_reference: _ArtifactPath = Field(alias="attestationReference")
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")

    @model_validator(mode="after")
    def bind_execution_projection(self) -> Self:
        prepared = self.preparation.prepared_action
        permit = self.action_permit
        statement = self.execution_bundle.statement
        receipt = self.result_receipt
        verified = verify_system_inspection_execution_bundle(
            self.execution_bundle,
            trust_anchor=self.trust_anchor,
        )
        expected_source_root_digest = system_inspection_source_root_digest(
            attestation_sha256=self.attestation_sha256,
            result_receipt_sha256=self.result_receipt_sha256,
            trust_anchor_digest=verified.trust_anchor_digest,
            statement_sha256=verified.statement_sha256,
        )
        if (
            verified != self.verification
            or self.source_root_digest != expected_source_root_digest
            or self.attestation_reference == self.result_receipt_reference
            or self.trust_anchor.deployment != self.preparation.host_agent_deployment
            or self.trust_anchor.capability != self.preparation.binding.capability
            or self.trust_anchor.capability_release != self.preparation.release
            or permit.capability != prepared.capability
            or permit.request_id != prepared.request.request_id
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
            or self.approval_receipt.action_permit != permit
            or statement.run_id != permit.run_id
            or statement.preparation_id != self.preparation.preparation_id
            or statement.preparation_digest != self.preparation.preparation_digest
            or statement.request_id != permit.request_id
            or statement.request_digest != permit.request_digest
            or statement.action_permit_id != permit.permit_id
            or statement.action_permit_digest != permit.permit_digest
            or statement.approval_receipt_id != self.approval_receipt.receipt_id
            or statement.approval_receipt_digest != self.approval_receipt.receipt_digest
            or receipt.execution_id != statement.execution_id
            or receipt.request_id != permit.request_id
            or receipt.request_digest != permit.request_digest
            or receipt.preparation_id != self.preparation.preparation_id
            or receipt.preparation_digest != self.preparation.preparation_digest
            or receipt.operation is not self.preparation.operation
            or receipt.surface != self.preparation.surface.reference()
            or statement.result_receipt_reference != self.result_receipt_reference
            or statement.result_receipt_sha256 != self.result_receipt_sha256
            or statement.result_receipt_id != receipt.receipt_id
            or statement.result_receipt_digest != receipt.receipt_digest
        ):
            raise ValueError("SYS-001D execution projection differs from sealed authority")
        return self


class SystemInspectionReplayValidation(_FrozenStrictModel):
    """Non-authorizing wire projection; bare model parsing is not verification."""

    api_version: Literal["pajin.dev/system-inspection-replay-validation/v1alpha1"] = Field(
        default=SYSTEM_INSPECTION_REPLAY_VALIDATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemInspectionReplayValidation"] = "SystemInspectionReplayValidation"
    validation_id: str = Field(default="", alias="validationId", max_length=110)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    source_admission: SystemInspectionKnowledgeAdmission = Field(alias="sourceAdmission")
    source_execution: SystemInspectionReplayExecution = Field(alias="sourceExecution")
    replay_execution: SystemInspectionReplayExecution = Field(alias="replayExecution")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    replay_mode: SystemInspectionReplayMode = Field(alias="replayMode")
    comparison: SystemInspectionReplayComparison
    result_body_digest_matched: bool = Field(alias="resultBodyDigestMatched")
    result_bytes_matched: bool = Field(alias="resultBytesMatched")
    review_signal_matched: bool = Field(alias="reviewSignalMatched")
    domain_validation_strategy_satisfied: bool = Field(alias="domainValidationStrategySatisfied")
    state: _ReplayState
    sealed_source_reverified: Literal[True] = Field(
        default=True,
        alias="sealedSourceReverified",
    )
    sealed_replay_reverified: Literal[True] = Field(
        default=True,
        alias="sealedReplayReverified",
    )
    stored_source_admission_verified: Literal[True] = Field(
        default=True,
        alias="storedSourceAdmissionVerified",
    )
    separate_authorization_verified: Literal[True] = Field(
        default=True,
        alias="separateAuthorizationVerified",
    )
    causal_replay_order_verified: Literal[True] = Field(
        default=True,
        alias="causalReplayOrderVerified",
    )
    exact_surface_semantics_verified: Literal[True] = Field(
        default=True,
        alias="exactSurfaceSemanticsVerified",
    )
    input_provenance_verified: Literal[True] = Field(
        default=True,
        alias="inputProvenanceVerified",
    )
    non_root_runtime_verified: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeVerified",
    )
    deployment_context_reverification_required: Literal[True] = Field(
        default=True,
        alias="deploymentContextReverificationRequired",
    )
    host_state_confirmed: Literal[False] = Field(default=False, alias="hostStateConfirmed")
    process_state_confirmed: Literal[False] = Field(
        default=False,
        alias="processStateConfirmed",
    )
    filesystem_state_confirmed: Literal[False] = Field(
        default=False,
        alias="filesystemStateConfirmed",
    )
    service_state_confirmed: Literal[False] = Field(
        default=False,
        alias="serviceStateConfirmed",
    )
    configuration_state_confirmed: Literal[False] = Field(
        default=False,
        alias="configurationStateConfirmed",
    )
    ground_truth_case_bound: Literal[False] = Field(
        default=False,
        alias="groundTruthCaseBound",
    )
    negative_control_observed: Literal[False] = Field(
        default=False,
        alias="negativeControlObserved",
    )
    privilege_denial_observed: Literal[False] = Field(
        default=False,
        alias="privilegeDenialObserved",
    )
    evidence_completeness_measured: Literal[False] = Field(
        default=False,
        alias="evidenceCompletenessMeasured",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    configuration_control_coverage_measured: Literal[False] = Field(
        default=False,
        alias="configurationControlCoverageMeasured",
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
    agent_selection_authorized: Literal[False] = Field(
        default=False,
        alias="agentSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    root_authority_asserted: Literal[False] = Field(
        default=False,
        alias="rootAuthorityAsserted",
    )
    privilege_escalation_authorized: Literal[False] = Field(
        default=False,
        alias="privilegeEscalationAuthorized",
    )
    service_control_authorized: Literal[False] = Field(
        default=False,
        alias="serviceControlAuthorized",
    )
    host_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="hostMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_REPLAY_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("SYS-001D verified markers must be boolean true")
        return value

    @field_validator(
        "result_body_digest_matched",
        "result_bytes_matched",
        "review_signal_matched",
        "domain_validation_strategy_satisfied",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("SYS-001D comparison markers must be booleans")
        return value

    @field_validator(*_REPLAY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("SYS-001D Replay authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_replay_validation(self) -> Self:
        _require_system_domain_plan(self.domain_benchmark_plan)
        _require_admission_projection(self.source_admission, self.source_execution)
        _require_equivalent_replay_semantics(self.source_execution, self.replay_execution)
        _require_distinct_replay_authority(self.source_execution, self.replay_execution)
        expected_mode = _replay_mode(self.source_execution, self.replay_execution)
        source_result = self.source_execution.result_receipt
        replay_result = self.replay_execution.result_receipt
        body_matched = source_result.result_body_sha256 == replay_result.result_body_sha256
        bytes_matched = source_result.result_bytes == replay_result.result_bytes
        signal_matched = source_result.review_signal is replay_result.review_signal
        comparison = _comparison(
            source=source_result,
            replay=replay_result,
        )
        strategy_satisfied = (
            expected_mode is SystemInspectionReplayMode.IMMUTABLE_SNAPSHOT_REANALYSIS
        )
        if (
            self.replay_mode is not expected_mode
            or self.result_body_digest_matched is not body_matched
            or self.result_bytes_matched is not bytes_matched
            or self.review_signal_matched is not signal_matched
            or self.domain_validation_strategy_satisfied is not strategy_satisfied
            or self.comparison is not comparison
            or self.state != _replay_state(expected_mode, comparison)
        ):
            raise ValueError("SYS-001D neutral Replay comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.system-inspection-replay-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"system-inspection-replay_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("SYS-001D Replay validation Digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("SYS-001D Replay validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


class SystemInspectionBenchmarkFixtureCase(_FrozenStrictModel):
    """One private expected System outcome without a raw host value."""

    fixture_id: _Identifier = Field(alias="fixtureId")
    ground_truth_class: SystemBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    surface_class: SystemSurfaceClass = Field(alias="surfaceClass")
    expected_outcome: SystemBenchmarkExpectedOutcome = Field(alias="expectedOutcome")
    expected_review_signal: SystemInspectionReviewSignal | None = Field(
        default=None,
        alias="expectedReviewSignal",
    )
    required_evidence: tuple[_EvidenceRequirement, ...] = Field(
        min_length=4,
        max_length=4,
        alias="requiredEvidence",
    )
    fixture_materialization: Literal["seeded-sanitized-system-metadata"] = Field(
        default="seeded-sanitized-system-metadata",
        alias="fixtureMaterialization",
    )
    isolation_requirement: Literal["disposable-non-root-container-or-vm-per-case"] = Field(
        default="disposable-non-root-container-or-vm-per-case",
        alias="isolationRequirement",
    )
    raw_host_value_embedded: Literal[False] = Field(
        default=False,
        alias="rawHostValueEmbedded",
    )
    root_required: Literal[False] = Field(default=False, alias="rootRequired")
    host_mutation_operations: Literal[0] = Field(default=0, alias="hostMutationOperations")

    @field_validator("raw_host_value_embedded", "root_required", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("SYS-001D fixture cases cannot embed values or require root")
        return value

    @field_validator("host_mutation_operations", mode="before")
    @classmethod
    def require_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("SYS-001D fixture host mutation count must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_fixture_case(self) -> Self:
        success_evidence: tuple[_EvidenceRequirement, ...] = (
            "execution-attestation",
            "non-root-runtime-receipt",
            "result-receipt",
            "cleanup-receipt",
        )
        denial_evidence: tuple[_EvidenceRequirement, ...] = (
            "execution-attestation",
            "non-root-runtime-receipt",
            "privilege-denial-receipt",
            "cleanup-receipt",
        )
        if self.ground_truth_class is SystemBenchmarkGroundTruthClass.KNOWN_POSITIVE:
            valid = (
                self.expected_outcome is SystemBenchmarkExpectedOutcome.REVIEW_SIGNAL
                and self.expected_review_signal is not None
                and self.required_evidence == success_evidence
            )
        elif self.ground_truth_class is SystemBenchmarkGroundTruthClass.NEGATIVE_CONTROL:
            valid = (
                self.expected_outcome is SystemBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
                and self.expected_review_signal is None
                and self.required_evidence == success_evidence
            )
        else:
            valid = (
                self.expected_outcome is SystemBenchmarkExpectedOutcome.PRIVILEGE_DENIED
                and self.expected_review_signal is None
                and self.required_evidence == denial_evidence
            )
        signal_surface = {
            SystemInspectionReviewSignal.CONFIGURATION_METADATA_DRIFT: (
                SystemSurfaceClass.CONFIGURATION
            ),
            SystemInspectionReviewSignal.SERVICE_STATUS_REVIEW: SystemSurfaceClass.SERVICE,
        }
        if not valid or (
            self.expected_review_signal is not None
            and signal_surface[self.expected_review_signal] is not self.surface_class
        ):
            raise ValueError("SYS-001D fixture Ground Truth shape differs")
        return self


class SystemInspectionBenchmarkFixtureProfile(_FrozenStrictModel):
    """Registered disposable-host Ground Truth requirements, never a measurement."""

    api_version: Literal["pajin.dev/system-inspection-benchmark-fixture-profile/v1alpha1"] = Field(
        default=SYSTEM_INSPECTION_BENCHMARK_FIXTURE_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SystemInspectionBenchmarkFixtureProfile"] = (
        "SystemInspectionBenchmarkFixtureProfile"
    )
    profile_id: str = Field(default="", alias="profileId", max_length=110)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    covered_surface_classes: tuple[SystemSurfaceClass, ...] = Field(
        min_length=5,
        max_length=5,
        alias="coveredSurfaceClasses",
    )
    cases: tuple[SystemInspectionBenchmarkFixtureCase, ...] = Field(
        min_length=5,
        max_length=5,
    )
    state: Literal["registered-fixture-ground-truth-not-measured"] = (
        "registered-fixture-ground-truth-not-measured"
    )
    private_ground_truth_requirements_registered: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthRequirementsRegistered",
    )
    disposable_host_required: Literal[True] = Field(
        default=True,
        alias="disposableHostRequired",
    )
    non_root_runtime_required: Literal[True] = Field(
        default=True,
        alias="nonRootRuntimeRequired",
    )
    negative_control_registered: Literal[True] = Field(
        default=True,
        alias="negativeControlRegistered",
    )
    privilege_denial_control_registered: Literal[True] = Field(
        default=True,
        alias="privilegeDenialControlRegistered",
    )
    evidence_completeness_required: Literal[True] = Field(
        default=True,
        alias="evidenceCompletenessRequired",
    )
    immutable_snapshot_reanalysis_required: Literal[True] = Field(
        default=True,
        alias="immutableSnapshotReanalysisRequired",
    )
    target_profile_selected: Literal[False] = Field(
        default=False,
        alias="targetProfileSelected",
    )
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    host_agent_provisioned: Literal[False] = Field(
        default=False,
        alias="hostAgentProvisioned",
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
    replay_evidence_bound: Literal[False] = Field(
        default=False,
        alias="replayEvidenceBound",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    configuration_control_coverage_measured: Literal[False] = Field(
        default=False,
        alias="configurationControlCoverageMeasured",
    )
    privilege_denial_measured: Literal[False] = Field(
        default=False,
        alias="privilegeDenialMeasured",
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
    host_state_confirmed: Literal[False] = Field(default=False, alias="hostStateConfirmed")
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
    agent_selection_authorized: Literal[False] = Field(
        default=False,
        alias="agentSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    root_authority_asserted: Literal[False] = Field(
        default=False,
        alias="rootAuthorityAsserted",
    )
    privilege_escalation_authorized: Literal[False] = Field(
        default=False,
        alias="privilegeEscalationAuthorized",
    )
    service_control_authorized: Literal[False] = Field(
        default=False,
        alias="serviceControlAuthorized",
    )
    host_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="hostMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_FIXTURE_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("SYS-001D fixture requirement markers must be boolean true")
        return value

    @field_validator(*_FIXTURE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("SYS-001D fixture authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_fixture_profile(self) -> Self:
        _require_system_domain_plan(self.domain_benchmark_plan)
        if (
            self.covered_surface_classes != tuple(SystemSurfaceClass)
            or self.cases != _registered_fixture_cases()
        ):
            raise ValueError("SYS-001D disposable-host fixture profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.system-inspection-benchmark-fixture-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"system-inspection-fixtures_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("SYS-001D fixture profile Digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("SYS-001D fixture profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


class SystemInspectionReplayBenchmarkGate:
    """Reopen sealed C evidence without invoking a host agent, Tool, or Worker."""

    def __init__(self, *, trust_anchor: SystemInspectionExecutionTrustAnchor) -> None:
        if not isinstance(trust_anchor, SystemInspectionExecutionTrustAnchor):
            raise TypeError("SYS-001D requires a deployment System trust anchor")
        self._trust_anchor = SystemInspectionExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )

    def bind_replay(
        self,
        source_inputs: SystemInspectionObservationSourceInputs,
        source_admission: SystemInspectionKnowledgeAdmission,
        replay_inputs: SystemInspectionObservationSourceInputs,
        *,
        source_graph_store: SQLiteGraphStore,
        replay_graph_store: SQLiteGraphStore,
    ) -> SystemInspectionReplayValidation:
        """Return one neutral comparison of separately authorized sealed executions."""

        try:
            canonical_admission = SystemInspectionKnowledgeAdmission.model_validate(
                source_admission.model_dump(mode="json", by_alias=True)
            )
            source = load_verified_system_inspection_observation_source(
                source_inputs,
                graph_store=source_graph_store,
                trust_anchor=self._trust_anchor,
            )
            replay = load_verified_system_inspection_observation_source(
                replay_inputs,
                graph_store=replay_graph_store,
                trust_anchor=self._trust_anchor,
            )
            _require_stored_source_admission(canonical_admission, source_graph_store)
            source_projection = _execution_projection(source)
            replay_projection = _execution_projection(replay)
            _require_admission_projection(canonical_admission, source_projection)
            mode = _replay_mode(source_projection, replay_projection)
            comparison = _comparison(
                source=source_projection.result_receipt,
                replay=replay_projection.result_receipt,
            )
            return SystemInspectionReplayValidation(
                sourceAdmission=canonical_admission,
                sourceExecution=source_projection,
                replayExecution=replay_projection,
                domainBenchmarkPlan=_system_domain_benchmark_plan_ref(),
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
                reviewSignalMatched=(
                    source_projection.result_receipt.review_signal
                    is replay_projection.result_receipt.review_signal
                ),
                domainValidationStrategySatisfied=(
                    mode is SystemInspectionReplayMode.IMMUTABLE_SNAPSHOT_REANALYSIS
                ),
                state=_replay_state(mode, comparison),
            )
        except SystemInspectionReplayBenchmarkError:
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
            raise SystemInspectionReplayBenchmarkError(
                "SYS-001D System inspection Replay failed closed"
            ) from exc


def bind_system_inspection_replay(
    source_inputs: SystemInspectionObservationSourceInputs,
    source_admission: SystemInspectionKnowledgeAdmission,
    replay_inputs: SystemInspectionObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    replay_graph_store: SQLiteGraphStore,
    trust_anchor: SystemInspectionExecutionTrustAnchor,
) -> SystemInspectionReplayValidation:
    """Functional entry point for the deployment-configured SYS-001D gate."""

    return SystemInspectionReplayBenchmarkGate(trust_anchor=trust_anchor).bind_replay(
        source_inputs,
        source_admission,
        replay_inputs,
        source_graph_store=source_graph_store,
        replay_graph_store=replay_graph_store,
    )


def load_verified_system_inspection_replay_validation(
    validation: object,
    source_inputs: SystemInspectionObservationSourceInputs,
    replay_inputs: SystemInspectionObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    replay_graph_store: SQLiteGraphStore,
    trust_anchor: SystemInspectionExecutionTrustAnchor,
) -> SystemInspectionReplayValidation:
    """Reverify one wire projection against deployment evidence and Graph authority."""

    try:
        if isinstance(validation, SystemInspectionReplayValidation):
            payload: object = validation.model_dump(mode="json", by_alias=True)
        else:
            payload = validation
        canonical = SystemInspectionReplayValidation.model_validate(payload)
        expected = bind_system_inspection_replay(
            source_inputs,
            canonical.source_admission,
            replay_inputs,
            source_graph_store=source_graph_store,
            replay_graph_store=replay_graph_store,
            trust_anchor=trust_anchor,
        )
        if canonical != expected:
            raise ValueError(
                "SYS-001D wire projection differs from deployment evidence and Graph authority"
            )
        return expected
    except SystemInspectionReplayBenchmarkError:
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
        raise SystemInspectionReplayBenchmarkError(
            "SYS-001D wire re-verification failed closed"
        ) from exc


def registered_system_inspection_benchmark_fixture_profile() -> (
    SystemInspectionBenchmarkFixtureProfile
):
    """Return exact disposable-host requirements without provisioning or measuring them."""

    try:
        return SystemInspectionBenchmarkFixtureProfile(
            domainBenchmarkPlan=_system_domain_benchmark_plan_ref(),
            coveredSurfaceClasses=tuple(SystemSurfaceClass),
            cases=_registered_fixture_cases(),
        )
    except (RuntimeError, ValidationError, ValueError) as exc:
        raise SystemInspectionReplayBenchmarkError(
            "SYS-001D disposable-host fixture registration failed closed"
        ) from exc


def _execution_projection(
    source: VerifiedSystemInspectionObservationSource,
) -> SystemInspectionReplayExecution:
    return SystemInspectionReplayExecution(
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
    admission: SystemInspectionKnowledgeAdmission,
    graph_store: SQLiteGraphStore,
) -> None:
    observation = admission.candidate.observation_proposal
    stored_observation = graph_store.event_log.event_for_attempt(
        observation.proposal_id,
        observation.digest(),
    )
    if stored_observation != admission.observation_graph_event:
        raise ValueError("SYS-001D source Observation admission is not stored exactly")
    hypothesis = admission.candidate.hypothesis_proposal
    if hypothesis is None:
        if admission.hypothesis_graph_event is not None:
            raise ValueError("SYS-001D source Hypothesis admission differs")
        return
    stored_hypothesis = graph_store.event_log.event_for_attempt(
        hypothesis.proposal_id,
        hypothesis.digest(),
    )
    if stored_hypothesis != admission.hypothesis_graph_event:
        raise ValueError("SYS-001D source Hypothesis admission is not stored exactly")


def _require_admission_projection(
    admission: SystemInspectionKnowledgeAdmission,
    execution: SystemInspectionReplayExecution,
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
        or candidate.source_kind is not receipt.source_kind
        or candidate.immutable_snapshot_sha256 != receipt.immutable_snapshot_sha256
        or candidate.operation is not receipt.operation
        or candidate.review_signal is not receipt.review_signal
    ):
        raise ValueError("SYS-001D source admission differs from its sealed execution")


def _require_equivalent_replay_semantics(
    source: SystemInspectionReplayExecution,
    replay: SystemInspectionReplayExecution,
) -> None:
    source_preparation = source.preparation
    replay_preparation = replay.preparation
    source_prepared = source_preparation.prepared_action
    replay_prepared = replay_preparation.prepared_action
    source_request = source_prepared.request
    replay_request = replay_prepared.request
    if (
        source.trust_anchor != replay.trust_anchor
        or source_preparation.binding != replay_preparation.binding
        or source_preparation.surface != replay_preparation.surface
        or source_preparation.operation is not replay_preparation.operation
        or source_preparation.host_agent_deployment != replay_preparation.host_agent_deployment
        or source_preparation.campaign_scope != replay_preparation.campaign_scope
        or source_preparation.matched_surface_allow_rule
        != replay_preparation.matched_surface_allow_rule
        or source_preparation.release != replay_preparation.release
        or source_preparation.inspection_request.budget
        != replay_preparation.inspection_request.budget
        or source_prepared.activation_set_digest != replay_prepared.activation_set_digest
        or source_prepared.capability != replay_prepared.capability
        or source_prepared.normalized_parameters_digest
        != replay_prepared.normalized_parameters_digest
        or source_request.model_dump(mode="json", exclude={"request_id"})
        != replay_request.model_dump(mode="json", exclude={"request_id"})
    ):
        raise ValueError("SYS-001D Replay action differs from source System semantics")
    if (
        source.result_receipt.result_body_sha256 == replay.result_receipt.result_body_sha256
        and source.result_receipt.result_bytes != replay.result_receipt.result_bytes
    ):
        raise ValueError("SYS-001D equal result digest has inconsistent result byte count")


def _require_distinct_replay_authority(
    source: SystemInspectionReplayExecution,
    replay: SystemInspectionReplayExecution,
) -> None:
    left = _execution_identity_coordinates(source)
    right = _execution_identity_coordinates(replay)
    reused = tuple(name for name in left if left[name] == right[name])
    if reused:
        raise ValueError("SYS-001D Replay reused source execution authority: " + ", ".join(reused))
    if (
        replay.execution_bundle.statement.started_at
        <= source.execution_bundle.statement.finished_at
    ):
        raise ValueError("SYS-001D Replay execution is not causally after the source")


def _execution_identity_coordinates(
    execution: SystemInspectionReplayExecution,
) -> dict[str, str]:
    permit = execution.action_permit
    receipt = execution.approval_receipt
    statement = execution.execution_bundle.statement
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
        "approvalReceiptId": receipt.receipt_id,
        "approvalReceiptDigest": receipt.receipt_digest,
        "executionId": statement.execution_id,
        "statementSha256": execution.verification.statement_sha256,
        "attestationSha256": execution.attestation_sha256,
        "resultReceiptId": result.receipt_id,
        "resultReceiptDigest": result.receipt_digest,
        "resultReceiptSha256": execution.result_receipt_sha256,
    }


def _replay_mode(
    source: SystemInspectionReplayExecution,
    replay: SystemInspectionReplayExecution,
) -> SystemInspectionReplayMode:
    source_receipt = source.result_receipt
    replay_receipt = replay.result_receipt
    if (
        source_receipt.source_kind is SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT
        and replay_receipt.source_kind is SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT
        and source_receipt.immutable_snapshot_sha256 == replay_receipt.immutable_snapshot_sha256
    ):
        return SystemInspectionReplayMode.IMMUTABLE_SNAPSHOT_REANALYSIS
    if (
        source_receipt.source_kind is SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST
        and replay_receipt.source_kind is SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST
        and source_receipt.immutable_snapshot_sha256 is None
        and replay_receipt.immutable_snapshot_sha256 is None
    ):
        return SystemInspectionReplayMode.FRESH_AUTHENTICATED_INSPECTION
    raise ValueError("SYS-001D source and Replay input provenance is not comparable")


def _comparison(
    *,
    source: SystemInspectionResultReceipt,
    replay: SystemInspectionResultReceipt,
) -> SystemInspectionReplayComparison:
    body_matched = source.result_body_sha256 == replay.result_body_sha256
    bytes_matched = source.result_bytes == replay.result_bytes
    signal_matched = source.review_signal is replay.review_signal
    if body_matched and not bytes_matched:
        raise ValueError("SYS-001D equal result digest has inconsistent result byte count")
    if body_matched and bytes_matched and signal_matched:
        return SystemInspectionReplayComparison.MATCHED
    if source.review_signal is None and replay.review_signal is None:
        return SystemInspectionReplayComparison.UNRESOLVED
    return SystemInspectionReplayComparison.CHANGED


def _replay_state(
    mode: SystemInspectionReplayMode,
    comparison: SystemInspectionReplayComparison,
) -> _ReplayState:
    states: dict[
        tuple[SystemInspectionReplayMode, SystemInspectionReplayComparison],
        _ReplayState,
    ] = {
        (
            SystemInspectionReplayMode.IMMUTABLE_SNAPSHOT_REANALYSIS,
            SystemInspectionReplayComparison.MATCHED,
        ): "immutable-snapshot-reanalysis-match",
        (
            SystemInspectionReplayMode.IMMUTABLE_SNAPSHOT_REANALYSIS,
            SystemInspectionReplayComparison.CHANGED,
        ): "immutable-snapshot-reanalysis-changed",
        (
            SystemInspectionReplayMode.IMMUTABLE_SNAPSHOT_REANALYSIS,
            SystemInspectionReplayComparison.UNRESOLVED,
        ): "immutable-snapshot-reanalysis-unresolved",
        (
            SystemInspectionReplayMode.FRESH_AUTHENTICATED_INSPECTION,
            SystemInspectionReplayComparison.MATCHED,
        ): "fresh-authenticated-inspection-match",
        (
            SystemInspectionReplayMode.FRESH_AUTHENTICATED_INSPECTION,
            SystemInspectionReplayComparison.CHANGED,
        ): "fresh-authenticated-inspection-changed",
        (
            SystemInspectionReplayMode.FRESH_AUTHENTICATED_INSPECTION,
            SystemInspectionReplayComparison.UNRESOLVED,
        ): "fresh-authenticated-inspection-unresolved",
    }
    return states[(mode, comparison)]


def _fixture_case(
    *,
    fixture_id: str,
    ground_truth_class: SystemBenchmarkGroundTruthClass,
    surface_class: SystemSurfaceClass,
    expected_outcome: SystemBenchmarkExpectedOutcome,
    expected_review_signal: SystemInspectionReviewSignal | None = None,
) -> SystemInspectionBenchmarkFixtureCase:
    result_evidence: _EvidenceRequirement = (
        "privilege-denial-receipt"
        if expected_outcome is SystemBenchmarkExpectedOutcome.PRIVILEGE_DENIED
        else "result-receipt"
    )
    return SystemInspectionBenchmarkFixtureCase(
        fixtureId=fixture_id,
        groundTruthClass=ground_truth_class,
        surfaceClass=surface_class,
        expectedOutcome=expected_outcome,
        expectedReviewSignal=expected_review_signal,
        requiredEvidence=(
            "execution-attestation",
            "non-root-runtime-receipt",
            result_evidence,
            "cleanup-receipt",
        ),
    )


def _registered_fixture_cases() -> tuple[SystemInspectionBenchmarkFixtureCase, ...]:
    cases = (
        _fixture_case(
            fixture_id="system-fixture:configuration-drift-known-positive",
            ground_truth_class=SystemBenchmarkGroundTruthClass.KNOWN_POSITIVE,
            surface_class=SystemSurfaceClass.CONFIGURATION,
            expected_outcome=SystemBenchmarkExpectedOutcome.REVIEW_SIGNAL,
            expected_review_signal=(SystemInspectionReviewSignal.CONFIGURATION_METADATA_DRIFT),
        ),
        _fixture_case(
            fixture_id="system-fixture:filesystem-privilege-denial-control",
            ground_truth_class=SystemBenchmarkGroundTruthClass.PRIVILEGE_DENIAL_CONTROL,
            surface_class=SystemSurfaceClass.FILESYSTEM,
            expected_outcome=SystemBenchmarkExpectedOutcome.PRIVILEGE_DENIED,
        ),
        _fixture_case(
            fixture_id="system-fixture:host-negative-control",
            ground_truth_class=SystemBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
            surface_class=SystemSurfaceClass.HOST,
            expected_outcome=SystemBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL,
        ),
        _fixture_case(
            fixture_id="system-fixture:process-negative-control",
            ground_truth_class=SystemBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
            surface_class=SystemSurfaceClass.PROCESS,
            expected_outcome=SystemBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL,
        ),
        _fixture_case(
            fixture_id="system-fixture:service-status-known-positive",
            ground_truth_class=SystemBenchmarkGroundTruthClass.KNOWN_POSITIVE,
            surface_class=SystemSurfaceClass.SERVICE,
            expected_outcome=SystemBenchmarkExpectedOutcome.REVIEW_SIGNAL,
            expected_review_signal=SystemInspectionReviewSignal.SERVICE_STATUS_REVIEW,
        ),
    )
    return tuple(sorted(cases, key=lambda item: item.fixture_id))


def _require_system_domain_plan(reference: DomainBenchmarkPlanRef) -> None:
    try:
        plan = resolve_registered_domain_benchmark_plan(reference)
    except Exception as exc:
        raise ValueError("SYS-001D Domain benchmark plan is not registered exactly") from exc
    if (
        plan.domain_classification.domain is not SecurityDomain.SYSTEM
        or plan.validation_strategy is not DomainValidationStrategy.IMMUTABLE_SNAPSHOT_REANALYSIS
    ):
        raise ValueError("SYS-001D Domain benchmark strategy differs")


def _system_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.SYSTEM:
            return plan.reference()
    raise SystemInspectionReplayBenchmarkError("DOMAIN-006 System benchmark plan is missing")


__all__ = [
    "SYSTEM_INSPECTION_BENCHMARK_FIXTURE_PROFILE_API_VERSION",
    "SYSTEM_INSPECTION_REPLAY_VALIDATION_API_VERSION",
    "SystemBenchmarkExpectedOutcome",
    "SystemBenchmarkGroundTruthClass",
    "SystemInspectionBenchmarkFixtureCase",
    "SystemInspectionBenchmarkFixtureProfile",
    "SystemInspectionReplayBenchmarkError",
    "SystemInspectionReplayBenchmarkGate",
    "SystemInspectionReplayComparison",
    "SystemInspectionReplayExecution",
    "SystemInspectionReplayMode",
    "SystemInspectionReplayValidation",
    "bind_system_inspection_replay",
    "load_verified_system_inspection_replay_validation",
    "registered_system_inspection_benchmark_fixture_profile",
]
