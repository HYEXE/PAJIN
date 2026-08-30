"""WEB-002B exact registry-governed ZAP source-measurement lifecycle."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderError,
    DockerBenchmarkProviderEvidence,
)
from pajin.benchmark.measurement import WalkingBenchmarkRunObservationOutcome
from pajin.benchmark.measurement_harness import (
    BenchmarkRegistryGovernedHarnessError,
    BenchmarkRegistryGovernedHarnessOutcome,
    BenchmarkRegistryGovernedHarnessRunner,
    load_registry_governed_benchmark_observation,
)
from pajin.benchmark.measurement_registry_distribution import (
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionBundle,
    BenchmarkMeasurementRegistryDistributionError,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    verify_benchmark_measurement_registry_distribution_bundle,
)
from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.scanner_baseline import ScannerBaselineMeasurementPlanAuthority
from pajin.benchmark.scanner_docker_provider import (
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    ZAPScannerRequestUnitEvidence,
)
from pajin.benchmark.scanner_measurement import (
    ScannerBaselineMeasurementAuthority,
    ScannerBaselineMeasurementError,
    ScannerBaselineMeasurementOutcome,
    ScannerBaselineMeasurementRunner,
    ScannerBaselineSourceBinding,
    load_scanner_baseline_measurement_authority,
)
from pajin.benchmark.scanner_sarif import ZAPSarifNormalization, ZAPScannerRegistration
from pajin.benchmark.target_catalog import BenchmarkTargetCatalogError
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementTrustAnchor,
    BenchmarkTargetFactoryError,
    BenchmarkTargetRunAuthority,
    RegisteredBenchmarkTargetFactoryAdapter,
    load_benchmark_target_run_authority,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetAttempt,
    BenchmarkTargetOperation,
    BenchmarkTargetOperationJournal,
    BenchmarkTargetRecoveryError,
    RecoverableBenchmarkTargetFactoryRunner,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleRegistry,
    CapabilityReleaseRef,
)
from pajin.capabilities.web_measured_validation import (
    WebMeasuredValidationCapabilityBundle,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.workflow.web_measured_case_authority import (
    WebMeasuredCaseAuthority,
    WebMeasuredCaseAuthorityError,
    WebMeasuredCaseAuthorityRef,
    load_web_measured_case_authority,
)
from pajin.workflow.web_replay_benchmark import WebAPIBenchmarkGroundTruthProfile

WEB_ZAP_SOURCE_LINEAGE_API_VERSION: Literal["pajin.dev/web-zap-source-lineage/v1alpha1"] = (
    "pajin.dev/web-zap-source-lineage/v1alpha1"
)
WEB_ZAP_SOURCE_MEASUREMENT_API_VERSION: Literal["pajin.dev/web-zap-source-measurement/v1alpha1"] = (
    "pajin.dev/web-zap-source-measurement/v1alpha1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageId = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_AuthorityId = Annotated[
    str,
    Field(pattern=r"^web-zap-source-measurement:[a-f0-9]{64}$"),
]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_PositiveInt = Annotated[int, Field(strict=True, ge=1, le=2**63 - 1)]
_NonNegativeInt = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
_AUTHORITY_ARTIFACT = "web-zap-source-measurement-authority.json"
_MAX_AUTHORITY_BYTES = 16 * 1024 * 1024
_MAX_SCANNER_AUTHORITY_BYTES = 32 * 1024 * 1024
_MAX_RESULT_BYTES = 4 * 1024 * 1024
_JOURNAL_STAGES = ("reset", "isolation", "execution", "cleanup")
_AUTHORITY_TRUE_FIELDS = (
    "source_measurement_observed",
    "raw_sarif_custody_verified",
    "strict_normalization_verified",
    "signed_registry_authority_verified",
    "target_run_completed",
    "target_cleanup_verified",
    "internal_network_verified",
    "no_published_ports_verified",
    "source_and_controlled_validation_identity_separated",
)
_AUTHORITY_FALSE_FIELDS = (
    "controlled_validation_route_used",
    "controlled_validation_executed",
    "private_ground_truth_disclosed",
    "domain_metric_floor_evaluated",
    "benchmark_validation_floor_satisfied",
    "graph_admission_authorized",
    "graph_write_authorized",
    "finding_projection_authorized",
    "finding_authorized",
    "candidate_comparison_eligible",
    "supervisor_activation_eligible",
    "product_activation_authorized",
    "report_delivery_authorized",
    "additional_execution_authorized",
)


class WebZAPSourceMeasurementError(RuntimeError):
    """Raised when WEB-002B execution or source revalidation fails closed."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
    )


class WebZAPSourceLineage(_FrozenStrictModel):
    """Content-only reference to one completed source Target lifecycle."""

    api_version: Literal["pajin.dev/web-zap-source-lineage/v1alpha1"] = Field(
        default=WEB_ZAP_SOURCE_LINEAGE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebZAPSourceLineage"] = "WebZAPSourceLineage"
    lineage_digest: str = Field(default="", alias="lineageDigest", max_length=64)
    scanner_coordinate_digest: _Sha256 = Field(alias="scannerCoordinateDigest")
    target_coordinate_id: _Identifier = Field(alias="targetCoordinateId")
    target_coordinate_digest: _Sha256 = Field(alias="targetCoordinateDigest")
    seed: _NonNegativeInt
    repetition: _PositiveInt
    harness_run_id: _Identifier = Field(alias="harnessRunId")
    harness_root_digest: _Sha256 = Field(alias="harnessRootDigest")
    harness_authority_digest: _Sha256 = Field(alias="harnessAuthorityDigest")
    registry_activation_digest: _Sha256 = Field(alias="registryActivationDigest")
    registry_bundle_digest: _Sha256 = Field(alias="registryBundleDigest")
    registry_admission_authority_digest: _Sha256 = Field(alias="registryAdmissionAuthorityDigest")
    target_run_id: _Identifier = Field(alias="targetRunId")
    target_root_digest: _Sha256 = Field(alias="targetRootDigest")
    target_authority_digest: _Sha256 = Field(alias="targetAuthorityDigest")
    target_attestation_digest: _Sha256 = Field(alias="targetAttestationDigest")
    target_attempt_id: _Identifier = Field(alias="targetAttemptId")
    target_attempt_digest: _Sha256 = Field(alias="targetAttemptDigest")
    target_fence: _PositiveInt = Field(alias="targetFence")
    target_image_id: _ImageId = Field(alias="targetImageId")
    target_container_id: _Sha256 = Field(alias="targetContainerId")
    worker_image_id: _ImageId = Field(alias="workerImageId")
    scanner_image_id: _ImageId = Field(alias="scannerImageId")
    execution_operation_id: _Identifier = Field(alias="executionOperationId")
    execution_operation_digest: _Sha256 = Field(alias="executionOperationDigest")
    execution_receipt_digest: _Sha256 = Field(alias="executionReceiptDigest")
    execution_provider_evidence_digest: _Sha256 = Field(alias="executionProviderEvidenceDigest")
    request_unit_evidence: ZAPScannerRequestUnitEvidence = Field(alias="requestUnitEvidence")
    cleanup_operation_id: _Identifier = Field(alias="cleanupOperationId")
    cleanup_operation_digest: _Sha256 = Field(alias="cleanupOperationDigest")
    cleanup_receipt_digest: _Sha256 = Field(alias="cleanupReceiptDigest")
    cleanup_provider_evidence_digest: _Sha256 = Field(alias="cleanupProviderEvidenceDigest")
    raw_sarif_sha256: _Sha256 = Field(alias="rawSarifSha256")
    raw_sarif_size_bytes: _PositiveInt = Field(alias="rawSarifSizeBytes")
    normalization_digest: _Sha256 = Field(alias="normalizationDigest")
    scanner_source_binding_digest: _Sha256 = Field(alias="scannerSourceBindingDigest")
    journal_completed: Literal[True] = Field(default=True, alias="journalCompleted")
    cleanup_resources_absent: Literal[True] = Field(
        default=True,
        alias="cleanupResourcesAbsent",
    )

    @field_validator("journal_completed", "cleanup_resources_absent", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB ZAP source lineage markers must be boolean true")
        return value

    @model_validator(mode="after")
    def bind_lineage(self) -> Self:
        if (
            self.request_unit_evidence.operation_id != self.execution_operation_id
            or self.request_unit_evidence.operation_digest != self.execution_operation_digest
            or self.request_unit_evidence.target_container_id != self.target_container_id
        ):
            raise ValueError("WEB ZAP source request-unit Evidence differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"lineage_digest"})
        digest = benchmark_digest(
            "pajin.workflow.web-zap-source-lineage/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.lineage_digest and self.lineage_digest != digest:
            raise ValueError("WEB ZAP source lineage digest differs")
        object.__setattr__(self, "lineage_digest", digest)
        return self


class WebZAPSourceMeasurementAuthorityRef(_FrozenStrictModel):
    authority_id: _AuthorityId = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.authority_id != f"web-zap-source-measurement:{self.authority_digest}":
            raise ValueError("WEB ZAP Source Measurement Authority reference differs")
        return self


class WebZAPSourceMeasurementAuthority(_FrozenStrictModel):
    """Public-safe identity for one fully revalidated WEB-002B source measurement."""

    api_version: Literal["pajin.dev/web-zap-source-measurement/v1alpha1"] = Field(
        default=WEB_ZAP_SOURCE_MEASUREMENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebZAPSourceMeasurementAuthority"] = "WebZAPSourceMeasurementAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    capability_release_id: _Identifier = Field(alias="capabilityReleaseId")
    capability_release_digest: _Sha256 = Field(alias="capabilityReleaseDigest")
    scanner_plan_digest: _Sha256 = Field(alias="scannerPlanDigest")
    scanner_registration_digest: _Sha256 = Field(alias="scannerRegistrationDigest")
    target_selection_digest: _Sha256 = Field(alias="targetSelectionDigest")
    measurement_run_id: _Identifier = Field(alias="measurementRunId")
    measurement_root_digest: _Sha256 = Field(alias="measurementRootDigest")
    scanner_measurement_authority_id: _Identifier = Field(alias="scannerMeasurementAuthorityId")
    scanner_measurement_authority_digest: _Sha256 = Field(alias="scannerMeasurementAuthorityDigest")
    scanner_measurement_authority_sha256: _Sha256 = Field(alias="scannerMeasurementAuthoritySha256")
    baseline_result_digest: _Sha256 = Field(alias="baselineResultDigest")
    source_request_units: _PositiveInt = Field(alias="sourceRequestUnits")
    lineages: tuple[WebZAPSourceLineage, ...] = Field(min_length=1, max_length=2_000)
    measurement_state: Literal["registry-governed-zap-source-measurement-complete"] = Field(
        default="registry-governed-zap-source-measurement-complete",
        alias="measurementState",
    )
    source_measurement_observed: Literal[True] = Field(
        default=True,
        alias="sourceMeasurementObserved",
    )
    raw_sarif_custody_verified: Literal[True] = Field(
        default=True,
        alias="rawSarifCustodyVerified",
    )
    strict_normalization_verified: Literal[True] = Field(
        default=True,
        alias="strictNormalizationVerified",
    )
    signed_registry_authority_verified: Literal[True] = Field(
        default=True,
        alias="signedRegistryAuthorityVerified",
    )
    target_run_completed: Literal[True] = Field(
        default=True,
        alias="targetRunCompleted",
    )
    target_cleanup_verified: Literal[True] = Field(
        default=True,
        alias="targetCleanupVerified",
    )
    internal_network_verified: Literal[True] = Field(
        default=True,
        alias="internalNetworkVerified",
    )
    no_published_ports_verified: Literal[True] = Field(
        default=True,
        alias="noPublishedPortsVerified",
    )
    source_and_controlled_validation_identity_separated: Literal[True] = Field(
        default=True,
        alias="sourceAndControlledValidationIdentitySeparated",
    )
    controlled_validation_route_used: Literal[False] = Field(
        default=False,
        alias="controlledValidationRouteUsed",
    )
    controlled_validation_executed: Literal[False] = Field(
        default=False,
        alias="controlledValidationExecuted",
    )
    private_ground_truth_disclosed: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthDisclosed",
    )
    domain_metric_floor_evaluated: Literal[False] = Field(
        default=False,
        alias="domainMetricFloorEvaluated",
    )
    benchmark_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="benchmarkValidationFloorSatisfied",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    graph_write_authorized: Literal[False] = Field(
        default=False,
        alias="graphWriteAuthorized",
    )
    finding_projection_authorized: Literal[False] = Field(
        default=False,
        alias="findingProjectionAuthorized",
    )
    finding_authorized: Literal[False] = Field(default=False, alias="findingAuthorized")
    candidate_comparison_eligible: Literal[False] = Field(
        default=False,
        alias="candidateComparisonEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )
    product_activation_authorized: Literal[False] = Field(
        default=False,
        alias="productActivationAuthorized",
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(*_AUTHORITY_TRUE_FIELDS, mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002B verification markers must be boolean true")
        return value

    @field_validator(*_AUTHORITY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "WEB-002B authority markers must be boolean false and cannot grant "
                "validation or downstream authority"
            )
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        ordered = tuple(
            sorted(
                self.lineages,
                key=lambda item: (item.seed, item.repetition, item.target_run_id),
            )
        )
        unique_fields = (
            {item.lineage_digest for item in ordered},
            {item.harness_run_id for item in ordered},
            {item.target_run_id for item in ordered},
            {item.target_attempt_id for item in ordered},
            {item.execution_operation_id for item in ordered},
            {item.cleanup_operation_id for item in ordered},
            {item.scanner_source_binding_digest for item in ordered},
        )
        if self.lineages != ordered or any(len(values) != len(ordered) for values in unique_fields):
            raise ValueError("WEB ZAP source lineages are not canonical and fresh")
        if self.source_request_units != sum(
            item.request_unit_evidence.request_units for item in ordered
        ):
            raise ValueError("WEB ZAP source request-unit total differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-zap-source-measurement/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"web-zap-source-measurement:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("WEB ZAP Source Measurement Authority digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("WEB ZAP Source Measurement Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self

    def reference(self) -> WebZAPSourceMeasurementAuthorityRef:
        return WebZAPSourceMeasurementAuthorityRef(
            authorityId=self.authority_id,
            authorityDigest=self.authority_digest,
        )


@dataclass(frozen=True, slots=True)
class WebZAPSourceMeasurementOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    source_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...]
    scanner_measurement_outcome: ScannerBaselineMeasurementOutcome
    authority: WebZAPSourceMeasurementAuthority


@dataclass(frozen=True, slots=True)
class WebZAPSourceMeasurementReopenContext:
    """Host-owned inputs that independently reopen one sealed WEB-002B source."""

    outcome: WebZAPSourceMeasurementOutcome
    measured_case: WebMeasuredCaseAuthority
    capability_bundle: WebMeasuredValidationCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    release: CapabilityReleaseRef
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile
    scanner_plan: ScannerBaselineMeasurementPlanAuthority
    scanner_registration: ZAPScannerRegistration
    journal_path: Path
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor
    activation_store: BenchmarkMeasurementRegistryActivationStore
    distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor

    def reopen(self) -> WebZAPSourceMeasurementAuthority:
        if type(self) is not WebZAPSourceMeasurementReopenContext:
            raise WebZAPSourceMeasurementError(
                "WEB-002B source reopen context requires its exact type"
            )
        return load_web_zap_source_measurement_authority(
            self.outcome,
            measured_case=self.measured_case,
            capability_bundle=self.capability_bundle,
            lifecycle=self.lifecycle,
            release=self.release,
            target_adapter=self.target_adapter,
            private_ground_truth_profile=self.private_ground_truth_profile,
            scanner_plan=self.scanner_plan,
            scanner_registration=self.scanner_registration,
            journal_path=self.journal_path,
            catalog_provider=self.catalog_provider,
            measurement_trust_anchor=self.measurement_trust_anchor,
            activation_store=self.activation_store,
            distribution_bundle=self.distribution_bundle,
            distribution_trust_anchor=self.distribution_trust_anchor,
        )


class WebZAPSourceMeasurementRunner:
    """Execute the exact WEB source plan using constructor-owned deployment trust."""

    def __init__(
        self,
        *,
        output_root: Path,
        journal_path: Path,
        catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
        measurement_trust_anchor: BenchmarkMeasurementTrustAnchor,
        activation_store: BenchmarkMeasurementRegistryActivationStore,
        distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle,
        distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
    ) -> None:
        try:
            self._measurement_trust_anchor = BenchmarkMeasurementTrustAnchor.model_validate(
                measurement_trust_anchor.model_dump(mode="json", by_alias=True)
            )
            self._distribution_bundle = (
                BenchmarkMeasurementRegistryDistributionBundle.model_validate(
                    distribution_bundle.model_dump(mode="json", by_alias=True)
                )
            )
            self._distribution_trust_anchor = (
                BenchmarkMeasurementRegistryDistributionTrustAnchor.model_validate(
                    distribution_trust_anchor.model_dump(mode="json", by_alias=True)
                )
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise WebZAPSourceMeasurementError(
                "WEB ZAP source deployment context is structurally invalid"
            ) from exc
        self._output_root = output_root
        self._catalog_provider = catalog_provider
        self._activation_store = activation_store
        self._journal = BenchmarkTargetOperationJournal(journal_path)

    async def run(
        self,
        measured_case: WebMeasuredCaseAuthority,
        *,
        capability_bundle: WebMeasuredValidationCapabilityBundle,
        lifecycle: CapabilityLifecycleRegistry,
        release: CapabilityReleaseRef,
        target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
        private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
        scanner_plan: ScannerBaselineMeasurementPlanAuthority,
        scanner_registration: ZAPScannerRegistration,
    ) -> WebZAPSourceMeasurementOutcome:
        """Execute only the coordinates committed by one exact WEB-002A case."""

        try:
            case = _load_exact_case(
                measured_case,
                capability_bundle=capability_bundle,
                lifecycle=lifecycle,
                release=release,
                target_adapter=target_adapter,
                private_ground_truth_profile=private_ground_truth_profile,
                scanner_plan=scanner_plan,
                scanner_registration=scanner_registration,
            )
            _require_runtime_context(
                case,
                catalog_provider=self._catalog_provider,
                measurement_trust_anchor=self._measurement_trust_anchor,
                distribution_bundle=self._distribution_bundle,
                distribution_trust_anchor=self._distribution_trust_anchor,
            )
            target_runner = RecoverableBenchmarkTargetFactoryRunner(
                output_root=self._output_root,
                journal_path=self._journal.path,
                adapter=self._catalog_provider,
                trust_anchor=self._measurement_trust_anchor,
            )
            harness = BenchmarkRegistryGovernedHarnessRunner(
                output_root=self._output_root,
                activation_store=self._activation_store,
                bundle=self._distribution_bundle,
                distribution_trust_anchor=self._distribution_trust_anchor,
                target_runner=target_runner,
            )
            source_outcomes = tuple(
                [
                    await harness.run(
                        case.scanner_plan.manifest,
                        arm_id=coordinate.arm_id,
                        seed=coordinate.seed,
                        repetition=coordinate.repetition,
                    )
                    for coordinate in case.scanner_plan.coordinates
                ]
            )
            for source_outcome in source_outcomes:
                _require_completed_source_before_measurement(
                    case,
                    source_outcome=source_outcome,
                    catalog_provider=self._catalog_provider,
                    journal=self._journal,
                    activation_store=self._activation_store,
                    distribution_trust_anchor=self._distribution_trust_anchor,
                )
            scanner_outcome = ScannerBaselineMeasurementRunner(output_root=self._output_root).run(
                case.scanner_plan,
                catalog_provider=self._catalog_provider,
                source_outcomes=source_outcomes,
                activation_store=self._activation_store,
                distribution_trust_anchor=self._distribution_trust_anchor,
            )
            scanner_authority = load_scanner_baseline_measurement_authority(
                case.scanner_plan,
                scanner_outcome,
                catalog_provider=self._catalog_provider,
                source_outcomes=source_outcomes,
                activation_store=self._activation_store,
                distribution_trust_anchor=self._distribution_trust_anchor,
            )
            authority = _build_authority(
                case,
                scanner_outcome=scanner_outcome,
                scanner_authority=scanner_authority,
                source_outcomes=source_outcomes,
                catalog_provider=self._catalog_provider,
                journal=self._journal,
                activation_store=self._activation_store,
                distribution_bundle=self._distribution_bundle,
                distribution_trust_anchor=self._distribution_trust_anchor,
            )
            outcome = _seal(self._output_root, source_outcomes, scanner_outcome, authority)
            verified = load_web_zap_source_measurement_authority(
                outcome,
                measured_case=case,
                capability_bundle=capability_bundle,
                lifecycle=lifecycle,
                release=release,
                target_adapter=target_adapter,
                private_ground_truth_profile=private_ground_truth_profile,
                scanner_plan=scanner_plan,
                scanner_registration=scanner_registration,
                journal_path=self._journal.path,
                catalog_provider=self._catalog_provider,
                measurement_trust_anchor=self._measurement_trust_anchor,
                activation_store=self._activation_store,
                distribution_bundle=self._distribution_bundle,
                distribution_trust_anchor=self._distribution_trust_anchor,
            )
            return replace(outcome, authority=verified)
        except WebZAPSourceMeasurementError:
            raise
        except (
            BenchmarkMeasurementRegistryDistributionError,
            BenchmarkRegistryGovernedHarnessError,
            BenchmarkTargetCatalogError,
            BenchmarkTargetFactoryError,
            BenchmarkTargetRecoveryError,
            DockerBenchmarkProviderError,
            OSError,
            RunIntegrityError,
            ScannerBaselineMeasurementError,
            ValidationError,
            ValueError,
            WebMeasuredCaseAuthorityError,
        ) as exc:
            raise WebZAPSourceMeasurementError("WEB-002B source measurement failed closed") from exc


def load_web_zap_source_measurement_authority(
    outcome: WebZAPSourceMeasurementOutcome,
    *,
    measured_case: WebMeasuredCaseAuthority,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
    journal_path: Path,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> WebZAPSourceMeasurementAuthority:
    """Reopen the outer seal and every WEB-002B source predecessor read-only."""

    try:
        case = _load_exact_case(
            measured_case,
            capability_bundle=capability_bundle,
            lifecycle=lifecycle,
            release=release,
            target_adapter=target_adapter,
            private_ground_truth_profile=private_ground_truth_profile,
            scanner_plan=scanner_plan,
            scanner_registration=scanner_registration,
        )
        _require_runtime_context(
            case,
            catalog_provider=catalog_provider,
            measurement_trust_anchor=measurement_trust_anchor,
            distribution_bundle=distribution_bundle,
            distribution_trust_anchor=distribution_trust_anchor,
            require_current_validity=False,
        )
        journal = BenchmarkTargetOperationJournal.open_existing(journal_path)
        scanner_authority = load_scanner_baseline_measurement_authority(
            case.scanner_plan,
            outcome.scanner_measurement_outcome,
            catalog_provider=catalog_provider,
            source_outcomes=outcome.source_outcomes,
            activation_store=activation_store,
            distribution_trust_anchor=distribution_trust_anchor,
        )
        expected = _build_authority(
            case,
            scanner_outcome=outcome.scanner_measurement_outcome,
            scanner_authority=scanner_authority,
            source_outcomes=outcome.source_outcomes,
            catalog_provider=catalog_provider,
            journal=journal,
            activation_store=activation_store,
            distribution_bundle=distribution_bundle,
            distribution_trust_anchor=distribution_trust_anchor,
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={outcome.authority_path: _MAX_AUTHORITY_BYTES},
            expected_run_id=outcome.run_id,
        )
        sealed_bytes = snapshot.artifact_bytes(outcome.authority_path)
        sealed = WebZAPSourceMeasurementAuthority.model_validate_json(sealed_bytes)
    except WebZAPSourceMeasurementError:
        raise
    except (
        BenchmarkMeasurementRegistryDistributionError,
        BenchmarkRegistryGovernedHarnessError,
        BenchmarkTargetCatalogError,
        BenchmarkTargetFactoryError,
        BenchmarkTargetRecoveryError,
        DockerBenchmarkProviderError,
        OSError,
        RunIntegrityError,
        ScannerBaselineMeasurementError,
        ValidationError,
        ValueError,
        WebMeasuredCaseAuthorityError,
    ) as exc:
        raise WebZAPSourceMeasurementError(
            "WEB-002B source measurement is not sealed and valid"
        ) from exc
    if (
        outcome.authority_path != _AUTHORITY_ARTIFACT
        or sealed != expected
        or outcome.authority != expected
        or sealed_bytes != _strict_run_json_bytes(sealed.model_dump(mode="json", by_alias=True))
        or [event.event_type for event in snapshot.events]
        != [
            "campaign.started",
            "benchmark.web-zap-source-measurement.sealed",
            "campaign.completed",
        ]
        or snapshot.events[0].payload != _started_event_payload(expected)
        or snapshot.events[1].payload != _event_payload(expected)
        or snapshot.events[2].payload != _completed_event_payload()
    ):
        raise WebZAPSourceMeasurementError(
            "WEB-002B source measurement differs from exact authority"
        )
    return sealed.model_copy(deep=True)


def _load_exact_case(
    measured_case: WebMeasuredCaseAuthority,
    *,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
) -> WebMeasuredCaseAuthority:
    return load_web_measured_case_authority(
        measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        release=release,
        target_adapter=target_adapter,
        private_ground_truth_profile=private_ground_truth_profile,
        scanner_plan=scanner_plan,
        scanner_registration=scanner_registration,
    )


def _require_runtime_context(
    case: WebMeasuredCaseAuthority,
    *,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor,
    distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
    require_current_validity: bool = True,
) -> None:
    if require_current_validity:
        verify_benchmark_measurement_registry_distribution_bundle(
            distribution_bundle,
            trust_anchor=distribution_trust_anchor,
            now=datetime.now(UTC),
        )
    registry = distribution_bundle.statement.registry
    if (
        len(case.scanner_plan.coordinates) != 1
        or catalog_provider.definition != case.target_adapter
        or catalog_provider.selection != case.scanner_plan.target_selection
        or catalog_provider.scanner_registration != case.scanner_registration
        or measurement_trust_anchor.anchor_digest
        != case.target_adapter.measurement_authority_digest
        or measurement_trust_anchor.authority_id != case.target_adapter.measurement_authority_id
        or measurement_trust_anchor.authority_version
        != case.target_adapter.measurement_authority_version
        or registry.measurement_authority_id != measurement_trust_anchor.authority_id
        or registry.measurement_authority_version != measurement_trust_anchor.authority_version
        or registry.active_key.trust_anchor != measurement_trust_anchor
    ):
        raise WebZAPSourceMeasurementError(
            "WEB-002B provider or deployment trust differs from the exact case"
        )


def _build_authority(
    case: WebMeasuredCaseAuthority,
    *,
    scanner_outcome: ScannerBaselineMeasurementOutcome,
    scanner_authority: ScannerBaselineMeasurementAuthority,
    source_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    journal: BenchmarkTargetOperationJournal,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> WebZAPSourceMeasurementAuthority:
    if (
        scanner_authority.plan != case.scanner_plan
        or scanner_authority.registration != case.scanner_registration
        or scanner_authority.catalog_selection != case.scanner_plan.target_selection
        or scanner_authority.candidate_comparison_eligible is not False
        or scanner_authority.supervisor_activation_eligible is not False
        or len(scanner_authority.sources) != len(source_outcomes)
        or len(source_outcomes) != len(case.scanner_plan.coordinates)
        or any(
            source.authority.activation.bundle != distribution_bundle
            or source.authority.distribution_trust_anchor != distribution_trust_anchor
            for source in source_outcomes
        )
    ):
        raise WebZAPSourceMeasurementError(
            "WEB-002B Scanner authority differs from its exact measured case"
        )
    source_by_target = {source.target_run_id: source for source in scanner_authority.sources}
    outcome_by_target = {source.target.run_id: source for source in source_outcomes}
    if (
        len(source_by_target) != len(scanner_authority.sources)
        or len(outcome_by_target) != len(source_outcomes)
        or set(source_by_target) != set(outcome_by_target)
    ):
        raise WebZAPSourceMeasurementError(
            "WEB-002B Scanner sources are absent, duplicate, or foreign"
        )
    lineages = tuple(
        sorted(
            (
                _build_lineage(
                    case,
                    source=source_by_target[target_run_id],
                    source_outcome=outcome_by_target[target_run_id],
                    catalog_provider=catalog_provider,
                    journal=journal,
                    activation_store=activation_store,
                    distribution_trust_anchor=distribution_trust_anchor,
                )
                for target_run_id in sorted(source_by_target)
            ),
            key=lambda item: (item.seed, item.repetition, item.target_run_id),
        )
    )
    scanner_snapshot = load_verified_run_artifacts(
        scanner_outcome.run_path,
        requests={scanner_outcome.authority_path: _MAX_SCANNER_AUTHORITY_BYTES},
        expected_run_id=scanner_outcome.run_id,
    )
    scanner_bytes = scanner_snapshot.artifact_bytes(scanner_outcome.authority_path)
    return WebZAPSourceMeasurementAuthority(
        measuredCase=case.reference(),
        capabilityReleaseId=case.capability_release.release_id,
        capabilityReleaseDigest=case.capability_release.release_digest,
        scannerPlanDigest=case.scanner_plan.authority_digest,
        scannerRegistrationDigest=case.scanner_registration.registration_digest,
        targetSelectionDigest=case.scanner_plan.target_selection.authority_digest,
        measurementRunId=scanner_outcome.run_id,
        measurementRootDigest=scanner_snapshot.verification.root_digest,
        scannerMeasurementAuthorityId=scanner_authority.authority_id,
        scannerMeasurementAuthorityDigest=scanner_authority.authority_digest,
        scannerMeasurementAuthoritySha256=sha256(scanner_bytes).hexdigest(),
        baselineResultDigest=scanner_authority.baseline_result_digest,
        sourceRequestUnits=sum(lineage.request_unit_evidence.request_units for lineage in lineages),
        lineages=lineages,
    )


def _build_lineage(
    case: WebMeasuredCaseAuthority,
    *,
    source: ScannerBaselineSourceBinding,
    source_outcome: BenchmarkRegistryGovernedHarnessOutcome,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    journal: BenchmarkTargetOperationJournal,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> WebZAPSourceLineage:
    observation_outcome = load_registry_governed_benchmark_observation(
        case.scanner_plan.manifest,
        source_outcome,
        activation_store=activation_store,
        distribution_trust_anchor=distribution_trust_anchor,
    )
    target = load_benchmark_target_run_authority(
        case.scanner_plan.manifest,
        source_outcome.target,
    )
    execution_evidence, raw_sarif, normalization = catalog_provider.verify_target_run_match(target)
    request_unit_evidence = catalog_provider.request_unit_evidence(target.execution_receipt)
    if (
        execution_evidence.target_container_id is None
        or not target.execution_receipt.started_at
        <= request_unit_evidence.observed_at
        <= target.execution_receipt.completed_at
    ):
        raise WebZAPSourceMeasurementError(
            "WEB-002B request-unit Evidence differs from execution Evidence"
        )
    cleanup_evidence = catalog_provider.evidence(target.cleanup_receipt)
    attempt, execution_operation, cleanup_operation = _completed_journal_context(
        journal,
        target,
    )
    coordinate_matches = tuple(
        coordinate
        for coordinate in case.scanner_plan.coordinates
        if coordinate.manifest_digest == target.coordinate.manifest_digest
        and coordinate.arm_id == target.coordinate.arm.arm_id
        and coordinate.seed == target.coordinate.seed
        and coordinate.repetition == target.coordinate.repetition
    )
    if len(coordinate_matches) != 1:
        raise WebZAPSourceMeasurementError(
            "WEB-002B Target coordinate differs from the exact Scanner plan"
        )
    scanner_coordinate = coordinate_matches[0]
    _require_source_evidence(
        case,
        source=source,
        source_outcome=source_outcome,
        target=target,
        execution_operation=execution_operation,
        cleanup_operation=cleanup_operation,
        execution_evidence=execution_evidence,
        cleanup_evidence=cleanup_evidence,
        raw_sarif=raw_sarif,
        normalization=normalization,
        observation_outcome=observation_outcome,
        catalog_provider=catalog_provider,
    )
    harness = source_outcome.authority
    return WebZAPSourceLineage(
        scannerCoordinateDigest=scanner_coordinate.coordinate_digest,
        targetCoordinateId=target.coordinate.coordinate_id,
        targetCoordinateDigest=target.coordinate.coordinate_digest,
        seed=target.coordinate.seed,
        repetition=target.coordinate.repetition,
        harnessRunId=source_outcome.run_id,
        harnessRootDigest=source.harness_root_digest,
        harnessAuthorityDigest=source.harness_authority_digest,
        registryActivationDigest=harness.activation.activation_digest,
        registryBundleDigest=harness.activation.bundle_digest,
        registryAdmissionAuthorityDigest=(harness.registry_admission_authority.authority_digest),
        targetRunId=source_outcome.target.run_id,
        targetRootDigest=source.target_root_digest,
        targetAuthorityDigest=target.authority_digest,
        targetAttestationDigest=target.attestation.digest,
        targetAttemptId=attempt.attempt_id,
        targetAttemptDigest=attempt.attempt_digest,
        targetFence=attempt.fence,
        targetImageId=execution_evidence.target_image_id,
        targetContainerId=execution_evidence.target_container_id,
        workerImageId=execution_evidence.worker_image_id,
        scannerImageId=case.scanner_registration.scanner_image_id,
        executionOperationId=execution_operation.operation_id,
        executionOperationDigest=execution_operation.operation_digest,
        executionReceiptDigest=target.execution_receipt.receipt_digest,
        executionProviderEvidenceDigest=execution_evidence.evidence_digest,
        requestUnitEvidence=request_unit_evidence,
        cleanupOperationId=cleanup_operation.operation_id,
        cleanupOperationDigest=cleanup_operation.operation_digest,
        cleanupReceiptDigest=target.cleanup_receipt.receipt_digest,
        cleanupProviderEvidenceDigest=cleanup_evidence.evidence_digest,
        rawSarifSha256=sha256(raw_sarif).hexdigest(),
        rawSarifSizeBytes=normalization.raw_sarif_size_bytes,
        normalizationDigest=normalization.normalization_digest,
        scannerSourceBindingDigest=source.binding_digest,
    )


def _completed_journal_context(
    journal: BenchmarkTargetOperationJournal,
    target: BenchmarkTargetRunAuthority,
) -> tuple[BenchmarkTargetAttempt, BenchmarkTargetOperation, BenchmarkTargetOperation]:
    execution_context = journal.completed_attempt_for_operation(
        target.execution_receipt.operation_id
    )
    cleanup_context = journal.completed_attempt_for_operation(target.cleanup_receipt.operation_id)
    if execution_context != cleanup_context:
        raise WebZAPSourceMeasurementError(
            "WEB-002B execution and cleanup do not share one completed attempt"
        )
    adapter, coordinate, attempt, records = execution_context
    receipts = (
        target.reset_receipt,
        target.isolation_receipt,
        target.execution_receipt,
        target.cleanup_receipt,
    )
    if (
        adapter != target.adapter
        or coordinate != target.coordinate
        or attempt.adapter_digest != target.adapter.adapter_digest
        or attempt.coordinate_digest != target.coordinate.coordinate_digest
        or len(records) != 8
        or attempt.started_at > records[0].occurred_at
    ):
        raise WebZAPSourceMeasurementError("WEB-002B completed Target attempt identity differs")
    previous_time = attempt.started_at
    operations: list[BenchmarkTargetOperation] = []
    for index, (stage, receipt) in enumerate(zip(_JOURNAL_STAGES, receipts, strict=True)):
        intent = records[index * 2]
        completed = records[index * 2 + 1]
        operation = intent.operation
        if (
            intent.sequence != index * 2 + 1
            or completed.sequence != index * 2 + 2
            or intent.record_type != "intent"
            or completed.record_type != "receipt"
            or intent.receipt is not None
            or completed.receipt != receipt
            or intent.operation != completed.operation
            or operation.stage != stage
            or operation.ordinal != 1
            or operation.attempt_id != attempt.attempt_id
            or operation.attempt_digest != attempt.attempt_digest
            or operation.adapter_digest != adapter.adapter_digest
            or operation.coordinate_digest != coordinate.coordinate_digest
            or operation.fence != attempt.fence
            or previous_time > intent.occurred_at
            or intent.occurred_at > receipt.started_at
            or receipt.completed_at > completed.occurred_at
        ):
            raise WebZAPSourceMeasurementError(
                "WEB-002B completed Target journal lifecycle differs"
            )
        operations.append(operation)
        previous_time = completed.occurred_at
    return attempt, operations[2], operations[3]


def _require_completed_source_before_measurement(
    case: WebMeasuredCaseAuthority,
    *,
    source_outcome: BenchmarkRegistryGovernedHarnessOutcome,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    journal: BenchmarkTargetOperationJournal,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> None:
    load_registry_governed_benchmark_observation(
        case.scanner_plan.manifest,
        source_outcome,
        activation_store=activation_store,
        distribution_trust_anchor=distribution_trust_anchor,
    )
    target = load_benchmark_target_run_authority(
        case.scanner_plan.manifest,
        source_outcome.target,
    )
    execution_evidence, raw_sarif, normalization = catalog_provider.verify_target_run_match(target)
    cleanup_evidence = catalog_provider.evidence(target.cleanup_receipt)
    _, execution_operation, cleanup_operation = _completed_journal_context(
        journal,
        target,
    )
    _require_completed_target_evidence(
        case,
        target=target,
        execution_operation=execution_operation,
        cleanup_operation=cleanup_operation,
        execution_evidence=execution_evidence,
        cleanup_evidence=cleanup_evidence,
        raw_sarif=raw_sarif,
        normalization=normalization,
        catalog_provider=catalog_provider,
    )


def _require_completed_target_evidence(
    case: WebMeasuredCaseAuthority,
    *,
    target: BenchmarkTargetRunAuthority,
    execution_operation: BenchmarkTargetOperation,
    cleanup_operation: BenchmarkTargetOperation,
    execution_evidence: DockerBenchmarkProviderEvidence,
    cleanup_evidence: DockerBenchmarkProviderEvidence,
    raw_sarif: bytes,
    normalization: ZAPSarifNormalization,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
) -> None:
    profile = catalog_provider.profile
    execution = target.execution_receipt
    cleanup = target.cleanup_receipt
    raw_sha256 = sha256(raw_sarif).hexdigest()
    if (
        cleanup.status != "succeeded"
        or target.observation.cleanup_succeeded is not True
        or execution.provider_evidence_digest != execution_evidence.evidence_digest
        or cleanup.provider_evidence_digest != cleanup_evidence.evidence_digest
        or execution_evidence.stage != "execution"
        or cleanup_evidence.stage != "cleanup"
        or execution_evidence.operation_id != execution_operation.operation_id
        or execution_evidence.operation_digest != execution_operation.operation_digest
        or cleanup_evidence.operation_id != cleanup_operation.operation_id
        or cleanup_evidence.operation_digest != cleanup_operation.operation_digest
        or execution_evidence.fence != execution_operation.fence
        or cleanup_evidence.fence != cleanup_operation.fence
        or execution_evidence.adapter_digest != target.adapter.adapter_digest
        or cleanup_evidence.adapter_digest != target.adapter.adapter_digest
        or execution_evidence.coordinate_digest != target.coordinate.coordinate_digest
        or cleanup_evidence.coordinate_digest != target.coordinate.coordinate_digest
        or execution_evidence.environment_id != execution.environment_id
        or cleanup_evidence.environment_id != cleanup.environment_id
        or execution_evidence.isolation_id != execution.isolation_id
        or cleanup_evidence.isolation_id != cleanup.isolation_id
        or not execution.started_at <= execution_evidence.observed_at <= execution.completed_at
        or not cleanup.started_at <= cleanup_evidence.observed_at <= cleanup.completed_at
        or execution_evidence.target_image_id != profile.target_image_id
        or cleanup_evidence.target_image_id != profile.target_image_id
        or execution_evidence.worker_image_id != profile.worker_image_id
        or cleanup_evidence.worker_image_id != profile.worker_image_id
        or execution_evidence.scanner_registration_digest
        != case.scanner_registration.registration_digest
        or execution_evidence.scanner_plan_digest != case.scanner_plan.authority_digest
        or execution_evidence.scanner_image_id != case.scanner_registration.scanner_image_id
        or execution_evidence.network_internal is not True
        or execution_evidence.published_port_count != 0
        or execution_evidence.raw_sarif_sha256 != raw_sha256
        or execution_evidence.raw_sarif_size_bytes != len(raw_sarif)
        or execution_evidence.raw_sarif_size_bytes != normalization.raw_sarif_size_bytes
        or normalization.raw_sarif_sha256 != raw_sha256
        or execution_evidence.sarif_normalization_digest != normalization.normalization_digest
        or cleanup_evidence.resources_absent is not True
    ):
        raise WebZAPSourceMeasurementError("WEB-002B completed Target provider evidence differs")


def _require_source_evidence(
    case: WebMeasuredCaseAuthority,
    *,
    source: ScannerBaselineSourceBinding,
    source_outcome: BenchmarkRegistryGovernedHarnessOutcome,
    target: BenchmarkTargetRunAuthority,
    execution_operation: BenchmarkTargetOperation,
    cleanup_operation: BenchmarkTargetOperation,
    execution_evidence: DockerBenchmarkProviderEvidence,
    cleanup_evidence: DockerBenchmarkProviderEvidence,
    raw_sarif: bytes,
    normalization: ZAPSarifNormalization,
    observation_outcome: WalkingBenchmarkRunObservationOutcome,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
) -> None:
    harness = source_outcome.authority
    _require_completed_target_evidence(
        case,
        target=target,
        execution_operation=execution_operation,
        cleanup_operation=cleanup_operation,
        execution_evidence=execution_evidence,
        cleanup_evidence=cleanup_evidence,
        raw_sarif=raw_sarif,
        normalization=normalization,
        catalog_provider=catalog_provider,
    )
    if (
        observation_outcome.observation != target.observation
        or source.observation != target.observation
        or source.harness_run_id != source_outcome.run_id
        or source.harness_authority_digest != harness.authority_digest
        or source.registry_admission_authority_digest
        != harness.registry_admission_authority.authority_digest
        or source.target_run_id != source_outcome.target.run_id
        or source.target_authority_digest != target.authority_digest
        or source.target_attestation_digest != target.attestation.digest
        or source.target_coordinate_digest != target.coordinate.coordinate_digest
        or source.execution_receipt_digest != target.execution_receipt.receipt_digest
        or source.execution_operation_id != execution_operation.operation_id
        or source.execution_provider_evidence_digest != execution_evidence.evidence_digest
        or source.provider_evidence != execution_evidence
        or source.raw_sarif_sha256 != sha256(raw_sarif).hexdigest()
        or source.normalization != normalization
    ):
        raise WebZAPSourceMeasurementError("WEB-002B source evidence or cleanup lineage differs")


def _seal(
    output_root: Path,
    source_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
    scanner_outcome: ScannerBaselineMeasurementOutcome,
    authority: WebZAPSourceMeasurementAuthority,
) -> WebZAPSourceMeasurementOutcome:
    store = RunStore.create(output_root, "web-zap-source-measurement")
    store.append_event(
        "campaign.started",
        _started_event_payload(authority),
    )
    authority_path = store.write_json(
        _AUTHORITY_ARTIFACT,
        authority.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "benchmark.web-zap-source-measurement.sealed",
        _event_payload(authority),
    )
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "completed",
            "stage": "web-zap-source-measurement-sealed",
            "authorityId": authority.authority_id,
        },
    )
    store.append_event(
        "campaign.completed",
        _completed_event_payload(),
    )
    store.seal()
    return WebZAPSourceMeasurementOutcome(
        run_id=store.run_id,
        run_path=store.path,
        authority_path=authority_path,
        source_outcomes=source_outcomes,
        scanner_measurement_outcome=scanner_outcome,
        authority=authority.model_copy(deep=True),
    )


def _event_payload(authority: WebZAPSourceMeasurementAuthority) -> dict[str, object]:
    return {
        "artifact": _AUTHORITY_ARTIFACT,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "measuredCaseAuthorityId": authority.measured_case.authority_id,
        "measuredCaseAuthorityDigest": authority.measured_case.authority_digest,
        "measurementRunId": authority.measurement_run_id,
        "measurementRootDigest": authority.measurement_root_digest,
        "scannerMeasurementAuthorityDigest": (authority.scanner_measurement_authority_digest),
        "baselineResultDigest": authority.baseline_result_digest,
        "sourceCount": len(authority.lineages),
        "measurementState": authority.measurement_state,
        "targetCleanupVerified": authority.target_cleanup_verified,
        "controlledValidationExecuted": authority.controlled_validation_executed,
        "benchmarkValidationFloorSatisfied": (authority.benchmark_validation_floor_satisfied),
        "findingAuthorized": authority.finding_authorized,
        "graphAdmissionAuthorized": authority.graph_admission_authorized,
        "additionalExecutionAuthorized": authority.additional_execution_authorized,
    }


def _started_event_payload(
    authority: WebZAPSourceMeasurementAuthority,
) -> dict[str, object]:
    return {
        "purpose": "web-zap-source-measurement",
        "measuredCaseAuthorityId": authority.measured_case.authority_id,
        "measurementRunId": authority.measurement_run_id,
    }


def _completed_event_payload() -> dict[str, object]:
    return {
        "purpose": "web-zap-source-measurement",
        "artifact": _AUTHORITY_ARTIFACT,
    }


def _strict_run_json_bytes(value: object) -> bytes:
    serialized = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return (serialized + "\n").encode("utf-8")


__all__ = [
    "WEB_ZAP_SOURCE_LINEAGE_API_VERSION",
    "WEB_ZAP_SOURCE_MEASUREMENT_API_VERSION",
    "WebZAPSourceLineage",
    "WebZAPSourceMeasurementAuthority",
    "WebZAPSourceMeasurementAuthorityRef",
    "WebZAPSourceMeasurementError",
    "WebZAPSourceMeasurementOutcome",
    "WebZAPSourceMeasurementReopenContext",
    "WebZAPSourceMeasurementRunner",
    "load_web_zap_source_measurement_authority",
]
