"""Sealed WEB-002D controlled validation, floor evaluation, and bounded Finding."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderError,
    DockerBenchmarkProviderEvidence,
)
from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.scanner_docker_provider import (
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    require_production_zap_catalog_provider,
)
from pajin.benchmark.target_factory import (
    BenchmarkTargetCoordinate,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetAttempt,
    BenchmarkTargetOperation,
    BenchmarkTargetOperationJournal,
    BenchmarkTargetOperationRecord,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimLedger,
    WebControlledValidationRouteClaimReceipt,
    WebControlledValidationRouteDenialReceipt,
    load_web_controlled_validation_route_claim_receipt,
    load_web_controlled_validation_route_denial_receipt,
)
from pajin.workflow.web_controlled_validation_runtime import (
    DockerWebControlledValidationAdapter,
    WebControlledValidationWorkerEvidence,
    require_production_web_controlled_validation_adapter,
)
from pajin.workflow.web_measured_case_authority import (
    WebMeasuredCaseAuthority,
    WebMeasuredCaseAuthorityRef,
)
from pajin.workflow.web_proxy_route_authority import (
    WebProxyRouteAuthorityError,
    WebProxyRouteBundle,
    WebProxyRouteLiveAuthorityContext,
    WebProxyRouteTargetCleanupInvalidated,
    WebProxyRouteTrustAnchor,
    WebProxyRouteVerification,
    load_spent_web_proxy_route_verification,
)
from pajin.workflow.web_replay_benchmark import WebAPIBenchmarkGroundTruthProfile
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementAuthorityRef,
    WebZAPSourceMeasurementReopenContext,
)
from pajin.workflow.web_validation_evaluation import (
    WebBenchmarkFindingProjection,
    WebControlledValidationIdentitySet,
    WebObservedPolicyDenial,
    WebValidationFloorEvaluation,
    _WebValidationEvaluationGate,
    observe_web_source_request_units,
    web_controlled_validation_identity_digest,
)
from pajin.workflow.web_validation_floor import (
    WebBenchmarkFindingProjectionPolicyRef,
    WebBenchmarkValidationFloorPolicy,
    WebBenchmarkValidationFloorPolicyRef,
    WebExpectedFindingProjectionMapping,
)

WEB_CONTROLLED_VALIDATION_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/web-controlled-validation-authority/v1alpha1"
] = "pajin.dev/web-controlled-validation-authority/v1alpha1"

_AUTHORITY_ARTIFACT = "web-controlled-validation-authority.json"
_MAX_AUTHORITY_BYTES = 24 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class WebControlledValidationAuthorityError(RuntimeError):
    """Raised when WEB-002D lineage cannot be rebuilt exactly."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class WebControlledValidationTargetLifecycle(_FrozenStrictModel):
    """One completed fresh P0-D1 Target lifecycle around controlled validation."""

    lifecycle_digest: str = Field(default="", alias="lifecycleDigest", max_length=64)
    adapter: RegisteredBenchmarkTargetFactoryAdapter
    coordinate: BenchmarkTargetCoordinate
    attempt: BenchmarkTargetAttempt
    reset_operation: BenchmarkTargetOperation = Field(alias="resetOperation")
    reset_receipt: BenchmarkTargetStageReceipt = Field(alias="resetReceipt")
    reset_evidence: DockerBenchmarkProviderEvidence = Field(alias="resetEvidence")
    isolation_operation: BenchmarkTargetOperation = Field(alias="isolationOperation")
    isolation_receipt: BenchmarkTargetStageReceipt = Field(alias="isolationReceipt")
    isolation_evidence: DockerBenchmarkProviderEvidence = Field(alias="isolationEvidence")
    execution_operation: BenchmarkTargetOperation = Field(alias="executionOperation")
    execution_receipt: BenchmarkTargetStageReceipt = Field(alias="executionReceipt")
    worker_evidence: WebControlledValidationWorkerEvidence = Field(alias="workerEvidence")
    cleanup_operation: BenchmarkTargetOperation = Field(alias="cleanupOperation")
    cleanup_receipt: BenchmarkTargetStageReceipt = Field(alias="cleanupReceipt")
    cleanup_evidence: DockerBenchmarkProviderEvidence = Field(alias="cleanupEvidence")

    @model_validator(mode="after")
    def bind_lifecycle(self) -> Self:
        operations = (
            self.reset_operation,
            self.isolation_operation,
            self.execution_operation,
            self.cleanup_operation,
        )
        receipts = (
            self.reset_receipt,
            self.isolation_receipt,
            self.execution_receipt,
            self.cleanup_receipt,
        )
        stages = ("reset", "isolation", "execution", "cleanup")
        common = (
            self.attempt.attempt_id,
            self.attempt.attempt_digest,
            self.adapter.adapter_digest,
            self.coordinate.coordinate_digest,
            self.attempt.fence,
        )
        for stage, operation, receipt in zip(stages, operations, receipts, strict=True):
            if (
                operation.stage != stage
                or operation.ordinal != 1
                or (
                    operation.attempt_id,
                    operation.attempt_digest,
                    operation.adapter_digest,
                    operation.coordinate_digest,
                    operation.fence,
                )
                != common
                or receipt.stage != stage
                or receipt.operation_id != operation.operation_id
                or receipt.adapter_digest != self.adapter.adapter_digest
                or receipt.coordinate_digest != self.coordinate.coordinate_digest
                or receipt.status != "succeeded"
            ):
                raise ValueError("WEB-002D Target lifecycle operation or receipt differs")
        provider_pairs = (
            (self.reset_operation, self.reset_receipt, self.reset_evidence),
            (self.isolation_operation, self.isolation_receipt, self.isolation_evidence),
            (self.cleanup_operation, self.cleanup_receipt, self.cleanup_evidence),
        )
        for operation, receipt, evidence in provider_pairs:
            if (
                evidence.stage != operation.stage
                or evidence.operation_id != operation.operation_id
                or evidence.operation_digest != operation.operation_digest
                or evidence.adapter_digest != self.adapter.adapter_digest
                or evidence.coordinate_digest != self.coordinate.coordinate_digest
                or evidence.fence != self.attempt.fence
                or evidence.evidence_digest != receipt.provider_evidence_digest
                or evidence.environment_id != receipt.environment_id
                or evidence.isolation_id != receipt.isolation_id
            ):
                raise ValueError("WEB-002D Target provider Evidence differs")
        if (
            len(
                {
                    (evidence.target_image_id, evidence.worker_image_id)
                    for _, _, evidence in provider_pairs
                }
            )
            != 1
        ):
            raise ValueError("WEB-002D Target provider image identities differ by stage")
        worker = self.worker_evidence
        isolation_id = self.isolation_receipt.isolation_id
        if (
            self.attempt.adapter_digest != self.adapter.adapter_digest
            or self.attempt.coordinate_digest != self.coordinate.coordinate_digest
            or self.execution_receipt.provider_evidence_digest != worker.evidence_digest
            or self.execution_receipt.environment_id != self.isolation_receipt.environment_id
            or self.execution_receipt.isolation_id != isolation_id
            or self.cleanup_receipt.environment_id != self.isolation_receipt.environment_id
            or self.cleanup_receipt.isolation_id != isolation_id
            or worker.target_attempt_id != self.attempt.attempt_id
            or worker.target_execution_operation_id != self.execution_operation.operation_id
            or worker.target_fence != self.attempt.fence
            or self.reset_evidence.resources_absent is not True
            or self.cleanup_evidence.resources_absent is not True
            or self.isolation_evidence.network_internal is not True
            or self.isolation_evidence.published_port_count != 0
            or self.isolation_evidence.network_container_count != 1
            or self.isolation_evidence.target_healthy is not True
            or not self.attempt.started_at <= self.reset_receipt.started_at
            or not self.reset_receipt.completed_at <= self.isolation_receipt.started_at
            or not self.isolation_receipt.completed_at <= self.execution_receipt.started_at
            or not self.execution_receipt.completed_at <= self.cleanup_receipt.started_at
        ):
            raise ValueError("WEB-002D Target lifecycle lineage differs")
        digest = benchmark_digest(
            "pajin.workflow.web-controlled-validation-target-lifecycle/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"lifecycle_digest"}),
            max_bytes=16 * 1024 * 1024,
        )
        if self.lifecycle_digest and self.lifecycle_digest != digest:
            raise ValueError("WEB-002D Target lifecycle Digest differs")
        object.__setattr__(self, "lifecycle_digest", digest)
        return self


class WebCleanupBeforeRouteDenialLifecycle(_FrozenStrictModel):
    """A fresh Target attempt cleaned up before route verification or execution."""

    lifecycle_digest: str = Field(default="", alias="lifecycleDigest", max_length=64)
    adapter: RegisteredBenchmarkTargetFactoryAdapter
    coordinate: BenchmarkTargetCoordinate
    attempt: BenchmarkTargetAttempt
    reset_operation: BenchmarkTargetOperation = Field(alias="resetOperation")
    reset_receipt: BenchmarkTargetStageReceipt = Field(alias="resetReceipt")
    reset_evidence: DockerBenchmarkProviderEvidence = Field(alias="resetEvidence")
    isolation_operation: BenchmarkTargetOperation = Field(alias="isolationOperation")
    isolation_receipt: BenchmarkTargetStageReceipt = Field(alias="isolationReceipt")
    isolation_evidence: DockerBenchmarkProviderEvidence = Field(alias="isolationEvidence")
    execution_operation: BenchmarkTargetOperation = Field(alias="executionOperation")
    cleanup_operation: BenchmarkTargetOperation = Field(alias="cleanupOperation")
    cleanup_receipt: BenchmarkTargetStageReceipt = Field(alias="cleanupReceipt")
    cleanup_evidence: DockerBenchmarkProviderEvidence = Field(alias="cleanupEvidence")

    @model_validator(mode="after")
    def bind_lifecycle(self) -> Self:
        operations = (
            self.reset_operation,
            self.isolation_operation,
            self.execution_operation,
            self.cleanup_operation,
        )
        common = (
            self.attempt.attempt_id,
            self.attempt.attempt_digest,
            self.adapter.adapter_digest,
            self.coordinate.coordinate_digest,
            self.attempt.fence,
        )
        if (
            self.attempt.adapter_digest != self.adapter.adapter_digest
            or self.attempt.coordinate_digest != self.coordinate.coordinate_digest
            or tuple(operation.stage for operation in operations)
            != ("reset", "isolation", "execution", "cleanup")
            or any(
                operation.ordinal != 1
                or (
                    operation.attempt_id,
                    operation.attempt_digest,
                    operation.adapter_digest,
                    operation.coordinate_digest,
                    operation.fence,
                )
                != common
                for operation in operations
            )
        ):
            raise ValueError("WEB-002D denial Target operation lineage differs")
        for operation, receipt, evidence in (
            (self.reset_operation, self.reset_receipt, self.reset_evidence),
            (
                self.isolation_operation,
                self.isolation_receipt,
                self.isolation_evidence,
            ),
            (self.cleanup_operation, self.cleanup_receipt, self.cleanup_evidence),
        ):
            if (
                receipt.stage != operation.stage
                or receipt.operation_id != operation.operation_id
                or receipt.adapter_digest != self.adapter.adapter_digest
                or receipt.coordinate_digest != self.coordinate.coordinate_digest
                or receipt.status != "succeeded"
                or evidence.stage != operation.stage
                or evidence.operation_id != operation.operation_id
                or evidence.operation_digest != operation.operation_digest
                or evidence.adapter_digest != self.adapter.adapter_digest
                or evidence.coordinate_digest != self.coordinate.coordinate_digest
                or evidence.fence != self.attempt.fence
                or evidence.evidence_digest != receipt.provider_evidence_digest
                or evidence.environment_id != receipt.environment_id
                or evidence.isolation_id != receipt.isolation_id
                or not receipt.started_at <= evidence.observed_at <= receipt.completed_at
            ):
                raise ValueError("WEB-002D denial Target provider Evidence differs")
        if (
            len(
                {
                    (evidence.target_image_id, evidence.worker_image_id)
                    for evidence in (
                        self.reset_evidence,
                        self.isolation_evidence,
                        self.cleanup_evidence,
                    )
                }
            )
            != 1
        ):
            raise ValueError("WEB-002D denial provider image identities differ by stage")
        isolation_id = self.isolation_receipt.isolation_id
        if (
            self.reset_evidence.resources_absent is not True
            or self.cleanup_evidence.resources_absent is not True
            or self.isolation_evidence.network_internal is not True
            or self.isolation_evidence.published_port_count != 0
            or self.isolation_evidence.network_container_count != 1
            or self.isolation_evidence.target_healthy is not True
            or isolation_id is None
            or self.reset_receipt.environment_id != self.isolation_receipt.environment_id
            or self.cleanup_receipt.environment_id != self.isolation_receipt.environment_id
            or self.cleanup_receipt.isolation_id != isolation_id
            or not self.attempt.started_at <= self.reset_receipt.started_at
            or not self.reset_receipt.completed_at <= self.isolation_receipt.started_at
            or not self.isolation_receipt.completed_at <= self.cleanup_receipt.started_at
        ):
            raise ValueError("WEB-002D denial Target lifecycle boundary differs")
        digest = benchmark_digest(
            "pajin.workflow.web-cleanup-before-route-denial-lifecycle/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"lifecycle_digest"}),
            max_bytes=16 * 1024 * 1024,
        )
        if self.lifecycle_digest and self.lifecycle_digest != digest:
            raise ValueError("WEB-002D denial Target lifecycle Digest differs")
        object.__setattr__(self, "lifecycle_digest", digest)
        return self


class WebCleanupBeforeRouteDenialEvidence(_FrozenStrictModel):
    """Durable proof that exact cleanup terminally denied a route pre-execution."""

    evidence_id: str = Field(default="", alias="evidenceId", max_length=120)
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    route_bundle: WebProxyRouteBundle = Field(alias="routeBundle")
    route_denial_receipt: WebControlledValidationRouteDenialReceipt = Field(
        alias="routeDenialReceipt"
    )
    target_lifecycle: WebCleanupBeforeRouteDenialLifecycle = Field(alias="targetLifecycle")
    observation: WebObservedPolicyDenial
    evaluated_at: datetime = Field(alias="evaluatedAt")
    typed_cleanup_invalidation_observed: Literal[True] = Field(
        default=True,
        alias="typedCleanupInvalidationObserved",
    )
    route_claim_absent: Literal[True] = Field(default=True, alias="routeClaimAbsent")
    execution_receipt_absent: Literal[True] = Field(
        default=True,
        alias="executionReceiptAbsent",
    )
    worker_dispatched: Literal[False] = Field(default=False, alias="workerDispatched")
    controlled_provider_execution_performed: Literal[False] = Field(
        default=False,
        alias="controlledProviderExecutionPerformed",
    )
    network_access_performed: Literal[False] = Field(
        default=False,
        alias="networkAccessPerformed",
    )

    @field_validator(
        "typed_cleanup_invalidation_observed",
        "route_claim_absent",
        "execution_receipt_absent",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002D denial Evidence markers must be boolean true")
        return value

    @field_validator(
        "worker_dispatched",
        "controlled_provider_execution_performed",
        "network_access_performed",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002D denial Evidence side effects must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        statement = self.route_bundle.route.statement
        lifecycle = self.target_lifecycle
        target = statement.target
        if (
            self.evaluated_at.tzinfo is None
            or self.evaluated_at.utcoffset() is None
            or self.route_denial_receipt.slot_digest != statement.consumption_slot_digest
            or self.route_denial_receipt.route_digest != statement.route_digest
            or self.route_denial_receipt.denied_at != self.evaluated_at
            or not statement.not_before <= self.evaluated_at < statement.expires_at
            or statement.issued_at > lifecycle.cleanup_receipt.started_at
            or target.adapter_digest != lifecycle.adapter.adapter_digest
            or target.coordinate_id != lifecycle.coordinate.coordinate_id
            or target.coordinate_digest != lifecycle.coordinate.coordinate_digest
            or target.attempt_id != lifecycle.attempt.attempt_id
            or target.attempt_digest != lifecycle.attempt.attempt_digest
            or target.active_fence != lifecycle.attempt.fence
            or target.isolation_operation_id != lifecycle.isolation_operation.operation_id
            or target.isolation_operation_digest != lifecycle.isolation_operation.operation_digest
            or target.execution_operation_id != lifecycle.execution_operation.operation_id
            or target.execution_operation_digest != lifecycle.execution_operation.operation_digest
            or target.isolation_receipt_id != lifecycle.isolation_receipt.receipt_id
            or target.isolation_receipt_digest != lifecycle.isolation_receipt.receipt_digest
            or target.isolation_provider_evidence_digest
            != lifecycle.isolation_evidence.evidence_digest
            or target.environment_id != lifecycle.isolation_receipt.environment_id
            or target.isolation_id != lifecycle.isolation_receipt.isolation_id
            or target.target_image_id != lifecycle.isolation_evidence.target_image_id
            or target.benchmark_worker_image_id != lifecycle.isolation_evidence.worker_image_id
        ):
            raise ValueError("WEB-002D denial Evidence route lineage differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_id", "evidence_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-cleanup-before-route-denial-evidence/v1",
            material,
            max_bytes=20 * 1024 * 1024,
        )
        evidence_id = f"web-cleanup-before-route-denial:{digest}"
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("WEB-002D denial Evidence Digest differs")
        if self.evidence_id and self.evidence_id != evidence_id:
            raise ValueError("WEB-002D denial Evidence ID differs")
        object.__setattr__(self, "evidence_digest", digest)
        object.__setattr__(self, "evidence_id", evidence_id)
        return self


class WebControlledValidationAuthority(_FrozenStrictModel):
    """Public-safe sealed proof of one bounded independent benchmark Finding."""

    api_version: Literal["pajin.dev/web-controlled-validation-authority/v1alpha1"] = Field(
        default=WEB_CONTROLLED_VALIDATION_AUTHORITY_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebControlledValidationAuthority"] = "WebControlledValidationAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    source_measurement: WebZAPSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    floor_policy: WebBenchmarkValidationFloorPolicyRef = Field(alias="floorPolicy")
    projection_policy: WebBenchmarkFindingProjectionPolicyRef = Field(alias="projectionPolicy")
    validation_identities: WebControlledValidationIdentitySet = Field(alias="validationIdentities")
    route_bundle: WebProxyRouteBundle = Field(alias="routeBundle")
    route_verification: WebProxyRouteVerification = Field(alias="routeVerification")
    route_claim_receipt: WebControlledValidationRouteClaimReceipt = Field(alias="routeClaimReceipt")
    target_lifecycle: WebControlledValidationTargetLifecycle = Field(alias="targetLifecycle")
    denial_evidence: WebCleanupBeforeRouteDenialEvidence = Field(alias="denialEvidence")
    floor_evaluation: WebValidationFloorEvaluation = Field(alias="floorEvaluation")
    finding: WebBenchmarkFindingProjection
    state: Literal["sealed-independent-controlled-validation-bounded-finding"] = (
        "sealed-independent-controlled-validation-bounded-finding"
    )
    source_measurement_verified: Literal[True] = Field(
        default=True, alias="sourceMeasurementVerified"
    )
    fresh_identity_separation_verified: Literal[True] = Field(
        default=True, alias="freshIdentitySeparationVerified"
    )
    route_signature_verified: Literal[True] = Field(default=True, alias="routeSignatureVerified")
    route_consumed_once: Literal[True] = Field(default=True, alias="routeConsumedOnce")
    proxy_only_controlled_validation_verified: Literal[True] = Field(
        default=True, alias="proxyOnlyControlledValidationVerified"
    )
    independent_replay_verified: Literal[True] = Field(
        default=True, alias="independentReplayVerified"
    )
    policy_denial_control_satisfied: Literal[True] = Field(
        default=True, alias="policyDenialControlSatisfied"
    )
    target_cleanup_verified: Literal[True] = Field(default=True, alias="targetCleanupVerified")
    benchmark_validation_floor_satisfied: Literal[True] = Field(
        default=True, alias="benchmarkValidationFloorSatisfied"
    )
    finding_projection_performed: Literal[True] = Field(
        default=True, alias="findingProjectionPerformed"
    )
    bounded_product_finding_confirmed: Literal[True] = Field(
        default=True, alias="boundedProductFindingConfirmed"
    )
    private_ground_truth_disclosure_authorized: Literal[False] = Field(
        default=False, alias="privateGroundTruthDisclosureAuthorized"
    )
    raw_sarif_disclosure_authorized: Literal[False] = Field(
        default=False, alias="rawSarifDisclosureAuthorized"
    )
    controlled_query_disclosure_authorized: Literal[False] = Field(
        default=False, alias="controlledQueryDisclosureAuthorized"
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False, alias="graphMutationAuthorized"
    )
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False, alias="externalDeliveryAuthorized"
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False, alias="additionalExecutionAuthorized"
    )

    @field_validator(
        "source_measurement_verified",
        "fresh_identity_separation_verified",
        "route_signature_verified",
        "route_consumed_once",
        "proxy_only_controlled_validation_verified",
        "independent_replay_verified",
        "policy_denial_control_satisfied",
        "target_cleanup_verified",
        "benchmark_validation_floor_satisfied",
        "finding_projection_performed",
        "bounded_product_finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002D completion markers must be boolean true")
        return value

    @field_validator(
        "private_ground_truth_disclosure_authorized",
        "raw_sarif_disclosure_authorized",
        "controlled_query_disclosure_authorized",
        "scope_expansion_authorized",
        "graph_mutation_authorized",
        "reporting_authorized",
        "external_delivery_authorized",
        "permit_issuance_authorized",
        "additional_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002D cannot grant downstream authority")
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        statement = self.route_bundle.route.statement
        lifecycle = self.target_lifecycle
        denial = self.denial_evidence
        denial_statement = denial.route_bundle.route.statement
        denial_lifecycle = denial.target_lifecycle
        claim = self.route_claim_receipt
        worker = lifecycle.worker_evidence
        identities = self.validation_identities
        success_ids = {
            lifecycle.attempt.attempt_id,
            lifecycle.execution_operation.operation_id,
            lifecycle.cleanup_operation.operation_id,
            statement.route_id,
            statement.approval_id,
            statement.permit_id,
            statement.request_id,
            statement.dispatch_id,
            statement.consumption_slot_digest,
        }
        denial_ids = {
            denial_lifecycle.attempt.attempt_id,
            denial_lifecycle.execution_operation.operation_id,
            denial_lifecycle.cleanup_operation.operation_id,
            denial_statement.route_id,
            denial_statement.approval_id,
            denial_statement.permit_id,
            denial_statement.request_id,
            denial_statement.dispatch_id,
            denial_statement.consumption_slot_digest,
        }
        if (
            statement.measured_case != self.measured_case
            or self.route_verification.route_id != statement.route_id
            or self.route_verification.route_digest != statement.route_digest
            or self.route_verification.bundle_digest != self.route_bundle.digest
            or claim.slot_digest != statement.consumption_slot_digest
            or claim.route_digest != statement.route_digest
            or claim.verification_digest != self.route_verification.verification_digest
            or worker.route_claim_receipt_digest != claim.receipt_digest
            or identities.target_attempt_id != lifecycle.attempt.attempt_id
            or identities.execution_operation_id != lifecycle.execution_operation.operation_id
            or identities.cleanup_operation_id != lifecycle.cleanup_operation.operation_id
            or identities.route_id != statement.route_id
            or identities.approval_id != statement.approval_id
            or identities.permit_id != statement.permit_id
            or identities.worker_execution_id != worker.worker_result.execution_id
            or identities.dispatch_id != statement.dispatch_id
            or identities.tool_request_id != worker.request.request_id
            or identities.result_evidence_id != worker.evidence_id
            or identities.target_fence != lifecycle.attempt.fence
            or self.floor_evaluation.floor_policy != self.floor_policy
            or self.floor_evaluation.projection_policy != self.projection_policy
            or self.floor_evaluation.source_measurement != self.source_measurement
            or self.floor_evaluation.validation_identity_digest
            != web_controlled_validation_identity_digest(identities)
            or self.floor_evaluation.denial_control != denial.observation
            or self.finding.evaluation != self.floor_evaluation.reference()
            or self.finding.projection_policy != self.projection_policy
            or self.finding.source_measurement != self.source_measurement
            or claim.claimed_at > worker.target_before.observed_at
            or denial_statement.measured_case != self.measured_case
            or denial_lifecycle.adapter != lifecycle.adapter
            or denial_lifecycle.coordinate != lifecycle.coordinate
            or denial_lifecycle.attempt.fence <= lifecycle.attempt.fence
            or not success_ids.isdisjoint(denial_ids)
        ):
            raise ValueError("WEB-002D sealed authority lineage differs")
        digest = benchmark_digest(
            "pajin.workflow.web-controlled-validation-authority/v1",
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"authority_id", "authority_digest"},
            ),
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"web-controlled-validation:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("WEB-002D authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("WEB-002D authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self

    @property
    def denial_control(self) -> WebObservedPolicyDenial:
        return self.denial_evidence.observation


@dataclass(frozen=True, slots=True)
class WebControlledValidationAuthorityOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    authority: WebControlledValidationAuthority


class WebControlledValidationEvidenceProvider(Protocol):
    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter: ...

    def evidence(self, receipt: BenchmarkTargetStageReceipt) -> DockerBenchmarkProviderEvidence: ...


def observe_web_cleanup_route_denial(
    *,
    floor_policy: WebBenchmarkValidationFloorPolicy,
    bundle: WebProxyRouteBundle,
    lifecycle: WebCleanupBeforeRouteDenialLifecycle,
    route_authority: WebProxyRouteLiveAuthorityContext,
    claim_ledger: WebControlledValidationRouteClaimLedger,
    provider: WebControlledValidationEvidenceProvider,
    evaluated_at: datetime,
) -> WebCleanupBeforeRouteDenialEvidence:
    """Prove exact cleanup invalidation before claim, Worker, or network activity."""

    try:
        floor = _canonical_exact(
            WebBenchmarkValidationFloorPolicy,
            floor_policy,
            label="WEB-002D denial floor",
        )
        completed = _canonical_exact(
            WebCleanupBeforeRouteDenialLifecycle,
            lifecycle,
            label="WEB-002D denial Target lifecycle",
        )
        route = _canonical_exact(
            WebProxyRouteBundle,
            bundle,
            label="WEB-002D denial route",
        )
        if (
            type(route_authority) is not WebProxyRouteLiveAuthorityContext
            or type(claim_ledger) is not WebControlledValidationRouteClaimLedger
        ):
            raise TypeError("WEB-002D denial requires exact live route and claim state")
        _require_denial_provider_evidence(provider, completed)
        _require_cleanup_before_route_target_journal(
            route_authority.target_journal,
            completed,
            issued_at=route.route.statement.issued_at,
            evaluated_at=evaluated_at,
        )
        statement = route.route.statement
        if (
            route_authority.target_attempt_id != completed.attempt.attempt_id
            or statement.target.attempt_id != completed.attempt.attempt_id
            or statement.target.execution_operation_id != completed.execution_operation.operation_id
            or statement.measured_case != floor.measured_case
            or evaluated_at.tzinfo is None
            or evaluated_at.utcoffset() is None
            or not statement.not_before <= evaluated_at < statement.expires_at
        ):
            raise ValueError("WEB-002D denial verification context differs")
        try:
            route_authority.verify(
                route,
                evaluated_at=evaluated_at,
            )
        except WebProxyRouteTargetCleanupInvalidated:
            denial_receipt = claim_ledger.seal_denial_if_unclaimed(
                slot_digest=statement.consumption_slot_digest,
                route_digest=statement.route_digest,
                denied_at=evaluated_at,
            )
            registry = floor.policy_denial_control_registry
            case = registry.cases[0]
            observation = WebObservedPolicyDenial(
                registryId=registry.registry_id,
                registryDigest=registry.registry_digest,
                caseId=case.case_id,
                caseDigest=case.case_digest,
            )
            return WebCleanupBeforeRouteDenialEvidence(
                routeBundle=route,
                routeDenialReceipt=denial_receipt,
                targetLifecycle=completed,
                observation=observation,
                evaluatedAt=evaluated_at,
            )
        except WebProxyRouteAuthorityError as exc:
            raise WebControlledValidationAuthorityError(
                "WEB-002D denial was not exact cleanup invalidation"
            ) from exc
        raise WebControlledValidationAuthorityError(
            "WEB-002D route remained live after Target cleanup"
        )
    except WebControlledValidationAuthorityError:
        raise
    except (AttributeError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
        raise WebControlledValidationAuthorityError(
            "WEB-002D cleanup denial Control failed closed"
        ) from exc


def _rebuild_web_cleanup_route_denial_evidence(
    *,
    floor: WebBenchmarkValidationFloorPolicy,
    denial: WebCleanupBeforeRouteDenialEvidence,
    route_authority: WebProxyRouteLiveAuthorityContext,
    provider: WebControlledValidationEvidenceProvider,
    durable_receipt: WebControlledValidationRouteDenialReceipt,
) -> WebCleanupBeforeRouteDenialEvidence:
    """Historically rebuild one sealed denial without issuing live authority."""

    if type(route_authority) is not WebProxyRouteLiveAuthorityContext:
        raise TypeError("WEB-002D historical denial requires exact route context")
    route = denial.route_bundle
    completed = denial.target_lifecycle
    evaluated_at = denial.evaluated_at
    _require_denial_provider_evidence(provider, completed)
    _require_cleanup_before_route_target_journal(
        route_authority.target_journal,
        completed,
        issued_at=route.route.statement.issued_at,
        evaluated_at=evaluated_at,
        require_latest_scope_fence=False,
    )
    statement = route.route.statement
    if (
        route_authority.target_attempt_id != completed.attempt.attempt_id
        or statement.target.attempt_id != completed.attempt.attempt_id
        or statement.target.execution_operation_id != completed.execution_operation.operation_id
        or statement.measured_case != floor.measured_case
        or evaluated_at.tzinfo is None
        or evaluated_at.utcoffset() is None
        or not statement.not_before <= evaluated_at < statement.expires_at
    ):
        raise ValueError("WEB-002D historical denial context differs")
    route_authority.verify_cleanup_invalidated_history(
        route,
        evaluated_at=evaluated_at,
    )
    registry = floor.policy_denial_control_registry
    case = registry.cases[0]
    observation = WebObservedPolicyDenial(
        registryId=registry.registry_id,
        registryDigest=registry.registry_digest,
        caseId=case.case_id,
        caseDigest=case.case_digest,
    )
    return WebCleanupBeforeRouteDenialEvidence(
        routeBundle=route,
        routeDenialReceipt=durable_receipt,
        targetLifecycle=completed,
        observation=observation,
        evaluatedAt=evaluated_at,
    )


def build_web_controlled_validation_execution_receipt(
    operation: BenchmarkTargetOperation,
    *,
    isolation_receipt: BenchmarkTargetStageReceipt,
    worker_evidence: WebControlledValidationWorkerEvidence,
) -> BenchmarkTargetStageReceipt:
    """Bind controlled Worker Evidence to the existing fenced Target execution stage."""

    if (
        type(operation) is not BenchmarkTargetOperation
        or type(isolation_receipt) is not BenchmarkTargetStageReceipt
        or type(worker_evidence) is not WebControlledValidationWorkerEvidence
        or operation.stage != "execution"
        or isolation_receipt.stage != "isolation"
        or isolation_receipt.status != "succeeded"
        or worker_evidence.target_execution_operation_id != operation.operation_id
        or worker_evidence.target_execution_operation_digest != operation.operation_digest
        or worker_evidence.target_attempt_id != operation.attempt_id
        or worker_evidence.target_attempt_digest != operation.attempt_digest
        or worker_evidence.target_fence != operation.fence
    ):
        raise WebControlledValidationAuthorityError(
            "WEB-002D execution receipt inputs differ from the fenced Worker Evidence"
        )
    return BenchmarkTargetStageReceipt(
        adapterDigest=operation.adapter_digest,
        coordinateDigest=operation.coordinate_digest,
        stage="execution",
        operationId=operation.operation_id,
        environmentId=isolation_receipt.environment_id,
        isolationId=isolation_receipt.isolation_id,
        status="succeeded",
        startedAt=worker_evidence.worker_result.started_at,
        completedAt=worker_evidence.worker_result.finished_at,
        providerEvidenceDigest=worker_evidence.evidence_digest,
    )


def _require_source_owned_production_provider(
    source_reopen_context: WebZAPSourceMeasurementReopenContext,
    provider: object,
) -> CatalogBoundDockerZAPScannerTargetFactoryAdapter:
    if (
        type(provider) is not CatalogBoundDockerZAPScannerTargetFactoryAdapter
        or provider is not source_reopen_context.catalog_provider
    ):
        raise TypeError("WEB-002D requires the source-owned catalog provider")
    try:
        require_production_zap_catalog_provider(provider)
    except DockerBenchmarkProviderError as exc:
        raise TypeError("WEB-002D requires the production ZAP provider boundary") from exc
    return provider


def build_web_controlled_validation_authority(
    *,
    validation_run_id: str,
    measured_case_authority: WebMeasuredCaseAuthority,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    source_reopen_context: WebZAPSourceMeasurementReopenContext,
    floor_policy: WebBenchmarkValidationFloorPolicy,
    mapping: WebExpectedFindingProjectionMapping,
    route_bundle: WebProxyRouteBundle,
    route_verification: WebProxyRouteVerification,
    route_claim_receipt: WebControlledValidationRouteClaimReceipt,
    target_lifecycle: WebControlledValidationTargetLifecycle,
    denial_evidence: WebCleanupBeforeRouteDenialEvidence,
    denial_route_authority: WebProxyRouteLiveAuthorityContext,
    trust_anchor: WebProxyRouteTrustAnchor,
    claim_ledger: WebControlledValidationRouteClaimLedger,
    target_journal: BenchmarkTargetOperationJournal,
    provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    adapter: DockerWebControlledValidationAdapter,
) -> WebControlledValidationAuthority:
    """Rebuild every predecessor, evaluate the floor, and project one bounded Finding."""

    try:
        if type(source_reopen_context) is not WebZAPSourceMeasurementReopenContext:
            raise TypeError("WEB-002D requires the exact source reopen context")
        if type(adapter) is not DockerWebControlledValidationAdapter:
            raise TypeError("WEB-002D requires the exact controlled Docker adapter")
        _require_source_owned_production_provider(source_reopen_context, provider)
        require_production_web_controlled_validation_adapter(adapter)
        source = source_reopen_context.reopen()
        measured_case = _canonical_exact(
            WebMeasuredCaseAuthority,
            measured_case_authority,
            label="WEB-002D measured-case authority",
        )
        private_profile = _canonical_exact(
            WebAPIBenchmarkGroundTruthProfile,
            private_ground_truth_profile,
            label="WEB-002D private Ground Truth profile",
        )
        floor = _canonical_exact(
            WebBenchmarkValidationFloorPolicy,
            floor_policy,
            label="WEB-002D floor policy",
        )
        lifecycle = _canonical_exact(
            WebControlledValidationTargetLifecycle,
            target_lifecycle,
            label="WEB-002D Target lifecycle",
        )
        denial = _canonical_exact(
            WebCleanupBeforeRouteDenialEvidence,
            denial_evidence,
            label="WEB-002D denial Evidence",
        )
        if (
            type(validation_run_id) is not str
            or not validation_run_id
            or len(validation_run_id) > 200
            or validation_run_id.strip() != validation_run_id
        ):
            raise ValueError("WEB-002D validation Run ID is invalid")
        spent_verification = load_spent_web_proxy_route_verification(
            route_verification,
            route_bundle,
            trust_anchor=trust_anchor,
        )
        claim = load_web_controlled_validation_route_claim_receipt(
            ledger=claim_ledger,
            receipt=route_claim_receipt,
        )
        durable_denial_receipt = load_web_controlled_validation_route_denial_receipt(
            ledger=claim_ledger,
            receipt=denial.route_denial_receipt,
        )
        observed_denial = _rebuild_web_cleanup_route_denial_evidence(
            floor=floor,
            denial=denial,
            route_authority=denial_route_authority,
            provider=provider,
            durable_receipt=durable_denial_receipt,
        )
        worker = adapter.reopen_worker_evidence(
            lifecycle.worker_evidence,
            bundle=route_bundle,
            verification=spent_verification,
            route_claim_receipt=claim,
            coordinate=lifecycle.coordinate,
        )
        _require_provider_evidence(provider, lifecycle)
        _require_completed_target_journal(target_journal, lifecycle)
        statement = route_bundle.route.statement
        target = statement.target
        denial_statement = denial.route_bundle.route.statement
        denial_lifecycle = denial.target_lifecycle
        source_lifecycle_ids = {
            identity
            for lineage in source.lineages
            for identity in (
                lineage.target_attempt_id,
                lineage.execution_operation_id,
                lineage.cleanup_operation_id,
            )
        }
        denial_lifecycle_ids = {
            denial_lifecycle.attempt.attempt_id,
            denial_lifecycle.execution_operation.operation_id,
            denial_lifecycle.cleanup_operation.operation_id,
        }
        source_identity_strings = _collect_strings(source.model_dump(mode="python"))
        source_fences = {lineage.target_fence for lineage in source.lineages}
        denial_identity_strings = {
            denial_lifecycle.attempt.attempt_id,
            denial_lifecycle.execution_operation.operation_id,
            denial_lifecycle.cleanup_operation.operation_id,
            denial_statement.route_id,
            denial_statement.approval_id,
            denial_statement.permit_id,
            denial_statement.dispatch_id,
            denial_statement.request_id,
            denial_statement.consumption_slot_digest,
        }
        if (
            durable_denial_receipt != denial.route_denial_receipt
            or observed_denial != denial
            or adapter.production_boundary_verified is not True
            or source.measured_case != statement.measured_case
            or measured_case.reference() != statement.measured_case
            or floor.measured_case != statement.measured_case
            or floor.reference() != mapping.public_policy.floor_policy
            or mapping.public_policy.reference() != mapping.private_binding.public_projection
            or target.adapter_digest != lifecycle.adapter.adapter_digest
            or target.coordinate_id != lifecycle.coordinate.coordinate_id
            or target.coordinate_digest != lifecycle.coordinate.coordinate_digest
            or target.attempt_id != lifecycle.attempt.attempt_id
            or target.attempt_digest != lifecycle.attempt.attempt_digest
            or target.active_fence != lifecycle.attempt.fence
            or target.isolation_operation_id != lifecycle.isolation_operation.operation_id
            or target.isolation_operation_digest != lifecycle.isolation_operation.operation_digest
            or target.execution_operation_id != lifecycle.execution_operation.operation_id
            or target.execution_operation_digest != lifecycle.execution_operation.operation_digest
            or target.isolation_receipt_id != lifecycle.isolation_receipt.receipt_id
            or target.isolation_receipt_digest != lifecycle.isolation_receipt.receipt_digest
            or target.isolation_provider_evidence_digest
            != lifecycle.isolation_evidence.evidence_digest
            or target.environment_id != lifecycle.isolation_receipt.environment_id
            or target.isolation_id != lifecycle.isolation_receipt.isolation_id
            or target.target_image_id != lifecycle.isolation_evidence.target_image_id
            or target.benchmark_worker_image_id != lifecycle.isolation_evidence.worker_image_id
            or denial_statement.measured_case != statement.measured_case
            or denial_lifecycle.adapter != lifecycle.adapter
            or denial_lifecycle.coordinate != lifecycle.coordinate
            or denial_lifecycle.attempt.fence <= lifecycle.attempt.fence
            or not source_lifecycle_ids.isdisjoint(denial_lifecycle_ids)
            or not source_identity_strings.isdisjoint(denial_identity_strings)
            or denial_lifecycle.attempt.fence in source_fences
            or denial_route_authority.trust_anchor != trust_anchor
            or denial_route_authority.target_journal.path != target_journal.path
        ):
            raise ValueError("WEB-002D route, source, policy, or Target lineage differs")
        identities = WebControlledValidationIdentitySet(
            validationRunId=validation_run_id,
            targetRunId=f"web-controlled-target-run:{lifecycle.attempt.attempt_digest}",
            targetAttemptId=lifecycle.attempt.attempt_id,
            executionOperationId=lifecycle.execution_operation.operation_id,
            cleanupOperationId=lifecycle.cleanup_operation.operation_id,
            routeId=statement.route_id,
            approvalId=statement.approval_id,
            permitId=statement.permit_id,
            workerExecutionId=worker.worker_result.execution_id,
            dispatchId=statement.dispatch_id,
            toolRequestId=worker.request.request_id,
            resultEvidenceId=worker.evidence_id,
            targetFence=lifecycle.attempt.fence,
        )
        evaluated = _WebValidationEvaluationGate().evaluate(
            floor_policy=floor,
            mapping=mapping,
            measured_case_authority=measured_case,
            private_ground_truth_profile=private_profile,
            source_authority=source,
            validation_identities=identities,
            worker_evidence=worker,
            denial_control=denial.observation,
            source_request_units=observe_web_source_request_units(source),
        )
        return WebControlledValidationAuthority(
            measuredCase=statement.measured_case,
            sourceMeasurement=source.reference(),
            floorPolicy=floor.reference(),
            projectionPolicy=mapping.public_policy.reference(),
            validationIdentities=identities,
            routeBundle=route_bundle,
            routeVerification=spent_verification,
            routeClaimReceipt=claim,
            targetLifecycle=lifecycle,
            denialEvidence=denial,
            floorEvaluation=evaluated.evaluation,
            finding=evaluated.finding,
        )
    except WebControlledValidationAuthorityError:
        raise
    except (AttributeError, OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
        raise WebControlledValidationAuthorityError(
            "WEB-002D controlled validation authority failed closed"
        ) from exc


def _canonical_exact[ModelT: StrictModel](
    model: type[ModelT], value: object, *, label: str
) -> ModelT:
    if type(value) is not model or not isinstance(value, StrictModel):
        raise WebControlledValidationAuthorityError(f"{label} requires its exact model type")
    if set(value.__dict__) != set(model.model_fields):
        raise WebControlledValidationAuthorityError(f"{label} contains hidden or missing state")
    canonical = model.model_validate(value.model_dump(mode="python", by_alias=True))
    if canonical != value:
        raise WebControlledValidationAuthorityError(f"{label} is not canonical")
    return canonical


def _collect_strings(value: object) -> set[str]:
    strings: set[str] = set()
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str:
            strings.add(item)
        elif isinstance(item, Mapping):
            pending.extend(item.values())
        elif isinstance(item, (tuple, list, set, frozenset)):
            pending.extend(item)
    return strings


def _require_provider_evidence(
    provider: WebControlledValidationEvidenceProvider,
    lifecycle: WebControlledValidationTargetLifecycle,
) -> None:
    definition = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
        provider.definition.model_dump(mode="python", by_alias=True)
    )
    if definition != lifecycle.adapter:
        raise WebControlledValidationAuthorityError("WEB-002D provider identity differs")
    for receipt, expected in (
        (lifecycle.reset_receipt, lifecycle.reset_evidence),
        (lifecycle.isolation_receipt, lifecycle.isolation_evidence),
        (lifecycle.cleanup_receipt, lifecycle.cleanup_evidence),
    ):
        observed = DockerBenchmarkProviderEvidence.model_validate(
            provider.evidence(receipt).model_dump(mode="python", by_alias=True)
        )
        if observed != expected:
            raise WebControlledValidationAuthorityError(
                "WEB-002D provider Evidence differs from durable state"
            )


def _require_denial_provider_evidence(
    provider: WebControlledValidationEvidenceProvider,
    lifecycle: WebCleanupBeforeRouteDenialLifecycle,
) -> None:
    definition = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
        provider.definition.model_dump(mode="python", by_alias=True)
    )
    if definition != lifecycle.adapter:
        raise WebControlledValidationAuthorityError("WEB-002D denial provider identity differs")
    for receipt, expected in (
        (lifecycle.reset_receipt, lifecycle.reset_evidence),
        (lifecycle.isolation_receipt, lifecycle.isolation_evidence),
        (lifecycle.cleanup_receipt, lifecycle.cleanup_evidence),
    ):
        observed = DockerBenchmarkProviderEvidence.model_validate(
            provider.evidence(receipt).model_dump(mode="python", by_alias=True)
        )
        if observed != expected:
            raise WebControlledValidationAuthorityError(
                "WEB-002D denial provider Evidence differs from durable state"
            )


def _require_cleanup_before_route_target_journal(
    journal: BenchmarkTargetOperationJournal,
    lifecycle: WebCleanupBeforeRouteDenialLifecycle,
    *,
    issued_at: datetime,
    evaluated_at: datetime,
    require_latest_scope_fence: bool = True,
) -> None:
    if type(journal) is not BenchmarkTargetOperationJournal:
        raise WebControlledValidationAuthorityError(
            "WEB-002D denial requires the exact Target operation journal"
        )
    execution = journal.completed_attempt_for_operation(lifecycle.execution_operation.operation_id)
    cleanup = journal.completed_attempt_for_operation(lifecycle.cleanup_operation.operation_id)
    if execution != cleanup:
        raise WebControlledValidationAuthorityError(
            "WEB-002D denial execution and cleanup are not one completed attempt"
        )
    adapter, coordinate, attempt, raw_records = execution
    records = tuple(
        BenchmarkTargetOperationRecord.model_validate(
            record.model_dump(mode="python", by_alias=True)
        )
        for record in raw_records
    )
    expected_sequence = (
        ("intent", lifecycle.reset_operation, None),
        ("receipt", lifecycle.reset_operation, lifecycle.reset_receipt),
        ("intent", lifecycle.isolation_operation, None),
        ("receipt", lifecycle.isolation_operation, lifecycle.isolation_receipt),
        ("intent", lifecycle.execution_operation, None),
        ("intent", lifecycle.cleanup_operation, None),
        ("receipt", lifecycle.cleanup_operation, lifecycle.cleanup_receipt),
    )
    if (
        adapter != lifecycle.adapter
        or coordinate != lifecycle.coordinate
        or attempt != lifecycle.attempt
        or (
            require_latest_scope_fence
            and journal.latest_scope_fence(
                adapter_digest=adapter.adapter_digest,
                coordinate_digest=coordinate.coordinate_digest,
            )
            != attempt.fence
        )
        or len(records) != 7
        or tuple(record.sequence for record in records) != tuple(range(1, 8))
        or tuple(record.previous_record_digest for record in records)
        != (None, *(record.record_digest for record in records[:-1]))
        or any(
            record.record_type != record_type
            or record.operation != operation
            or record.receipt != receipt
            for record, (record_type, operation, receipt) in zip(
                records,
                expected_sequence,
                strict=True,
            )
        )
    ):
        raise WebControlledValidationAuthorityError(
            "WEB-002D denial completed Target journal sequence differs"
        )
    record_times = tuple(record.occurred_at for record in records)
    reset = lifecycle.reset_receipt
    isolation = lifecycle.isolation_receipt
    cleanup_receipt = lifecycle.cleanup_receipt
    if (
        issued_at.tzinfo is None
        or issued_at.utcoffset() is None
        or evaluated_at.tzinfo is None
        or evaluated_at.utcoffset() is None
        or attempt.started_at > record_times[0]
        or any(previous > current for previous, current in pairwise(record_times))
        or record_times[0] > reset.started_at
        or reset.completed_at > record_times[1]
        or reset.completed_at > isolation.started_at
        or record_times[2] > isolation.started_at
        or isolation.completed_at > record_times[3]
        or record_times[4] > issued_at
        or issued_at > record_times[5]
        or record_times[5] > cleanup_receipt.started_at
        or cleanup_receipt.completed_at > record_times[6]
        or record_times[6] > evaluated_at
    ):
        raise WebControlledValidationAuthorityError(
            "WEB-002D denial Target journal time ordering differs"
        )


def _require_completed_target_journal(
    journal: BenchmarkTargetOperationJournal,
    lifecycle: WebControlledValidationTargetLifecycle,
) -> None:
    if type(journal) is not BenchmarkTargetOperationJournal:
        raise WebControlledValidationAuthorityError(
            "WEB-002D requires the exact Target operation journal"
        )
    execution = journal.completed_attempt_for_operation(lifecycle.execution_operation.operation_id)
    cleanup = journal.completed_attempt_for_operation(lifecycle.cleanup_operation.operation_id)
    if execution != cleanup:
        raise WebControlledValidationAuthorityError(
            "WEB-002D execution and cleanup are not one completed Target attempt"
        )
    adapter, coordinate, attempt, records = execution
    operations = (
        lifecycle.reset_operation,
        lifecycle.isolation_operation,
        lifecycle.execution_operation,
        lifecycle.cleanup_operation,
    )
    receipts = (
        lifecycle.reset_receipt,
        lifecycle.isolation_receipt,
        lifecycle.execution_receipt,
        lifecycle.cleanup_receipt,
    )
    if (
        adapter != lifecycle.adapter
        or coordinate != lifecycle.coordinate
        or attempt != lifecycle.attempt
        or len(records) != 8
    ):
        raise WebControlledValidationAuthorityError(
            "WEB-002D completed Target attempt identity differs"
        )
    for index, (operation, receipt) in enumerate(zip(operations, receipts, strict=True)):
        intent = records[index * 2]
        completed = records[index * 2 + 1]
        if (
            intent.sequence != index * 2 + 1
            or completed.sequence != index * 2 + 2
            or intent.record_type != "intent"
            or completed.record_type != "receipt"
            or intent.operation != operation
            or completed.operation != operation
            or intent.receipt is not None
            or completed.receipt != receipt
        ):
            raise WebControlledValidationAuthorityError(
                "WEB-002D completed Target journal sequence differs"
            )


def build_and_seal_web_controlled_validation_authority(
    output_root: Path,
    *,
    validation_run_id: str,
    measured_case_authority: WebMeasuredCaseAuthority,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    source_reopen_context: WebZAPSourceMeasurementReopenContext,
    floor_policy: WebBenchmarkValidationFloorPolicy,
    mapping: WebExpectedFindingProjectionMapping,
    route_bundle: WebProxyRouteBundle,
    route_verification: WebProxyRouteVerification,
    route_claim_receipt: WebControlledValidationRouteClaimReceipt,
    target_lifecycle: WebControlledValidationTargetLifecycle,
    denial_evidence: WebCleanupBeforeRouteDenialEvidence,
    denial_route_authority: WebProxyRouteLiveAuthorityContext,
    trust_anchor: WebProxyRouteTrustAnchor,
    claim_ledger: WebControlledValidationRouteClaimLedger,
    target_journal: BenchmarkTargetOperationJournal,
    provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    adapter: DockerWebControlledValidationAdapter,
) -> WebControlledValidationAuthorityOutcome:
    """Rebuild all live predecessors before writing one bounded authority seal."""

    authority = build_web_controlled_validation_authority(
        validation_run_id=validation_run_id,
        measured_case_authority=measured_case_authority,
        private_ground_truth_profile=private_ground_truth_profile,
        source_reopen_context=source_reopen_context,
        floor_policy=floor_policy,
        mapping=mapping,
        route_bundle=route_bundle,
        route_verification=route_verification,
        route_claim_receipt=route_claim_receipt,
        target_lifecycle=target_lifecycle,
        denial_evidence=denial_evidence,
        denial_route_authority=denial_route_authority,
        trust_anchor=trust_anchor,
        claim_ledger=claim_ledger,
        target_journal=target_journal,
        provider=provider,
        adapter=adapter,
    )
    return _seal_web_controlled_validation_authority(output_root, authority)


def _seal_web_controlled_validation_authority(
    output_root: Path,
    authority: WebControlledValidationAuthority,
) -> WebControlledValidationAuthorityOutcome:
    """Seal one fully rebuilt authority and its bounded audit sequence."""

    canonical = _canonical_exact(
        WebControlledValidationAuthority,
        authority,
        label="WEB-002D authority",
    )
    store = RunStore.create(output_root, "web-controlled-validation")
    store.append_event(
        "campaign.started",
        {
            "purpose": "web-controlled-validation",
            "measuredCaseAuthorityId": canonical.measured_case.authority_id,
        },
    )
    authority_path = store.write_json(
        _AUTHORITY_ARTIFACT,
        canonical.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "benchmark.web-controlled-validation.sealed",
        _event_payload(canonical),
    )
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "completed",
            "stage": "web-controlled-validation-sealed",
            "authorityId": canonical.authority_id,
        },
    )
    store.append_event(
        "campaign.completed",
        {"purpose": "web-controlled-validation", "artifact": _AUTHORITY_ARTIFACT},
    )
    store.seal()
    return WebControlledValidationAuthorityOutcome(
        run_id=store.run_id,
        run_path=store.path,
        authority_path=authority_path,
        authority=canonical.model_copy(deep=True),
    )


def load_web_controlled_validation_authority(
    outcome: WebControlledValidationAuthorityOutcome,
    *,
    measured_case_authority: WebMeasuredCaseAuthority,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    source_reopen_context: WebZAPSourceMeasurementReopenContext,
    floor_policy: WebBenchmarkValidationFloorPolicy,
    mapping: WebExpectedFindingProjectionMapping,
    trust_anchor: WebProxyRouteTrustAnchor,
    claim_ledger: WebControlledValidationRouteClaimLedger,
    target_journal: BenchmarkTargetOperationJournal,
    provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    adapter: DockerWebControlledValidationAdapter,
    denial_route_authority: WebProxyRouteLiveAuthorityContext,
) -> WebControlledValidationAuthority:
    """Reopen the seal and independently rebuild every WEB-002D predecessor."""

    try:
        _require_source_owned_production_provider(source_reopen_context, provider)
        require_production_web_controlled_validation_adapter(adapter)
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={_AUTHORITY_ARTIFACT: _MAX_AUTHORITY_BYTES},
            expected_run_id=outcome.run_id,
        )
        sealed_bytes = snapshot.artifact_bytes(_AUTHORITY_ARTIFACT)
        sealed = WebControlledValidationAuthority.model_validate_json(sealed_bytes)
        expected = build_web_controlled_validation_authority(
            validation_run_id=sealed.validation_identities.validation_run_id,
            measured_case_authority=measured_case_authority,
            private_ground_truth_profile=private_ground_truth_profile,
            source_reopen_context=source_reopen_context,
            floor_policy=floor_policy,
            mapping=mapping,
            route_bundle=sealed.route_bundle,
            route_verification=sealed.route_verification,
            route_claim_receipt=sealed.route_claim_receipt,
            target_lifecycle=sealed.target_lifecycle,
            denial_evidence=sealed.denial_evidence,
            denial_route_authority=denial_route_authority,
            trust_anchor=trust_anchor,
            claim_ledger=claim_ledger,
            target_journal=target_journal,
            provider=provider,
            adapter=adapter,
        )
        event_types = [event.event_type for event in snapshot.events]
        if (
            outcome.authority_path != _AUTHORITY_ARTIFACT
            or sealed != expected
            or outcome.authority != expected
            or sealed_bytes != _strict_run_json_bytes(sealed.model_dump(mode="json", by_alias=True))
            or event_types
            != [
                "campaign.started",
                "benchmark.web-controlled-validation.sealed",
                "campaign.completed",
            ]
            or snapshot.events[0].payload
            != {
                "purpose": "web-controlled-validation",
                "measuredCaseAuthorityId": expected.measured_case.authority_id,
            }
            or snapshot.events[1].payload != _event_payload(expected)
            or snapshot.events[2].payload
            != {"purpose": "web-controlled-validation", "artifact": _AUTHORITY_ARTIFACT}
        ):
            raise WebControlledValidationAuthorityError(
                "WEB-002D sealed authority or audit sequence differs"
            )
        return sealed.model_copy(deep=True)
    except WebControlledValidationAuthorityError:
        raise
    except (
        OSError,
        RunIntegrityError,
        RuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WebControlledValidationAuthorityError(
            "WEB-002D sealed authority could not be verified"
        ) from exc


def _event_payload(authority: WebControlledValidationAuthority) -> dict[str, object]:
    return {
        "artifact": _AUTHORITY_ARTIFACT,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "sourceMeasurementAuthorityId": authority.source_measurement.authority_id,
        "routeDigest": authority.route_bundle.route.statement.route_digest,
        "targetLifecycleDigest": authority.target_lifecycle.lifecycle_digest,
        "evaluationDigest": authority.floor_evaluation.evaluation_digest,
        "findingDigest": authority.finding.finding_digest,
        "state": authority.state,
        "benchmarkValidationFloorSatisfied": True,
        "boundedProductFindingConfirmed": True,
        "additionalExecutionAuthorized": False,
    }


def _strict_run_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


__all__ = [
    "WEB_CONTROLLED_VALIDATION_AUTHORITY_API_VERSION",
    "WebCleanupBeforeRouteDenialEvidence",
    "WebCleanupBeforeRouteDenialLifecycle",
    "WebControlledValidationAuthority",
    "WebControlledValidationAuthorityError",
    "WebControlledValidationAuthorityOutcome",
    "WebControlledValidationEvidenceProvider",
    "WebControlledValidationTargetLifecycle",
    "build_and_seal_web_controlled_validation_authority",
    "build_web_controlled_validation_authority",
    "build_web_controlled_validation_execution_receipt",
    "load_web_controlled_validation_authority",
    "observe_web_cleanup_route_denial",
]
