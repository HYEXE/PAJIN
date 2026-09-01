"""NET-002C independent fresh-Worker Replay and Network floor evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkMetricRef,
    DomainBenchmarkNotApplicableReason,
    resolve_registered_domain_benchmark_metric,
)
from pajin.benchmark.models import BenchmarkMetricUnit, benchmark_digest
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunStore, load_verified_run_artifacts
from pajin.workflow.network_fixture_runtime import (
    NetworkFixtureDockerProvider,
    NetworkFixtureRuntimeError,
    NetworkFixtureTargetLifecycleRunner,
    NetworkSourceImageBinding,
    NetworkSourceImageBindingRef,
)
from pajin.workflow.network_measured_case_authority import (
    NetworkBenchmarkMetricFloorRequirement,
    NetworkMeasuredCaseAuthority,
    NetworkMeasuredCaseAuthorityRef,
    NetworkMeasuredCaseMapping,
    NetworkMeasuredCaseRef,
    NetworkMeasurementProtocolRef,
    NetworkMetricFloorComparison,
    NetworkPrivateGroundTruthBinding,
    NetworkPrivateGroundTruthCase,
    NetworkValidationFloorPolicyRef,
    load_network_measured_case_authority,
    registered_network_measured_case_mapping,
    registered_network_validation_floor_policy,
)
from pajin.workflow.network_service_admission import (
    VerifiedNetworkServiceObservationSource,
    load_verified_network_service_observation_source,
)
from pajin.workflow.network_source_measurement import (
    NetworkPrivateSourceCaseMeasurement,
    NetworkPrivateSourceMeasurementBinding,
    NetworkSourceActionAuthorizer,
    NetworkSourceCaseLineage,
    NetworkSourceExecutionContext,
    NetworkSourceMeasurementAuthority,
    NetworkSourceMeasurementAuthorityRef,
    NetworkSourceMeasurementError,
    NetworkSourceMeasurementOutcome,
    NetworkSourceMeasurementRunner,
    _canonical_authority_context,
    load_network_source_measurement_authority,
)

NETWORK_REPLAY_CASE_EVALUATION_API_VERSION: Literal[
    "pajin.dev/network-replay-case-evaluation/v1alpha1"
] = "pajin.dev/network-replay-case-evaluation/v1alpha1"
NETWORK_REPLAY_FLOOR_EVALUATION_API_VERSION: Literal[
    "pajin.dev/network-replay-floor-evaluation/v1alpha1"
] = "pajin.dev/network-replay-floor-evaluation/v1alpha1"
NETWORK_PRIVATE_REPLAY_EVALUATION_BINDING_API_VERSION: Literal[
    "pajin.dev/network-private-replay-evaluation-binding/v1alpha1"
] = "pajin.dev/network-private-replay-evaluation-binding/v1alpha1"

NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES = (
    "sealed-run-root",
    "approval-consumption-receipt",
    "consumed-one-use-action-permit",
    "completed-dispatch-audit",
    "request-budget-reservation",
    "sealed-execution-evidence",
    "host-trusted-connect-receipt",
    "worker-and-tool-result",
    "isolated-target-coordinate",
    "proxy-only-topology",
    "single-banner-zero-application-write",
    "completed-target-cleanup-journal",
)

_PUBLIC_ARTIFACT = "network-replay-floor-evaluation.json"
_PRIVATE_ARTIFACT = "private/network-replay-evaluation-binding.json"
_MAX_CANONICAL_BYTES = 64 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=220, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,219}$"),
]
_DockerId = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_NonNegativeInt = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
_PositiveInt = Annotated[int, Field(strict=True, ge=1, le=2**63 - 1)]

_METRIC_IDS = (
    "common.ground-truth-coverage",
    "common.detection-recall",
    "common.task-success-rate",
    "common.false-positive-rate",
    "common.detection-precision",
    "common.replay-or-reanalysis-success-rate",
    "common.time-to-first-valid-result",
    "common.total-request-units",
    "common.total-tool-calls",
    "common.total-cost-usd",
    "common.evidence-completeness",
    "common.policy-denial-correctness",
    "common.cleanup-success-rate",
    "network.service-identification-accuracy",
)
_NOT_APPLICABLE_REASONS = {
    "common.task-success-rate": (
        DomainBenchmarkNotApplicableReason.DETECTION_RECALL_IS_PRIMARY_OUTCOME
    ),
    "common.total-cost-usd": DomainBenchmarkNotApplicableReason.NO_MONETARY_COST_MODEL,
    "common.cleanup-success-rate": (
        DomainBenchmarkNotApplicableReason.READ_ONLY_NO_CLEANUP_REQUIRED
    ),
}
_FIXED_RATIONALS = {
    "common.ground-truth-coverage": (6, 6),
    "common.detection-recall": (5, 5),
    "common.false-positive-rate": (0, 1),
    "common.detection-precision": (5, 5),
    "common.replay-or-reanalysis-success-rate": (6, 6),
    "common.total-request-units": (12, 1),
    "common.total-tool-calls": (12, 1),
    "common.evidence-completeness": (
        12 * len(NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES),
        12 * len(NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES),
    ),
    "common.policy-denial-correctness": (5, 5),
    "network.service-identification-accuracy": (6, 6),
}
_TRUE_AUTHORITY_FIELDS = (
    "source_measurement_reopened",
    "replay_measurement_reopened",
    "source_replay_identity_disjoint",
    "private_ground_truth_evaluated",
    "exact_metric_set_evaluated",
    "cleanup_admission_verified",
    "synthetic_benchmark_only",
    "validation_floor_satisfied",
)
_FALSE_AUTHORITY_FIELDS = (
    "image_build_authorized",
    "provider_selection_authorized",
    "caller_configuration_authorized",
    "replay_execution_authorized",
    "service_confirmation_authorized",
    "graph_admission_authorized",
    "graph_mutation_authorized",
    "finding_authority",
    "product_projection_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "dns_authorized",
    "udp_authorized",
    "port_range_authorized",
    "port_enumeration_authorized",
    "raw_socket_authorized",
    "application_protocol_write_authorized",
    "credential_access_authorized",
    "external_target_authorized",
    "production_target_authorized",
    "general_scanner_authorized",
    "permit_issuance_authorized",
    "additional_execution_authorized",
)


class NetworkReplayEvaluationError(RuntimeError):
    """Raised when NET-002C Replay identity or floor evidence differs."""


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        if set(value.__dict__) - set(type(value).model_fields):
            raise NetworkReplayEvaluationError(f"{label} contains unmodeled instance state")
        for field_name in type(value).model_fields:
            _require_known_instance_fields(getattr(value, field_name), label=label, _seen=seen)
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if not isinstance(value, type) and is_dataclass(value):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for item in fields(value):
            _require_known_instance_fields(getattr(value, item.name), label=label, _seen=seen)


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


class _FrozenEmbeddedModel(StrictModel):
    """Exact C model whose nested B artifacts retain their own wire validators."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=False,
        revalidate_instances="always",
    )

    @model_validator(mode="after")
    def reject_unmodeled_nested_instance_state(self) -> Self:
        _require_known_instance_fields(self, label=type(self).__name__)
        return self


class NetworkReplayExecutionIdentity(_FrozenStrictModel):
    """Private exact identity of one independently reopened approved execution."""

    identity_digest: str = Field(default="", alias="identityDigest", max_length=64)
    measurement_run_id: _Identifier = Field(alias="measurementRunId")
    measurement_authority_digest: _Sha256 = Field(alias="measurementAuthorityDigest")
    private_binding_digest: _Sha256 = Field(alias="privateBindingDigest")
    execution_run_id: _Identifier = Field(alias="executionRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    envelope_id: _Identifier = Field(alias="envelopeId")
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    proposal_id: _Identifier = Field(alias="proposalId")
    proposal_digest: _Sha256 = Field(alias="proposalDigest")
    decision_id: _Identifier = Field(alias="decisionId")
    decision_digest: _Sha256 = Field(alias="decisionDigest")
    approval_id: _Identifier = Field(alias="approvalId")
    approval_digest: _Sha256 = Field(alias="approvalDigest")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    permit_id: _Identifier = Field(alias="permitId")
    permit_digest: _Sha256 = Field(alias="permitDigest")
    dispatch_id: _Identifier = Field(alias="dispatchId")
    worker_execution_id: _Identifier = Field(alias="workerExecutionId")
    reservation_sha256: _Sha256 = Field(alias="reservationSha256")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    terminal_event_id: _Identifier = Field(alias="terminalEventId")
    terminal_event_digest: _Sha256 = Field(alias="terminalEventDigest")
    reconciliation_id: _Identifier = Field(alias="reconciliationId")
    reconciliation_digest: _Sha256 = Field(alias="reconciliationDigest")
    target_attempt_id: _Identifier = Field(alias="targetAttemptId")
    target_attempt_digest: _Sha256 = Field(alias="targetAttemptDigest")
    target_container_id: _DockerId = Field(alias="targetContainerId")
    target_network_id: _DockerId = Field(alias="targetNetworkId")
    worker_container_id: _DockerId = Field(alias="workerContainerId")
    proxy_container_id: _DockerId = Field(alias="proxyContainerId")
    internal_network_id: _DockerId = Field(alias="internalNetworkId")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"identity_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-replay-execution-identity/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.identity_digest and self.identity_digest != digest:
            raise ValueError("NET-002C execution identity Digest differs")
        object.__setattr__(self, "identity_digest", digest)
        return self

    def dynamic_values(self) -> frozenset[str]:
        payload = self.model_dump(mode="python", exclude={"identity_digest"})
        return frozenset(item for item in payload.values() if isinstance(item, str))


def _identity_matches_measurement(
    identity: NetworkReplayExecutionIdentity,
    measurement: NetworkPrivateSourceCaseMeasurement,
) -> bool:
    lifecycle = measurement.lifecycle
    topology = lifecycle.topology
    return (
        identity.execution_run_id == measurement.source_run_id
        and identity.source_root_digest == measurement.source_root_digest
        and identity.approval_receipt_id == measurement.approval_receipt_id
        and identity.approval_receipt_digest == measurement.approval_receipt_digest
        and identity.permit_id == measurement.permit_id
        and identity.permit_digest == measurement.permit_digest
        and identity.worker_execution_id == measurement.worker_result.execution_id
        and identity.reservation_sha256 == measurement.reservation_sha256
        and identity.execution_evidence_sha256 == measurement.execution_evidence_sha256
        and identity.target_attempt_id == lifecycle.attempt.attempt_id
        and identity.target_attempt_digest == lifecycle.attempt.attempt_digest
        and identity.target_container_id == lifecycle.coordinate.target_container_id
        and identity.target_network_id == lifecycle.coordinate.target_network_id
        and identity.worker_container_id == topology.worker_container_id
        and identity.proxy_container_id == topology.proxy_container_id
        and identity.internal_network_id == topology.internal_network_id
    )


class NetworkPrivateReplayCaseEvaluation(_FrozenEmbeddedModel):
    """Private Ground Truth comparison for one source/Replay case pair."""

    evaluation_digest: str = Field(default="", alias="evaluationDigest", max_length=64)
    case: NetworkPrivateGroundTruthCase
    source_measurement: NetworkPrivateSourceCaseMeasurement = Field(alias="sourceMeasurement")
    replay_measurement: NetworkPrivateSourceCaseMeasurement = Field(alias="replayMeasurement")
    source_identity: NetworkReplayExecutionIdentity = Field(alias="sourceIdentity")
    replay_identity: NetworkReplayExecutionIdentity = Field(alias="replayIdentity")
    comparison: Literal["exact-label-match", "unresolved-negative-control"]
    source_replay_identity_disjoint: Literal[True] = Field(
        default=True,
        alias="sourceReplayIdentityDisjoint",
    )
    banner_digest_matched: Literal[True] = Field(default=True, alias="bannerDigestMatched")
    ground_truth_satisfied: Literal[True] = Field(default=True, alias="groundTruthSatisfied")
    replay_succeeded: Literal[True] = Field(default=True, alias="replaySucceeded")
    service_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="serviceConfirmationAuthorized",
    )

    @field_validator(
        "source_replay_identity_disjoint",
        "banner_digest_matched",
        "ground_truth_satisfied",
        "replay_succeeded",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002C private comparison markers must be boolean true")
        return value

    @field_validator("service_confirmation_authorized", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002C private comparison cannot confirm a service")
        return value

    @model_validator(mode="after")
    def bind_case_evaluation(self) -> Self:
        source = self.source_measurement
        replay = self.replay_measurement
        expected_label = self.case.fixture.expected_service_name
        expected_comparison = (
            "exact-label-match" if expected_label is not None else "unresolved-negative-control"
        )
        if (
            source.case != self.case
            or replay.case != self.case
            or not _identity_matches_measurement(self.source_identity, source)
            or not _identity_matches_measurement(self.replay_identity, replay)
            or self.source_identity.dynamic_values().intersection(
                self.replay_identity.dynamic_values()
            )
            or source.raw_banner_base64 != replay.raw_banner_base64
            or source.tool_result.data.get("bannerSha256")
            != replay.tool_result.data.get("bannerSha256")
            or source.observed_service_name != expected_label
            or replay.observed_service_name != expected_label
            or self.comparison != expected_comparison
            or source.lifecycle.cleanup.resources_absent is not True
            or replay.lifecycle.cleanup.resources_absent is not True
        ):
            raise ValueError("NET-002C private source/Replay comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-private-replay-case-evaluation/v1",
            material,
            max_bytes=16 * 1024 * 1024,
        )
        if self.evaluation_digest and self.evaluation_digest != digest:
            raise ValueError("NET-002C private case evaluation Digest differs")
        object.__setattr__(self, "evaluation_digest", digest)
        return self


class NetworkReplayCaseEvaluation(_FrozenStrictModel):
    """Public-safe case lineage without private labels, banners, or runtime coordinates."""

    api_version: Literal["pajin.dev/network-replay-case-evaluation/v1alpha1"] = Field(
        default=NETWORK_REPLAY_CASE_EVALUATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkReplayCaseEvaluation"] = "NetworkReplayCaseEvaluation"
    case_evaluation_digest: str = Field(
        default="",
        alias="caseEvaluationDigest",
        max_length=64,
    )
    case: NetworkMeasuredCaseRef
    source_lineage_digest: _Sha256 = Field(alias="sourceLineageDigest")
    replay_lineage_digest: _Sha256 = Field(alias="replayLineageDigest")
    source_identity_digest: _Sha256 = Field(alias="sourceIdentityDigest")
    replay_identity_digest: _Sha256 = Field(alias="replayIdentityDigest")
    private_evaluation_digest: _Sha256 = Field(alias="privateEvaluationDigest")
    comparison_state: Literal[
        "synthetic-known-positive-matched",
        "synthetic-negative-control-unresolved",
    ] = Field(alias="comparisonState")
    replay_succeeded: Literal[True] = Field(default=True, alias="replaySucceeded")
    source_replay_identity_disjoint: Literal[True] = Field(
        default=True,
        alias="sourceReplayIdentityDisjoint",
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="serviceConfirmationAuthorized",
    )

    @field_validator("replay_succeeded", "source_replay_identity_disjoint", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002C public case markers must be boolean true")
        return value

    @field_validator("service_confirmation_authorized", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002C public case cannot confirm a service")
        return value

    @model_validator(mode="after")
    def bind_case_evaluation(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"case_evaluation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-replay-case-evaluation/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.case_evaluation_digest and self.case_evaluation_digest != digest:
            raise ValueError("NET-002C public case evaluation Digest differs")
        object.__setattr__(self, "case_evaluation_digest", digest)
        return self


class NetworkReplayMetricObservation(_FrozenStrictModel):
    """One exact DOMAIN-006 rational metric or registered N/A decision."""

    metric: DomainBenchmarkMetricRef
    unit: BenchmarkMetricUnit
    applicability: DomainBenchmarkMetricApplicability
    comparison: NetworkMetricFloorComparison
    numerator: _NonNegativeInt | None = None
    denominator: _PositiveInt | None = None
    not_applicable_reason: DomainBenchmarkNotApplicableReason | None = Field(
        default=None,
        alias="notApplicableReason",
    )
    satisfied: Literal[True] = True

    @field_validator("satisfied", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002C metric satisfaction marker must be true")
        return value

    @model_validator(mode="after")
    def require_complete_value(self) -> Self:
        if self.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE:
            if (
                self.comparison is not NetworkMetricFloorComparison.NOT_APPLICABLE
                or self.not_applicable_reason is None
                or self.numerator is not None
                or self.denominator is not None
            ):
                raise ValueError("NET-002C N/A metric observation differs")
        elif (
            self.comparison is NetworkMetricFloorComparison.NOT_APPLICABLE
            or self.not_applicable_reason is not None
            or self.numerator is None
            or self.denominator is None
        ):
            raise ValueError("NET-002C required metric needs one exact rational value")
        registered = resolve_registered_domain_benchmark_metric(self.metric)
        if self.unit is not registered.unit:
            raise ValueError("NET-002C metric unit differs from DOMAIN-006")
        return self


class NetworkReplayFloorEvaluationRef(_FrozenStrictModel):
    evaluation_id: str = Field(
        alias="evaluationId",
        pattern=r"^network-replay-floor_[a-f0-9]{64}$",
    )
    evaluation_digest: _Sha256 = Field(alias="evaluationDigest")

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.evaluation_id != f"network-replay-floor_{self.evaluation_digest}":
            raise ValueError("NET-002C floor evaluation reference differs")
        return self


class NetworkReplayFloorEvaluation(_FrozenStrictModel):
    """Public-safe proof of one exact six-case independent Replay floor."""

    api_version: Literal["pajin.dev/network-replay-floor-evaluation/v1alpha1"] = Field(
        default=NETWORK_REPLAY_FLOOR_EVALUATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkReplayFloorEvaluation"] = "NetworkReplayFloorEvaluation"
    evaluation_id: str = Field(default="", alias="evaluationId", max_length=110)
    evaluation_digest: str = Field(default="", alias="evaluationDigest", max_length=64)
    measured_case_authority: NetworkMeasuredCaseAuthorityRef = Field(alias="measuredCaseAuthority")
    measurement_protocol: NetworkMeasurementProtocolRef = Field(alias="measurementProtocol")
    floor_policy: NetworkValidationFloorPolicyRef = Field(alias="floorPolicy")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    images: NetworkSourceImageBindingRef
    source_measurement: NetworkSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    replay_measurement: NetworkSourceMeasurementAuthorityRef = Field(alias="replayMeasurement")
    cases: tuple[NetworkReplayCaseEvaluation, ...] = Field(min_length=6, max_length=6)
    observations: tuple[NetworkReplayMetricObservation, ...] = Field(
        min_length=14,
        max_length=14,
    )
    required_case_evidence_names: tuple[str, ...] = Field(
        alias="requiredCaseEvidenceNames",
        min_length=12,
        max_length=12,
    )
    state: Literal["floor-satisfied-independent-fresh-worker-replay"] = (
        "floor-satisfied-independent-fresh-worker-replay"
    )
    source_measurement_reopened: Literal[True] = Field(
        default=True,
        alias="sourceMeasurementReopened",
    )
    replay_measurement_reopened: Literal[True] = Field(
        default=True,
        alias="replayMeasurementReopened",
    )
    source_replay_identity_disjoint: Literal[True] = Field(
        default=True,
        alias="sourceReplayIdentityDisjoint",
    )
    private_ground_truth_evaluated: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthEvaluated",
    )
    exact_metric_set_evaluated: Literal[True] = Field(
        default=True,
        alias="exactMetricSetEvaluated",
    )
    cleanup_admission_verified: Literal[True] = Field(
        default=True,
        alias="cleanupAdmissionVerified",
    )
    synthetic_benchmark_only: Literal[True] = Field(
        default=True,
        alias="syntheticBenchmarkOnly",
    )
    validation_floor_satisfied: Literal[True] = Field(
        default=True,
        alias="validationFloorSatisfied",
    )
    image_build_authorized: Literal[False] = Field(
        default=False,
        alias="imageBuildAuthorized",
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    caller_configuration_authorized: Literal[False] = Field(
        default=False,
        alias="callerConfigurationAuthorized",
    )
    replay_execution_authorized: Literal[False] = Field(
        default=False,
        alias="replayExecutionAuthorized",
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="serviceConfirmationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="graphMutationAuthorized",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    product_projection_authorized: Literal[False] = Field(
        default=False,
        alias="productProjectionAuthorized",
    )
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
    dns_authorized: Literal[False] = Field(default=False, alias="dnsAuthorized")
    udp_authorized: Literal[False] = Field(default=False, alias="udpAuthorized")
    port_range_authorized: Literal[False] = Field(
        default=False,
        alias="portRangeAuthorized",
    )
    port_enumeration_authorized: Literal[False] = Field(
        default=False,
        alias="portEnumerationAuthorized",
    )
    raw_socket_authorized: Literal[False] = Field(
        default=False,
        alias="rawSocketAuthorized",
    )
    application_protocol_write_authorized: Literal[False] = Field(
        default=False,
        alias="applicationProtocolWriteAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    external_target_authorized: Literal[False] = Field(
        default=False,
        alias="externalTargetAuthorized",
    )
    production_target_authorized: Literal[False] = Field(
        default=False,
        alias="productionTargetAuthorized",
    )
    general_scanner_authorized: Literal[False] = Field(
        default=False,
        alias="generalScannerAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(
        "cases",
        "observations",
        "required_case_evidence_names",
        mode="before",
    )
    @classmethod
    def canonicalize_json_tuple(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @field_validator(*_TRUE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002C completion markers must be boolean true")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002C authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_evaluation(self) -> Self:
        registered = registered_network_measured_case_mapping()
        expected_cases = tuple(
            item.reference() for item in registered.public_authority.public_registry.cases
        )
        expected_states = (
            "synthetic-known-positive-matched",
            "synthetic-known-positive-matched",
            "synthetic-known-positive-matched",
            "synthetic-known-positive-matched",
            "synthetic-known-positive-matched",
            "synthetic-negative-control-unresolved",
        )
        if (
            self.measured_case_authority != registered.public_authority.reference()
            or self.measurement_protocol
            != registered.public_authority.measurement_protocol.reference()
            or self.floor_policy != registered.public_authority.validation_floor_policy.reference()
            or self.private_ground_truth_binding_digest != registered.private_binding.binding_digest
            or self.source_measurement == self.replay_measurement
            or tuple(item.case for item in self.cases) != expected_cases
            or tuple(item.comparison_state for item in self.cases) != expected_states
            or self.required_case_evidence_names != NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES
            or len({item.case.case_id for item in self.cases}) != 6
            or len({item.source_identity_digest for item in self.cases}) != 6
            or len({item.replay_identity_digest for item in self.cases}) != 6
        ):
            raise ValueError("NET-002C public membership, evidence, or identity differs")
        _validate_public_observations(self.observations)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_id", "evaluation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-replay-floor-evaluation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        evaluation_id = f"network-replay-floor_{digest}"
        if self.evaluation_digest and self.evaluation_digest != digest:
            raise ValueError("NET-002C floor evaluation Digest differs")
        if self.evaluation_id and self.evaluation_id != evaluation_id:
            raise ValueError("NET-002C floor evaluation ID differs")
        object.__setattr__(self, "evaluation_digest", digest)
        object.__setattr__(self, "evaluation_id", evaluation_id)
        return self

    def reference(self) -> NetworkReplayFloorEvaluationRef:
        return NetworkReplayFloorEvaluationRef(
            evaluationId=self.evaluation_id,
            evaluationDigest=self.evaluation_digest,
        )


class NetworkPrivateReplayEvaluationBinding(_FrozenEmbeddedModel):
    """Deployment-private source/Replay output, Ground Truth, and identity binding."""

    api_version: Literal["pajin.dev/network-private-replay-evaluation-binding/v1alpha1"] = Field(
        default=NETWORK_PRIVATE_REPLAY_EVALUATION_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkPrivateReplayEvaluationBinding"] = "NetworkPrivateReplayEvaluationBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=120)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    public_evaluation: NetworkReplayFloorEvaluationRef = Field(alias="publicEvaluation")
    private_ground_truth_binding_id: _Identifier = Field(alias="privateGroundTruthBindingId")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    source_private_binding_id: _Identifier = Field(alias="sourcePrivateBindingId")
    source_private_binding_digest: _Sha256 = Field(alias="sourcePrivateBindingDigest")
    replay_private_binding_id: _Identifier = Field(alias="replayPrivateBindingId")
    replay_private_binding_digest: _Sha256 = Field(alias="replayPrivateBindingDigest")
    cases: tuple[NetworkPrivateReplayCaseEvaluation, ...] = Field(
        min_length=6,
        max_length=6,
    )
    visibility: Literal["deployment-private"] = "deployment-private"
    private_output_public_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="privateOutputPublicDisclosureAuthorized",
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="serviceConfirmationAuthorized",
    )
    product_projection_authorized: Literal[False] = Field(
        default=False,
        alias="productProjectionAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(
        "private_output_public_disclosure_authorized",
        "service_confirmation_authorized",
        "product_projection_authorized",
        "additional_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002C private binding authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_private_evaluation(self) -> Self:
        if (
            self.source_private_binding_digest == self.replay_private_binding_digest
            or len({item.case.case_id for item in self.cases}) != 6
            or len({item.evaluation_digest for item in self.cases}) != 6
        ):
            raise ValueError("NET-002C private source/Replay binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-private-replay-evaluation-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"network-private-replay-evaluation_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("NET-002C private evaluation binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("NET-002C private evaluation binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


@dataclass(frozen=True, slots=True)
class NetworkReplayEvaluationMapping:
    public_evaluation: NetworkReplayFloorEvaluation
    private_binding: NetworkPrivateReplayEvaluationBinding


@dataclass(frozen=True, slots=True)
class NetworkReplayEvaluationOutcome:
    run_id: str
    run_path: Path
    evaluation_path: str
    private_binding_path: str
    mapping: NetworkReplayEvaluationMapping
    source: NetworkSourceMeasurementOutcome
    replay: NetworkSourceMeasurementOutcome


@dataclass(frozen=True, slots=True)
class _VerifiedCase:
    public_lineage: NetworkSourceCaseLineage
    private_measurement: NetworkPrivateSourceCaseMeasurement
    source: VerifiedNetworkServiceObservationSource
    identity: NetworkReplayExecutionIdentity


def _build_execution_identity(
    *,
    outcome: NetworkSourceMeasurementOutcome,
    context: NetworkSourceExecutionContext,
    private: NetworkPrivateSourceCaseMeasurement,
    source: VerifiedNetworkServiceObservationSource,
) -> NetworkReplayExecutionIdentity:
    approval = source.approval_receipt.approval
    permit = source.permit
    lifecycle = context.lifecycle
    topology = lifecycle.topology
    return NetworkReplayExecutionIdentity(
        measurementRunId=outcome.run_id,
        measurementAuthorityDigest=outcome.mapping.public_authority.authority_digest,
        privateBindingDigest=outcome.mapping.private_binding.binding_digest,
        executionRunId=source.snapshot.verification.run_id,
        sourceRootDigest=source.snapshot.verification.root_digest,
        requestId=permit.request_id,
        requestDigest=permit.request_digest,
        envelopeId=permit.envelope_id,
        envelopeDigest=permit.envelope_digest,
        proposalId=permit.proposal_id,
        proposalDigest=permit.proposal_digest,
        decisionId=permit.decision_id,
        decisionDigest=permit.decision_digest,
        approvalId=approval.approval_id,
        approvalDigest=approval.approval_digest,
        approvalReceiptId=source.approval_receipt.receipt_id,
        approvalReceiptDigest=source.approval_receipt.receipt_digest,
        permitId=permit.permit_id,
        permitDigest=permit.permit_digest,
        dispatchId=permit.dispatch_id,
        workerExecutionId=source.evidence.worker_result.execution_id,
        reservationSha256=source.reservation_sha256,
        executionEvidenceSha256=source.evidence_sha256,
        terminalEventId=source.terminal.event_id,
        terminalEventDigest=source.terminal.event_digest,
        reconciliationId=source.reconciliation.reconciliation_id,
        reconciliationDigest=source.reconciliation.reconciliation_digest,
        targetAttemptId=lifecycle.attempt.attempt_id,
        targetAttemptDigest=lifecycle.attempt.attempt_digest,
        targetContainerId=lifecycle.coordinate.target_container_id,
        targetNetworkId=lifecycle.coordinate.target_network_id,
        workerContainerId=topology.worker_container_id,
        proxyContainerId=topology.proxy_container_id,
        internalNetworkId=topology.internal_network_id,
    )


def _reopen_measurement_set(
    outcome: NetworkSourceMeasurementOutcome,
    *,
    measured_cases: NetworkMeasuredCaseMapping,
    provider: NetworkFixtureDockerProvider,
) -> tuple[
    NetworkSourceMeasurementAuthority,
    NetworkPrivateSourceMeasurementBinding,
    tuple[_VerifiedCase, ...],
]:
    if type(outcome) is not NetworkSourceMeasurementOutcome:
        raise NetworkReplayEvaluationError("NET-002C measurement set requires its exact outcome")
    try:
        public = load_network_source_measurement_authority(
            outcome,
            measured_cases=measured_cases,
            provider=provider,
        )
        private = NetworkPrivateSourceMeasurementBinding.model_validate_json(
            outcome.mapping.private_binding.model_dump_json(by_alias=True)
        )
    except (AttributeError, NetworkSourceMeasurementError, ValidationError, ValueError) as exc:
        raise NetworkReplayEvaluationError(
            "NET-002C measurement set could not be contextfully reopened"
        ) from exc
    if (
        public != outcome.mapping.public_authority
        or private != outcome.mapping.private_binding
        or len(outcome.executions) != 6
    ):
        raise NetworkReplayEvaluationError(
            "NET-002C measurement artifacts or execution count differ"
        )
    verified: list[_VerifiedCase] = []
    for lineage, private_case, context in zip(
        public.cases,
        private.cases,
        outcome.executions,
        strict=True,
    ):
        try:
            source = load_verified_network_service_observation_source(
                context.source_inputs,
                graph_store=context.graph_store,
            )
            identity = _build_execution_identity(
                outcome=outcome,
                context=context,
                private=private_case,
                source=source,
            )
        except (AttributeError, RuntimeError, ValidationError, ValueError) as exc:
            raise NetworkReplayEvaluationError(
                "NET-002C execution identity could not be reopened"
            ) from exc
        if context.lifecycle != private_case.lifecycle or not _identity_matches_measurement(
            identity, private_case
        ):
            raise NetworkReplayEvaluationError(
                "NET-002C execution identity differs from private measurement"
            )
        verified.append(
            _VerifiedCase(
                public_lineage=lineage,
                private_measurement=private_case,
                source=source,
                identity=identity,
            )
        )
    return public, private, tuple(verified)


def _require_disjoint_execution_sets(
    source_cases: tuple[_VerifiedCase, ...],
    replay_cases: tuple[_VerifiedCase, ...],
) -> None:
    source_values = frozenset(
        value for item in source_cases for value in item.identity.dynamic_values()
    )
    replay_values = frozenset(
        value for item in replay_cases for value in item.identity.dynamic_values()
    )
    if source_values.intersection(replay_values):
        raise NetworkReplayEvaluationError(
            "NET-002C source and Replay execution identities overlap"
        )


def _build_private_case_evaluation(
    *,
    ground_truth: NetworkPrivateGroundTruthCase,
    source: _VerifiedCase,
    replay: _VerifiedCase,
) -> NetworkPrivateReplayCaseEvaluation:
    comparison: Literal["exact-label-match", "unresolved-negative-control"] = (
        "exact-label-match"
        if ground_truth.fixture.expected_service_name is not None
        else "unresolved-negative-control"
    )
    return NetworkPrivateReplayCaseEvaluation(
        case=ground_truth,
        sourceMeasurement=source.private_measurement,
        replayMeasurement=replay.private_measurement,
        sourceIdentity=source.identity,
        replayIdentity=replay.identity,
        comparison=comparison,
    )


def _build_public_case_evaluation(
    private: NetworkPrivateReplayCaseEvaluation,
    *,
    source_lineage: NetworkSourceCaseLineage,
    replay_lineage: NetworkSourceCaseLineage,
) -> NetworkReplayCaseEvaluation:
    comparison_state: Literal[
        "synthetic-known-positive-matched",
        "synthetic-negative-control-unresolved",
    ] = (
        "synthetic-known-positive-matched"
        if private.case.fixture.expected_service_name is not None
        else "synthetic-negative-control-unresolved"
    )
    return NetworkReplayCaseEvaluation(
        case=source_lineage.case,
        sourceLineageDigest=source_lineage.lineage_digest,
        replayLineageDigest=replay_lineage.lineage_digest,
        sourceIdentityDigest=private.source_identity.identity_digest,
        replayIdentityDigest=private.replay_identity.identity_digest,
        privateEvaluationDigest=private.evaluation_digest,
        comparisonState=comparison_state,
    )


def _elapsed_microseconds(started_at: datetime, finished_at: datetime) -> int:
    if (
        started_at.tzinfo is None
        or started_at.utcoffset() is None
        or finished_at.tzinfo is None
        or finished_at.utcoffset() is None
    ):
        raise NetworkReplayEvaluationError("NET-002C Worker timestamps require UTC offsets")
    delta = finished_at - started_at
    microseconds = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    if microseconds < 0:
        raise NetworkReplayEvaluationError("NET-002C Worker completion precedes its start")
    return microseconds


def _require_threshold(
    requirement: NetworkBenchmarkMetricFloorRequirement,
    *,
    numerator: int,
    denominator: int,
) -> None:
    if (
        requirement.minimum_denominator is not None
        and denominator < requirement.minimum_denominator
    ):
        raise NetworkReplayEvaluationError(
            "NET-002C metric denominator is below the registered floor"
        )
    if requirement.comparison is NetworkMetricFloorComparison.MEASUREMENT_REQUIRED:
        return
    if requirement.threshold_numerator is None or requirement.threshold_denominator is None:
        raise NetworkReplayEvaluationError("NET-002C metric threshold is incomplete")
    left = numerator * requirement.threshold_denominator
    right = requirement.threshold_numerator * denominator
    if (requirement.comparison is NetworkMetricFloorComparison.AT_LEAST and left < right) or (
        requirement.comparison is NetworkMetricFloorComparison.AT_MOST and left > right
    ):
        raise NetworkReplayEvaluationError("NET-002C metric threshold is not satisfied")


def _metric_observations(
    floor: tuple[NetworkBenchmarkMetricFloorRequirement, ...],
    *,
    first_replay_result_microseconds: int,
) -> tuple[NetworkReplayMetricObservation, ...]:
    if tuple(item.metric.metric_id for item in floor) != _METRIC_IDS:
        raise NetworkReplayEvaluationError("NET-002C floor metric order differs")
    values = dict(_FIXED_RATIONALS)
    values["common.time-to-first-valid-result"] = (
        first_replay_result_microseconds,
        1_000_000,
    )
    observations: list[NetworkReplayMetricObservation] = []
    for requirement in floor:
        if requirement.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE:
            observation = NetworkReplayMetricObservation(
                metric=requirement.metric,
                unit=requirement.unit,
                applicability=requirement.applicability,
                comparison=requirement.comparison,
                notApplicableReason=requirement.not_applicable_reason,
            )
        else:
            numerator, denominator = values[requirement.metric.metric_id]
            _require_threshold(
                requirement,
                numerator=numerator,
                denominator=denominator,
            )
            observation = NetworkReplayMetricObservation(
                metric=requirement.metric,
                unit=requirement.unit,
                applicability=requirement.applicability,
                comparison=requirement.comparison,
                numerator=numerator,
                denominator=denominator,
            )
        observations.append(observation)
    return tuple(observations)


def _validate_public_observations(
    observations: tuple[NetworkReplayMetricObservation, ...],
) -> None:
    floor = registered_network_validation_floor_policy()
    if tuple(item.metric.metric_id for item in observations) != _METRIC_IDS or len(
        {item.metric.metric_id for item in observations}
    ) != len(_METRIC_IDS):
        raise ValueError("NET-002C public metric order or membership differs")
    requirements = {item.metric.metric_id: item for item in floor.requirements}
    for observation in observations:
        requirement = requirements[observation.metric.metric_id]
        if (
            observation.metric != requirement.metric
            or observation.unit is not requirement.unit
            or observation.applicability is not requirement.applicability
            or observation.comparison is not requirement.comparison
            or observation.not_applicable_reason is not requirement.not_applicable_reason
        ):
            raise ValueError("NET-002C public metric contract differs")
        if observation.applicability is DomainBenchmarkMetricApplicability.REQUIRED:
            assert observation.numerator is not None
            assert observation.denominator is not None
            _require_threshold(
                requirement,
                numerator=observation.numerator,
                denominator=observation.denominator,
            )
    by_id = {item.metric.metric_id: item for item in observations}
    for metric_id, expected in _FIXED_RATIONALS.items():
        item = by_id[metric_id]
        if (item.numerator, item.denominator) != expected:
            raise ValueError("NET-002C fixed metric rational differs")
    for metric_id, reason in _NOT_APPLICABLE_REASONS.items():
        item = by_id[metric_id]
        if item.not_applicable_reason is not reason:
            raise ValueError("NET-002C metric N/A reason differs")
    elapsed = by_id["common.time-to-first-valid-result"]
    if elapsed.numerator is None or elapsed.numerator < 0 or elapsed.denominator != 1_000_000:
        raise ValueError("NET-002C elapsed-time rational differs")


def _build_mapping(
    *,
    measured_authority: NetworkMeasuredCaseAuthority,
    private_ground_truth: NetworkPrivateGroundTruthBinding,
    source_public: NetworkSourceMeasurementAuthority,
    source_private: NetworkPrivateSourceMeasurementBinding,
    source_cases: tuple[_VerifiedCase, ...],
    replay_public: NetworkSourceMeasurementAuthority,
    replay_private: NetworkPrivateSourceMeasurementBinding,
    replay_cases: tuple[_VerifiedCase, ...],
) -> NetworkReplayEvaluationMapping:
    _require_disjoint_execution_sets(source_cases, replay_cases)
    expected_refs = tuple(item.reference() for item in measured_authority.public_registry.cases)
    if (
        source_public.reference() == replay_public.reference()
        or source_public.measured_case_authority != measured_authority.reference()
        or replay_public.measured_case_authority != measured_authority.reference()
        or source_public.measurement_protocol != measured_authority.measurement_protocol.reference()
        or replay_public.measurement_protocol != measured_authority.measurement_protocol.reference()
        or source_public.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or replay_public.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or source_public.images != replay_public.images
        or source_private.images != replay_private.images
        or source_public.action_authority_context_digest
        != replay_public.action_authority_context_digest
        or tuple(item.case for item in source_public.cases) != expected_refs
        or tuple(item.case for item in replay_public.cases) != expected_refs
        or len(source_cases) != 6
        or len(replay_cases) != 6
    ):
        raise NetworkReplayEvaluationError(
            "NET-002C source and Replay measurement semantics differ"
        )
    private_cases = tuple(
        _build_private_case_evaluation(
            ground_truth=ground_truth,
            source=source,
            replay=replay,
        )
        for ground_truth, source, replay in zip(
            private_ground_truth.cases,
            source_cases,
            replay_cases,
            strict=True,
        )
    )
    public_cases = tuple(
        _build_public_case_evaluation(
            private,
            source_lineage=source.public_lineage,
            replay_lineage=replay.public_lineage,
        )
        for private, source, replay in zip(
            private_cases,
            source_cases,
            replay_cases,
            strict=True,
        )
    )
    first_replay = replay_cases[0].private_measurement.worker_result
    observations = _metric_observations(
        measured_authority.validation_floor_policy.requirements,
        first_replay_result_microseconds=_elapsed_microseconds(
            first_replay.started_at,
            first_replay.finished_at,
        ),
    )
    public = NetworkReplayFloorEvaluation(
        measuredCaseAuthority=measured_authority.reference(),
        measurementProtocol=measured_authority.measurement_protocol.reference(),
        floorPolicy=measured_authority.validation_floor_policy.reference(),
        privateGroundTruthBindingDigest=private_ground_truth.binding_digest,
        images=source_public.images,
        sourceMeasurement=source_public.reference(),
        replayMeasurement=replay_public.reference(),
        cases=public_cases,
        observations=observations,
        requiredCaseEvidenceNames=NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES,
    )
    private = NetworkPrivateReplayEvaluationBinding(
        publicEvaluation=public.reference(),
        privateGroundTruthBindingId=private_ground_truth.binding_id,
        privateGroundTruthBindingDigest=private_ground_truth.binding_digest,
        sourcePrivateBindingId=source_private.binding_id,
        sourcePrivateBindingDigest=source_private.binding_digest,
        replayPrivateBindingId=replay_private.binding_id,
        replayPrivateBindingDigest=replay_private.binding_digest,
        cases=private_cases,
    )
    mapping = NetworkReplayEvaluationMapping(
        public_evaluation=public,
        private_binding=private,
    )
    _validate_mapping(
        mapping,
        measured_authority=measured_authority,
        private_ground_truth=private_ground_truth,
        source_public=source_public,
        source_private=source_private,
        replay_public=replay_public,
        replay_private=replay_private,
    )
    return mapping


def _validate_mapping(
    mapping: NetworkReplayEvaluationMapping,
    *,
    measured_authority: NetworkMeasuredCaseAuthority,
    private_ground_truth: NetworkPrivateGroundTruthBinding,
    source_public: NetworkSourceMeasurementAuthority,
    source_private: NetworkPrivateSourceMeasurementBinding,
    replay_public: NetworkSourceMeasurementAuthority,
    replay_private: NetworkPrivateSourceMeasurementBinding,
) -> None:
    if type(mapping) is not NetworkReplayEvaluationMapping:
        raise NetworkReplayEvaluationError("NET-002C mapping requires its exact separated type")
    try:
        public = NetworkReplayFloorEvaluation.model_validate_json(
            mapping.public_evaluation.model_dump_json(by_alias=True)
        )
        private = NetworkPrivateReplayEvaluationBinding.model_validate_json(
            mapping.private_binding.model_dump_json(by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise NetworkReplayEvaluationError(
            "NET-002C public/private mapping is not canonical"
        ) from exc
    expected_refs = tuple(item.reference() for item in measured_authority.public_registry.cases)
    source_measurements = tuple(item.source_measurement for item in private.cases)
    replay_measurements = tuple(item.replay_measurement for item in private.cases)
    source_identities = tuple(item.source_identity for item in private.cases)
    replay_identities = tuple(item.replay_identity for item in private.cases)
    source_values = frozenset(
        value for identity in source_identities for value in identity.dynamic_values()
    )
    replay_values = frozenset(
        value for identity in replay_identities for value in identity.dynamic_values()
    )
    expected_states = tuple(
        (
            "synthetic-known-positive-matched"
            if item.fixture.expected_service_name is not None
            else "synthetic-negative-control-unresolved"
        )
        for item in private_ground_truth.cases
    )
    if (
        public != mapping.public_evaluation
        or private != mapping.private_binding
        or public.measured_case_authority != measured_authority.reference()
        or public.measurement_protocol != measured_authority.measurement_protocol.reference()
        or public.floor_policy != measured_authority.validation_floor_policy.reference()
        or public.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or public.source_measurement != source_public.reference()
        or public.replay_measurement != replay_public.reference()
        or public.images != source_public.images
        or private.public_evaluation != public.reference()
        or private.private_ground_truth_binding_id != private_ground_truth.binding_id
        or private.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or private.source_private_binding_id != source_private.binding_id
        or private.source_private_binding_digest != source_private.binding_digest
        or private.replay_private_binding_id != replay_private.binding_id
        or private.replay_private_binding_digest != replay_private.binding_digest
        or tuple(item.case for item in public.cases) != expected_refs
        or tuple(item.case for item in private.cases) != private_ground_truth.cases
        or source_measurements != source_private.cases
        or replay_measurements != replay_private.cases
        or tuple(item.private_evaluation_digest for item in public.cases)
        != tuple(item.evaluation_digest for item in private.cases)
        or tuple(item.source_identity_digest for item in public.cases)
        != tuple(item.identity_digest for item in source_identities)
        or tuple(item.replay_identity_digest for item in public.cases)
        != tuple(item.identity_digest for item in replay_identities)
        or tuple(item.comparison_state for item in public.cases) != expected_states
        or source_values.intersection(replay_values)
        or any(
            item.source_measurement.lifecycle.cleanup.resources_absent is not True
            or item.replay_measurement.lifecycle.cleanup.resources_absent is not True
            for item in private.cases
        )
    ):
        raise NetworkReplayEvaluationError("NET-002C public/private authority binding differs")
    first_replay = replay_private.cases[0].worker_result
    expected_observations = _metric_observations(
        measured_authority.validation_floor_policy.requirements,
        first_replay_result_microseconds=_elapsed_microseconds(
            first_replay.started_at,
            first_replay.finished_at,
        ),
    )
    if public.observations != expected_observations:
        raise NetworkReplayEvaluationError(
            "NET-002C metric observations differ from private Evidence"
        )


class NetworkReplayEvaluationRunner:
    """Run one fresh six-case measurement set and evaluate it as NET-002C Replay."""

    def __init__(
        self,
        *,
        source: NetworkSourceMeasurementOutcome,
        measured_cases: NetworkMeasuredCaseMapping,
        images: NetworkSourceImageBinding,
        lifecycle: NetworkFixtureTargetLifecycleRunner,
        authorizer: NetworkSourceActionAuthorizer,
        replay_source_runs_root: Path,
        replay_measurement_runs_root: Path,
        evaluation_runs_root: Path,
    ) -> None:
        if type(source) is not NetworkSourceMeasurementOutcome:
            raise TypeError("NET-002C requires one exact NET-002B source outcome")
        if type(measured_cases) is not NetworkMeasuredCaseMapping:
            raise TypeError("NET-002C requires exact measured-case mapping")
        if type(images) is not NetworkSourceImageBinding:
            raise TypeError("NET-002C requires exact observed image binding")
        if not isinstance(lifecycle, NetworkFixtureTargetLifecycleRunner):
            raise TypeError("NET-002C requires exact Target lifecycle")
        if not callable(getattr(authorizer, "authorize", None)):
            raise TypeError("NET-002C requires a deployment action authorizer")
        try:
            measured_authority = load_network_measured_case_authority(
                measured_cases.public_authority,
                private_ground_truth_binding=measured_cases.private_binding,
            )
            source_public, source_private, _source_cases = _reopen_measurement_set(
                source,
                measured_cases=measured_cases,
                provider=lifecycle.provider,
            )
            _context, authority_context_digest = _canonical_authority_context(authorizer)
        except (
            NetworkFixtureRuntimeError,
            NetworkReplayEvaluationError,
            NetworkSourceMeasurementError,
            ValueError,
        ) as exc:
            raise NetworkReplayEvaluationError(
                "NET-002C source or execution authority could not be reopened"
            ) from exc
        if (
            source_public.images != images.reference()
            or source_private.images != images
            or source_public.action_authority_context_digest != authority_context_digest
        ):
            raise NetworkReplayEvaluationError(
                "NET-002C source image or deployment authority differs"
            )
        self._source = source
        self._measured_cases = measured_cases
        self._measured_authority = measured_authority
        self._private_ground_truth = measured_cases.private_binding.model_copy(deep=True)
        self._images = images.model_copy(deep=True)
        self._lifecycle = lifecycle
        self._authorizer = authorizer
        self._authority_context_digest = authority_context_digest
        self._replay_source_runs_root = Path(replay_source_runs_root)
        self._replay_measurement_runs_root = Path(replay_measurement_runs_root)
        self._evaluation_runs_root = Path(evaluation_runs_root)

    async def run(self) -> NetworkReplayEvaluationOutcome:
        if not self._lifecycle.provider.managed_resources_absent():
            raise NetworkReplayEvaluationError("NET-002C cannot start with managed Docker residue")
        _context, current_digest = _canonical_authority_context(self._authorizer)
        if current_digest != self._authority_context_digest:
            raise NetworkReplayEvaluationError(
                "NET-002C deployment authority changed before Replay"
            )
        replay_runner = NetworkSourceMeasurementRunner(
            measured_cases=self._measured_cases,
            images=self._images,
            lifecycle=self._lifecycle,
            authorizer=self._authorizer,
            source_runs_root=self._replay_source_runs_root,
            authority_runs_root=self._replay_measurement_runs_root,
        )
        replay = await replay_runner.run()
        source_public, source_private, source_cases = _reopen_measurement_set(
            self._source,
            measured_cases=self._measured_cases,
            provider=self._lifecycle.provider,
        )
        replay_public, replay_private, replay_cases = _reopen_measurement_set(
            replay,
            measured_cases=self._measured_cases,
            provider=self._lifecycle.provider,
        )
        if (
            source_public.action_authority_context_digest != self._authority_context_digest
            or replay_public.action_authority_context_digest != self._authority_context_digest
        ):
            raise NetworkReplayEvaluationError(
                "NET-002C source or Replay deployment authority differs"
            )
        mapping = _build_mapping(
            measured_authority=self._measured_authority,
            private_ground_truth=self._private_ground_truth,
            source_public=source_public,
            source_private=source_private,
            source_cases=source_cases,
            replay_public=replay_public,
            replay_private=replay_private,
            replay_cases=replay_cases,
        )
        if not self._lifecycle.provider.managed_resources_absent():
            raise NetworkReplayEvaluationError(
                "NET-002C managed Docker residue remains after Replay"
            )
        store = RunStore.create(
            self._evaluation_runs_root,
            "network-replay-evaluation",
        )
        store.write_json_create_only(
            _PUBLIC_ARTIFACT,
            mapping.public_evaluation.model_dump(mode="json", by_alias=True),
        )
        store.write_json_create_only(
            _PRIVATE_ARTIFACT,
            mapping.private_binding.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "network.replay-floor-evaluation.sealed",
            {
                "evaluationDigest": mapping.public_evaluation.evaluation_digest,
                "privateBindingDigest": mapping.private_binding.binding_digest,
                "caseCount": 6,
                "metricCount": 14,
                "floorSatisfied": True,
            },
        )
        store.seal()
        return NetworkReplayEvaluationOutcome(
            run_id=store.run_id,
            run_path=store.path,
            evaluation_path=_PUBLIC_ARTIFACT,
            private_binding_path=_PRIVATE_ARTIFACT,
            mapping=mapping,
            source=self._source,
            replay=replay,
        )


def load_network_replay_floor_evaluation(
    outcome: NetworkReplayEvaluationOutcome,
    *,
    measured_cases: NetworkMeasuredCaseMapping,
    provider: NetworkFixtureDockerProvider,
) -> NetworkReplayFloorEvaluation:
    """Contextfully reopen both six-case sets and the sealed NET-002C authority."""

    if type(outcome) is not NetworkReplayEvaluationOutcome:
        raise TypeError("NET-002C reload requires its exact outcome")
    if type(measured_cases) is not NetworkMeasuredCaseMapping:
        raise TypeError("NET-002C reload requires exact measured-case mapping")
    if not isinstance(provider, NetworkFixtureDockerProvider):
        raise TypeError("NET-002C reload requires exact Docker provider")
    try:
        measured_authority = load_network_measured_case_authority(
            measured_cases.public_authority,
            private_ground_truth_binding=measured_cases.private_binding,
        )
        source_public, source_private, source_cases = _reopen_measurement_set(
            outcome.source,
            measured_cases=measured_cases,
            provider=provider,
        )
        replay_public, replay_private, replay_cases = _reopen_measurement_set(
            outcome.replay,
            measured_cases=measured_cases,
            provider=provider,
        )
        public = NetworkReplayFloorEvaluation.model_validate_json(
            outcome.mapping.public_evaluation.model_dump_json(by_alias=True)
        )
        private = NetworkPrivateReplayEvaluationBinding.model_validate_json(
            outcome.mapping.private_binding.model_dump_json(by_alias=True)
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                outcome.evaluation_path: _MAX_CANONICAL_BYTES,
                outcome.private_binding_path: _MAX_CANONICAL_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_public = NetworkReplayFloorEvaluation.model_validate_json(
            snapshot.artifact_bytes(outcome.evaluation_path)
        )
        sealed_private = NetworkPrivateReplayEvaluationBinding.model_validate_json(
            snapshot.artifact_bytes(outcome.private_binding_path)
        )
        rebuilt = _build_mapping(
            measured_authority=measured_authority,
            private_ground_truth=measured_cases.private_binding,
            source_public=source_public,
            source_private=source_private,
            source_cases=source_cases,
            replay_public=replay_public,
            replay_private=replay_private,
            replay_cases=replay_cases,
        )
    except (
        AttributeError,
        NetworkReplayEvaluationError,
        NetworkSourceMeasurementError,
        OSError,
        ValidationError,
        ValueError,
    ) as exc:
        raise NetworkReplayEvaluationError(
            "NET-002C sealed evaluation could not be reopened"
        ) from exc
    paths = {
        Path(outcome.source.run_path).resolve(),
        Path(outcome.replay.run_path).resolve(),
        Path(outcome.run_path).resolve(),
    }
    if (
        len(paths) != 3
        or sealed_public != public
        or sealed_private != private
        or public != outcome.mapping.public_evaluation
        or private != outcome.mapping.private_binding
        or rebuilt != outcome.mapping
        or not provider.managed_resources_absent()
    ):
        raise NetworkReplayEvaluationError(
            "NET-002C sealed artifacts, execution sets, or cleanup differ"
        )
    return public.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class NetworkReplayEvaluationReopenContext:
    """Host-owned context required to trust one sealed NET-002C result."""

    outcome: NetworkReplayEvaluationOutcome
    measured_cases: NetworkMeasuredCaseMapping
    provider: NetworkFixtureDockerProvider

    def reopen(self) -> NetworkReplayFloorEvaluation:
        if type(self) is not NetworkReplayEvaluationReopenContext:
            raise NetworkReplayEvaluationError("NET-002C reopen context requires its exact type")
        return load_network_replay_floor_evaluation(
            self.outcome,
            measured_cases=self.measured_cases,
            provider=self.provider,
        )


__all__ = [
    "NETWORK_PRIVATE_REPLAY_EVALUATION_BINDING_API_VERSION",
    "NETWORK_REPLAY_CASE_EVALUATION_API_VERSION",
    "NETWORK_REPLAY_FLOOR_EVALUATION_API_VERSION",
    "NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES",
    "NetworkPrivateReplayCaseEvaluation",
    "NetworkPrivateReplayEvaluationBinding",
    "NetworkReplayCaseEvaluation",
    "NetworkReplayEvaluationError",
    "NetworkReplayEvaluationMapping",
    "NetworkReplayEvaluationOutcome",
    "NetworkReplayEvaluationReopenContext",
    "NetworkReplayEvaluationRunner",
    "NetworkReplayExecutionIdentity",
    "NetworkReplayFloorEvaluation",
    "NetworkReplayFloorEvaluationRef",
    "NetworkReplayMetricObservation",
    "load_network_replay_floor_evaluation",
]
