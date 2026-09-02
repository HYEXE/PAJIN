"""AI-002C independent fresh-session Replay, Controls, and AI floor evaluation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self, cast
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkMetricRef,
    DomainBenchmarkNotApplicableReason,
)
from pajin.benchmark.models import BenchmarkMetricUnit, benchmark_digest
from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    ExistingModeCapabilityActivation,
    capability_gateway_outcome_digest,
    capability_grant_digest,
)
from pajin.capabilities.ai_analysis import (
    AIMeasurementOperationPreparation,
    ai_provider_registration_digest,
    prepare_ai_measurement_operation,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.domain.models import (
    CampaignManifest,
    StrictModel,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.graph.approval import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalInputAuthority,
    ActionApprovalIssuerAuthorityBinding,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
)
from pajin.graph.authority import ActionPermit, MissionEnvelope
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.modes.ai_redteam.models import KISAScenarioDefinition
from pajin.modes.ai_redteam.validation_controls import (
    KISAAIChatValidationControlMaterializer,
)
from pajin.policy.engine import PolicyEngine
from pajin.policy.scope import InvalidScopeURL, normalize_scope_pattern
from pajin.providers.models import ProviderRegistration
from pajin.runtime.store import RunStore, load_verified_run_artifacts
from pajin.runtime.worker import DockerWorkerBackend, WorkerResult
from pajin.target_attestation import (
    AIMeasurementTargetExecutionChallenge,
    AIMeasurementTargetProxyBinding,
    TargetAttestationTrustAnchor,
    derive_ai_measurement_target_execution_challenge,
    verify_ai_measurement_target_execution_receipt,
)
from pajin.tools.ai import (
    AIChatProbeInput,
    AIChatProbeOutput,
    AIChatProbeTool,
    AIM03MeasurementChatProbeTool,
    AIM03SourceChatProbeTool,
    ai_measurement_target_proxy_binding,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway
from pajin.workflow.ai_analysis_admission import (
    AIAnalysisObservationSourceInputs,
    VerifiedAIAnalysisObservationSource,
    load_verified_ai_analysis_observation_source,
)
from pajin.workflow.ai_fixture_runtime import (
    AIDockerBoundaryInspector,
    AIFixtureDockerProvider,
    AIFixtureLiveTarget,
    AIFixtureRuntimeError,
    AIFixtureTargetCoordinate,
    AIMeasurementFixtureTargetLifecycleEvidence,
    AISourceImageBinding,
    AISourceImageBindingRef,
    load_ai_source_image_binding,
)
from pajin.workflow.ai_measured_case_authority import (
    AIBenchmarkMetricFloorRequirement,
    AIMeasuredCaseAuthority,
    AIMeasuredCaseAuthorityRef,
    AIMeasuredCaseMapping,
    AIMeasuredCaseRef,
    AIMeasurementImageRole,
    AIMeasurementOperation,
    AIMeasurementOperationStage,
    AIMeasurementProtocolRef,
    AIMetricFloorComparison,
    AIPrivateControlDerivation,
    AIPrivateGroundTruthBinding,
    AIPrivateGroundTruthCase,
    AIValidationFloorPolicyRef,
    load_ai_measured_case_authority,
    registered_ai_measurement_operations,
    registered_ai_private_ground_truth_binding,
    registered_ai_validation_floor_policy,
)
from pajin.workflow.ai_source_measurement import (
    AIPrivateSourceMeasurement,
    AIPrivateSourceMeasurementBinding,
    AISourceMeasurementAuthority,
    AISourceMeasurementAuthorityRef,
    AISourceMeasurementError,
    AISourceMeasurementOutcome,
    _canonical_authority_context,
    ai_source_provider_registration,
    load_ai_source_measurement_authority,
)

AI_REPLAY_FLOOR_EVALUATION_API_VERSION: Literal["pajin.dev/ai-replay-floor-evaluation/v1alpha1"] = (
    "pajin.dev/ai-replay-floor-evaluation/v1alpha1"
)
AI_PRIVATE_REPLAY_EVALUATION_BINDING_API_VERSION: Literal[
    "pajin.dev/ai-private-replay-evaluation-binding/v1alpha1"
] = "pajin.dev/ai-private-replay-evaluation-binding/v1alpha1"

AI_REPLAY_REQUIRED_OPERATION_EVIDENCE_NAMES = (
    "sealed-run-root",
    "approval-consumption-receipt",
    "consumed-one-use-action-permit",
    "bounded-capability-grant",
    "completed-dispatch-audit",
    "request-budget-reservation",
    "sealed-execution-evidence",
    "target-signed-execution-receipt",
    "worker-and-tool-result",
    "isolated-target-coordinate",
    "proxy-only-topology",
    "single-turn-private-transcript",
    "completed-target-cleanup",
    "measured-accounting-observation",
)

_PUBLIC_ARTIFACT = "ai-replay-floor-evaluation.json"
_PRIVATE_ARTIFACT = "private/ai-replay-evaluation-binding.json"
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
    "ai.threat-class-coverage",
)
_NOT_APPLICABLE_REASONS = {
    "common.task-success-rate": (
        DomainBenchmarkNotApplicableReason.DETECTION_RECALL_IS_PRIMARY_OUTCOME
    ),
    "common.cleanup-success-rate": (
        DomainBenchmarkNotApplicableReason.READ_ONLY_NO_CLEANUP_REQUIRED
    ),
}
_FIXED_RATIONALS = {
    "common.ground-truth-coverage": (1, 1),
    "common.detection-recall": (1, 1),
    "common.false-positive-rate": (0, 2),
    "common.detection-precision": (4, 4),
    "common.replay-or-reanalysis-success-rate": (2, 2),
    "common.total-request-units": (6, 1),
    "common.total-tool-calls": (6, 1),
    "common.total-cost-usd": (0, 1_000_000),
    "common.evidence-completeness": (
        6 * len(AI_REPLAY_REQUIRED_OPERATION_EVIDENCE_NAMES),
        6 * len(AI_REPLAY_REQUIRED_OPERATION_EVIDENCE_NAMES),
    ),
    "common.policy-denial-correctness": (8, 8),
    "ai.threat-class-coverage": (1, 1),
}
_TRUE_PUBLIC_FIELDS = (
    "source_measurement_reopened",
    "replay_measurements_reopened",
    "controls_reopened",
    "source_replay_control_identity_disjoint",
    "private_ground_truth_evaluated",
    "exact_metric_set_evaluated",
    "accounting_observed",
    "cleanup_admission_verified",
    "synthetic_benchmark_only",
    "validation_floor_satisfied",
)
_FALSE_PUBLIC_FIELDS = (
    "image_build_authorized",
    "target_creation_authorized",
    "network_creation_authorized",
    "provider_selection_authorized",
    "caller_configuration_authorized",
    "approval_issuance_authorized",
    "replay_execution_authorized",
    "control_execution_authorized",
    "gateway_execution_authorized",
    "worker_execution_authorized",
    "ai_observation_confirmed",
    "graph_admission_authorized",
    "graph_mutation_authorized",
    "finding_authority",
    "product_projection_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "credential_access_authorized",
    "external_provider_authorized",
    "external_target_authorized",
    "production_target_authorized",
    "arbitrary_prompt_authorized",
    "arbitrary_tool_authorized",
    "plugin_authorized",
    "rag_authorized",
    "mcp_authorized",
    "memory_mutation_authorized",
    "m06_authorized",
    "a04_authorized",
    "general_ai_scanner_authorized",
    "permit_issuance_authorized",
    "grant_issuance_authorized",
    "application_protocol_write_authorized",
    "model_call_authorized",
    "additional_execution_authorized",
)


class AIReplayEvaluationError(RuntimeError):
    """Raised when AI-002C execution identity, private Evidence, or floor drifts."""


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
            raise AIReplayEvaluationError(f"{label} contains unmodeled instance state")
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


def _operation_digest(operation: AIMeasurementOperation) -> str:
    return benchmark_digest(
        "pajin.workflow.ai-measurement-operation/v1",
        operation.model_dump(mode="json", by_alias=True),
        max_bytes=256 * 1024,
    )


def _operation_key(
    operation: AIMeasurementOperation,
) -> Literal[
    "replay-1",
    "replay-2",
    "control-baseline",
    "control-negative",
    "control-counterfactual",
]:
    keys = {
        2: "replay-1",
        3: "replay-2",
        4: "control-baseline",
        5: "control-negative",
        6: "control-counterfactual",
    }
    try:
        return cast(
            Literal[
                "replay-1",
                "replay-2",
                "control-baseline",
                "control-negative",
                "control-counterfactual",
            ],
            keys[operation.ordinal],
        )
    except KeyError as exc:
        raise AIReplayEvaluationError("AI-002C operation excludes the source ordinal") from exc


class AIMeasurementExecutionIdentity(_FrozenStrictModel):
    """Private exact identity of one source, Replay, or Control execution."""

    identity_digest: str = Field(default="", alias="identityDigest", max_length=64)
    operation_ordinal: int = Field(alias="operationOrdinal", strict=True, ge=1, le=6)
    execution_run_id: _Identifier = Field(alias="executionRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    session_id: _Identifier = Field(alias="sessionId")
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
    grant_id: _Identifier = Field(alias="grantId")
    worker_execution_id: _Identifier = Field(alias="workerExecutionId")
    reservation_sha256: _Sha256 = Field(alias="reservationSha256")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    terminal_event_id: _Identifier = Field(alias="terminalEventId")
    terminal_event_digest: _Sha256 = Field(alias="terminalEventDigest")
    reconciliation_id: _Identifier = Field(alias="reconciliationId")
    reconciliation_digest: _Sha256 = Field(alias="reconciliationDigest")
    challenge_id: _Identifier = Field(alias="challengeId")
    challenge_digest: _Sha256 = Field(alias="challengeDigest")
    target_receipt_key_id: _Identifier = Field(alias="targetReceiptKeyId")
    target_receipt_digest: _Sha256 = Field(alias="targetReceiptDigest")
    target_attempt_id: _Identifier = Field(alias="targetAttemptId")
    target_attempt_digest: _Sha256 = Field(alias="targetAttemptDigest")
    target_container_id: _DockerId = Field(alias="targetContainerId")
    target_network_id: _DockerId = Field(alias="targetNetworkId")
    worker_container_id: _DockerId = Field(alias="workerContainerId")
    proxy_container_id: _DockerId = Field(alias="proxyContainerId")
    internal_network_id: _DockerId = Field(alias="internalNetworkId")

    @field_validator("operation_ordinal", mode="before")
    @classmethod
    def require_exact_ordinal(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("AI-002C identity ordinal must be exact")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"identity_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-measurement-execution-identity/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.identity_digest and self.identity_digest != digest:
            raise ValueError("AI-002C execution identity Digest differs")
        object.__setattr__(self, "identity_digest", digest)
        return self

    def dynamic_values(self) -> frozenset[str]:
        payload = self.model_dump(
            mode="python",
            exclude={"identity_digest", "operation_ordinal"},
        )
        return frozenset(item for item in payload.values() if isinstance(item, str))


class AIMeasurementAccountingObservation(_FrozenStrictModel):
    """One admitted request/Tool/cost fact bound to sealed execution Evidence."""

    accounting_digest: str = Field(default="", alias="accountingDigest", max_length=64)
    operation_ordinal: int = Field(alias="operationOrdinal", strict=True, ge=1, le=6)
    request_id: _Identifier = Field(alias="requestId")
    execution_run_id: _Identifier = Field(alias="executionRunId")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    provider_registration_sha256: _Sha256 = Field(alias="providerRegistrationSha256")
    request_unit_count: Literal[1] = Field(alias="requestUnitCount")
    tool_call_count: Literal[1] = Field(alias="toolCallCount")
    model_provider_call_count: Literal[0] = Field(alias="modelProviderCallCount")
    model_provider_cost_micro_usd: Literal[0] = Field(alias="modelProviderCostMicroUsd")
    observation_method: Literal["sealed-gateway-worker-evidence-and-zero-priced-local-provider"] = (
        "sealed-gateway-worker-evidence-and-zero-priced-local-provider"
    )

    @field_validator(
        "operation_ordinal",
        "request_unit_count",
        "tool_call_count",
        "model_provider_call_count",
        "model_provider_cost_micro_usd",
        mode="before",
    )
    @classmethod
    def require_exact_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("AI-002C accounting facts must be exact integers")
        return value

    @model_validator(mode="after")
    def bind_accounting(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"accounting_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-measurement-accounting-observation/v1",
            material,
            max_bytes=512 * 1024,
        )
        if self.accounting_digest and self.accounting_digest != digest:
            raise ValueError("AI-002C accounting Digest differs")
        object.__setattr__(self, "accounting_digest", digest)
        return self


class AIReplayOperationLineage(_FrozenStrictModel):
    """Public-safe operation result without prompt, request, session, or transcript."""

    lineage_digest: str = Field(default="", alias="lineageDigest", max_length=64)
    operation: AIMeasurementOperation
    registered_operation_digest: _Sha256 = Field(alias="registeredOperationDigest")
    execution_identity_digest: _Sha256 = Field(alias="executionIdentityDigest")
    private_measurement_digest: _Sha256 = Field(alias="privateMeasurementDigest")
    accounting_digest: _Sha256 = Field(alias="accountingDigest")
    result_state: Literal[
        "known-positive-observed",
        "supporting-replay-observed",
        "baseline-control-observed",
        "negative-control-not-observed",
        "counterfactual-control-not-observed",
    ] = Field(alias="resultState")
    expected_result_satisfied: Literal[True] = Field(
        default=True,
        alias="expectedResultSatisfied",
    )
    cleanup_verified: Literal[True] = Field(default=True, alias="cleanupVerified")
    ai_observation_confirmed: Literal[False] = Field(
        default=False,
        alias="aiObservationConfirmed",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")

    @field_validator("expected_result_satisfied", "cleanup_verified", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI-002C public lineage completion markers must be true")
        return value

    @field_validator("ai_observation_confirmed", "finding_authority", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI-002C public lineage escalation markers must be false")
        return value

    @model_validator(mode="after")
    def bind_lineage(self) -> Self:
        expected_states = {
            1: "known-positive-observed",
            2: "supporting-replay-observed",
            3: "supporting-replay-observed",
            4: "baseline-control-observed",
            5: "negative-control-not-observed",
            6: "counterfactual-control-not-observed",
        }
        if (
            self.operation != registered_ai_measurement_operations()[self.operation.ordinal - 1]
            or self.registered_operation_digest != _operation_digest(self.operation)
            or self.result_state != expected_states[self.operation.ordinal]
        ):
            raise ValueError("AI-002C public operation lineage differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"lineage_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-replay-operation-lineage/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.lineage_digest and self.lineage_digest != digest:
            raise ValueError("AI-002C operation lineage Digest differs")
        object.__setattr__(self, "lineage_digest", digest)
        return self


class AIReplayMetricObservation(_FrozenStrictModel):
    """One exact DOMAIN-006 AI metric value or registered N/A reason."""

    metric: DomainBenchmarkMetricRef
    unit: BenchmarkMetricUnit
    applicability: DomainBenchmarkMetricApplicability
    comparison: AIMetricFloorComparison
    numerator: _NonNegativeInt | None = None
    denominator: _PositiveInt | None = None
    not_applicable_reason: DomainBenchmarkNotApplicableReason | None = Field(
        default=None,
        alias="notApplicableReason",
    )
    floor_satisfied: Literal[True] = Field(default=True, alias="floorSatisfied")

    @field_validator("floor_satisfied", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI-002C metric floor marker must be true")
        return value

    @model_validator(mode="after")
    def require_complete_value(self) -> Self:
        if self.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE:
            if (
                self.numerator is not None
                or self.denominator is not None
                or self.not_applicable_reason is None
            ):
                raise ValueError("AI-002C N/A metric carries a numeric value")
        elif (
            self.numerator is None
            or self.denominator is None
            or self.not_applicable_reason is not None
        ):
            raise ValueError("AI-002C required metric lacks one exact rational")
        return self


class AIReplayFloorEvaluationRef(_FrozenStrictModel):
    evaluation_id: str = Field(
        alias="evaluationId",
        pattern=r"^ai-replay-floor-evaluation_[a-f0-9]{64}$",
    )
    evaluation_digest: _Sha256 = Field(alias="evaluationDigest")

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.evaluation_id != f"ai-replay-floor-evaluation_{self.evaluation_digest}":
            raise ValueError("AI-002C evaluation reference differs")
        return self


class AIReplayFloorEvaluation(_FrozenStrictModel):
    """Public-safe AI-002C aggregate with no prompt, session, request, or transcript."""

    api_version: Literal["pajin.dev/ai-replay-floor-evaluation/v1alpha1"] = Field(
        default=AI_REPLAY_FLOOR_EVALUATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIReplayFloorEvaluation"] = "AIReplayFloorEvaluation"
    evaluation_id: str = Field(default="", alias="evaluationId", max_length=125)
    evaluation_digest: str = Field(default="", alias="evaluationDigest", max_length=64)
    measured_case_authority: AIMeasuredCaseAuthorityRef = Field(alias="measuredCaseAuthority")
    measurement_protocol: AIMeasurementProtocolRef = Field(alias="measurementProtocol")
    floor_policy: AIValidationFloorPolicyRef = Field(alias="floorPolicy")
    source_measurement: AISourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    images: AISourceImageBindingRef
    action_authority_context_digest: _Sha256 = Field(alias="actionAuthorityContextDigest")
    operations: tuple[AIReplayOperationLineage, ...] = Field(min_length=6, max_length=6)
    observations: tuple[AIReplayMetricObservation, ...] = Field(min_length=14, max_length=14)
    state: Literal["independent-fresh-session-replay-controls-ai-floor-satisfied"] = (
        "independent-fresh-session-replay-controls-ai-floor-satisfied"
    )
    source_measurement_reopened: Literal[True] = Field(
        default=True,
        alias="sourceMeasurementReopened",
    )
    replay_measurements_reopened: Literal[True] = Field(
        default=True,
        alias="replayMeasurementsReopened",
    )
    controls_reopened: Literal[True] = Field(default=True, alias="controlsReopened")
    source_replay_control_identity_disjoint: Literal[True] = Field(
        default=True,
        alias="sourceReplayControlIdentityDisjoint",
    )
    private_ground_truth_evaluated: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthEvaluated",
    )
    exact_metric_set_evaluated: Literal[True] = Field(
        default=True,
        alias="exactMetricSetEvaluated",
    )
    accounting_observed: Literal[True] = Field(default=True, alias="accountingObserved")
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
    target_creation_authorized: Literal[False] = Field(
        default=False,
        alias="targetCreationAuthorized",
    )
    network_creation_authorized: Literal[False] = Field(
        default=False,
        alias="networkCreationAuthorized",
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    caller_configuration_authorized: Literal[False] = Field(
        default=False,
        alias="callerConfigurationAuthorized",
    )
    approval_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="approvalIssuanceAuthorized",
    )
    replay_execution_authorized: Literal[False] = Field(
        default=False,
        alias="replayExecutionAuthorized",
    )
    control_execution_authorized: Literal[False] = Field(
        default=False,
        alias="controlExecutionAuthorized",
    )
    gateway_execution_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayExecutionAuthorized",
    )
    worker_execution_authorized: Literal[False] = Field(
        default=False,
        alias="workerExecutionAuthorized",
    )
    ai_observation_confirmed: Literal[False] = Field(
        default=False,
        alias="aiObservationConfirmed",
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
    reporting_authorized: Literal[False] = Field(
        default=False,
        alias="reportingAuthorized",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    external_provider_authorized: Literal[False] = Field(
        default=False,
        alias="externalProviderAuthorized",
    )
    external_target_authorized: Literal[False] = Field(
        default=False,
        alias="externalTargetAuthorized",
    )
    production_target_authorized: Literal[False] = Field(
        default=False,
        alias="productionTargetAuthorized",
    )
    arbitrary_prompt_authorized: Literal[False] = Field(
        default=False,
        alias="arbitraryPromptAuthorized",
    )
    arbitrary_tool_authorized: Literal[False] = Field(
        default=False,
        alias="arbitraryToolAuthorized",
    )
    plugin_authorized: Literal[False] = Field(default=False, alias="pluginAuthorized")
    rag_authorized: Literal[False] = Field(default=False, alias="ragAuthorized")
    mcp_authorized: Literal[False] = Field(default=False, alias="mcpAuthorized")
    memory_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="memoryMutationAuthorized",
    )
    m06_authorized: Literal[False] = Field(default=False, alias="m06Authorized")
    a04_authorized: Literal[False] = Field(default=False, alias="a04Authorized")
    general_ai_scanner_authorized: Literal[False] = Field(
        default=False,
        alias="generalAIScannerAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    grant_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="grantIssuanceAuthorized",
    )
    application_protocol_write_authorized: Literal[False] = Field(
        default=False,
        alias="applicationProtocolWriteAuthorized",
    )
    model_call_authorized: Literal[False] = Field(
        default=False,
        alias="modelCallAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator("operations", "observations", mode="before")
    @classmethod
    def accept_canonical_wire_arrays(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @field_validator(*_TRUE_PUBLIC_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI-002C completion markers must be boolean true")
        return value

    @field_validator(*_FALSE_PUBLIC_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI-002C authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_evaluation(self) -> Self:
        expected = registered_ai_measurement_operations()
        if tuple(item.operation for item in self.operations) != expected or tuple(
            item.operation.ordinal for item in self.operations
        ) != tuple(range(1, 7)):
            raise ValueError("AI-002C public operation order differs")
        try:
            _validate_public_observations(self.observations)
        except AIReplayEvaluationError as exc:
            raise ValueError(str(exc)) from exc
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_id", "evaluation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-replay-floor-evaluation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        evaluation_id = f"ai-replay-floor-evaluation_{digest}"
        if self.evaluation_digest and self.evaluation_digest != digest:
            raise ValueError("AI-002C floor evaluation Digest differs")
        if self.evaluation_id and self.evaluation_id != evaluation_id:
            raise ValueError("AI-002C floor evaluation ID differs")
        object.__setattr__(self, "evaluation_digest", digest)
        object.__setattr__(self, "evaluation_id", evaluation_id)
        return self

    def reference(self) -> AIReplayFloorEvaluationRef:
        return AIReplayFloorEvaluationRef(
            evaluationId=self.evaluation_id,
            evaluationDigest=self.evaluation_digest,
        )


class AIPrivateFollowupOperationMeasurement(_FrozenEmbeddedModel):
    """Private prompt, transcript, authority, runtime, receipt, and cleanup custody."""

    measurement_digest: str = Field(default="", alias="measurementDigest", max_length=64)
    operation: AIMeasurementOperation
    registered_operation_digest: _Sha256 = Field(alias="registeredOperationDigest")
    materialization_nonce: str = Field(
        alias="materializationNonce",
        pattern=r"^[a-f0-9]{32}$",
    )
    ground_truth: AIPrivateGroundTruthCase = Field(alias="groundTruth")
    control_derivation: AIPrivateControlDerivation | None = Field(
        default=None,
        alias="controlDerivation",
    )
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    reservation_path: str = Field(alias="reservationPath", min_length=1, max_length=300)
    reservation_sha256: _Sha256 = Field(alias="reservationSha256")
    execution_evidence_path: str = Field(
        alias="executionEvidencePath",
        min_length=1,
        max_length=300,
    )
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    request: ToolRequest
    challenge: AIMeasurementTargetExecutionChallenge
    trust_anchor: TargetAttestationTrustAnchor = Field(alias="trustAnchor")
    proxy_binding: AIMeasurementTargetProxyBinding = Field(alias="proxyBinding")
    lifecycle: AIMeasurementFixtureTargetLifecycleEvidence
    worker_result: WorkerResult = Field(alias="workerResult")
    tool_result: ToolResult = Field(alias="toolResult")
    output: AIChatProbeOutput
    accounting: AIMeasurementAccountingObservation
    expected_observed: bool = Field(alias="expectedObserved")
    observed: bool
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    finding_created: Literal[False] = Field(default=False, alias="findingCreated")

    @field_validator("expected_observed", "observed", mode="before")
    @classmethod
    def require_exact_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI-002C observation values must be exact booleans")
        return value

    @field_validator("graph_admitted", "finding_created", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI-002C private escalation markers must be false")
        return value

    @model_validator(mode="after")
    def bind_private_measurement(self) -> Self:
        operations = registered_ai_measurement_operations()
        if (
            self.operation.ordinal not in range(2, 7)
            or self.operation != operations[self.operation.ordinal - 1]
            or self.registered_operation_digest != _operation_digest(self.operation)
            or self.challenge.registered_operation_digest != self.registered_operation_digest
            or self.challenge.operation_key != _operation_key(self.operation)
            or self.challenge.operation_ordinal != self.operation.ordinal
            or self.challenge.operation_stage != self.operation.stage.value
        ):
            raise ValueError("AI-002C private operation registration differs")
        controls = registered_ai_private_ground_truth_binding().control_derivations
        expected_control = (
            None
            if self.operation.stage is AIMeasurementOperationStage.REPLAY
            else controls[self.operation.ordinal - 4]
        )
        expected_observed = (
            True
            if self.operation.stage is AIMeasurementOperationStage.REPLAY
            else expected_control.expected_observed
            if expected_control is not None
            else False
        )
        probe = AIChatProbeInput.model_validate(self.request.arguments)
        expected_probe = _materialize_operation_probe(
            self.operation,
            source_probe=_registered_source_probe("pajin:ai002c:private-validation"),
            nonce=self.materialization_nonce,
        )
        if (
            self.ground_truth != registered_ai_private_ground_truth_binding().case
            or self.control_derivation != expected_control
            or self.expected_observed is not expected_observed
            or self.observed is not expected_observed
            or probe != expected_probe
            or self.request.request_id != self.challenge.measurement_request_id
            or self.request.tool_id != AIChatProbeTool.spec.tool_id
            or self.request.method != "POST"
            or self.request.target != self.lifecycle.coordinate.target_url
            or self.output.target != self.request.target
            or self.output.scenario_id != self.ground_truth.scenario_id
            or self.output.threat_class != self.ground_truth.threat_class
            or self.output.session_id != probe.session_id
            or self.output.vulnerable is not expected_observed
            or self.output.sensitive_exposure_count != (1 if expected_observed else 0)
            or len(self.output.turns) != 1
            or len(self.output.checks) != 1
            or self.output.checks[0].matched is not expected_observed
            or self.tool_result.request_id != self.request.request_id
            or self.tool_result.tool_id != self.request.tool_id
            or self.tool_result.success is not True
            or self.lifecycle.attempt.case != self.operation.case
            or self.lifecycle.target_receipt.digest != self.proxy_binding.target_receipt_sha256
            or self.challenge.digest != self.proxy_binding.challenge_sha256
            or self.approval_receipt.action_permit.permit_digest != self.challenge.permit_digest
            or self.accounting.operation_ordinal != self.operation.ordinal
            or self.accounting.request_id != self.request.request_id
            or self.accounting.execution_run_id != self.source_run_id
            or self.accounting.execution_evidence_sha256 != self.execution_evidence_sha256
        ):
            raise ValueError("AI-002C private prompt, output, authority, or accounting differs")
        verify_ai_measurement_target_execution_receipt(
            self.lifecycle.target_receipt,
            trust_anchor=self.trust_anchor,
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"measurement_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-private-followup-operation-measurement/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.measurement_digest and self.measurement_digest != digest:
            raise ValueError("AI-002C private operation measurement Digest differs")
        object.__setattr__(self, "measurement_digest", digest)
        return self


class AIPrivateReplayEvaluationBinding(_FrozenEmbeddedModel):
    """Separate private AI-002C authority; raw material never enters the public artifact."""

    api_version: Literal["pajin.dev/ai-private-replay-evaluation-binding/v1alpha1"] = Field(
        default=AI_PRIVATE_REPLAY_EVALUATION_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIPrivateReplayEvaluationBinding"] = "AIPrivateReplayEvaluationBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=125)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    public_evaluation: AIReplayFloorEvaluationRef = Field(alias="publicEvaluation")
    measured_case_authority: AIMeasuredCaseAuthorityRef = Field(alias="measuredCaseAuthority")
    source_measurement: AISourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    private_ground_truth: AIPrivateGroundTruthBinding = Field(alias="privateGroundTruth")
    images: AISourceImageBinding
    source_private_measurement: AIPrivateSourceMeasurement = Field(alias="sourcePrivateMeasurement")
    followup_measurements: tuple[AIPrivateFollowupOperationMeasurement, ...] = Field(
        alias="followupMeasurements",
        min_length=5,
        max_length=5,
    )
    execution_identities: tuple[AIMeasurementExecutionIdentity, ...] = Field(
        alias="executionIdentities",
        min_length=6,
        max_length=6,
    )
    accounting_observations: tuple[AIMeasurementAccountingObservation, ...] = Field(
        alias="accountingObservations",
        min_length=6,
        max_length=6,
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
    reporting_authorized: Literal[False] = Field(
        default=False,
        alias="reportingAuthorized",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(
        "graph_admission_authorized",
        "graph_mutation_authorized",
        "finding_authority",
        "product_projection_authorized",
        "reporting_authorized",
        "external_delivery_authorized",
        "additional_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI-002C private authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_private_evaluation(self) -> Self:
        operations = registered_ai_measurement_operations()
        if (
            self.private_ground_truth != registered_ai_private_ground_truth_binding()
            or self.source_private_measurement.ground_truth != self.private_ground_truth.case
            or tuple(item.operation for item in self.followup_measurements) != operations[1:]
            or tuple(item.operation_ordinal for item in self.execution_identities)
            != tuple(range(1, 7))
            or tuple(item.operation_ordinal for item in self.accounting_observations)
            != tuple(range(1, 7))
            or tuple(item.accounting for item in self.followup_measurements)
            != self.accounting_observations[1:]
            or self.accounting_observations[0].request_id
            != self.source_private_measurement.request.request_id
        ):
            raise ValueError("AI-002C private membership or canonical order differs")
        try:
            _require_disjoint_identities(self.execution_identities)
        except AIReplayEvaluationError as exc:
            raise ValueError(str(exc)) from exc
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-private-replay-evaluation-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"ai-private-replay-evaluation_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI-002C private evaluation Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("AI-002C private evaluation ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


@dataclass(frozen=True, slots=True)
class AIReplayEvaluationMapping:
    public_evaluation: AIReplayFloorEvaluation
    private_binding: AIPrivateReplayEvaluationBinding


@dataclass(frozen=True, slots=True)
class AIMeasurementApprovedAction:
    """Deployment-owned approval inputs for one runner-materialized AI-002C request."""

    activation: ExistingModeCapabilityActivation
    campaign: CampaignManifest
    preparation: AIMeasurementOperationPreparation
    job: CapabilityGraphCampaignJobInput
    mission_envelope: MissionEnvelope
    graph_store: SQLiteGraphStore
    approval_input_authority: ActionApprovalInputAuthority
    approval_issuer: ActionApprovalIssuerAuthorityBinding
    provider_registration: ProviderRegistration
    authority_context_digest: str


class AIMeasurementActionAuthorizer(Protocol):
    """Deployment authority approving only the exact code-owned request supplied by AI-002C."""

    def stable_authority_context(self) -> Mapping[str, object]: ...

    def authorize(
        self,
        *,
        case: AIMeasuredCaseRef,
        operation: AIMeasurementOperation,
        target: AIFixtureTargetCoordinate,
        run_id: str,
        request: ToolRequest,
    ) -> AIMeasurementApprovedAction: ...


@dataclass(frozen=True, slots=True)
class AIMeasurementExecutionContext:
    source_inputs: AIAnalysisObservationSourceInputs
    graph_store: SQLiteGraphStore
    lifecycle: AIMeasurementFixtureTargetLifecycleEvidence
    challenge: AIMeasurementTargetExecutionChallenge


@dataclass(frozen=True, slots=True)
class AIReplayEvaluationOutcome:
    run_id: str
    run_path: Path
    evaluation_path: str
    private_binding_path: str
    mapping: AIReplayEvaluationMapping
    source: AISourceMeasurementOutcome
    executions: tuple[AIMeasurementExecutionContext, ...]


@dataclass(frozen=True, slots=True)
class _ExecutedOperation:
    source: VerifiedAIAnalysisObservationSource
    source_inputs: AIAnalysisObservationSourceInputs
    graph_store: SQLiteGraphStore
    approval_receipt: ActionApprovalConsumptionReceipt
    permit: ActionPermit
    challenge: AIMeasurementTargetExecutionChallenge
    measurement_tool: AIM03MeasurementChatProbeTool


@dataclass(frozen=True, slots=True)
class _DispatchedOperation:
    outcome: GatewayOutcome
    challenge: AIMeasurementTargetExecutionChallenge
    measurement_tool: AIM03MeasurementChatProbeTool


def _exact_m03_scenario() -> KISAScenarioDefinition:
    matches = tuple(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.model.system-prompt-disclosure"
    )
    if len(matches) != 1:
        raise AIReplayEvaluationError("AI-002C requires one exact registered M03 scenario")
    return matches[0]


def _registered_source_probe(session_id: str) -> AIChatProbeInput:
    ground_truth = registered_ai_private_ground_truth_binding().case
    return AIChatProbeInput.model_validate(
        {
            "scenario_id": ground_truth.scenario_id,
            "threat_class": ground_truth.threat_class,
            "session_id": session_id,
            "turns": [
                {
                    "name": "system-prompt-extraction",
                    "messages": [{"role": "user", "content": ground_truth.prompt_text}],
                }
            ],
            "checks": [
                {
                    "check_id": ground_truth.check_id,
                    "kind": ground_truth.check_kind,
                    "turn": ground_truth.check_turn,
                    "value": ground_truth.check_value,
                    "sensitive": True,
                }
            ],
        }
    )


def _materialize_operation_probe(
    operation: AIMeasurementOperation,
    *,
    source_probe: AIChatProbeInput,
    nonce: str,
) -> AIChatProbeInput:
    if operation != registered_ai_measurement_operations()[operation.ordinal - 1]:
        raise AIReplayEvaluationError("AI-002C operation is not registered")
    if operation.stage is AIMeasurementOperationStage.REPLAY:
        if operation.repetition is None:
            raise AIReplayEvaluationError("AI-002C Replay repetition is absent")
        payload = source_probe.model_dump(mode="json")
        payload["session_id"] = f"pajin:replay:{nonce}:{operation.repetition}"
        return AIChatProbeInput.model_validate(payload)
    if operation.stage is not AIMeasurementOperationStage.CONTROL:
        raise AIReplayEvaluationError("AI-002C follow-up operation stage differs")
    materializer = KISAAIChatValidationControlMaterializer(_exact_m03_scenario())
    original = cast(Mapping[str, JsonValue], source_probe.model_dump(mode="json"))
    controls = materializer.materialize(original, nonce=nonce)
    index = operation.ordinal - 4
    if (
        index not in range(3)
        or operation.control_kind is None
        or controls[index].control_kind is not operation.control_kind
    ):
        raise AIReplayEvaluationError("AI-002C Control materialization order differs")
    return AIChatProbeInput.model_validate(controls[index].arguments)


def _canonical_json_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, TypeError, ValueError) as exc:
        raise AIReplayEvaluationError("AI-002C JSON is not canonical") from exc
    return sha256(encoded).hexdigest()


def _canonical_backend_context(backend: DockerWorkerBackend) -> dict[str, object]:
    if type(backend) is not DockerWorkerBackend:
        raise AIReplayEvaluationError("AI-002C requires the exact Docker Worker backend")
    try:
        encoded = json.dumps(
            backend.stable_execution_context(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        parsed = json.loads(encoded)
    except (OverflowError, TypeError, ValueError) as exc:
        raise AIReplayEvaluationError("AI-002C Docker backend context is invalid") from exc
    if type(parsed) is not dict or len(encoded) > 1024 * 1024:
        raise AIReplayEvaluationError("AI-002C Docker backend context is not bounded")
    return parsed


def _provider_registration_sha256(provider: ProviderRegistration) -> str:
    return _canonical_json_sha256(provider.model_dump(mode="json"))


def _require_zero_priced_local_provider(provider: ProviderRegistration) -> None:
    if (
        provider.provider_id != "ai002b-local-target"
        or provider.model != "pajin-deterministic-lab-v1"
        or provider.input_cost_per_million_usd != 0
        or provider.output_cost_per_million_usd != 0
        or provider.allow_streaming is not False
        or provider.allowed_function_tools
        or provider.allow_private_networks is not True
    ):
        raise AIReplayEvaluationError(
            "AI-002C accounting requires the exact zero-priced deterministic local provider"
        )


def _require_disjoint_identities(
    identities: tuple[AIMeasurementExecutionIdentity, ...],
) -> None:
    if tuple(item.operation_ordinal for item in identities) != tuple(range(1, 7)):
        raise AIReplayEvaluationError("AI-002C execution identity order differs")
    seen: set[str] = set()
    for identity in identities:
        dynamic = set(identity.dynamic_values())
        if seen.intersection(dynamic):
            raise AIReplayEvaluationError(
                "AI-002C source, Replay, or Control execution identities overlap"
            )
        seen.update(dynamic)


def _validate_operation_pre_dispatch(
    plan: AIMeasurementApprovedAction,
    *,
    expected_case: AIMeasuredCaseRef,
    expected_operation: AIMeasurementOperation,
    expected_request: ToolRequest,
    target: AIFixtureTargetCoordinate,
    images: AISourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    inspector: AIDockerBoundaryInspector,
) -> None:
    """Fail closed on operation, request, mode, image, route, Scope, or authority."""

    if type(plan) is not AIMeasurementApprovedAction:
        raise AIReplayEvaluationError("AI-002C action plan requires its exact deployment type")
    if (
        not isinstance(plan.activation, ExistingModeCapabilityActivation)
        or not isinstance(plan.graph_store, SQLiteGraphStore)
        or not callable(getattr(plan.approval_input_authority, "verify_action_approval", None))
    ):
        raise AIReplayEvaluationError("AI-002C action authority inputs are invalid")
    try:
        case = AIMeasuredCaseRef.model_validate_json(expected_case.model_dump_json(by_alias=True))
        operation = AIMeasurementOperation.model_validate_json(
            expected_operation.model_dump_json(by_alias=True)
        )
        request = ToolRequest.model_validate_json(expected_request.model_dump_json())
        coordinate = AIFixtureTargetCoordinate.model_validate_json(
            target.model_dump_json(by_alias=True)
        )
        image_binding = AISourceImageBinding.model_validate_json(
            images.model_dump_json(by_alias=True)
        )
        campaign = CampaignManifest.model_validate_json(
            plan.campaign.model_dump_json(by_alias=True)
        )
        preparation = AIMeasurementOperationPreparation.model_validate_json(
            plan.preparation.model_dump_json(by_alias=True)
        )
        job = CapabilityGraphCampaignJobInput.model_validate_json(
            plan.job.model_dump_json(by_alias=True)
        )
        envelope = MissionEnvelope.model_validate_json(
            plan.mission_envelope.model_dump_json(by_alias=True)
        )
        issuer = ActionApprovalIssuerAuthorityBinding.model_validate_json(
            plan.approval_issuer.model_dump_json(by_alias=True)
        )
        provider = ProviderRegistration.model_validate_json(
            plan.provider_registration.model_dump_json()
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise AIReplayEvaluationError("AI-002C action plan is not canonical") from exc
    approval = job.approval
    expected_issuer = authority_context.get("approvalIssuer")
    try:
        normalized_allow = tuple(
            normalize_scope_pattern(item) for item in campaign.spec.scope.allow
        )
        normalized_deny = tuple(normalize_scope_pattern(item) for item in campaign.spec.scope.deny)
        expected_scope = normalize_scope_pattern(coordinate.target_url)
    except InvalidScopeURL as exc:
        raise AIReplayEvaluationError("AI-002C Campaign Scope is invalid") from exc
    rebuilt = prepare_ai_measurement_operation(
        activation=plan.activation,
        release=preparation.release,
        binding=preparation.binding,
        request=job.request,
        provider_registration=provider,
        registered_operation_digest=_operation_digest(operation),
        operation_key=_operation_key(operation),
        operation_ordinal=cast(Literal[2, 3, 4, 5, 6], operation.ordinal),
        operation_stage=cast(Literal["replay", "control"], operation.stage.value),
    )
    expected_provider = ai_source_provider_registration(coordinate)
    probe = AIChatProbeInput.model_validate(job.request.arguments)
    expected_probe = AIChatProbeInput.model_validate(request.arguments)
    actual_backend_context = _canonical_backend_context(backend)
    worker_image = image_binding.role(AIMeasurementImageRole.WORKER)
    proxy_image = image_binding.role(AIMeasurementImageRole.PROXY)
    target_image = image_binding.role(AIMeasurementImageRole.TARGET)
    campaign_targets = tuple(campaign.spec.targets)
    budgets = campaign.spec.budgets
    rules = campaign.spec.rules_of_engagement
    expected_observer_context = dict(inspector.stable_observer_context())
    expected_backend_keys = {
        "implementationVersion",
        "allowedImages",
        "dockerExecutable",
        "egressProxyImage",
        "externalNetwork",
        "runtimeImageBindings",
        "externalNetworkRoutes",
        "egressLifecycleObserver",
    }
    if (
        case != coordinate.case
        or operation != registered_ai_measurement_operations()[operation.ordinal - 1]
        or operation.case != case
        or request != expected_request
        or image_binding.reference() != coordinate.images
        or target_image.observed_image_id != coordinate.target_image_id
        or plan.authority_context_digest != authority_context_digest
        or not isinstance(expected_issuer, dict)
        or expected_issuer != issuer.model_dump(mode="json", by_alias=True)
        or approval is None
        or approval.issuer != issuer
        or campaign != plan.campaign
        or preparation != plan.preparation
        or job != plan.job
        or envelope != plan.mission_envelope
        or provider != plan.provider_registration
        or provider != expected_provider
        or rebuilt != preparation
        or job.profile != "redteam-llm-v1"
        or job.request != preparation.prepared_action.request
        or job.request != request
        or not job.request.request_id.startswith(f"tool_ai002c_operation_{operation.ordinal:02d}_")
        or len(job.request.request_id)
        != len(f"tool_ai002c_operation_{operation.ordinal:02d}_") + 32
        or job.request.target != coordinate.target_url
        or job.request.method != "POST"
        or job.request.tool_id != AIChatProbeTool.spec.tool_id
        or probe != expected_probe
        or len(campaign_targets) != 1
        or campaign_targets[0].type != "ai-chat-api"
        or campaign_targets[0].endpoint != coordinate.target_url
        or tuple(campaign.spec.threat_classes) != ("M03",)
        or campaign.spec.outputs
        or rules.max_tool_risk_tier is not ToolRiskTier.T2
        or rules.allowed_tool_categories != AIChatProbeTool.spec.categories
        or rules.max_requests_per_minute != 1
        or budgets.duration_seconds != 120
        or budgets.max_cost_usd != 0
        or budgets.max_agents != 1
        or budgets.max_spawn_depth != 0
        or budgets.max_tool_calls != 1
        or budgets.max_model_calls != 0
        or budgets.max_model_tokens != 0
        or coordinate.target_mode != "vulnerable"
        or coordinate.route_path != "/v1/chat"
        or normalized_allow != (expected_scope,)
        or normalized_deny
        or set(rules.allowed_methods) != {"POST"}
        or rules.allow_private_networks is not True
        or plan.graph_store.campaign_id != campaign.metadata.name
        or job.release != preparation.release
        or job.proposal.run_id != envelope.run_id
        or job.proposal.envelope_id != envelope.envelope_id
        or job.proposal.envelope_digest != envelope.envelope_digest
        or approval.mission_envelope != envelope
        or approval.proposal != job.proposal
        or approval.graph_decision != job.decision
        or set(actual_backend_context) != expected_backend_keys
        or actual_backend_context.get("implementationVersion") != "pajin.docker-worker/v4"
        or actual_backend_context.get("allowedImages") != ["pajin-worker:dev"]
        or actual_backend_context.get("runtimeImageBindings")
        != {"pajin-worker:dev": worker_image.observed_image_id}
        or actual_backend_context.get("egressProxyImage") != proxy_image.observed_image_id
        or actual_backend_context.get("externalNetwork") != "bridge"
        or actual_backend_context.get("externalNetworkRoutes")
        != {"ai-chat-probe": coordinate.target_network_name}
        or actual_backend_context.get("egressLifecycleObserver") != expected_observer_context
        or not backend.binds_egress_lifecycle_observer(inspector)
    ):
        raise AIReplayEvaluationError("AI-002C pre-dispatch authority differs")
    _require_zero_priced_local_provider(provider)
    if any(
        permit.run_id == envelope.run_id
        or permit.request_id == preparation.prepared_action.request.request_id
        for permit in plan.graph_store.permit_store.permits()
    ):
        raise AIReplayEvaluationError(
            "AI-002C Run, request, approval, or Permit authority was reused"
        )
    if (
        plan.graph_store.permit_store.approved_authorization(
            approval.approval_id,
            approval.expected_action_permit_id,
        )
        is not None
    ):
        raise AIReplayEvaluationError("AI-002C approval authority was already consumed")


async def _execute_approved_operation(
    plan: AIMeasurementApprovedAction,
    *,
    expected_case: AIMeasuredCaseRef,
    operation: AIMeasurementOperation,
    expected_request: ToolRequest,
    target: AIFixtureTargetCoordinate,
    images: AISourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    inspector: AIDockerBoundaryInspector,
    source_runs_root: Path,
) -> _ExecutedOperation:
    _validate_operation_pre_dispatch(
        plan,
        expected_case=expected_case,
        expected_operation=operation,
        expected_request=expected_request,
        target=target,
        images=images,
        authority_context=authority_context,
        authority_context_digest=authority_context_digest,
        backend=backend,
        inspector=inspector,
    )
    job = plan.job
    approval = job.approval
    if approval is None:
        raise AIReplayEvaluationError("AI-002C execution requires one explicit approval")
    run_store = RunStore.create(
        source_runs_root,
        plan.campaign.metadata.name,
        run_id=plan.mission_envelope.run_id,
    )
    permit_authority = GraphApprovedActionPermitAuthority(
        campaign_id=plan.campaign.metadata.name,
        compiler_id=plan.mission_envelope.compiler_id,
        compiler_version=plan.mission_envelope.compiler_version,
        compiler_digest=plan.mission_envelope.compiler_digest,
        capabilities=plan.activation.action_registry(),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=plan.preparation.prepared_action.capability,
                    sideEffectClass="read-only",
                    approvalRequired=True,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=plan.graph_store.permit_store,
        input_authority=plan.approval_input_authority,
    )
    dispatcher = GraphApprovedActionPermitDispatcher(permit_authority)

    async def dispatch(
        permit: ActionPermit,
        _receipt: ActionApprovalConsumptionReceipt,
    ) -> _DispatchedOperation:
        issued_at = datetime.now(UTC)
        expires_at = min(issued_at + timedelta(seconds=60), permit.expires_at)
        if expires_at <= issued_at:
            raise AIReplayEvaluationError("AI-002C Permit expires before its Target challenge")
        execution_digest = benchmark_digest(
            "pajin.workflow.ai-measurement-operation-execution/v1",
            {
                "registeredOperationDigest": _operation_digest(operation),
                "attemptDigest": target.attempt_digest,
                "permitDigest": permit.permit_digest,
                "requestDigest": permit.request_digest,
            },
            max_bytes=256 * 1024,
        )
        challenge = derive_ai_measurement_target_execution_challenge(
            permit_digest=permit.permit_digest,
            measurement_request_id=job.request.request_id,
            measurement_operation_id=f"ai-measurement-operation_{execution_digest}",
            registered_operation_digest=_operation_digest(operation),
            operation_key=_operation_key(operation),
            operation_ordinal=cast(Literal[2, 3, 4, 5, 6], operation.ordinal),
            operation_stage=cast(Literal["replay", "control"], operation.stage.value),
            target=job.request.target,
            method=job.request.method,
            compiled_argument_digest=_canonical_json_sha256(job.request.arguments),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        measurement_tool = AIM03MeasurementChatProbeTool(
            challenge=challenge,
            expected_request=job.request,
        )
        tools = ToolRegistry()
        tools.register(measurement_tool)
        gateway = ToolGateway(
            policy=PolicyEngine(),
            tools=tools,
            worker=backend,
            store=run_store,
        )
        claimed = CapabilityDispatchAuditEvent(
            stage=CapabilityDispatchStage.CLAIMED,
            occurredAt=issued_at,
            activationSetDigest=plan.preparation.prepared_action.activation_set_digest,
            release=plan.preparation.release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantDigest=capability_grant_digest(job.grant),
        )
        run_store.append_event(
            "capability.dispatch.claimed",
            claimed.model_dump(mode="json", by_alias=True),
            occurred_at=claimed.occurred_at,
        )
        outcome = await gateway.execute(
            plan.campaign,
            job.grant,
            job.request,
            used_calls=0,
        )
        completed = CapabilityDispatchAuditEvent(
            stage=CapabilityDispatchStage.COMPLETED,
            occurredAt=datetime.now(UTC),
            activationSetDigest=plan.preparation.prepared_action.activation_set_digest,
            release=plan.preparation.release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantDigest=capability_grant_digest(job.grant),
            gatewayOutcomeDigest=capability_gateway_outcome_digest(outcome),
            gatewayExecutionId=(
                outcome.worker_result.execution_id if outcome.worker_result is not None else None
            ),
            executed=outcome.executed,
            policyAllowed=outcome.decision.allowed,
            toolSuccess=outcome.result.success,
            evidence=tuple(sorted(set(outcome.result.evidence))),
        )
        run_store.append_event(
            "capability.dispatch.completed",
            completed.model_dump(mode="json", by_alias=True),
            occurred_at=completed.occurred_at,
        )
        return _DispatchedOperation(
            outcome=outcome,
            challenge=challenge,
            measurement_tool=measurement_tool,
        )

    dispatched = await dispatcher.dispatch_once(
        plan.mission_envelope,
        job.proposal,
        job.decision,
        approval,
        dispatch,
    )
    if dispatched.dispatched is not True or dispatched.result is None:
        raise AIReplayEvaluationError("AI-002C approval or Permit was reused before dispatch")
    run_store.seal()
    source_inputs = AIAnalysisObservationSourceInputs(
        run_path=run_store.path,
        expected_run_id=run_store.run_id,
        preparation=plan.preparation,
        job=job,
    )
    source = load_verified_ai_analysis_observation_source(
        source_inputs,
        graph_store=plan.graph_store,
        measurement_tool=dispatched.result.measurement_tool,
    )
    return _ExecutedOperation(
        source=source,
        source_inputs=source_inputs,
        graph_store=plan.graph_store,
        approval_receipt=dispatched.authorization.receipt,
        permit=dispatched.authorization.action.permit,
        challenge=dispatched.result.challenge,
        measurement_tool=dispatched.result.measurement_tool,
    )


def _build_accounting(
    *,
    operation_ordinal: int,
    source: VerifiedAIAnalysisObservationSource,
    provider: ProviderRegistration,
) -> AIMeasurementAccountingObservation:
    _require_zero_priced_local_provider(provider)
    provider_model = source.preparation.binding.provider_model
    if (
        provider_model is None
        or source.preparation.provider_registration_reverified is not True
        or provider_model.provider_registration_digest != ai_provider_registration_digest(provider)
        or source.evidence.result.success is not True
        or source.evidence.worker_result.status.value != "succeeded"
    ):
        raise AIReplayEvaluationError(
            "AI-002C accounting lacks sealed provider, Gateway, Tool, or Worker Evidence"
        )
    return AIMeasurementAccountingObservation(
        operationOrdinal=operation_ordinal,
        requestId=source.job.request.request_id,
        executionRunId=source.snapshot.verification.run_id,
        executionEvidenceSha256=source.evidence_sha256,
        providerRegistrationSha256=_provider_registration_sha256(provider),
        requestUnitCount=1,
        toolCallCount=1,
        modelProviderCallCount=0,
        modelProviderCostMicroUsd=0,
    )


def _build_followup_measurement(
    *,
    operation: AIMeasurementOperation,
    nonce: str,
    executed: _ExecutedOperation,
    trust_anchor: TargetAttestationTrustAnchor,
    lifecycle: AIMeasurementFixtureTargetLifecycleEvidence,
    provider: ProviderRegistration,
) -> AIPrivateFollowupOperationMeasurement:
    source = executed.source
    preparation = source.preparation
    if (
        type(preparation) is not AIMeasurementOperationPreparation
        or preparation.registered_operation_digest != _operation_digest(operation)
        or preparation.operation_key != _operation_key(operation)
        or preparation.operation_ordinal != operation.ordinal
        or preparation.operation_stage != operation.stage.value
    ):
        raise AIReplayEvaluationError("AI-002C preparation differs from its registered operation")
    try:
        output = AIChatProbeOutput.model_validate(source.evidence.result.data)
    except (TypeError, ValidationError, ValueError) as exc:
        raise AIReplayEvaluationError(
            "AI-002C Tool output is not the exact typed M03 transcript"
        ) from exc
    proxy_binding = ai_measurement_target_proxy_binding(
        source.job.request,
        source.evidence.worker_result,
        output,
        expected_challenge=executed.challenge,
        target_receipt=lifecycle.target_receipt,
        network_log_trusted=source.evidence.network_log_trusted,
    )
    if (
        verify_ai_measurement_target_execution_receipt(
            lifecycle.target_receipt,
            trust_anchor=trust_anchor,
        )
        != lifecycle.target_receipt.key_id
    ):
        raise AIReplayEvaluationError("AI-002C Target receipt signer identity differs")
    controls = registered_ai_private_ground_truth_binding().control_derivations
    control = (
        None
        if operation.stage is AIMeasurementOperationStage.REPLAY
        else controls[operation.ordinal - 4]
    )
    expected_observed = True if control is None else control.expected_observed
    accounting = _build_accounting(
        operation_ordinal=operation.ordinal,
        source=source,
        provider=provider,
    )
    return AIPrivateFollowupOperationMeasurement(
        operation=operation,
        registeredOperationDigest=_operation_digest(operation),
        materializationNonce=nonce,
        groundTruth=registered_ai_private_ground_truth_binding().case,
        controlDerivation=control,
        sourceRunId=source.snapshot.verification.run_id,
        sourceRootDigest=source.snapshot.verification.root_digest,
        reservationPath=source.reservation_path,
        reservationSha256=source.reservation_sha256,
        executionEvidencePath=source.evidence_path,
        executionEvidenceSha256=source.evidence_sha256,
        approvalReceipt=executed.approval_receipt,
        request=source.job.request,
        challenge=executed.challenge,
        trustAnchor=trust_anchor,
        proxyBinding=proxy_binding,
        lifecycle=lifecycle,
        workerResult=source.evidence.worker_result,
        toolResult=source.evidence.result,
        output=output,
        accounting=accounting,
        expectedObserved=expected_observed,
        observed=output.vulnerable,
    )


def _build_source_identity(
    source: VerifiedAIAnalysisObservationSource,
    private: AIPrivateSourceMeasurement,
) -> AIMeasurementExecutionIdentity:
    approval_receipt = private.approval_receipt
    approval = approval_receipt.approval
    permit = approval_receipt.action_permit
    lifecycle = private.lifecycle
    topology = lifecycle.topology
    probe = AIChatProbeInput.model_validate(private.request.arguments)
    return AIMeasurementExecutionIdentity(
        operationOrdinal=1,
        executionRunId=source.snapshot.verification.run_id,
        sourceRootDigest=source.snapshot.verification.root_digest,
        requestId=permit.request_id,
        requestDigest=permit.request_digest,
        sessionId=probe.session_id,
        envelopeId=permit.envelope_id,
        envelopeDigest=permit.envelope_digest,
        proposalId=permit.proposal_id,
        proposalDigest=permit.proposal_digest,
        decisionId=permit.decision_id,
        decisionDigest=permit.decision_digest,
        approvalId=approval.approval_id,
        approvalDigest=approval.approval_digest,
        approvalReceiptId=approval_receipt.receipt_id,
        approvalReceiptDigest=approval_receipt.receipt_digest,
        permitId=permit.permit_id,
        permitDigest=permit.permit_digest,
        dispatchId=permit.dispatch_id,
        grantId=source.job.grant.grant_id,
        workerExecutionId=source.evidence.worker_result.execution_id,
        reservationSha256=source.reservation_sha256,
        executionEvidenceSha256=source.evidence_sha256,
        terminalEventId=source.terminal.event_id,
        terminalEventDigest=source.terminal.event_digest,
        reconciliationId=source.reconciliation.reconciliation_id,
        reconciliationDigest=source.reconciliation.reconciliation_digest,
        challengeId=private.challenge.challenge_id,
        challengeDigest=private.challenge.digest,
        targetReceiptKeyId=lifecycle.target_receipt.key_id,
        targetReceiptDigest=lifecycle.target_receipt.digest,
        targetAttemptId=lifecycle.attempt.attempt_id,
        targetAttemptDigest=lifecycle.attempt.attempt_digest,
        targetContainerId=lifecycle.coordinate.target_container_id,
        targetNetworkId=lifecycle.coordinate.target_network_id,
        workerContainerId=topology.worker_container_id,
        proxyContainerId=topology.proxy_container_id,
        internalNetworkId=topology.internal_network_id,
    )


def _build_followup_identity(
    source: VerifiedAIAnalysisObservationSource,
    private: AIPrivateFollowupOperationMeasurement,
) -> AIMeasurementExecutionIdentity:
    approval_receipt = private.approval_receipt
    approval = approval_receipt.approval
    permit = approval_receipt.action_permit
    lifecycle = private.lifecycle
    topology = lifecycle.topology
    probe = AIChatProbeInput.model_validate(private.request.arguments)
    return AIMeasurementExecutionIdentity(
        operationOrdinal=private.operation.ordinal,
        executionRunId=source.snapshot.verification.run_id,
        sourceRootDigest=source.snapshot.verification.root_digest,
        requestId=permit.request_id,
        requestDigest=permit.request_digest,
        sessionId=probe.session_id,
        envelopeId=permit.envelope_id,
        envelopeDigest=permit.envelope_digest,
        proposalId=permit.proposal_id,
        proposalDigest=permit.proposal_digest,
        decisionId=permit.decision_id,
        decisionDigest=permit.decision_digest,
        approvalId=approval.approval_id,
        approvalDigest=approval.approval_digest,
        approvalReceiptId=approval_receipt.receipt_id,
        approvalReceiptDigest=approval_receipt.receipt_digest,
        permitId=permit.permit_id,
        permitDigest=permit.permit_digest,
        dispatchId=permit.dispatch_id,
        grantId=source.job.grant.grant_id,
        workerExecutionId=source.evidence.worker_result.execution_id,
        reservationSha256=source.reservation_sha256,
        executionEvidenceSha256=source.evidence_sha256,
        terminalEventId=source.terminal.event_id,
        terminalEventDigest=source.terminal.event_digest,
        reconciliationId=source.reconciliation.reconciliation_id,
        reconciliationDigest=source.reconciliation.reconciliation_digest,
        challengeId=private.challenge.challenge_id,
        challengeDigest=private.challenge.digest,
        targetReceiptKeyId=lifecycle.target_receipt.key_id,
        targetReceiptDigest=lifecycle.target_receipt.digest,
        targetAttemptId=lifecycle.attempt.attempt_id,
        targetAttemptDigest=lifecycle.attempt.attempt_digest,
        targetContainerId=lifecycle.coordinate.target_container_id,
        targetNetworkId=lifecycle.coordinate.target_network_id,
        workerContainerId=topology.worker_container_id,
        proxyContainerId=topology.proxy_container_id,
        internalNetworkId=topology.internal_network_id,
    )


def _identity_matches_source(
    identity: AIMeasurementExecutionIdentity,
    private: AIPrivateSourceMeasurement,
) -> bool:
    lifecycle = private.lifecycle
    topology = lifecycle.topology
    return (
        identity.operation_ordinal == 1
        and identity.execution_run_id == private.source_run_id
        and identity.source_root_digest == private.source_root_digest
        and identity.request_id == private.request.request_id
        and identity.approval_receipt_id == private.approval_receipt.receipt_id
        and identity.approval_receipt_digest == private.approval_receipt.receipt_digest
        and identity.permit_id == private.approval_receipt.action_permit.permit_id
        and identity.permit_digest == private.approval_receipt.action_permit.permit_digest
        and identity.worker_execution_id == private.worker_result.execution_id
        and identity.reservation_sha256 == private.reservation_sha256
        and identity.execution_evidence_sha256 == private.execution_evidence_sha256
        and identity.challenge_id == private.challenge.challenge_id
        and identity.challenge_digest == private.challenge.digest
        and identity.target_receipt_digest == lifecycle.target_receipt.digest
        and identity.target_attempt_id == lifecycle.attempt.attempt_id
        and identity.target_attempt_digest == lifecycle.attempt.attempt_digest
        and identity.target_container_id == lifecycle.coordinate.target_container_id
        and identity.target_network_id == lifecycle.coordinate.target_network_id
        and identity.worker_container_id == topology.worker_container_id
        and identity.proxy_container_id == topology.proxy_container_id
        and identity.internal_network_id == topology.internal_network_id
    )


def _identity_matches_followup(
    identity: AIMeasurementExecutionIdentity,
    private: AIPrivateFollowupOperationMeasurement,
) -> bool:
    lifecycle = private.lifecycle
    topology = lifecycle.topology
    return (
        identity.operation_ordinal == private.operation.ordinal
        and identity.execution_run_id == private.source_run_id
        and identity.source_root_digest == private.source_root_digest
        and identity.request_id == private.request.request_id
        and identity.approval_receipt_id == private.approval_receipt.receipt_id
        and identity.approval_receipt_digest == private.approval_receipt.receipt_digest
        and identity.permit_id == private.approval_receipt.action_permit.permit_id
        and identity.permit_digest == private.approval_receipt.action_permit.permit_digest
        and identity.worker_execution_id == private.worker_result.execution_id
        and identity.reservation_sha256 == private.reservation_sha256
        and identity.execution_evidence_sha256 == private.execution_evidence_sha256
        and identity.challenge_id == private.challenge.challenge_id
        and identity.challenge_digest == private.challenge.digest
        and identity.target_receipt_digest == lifecycle.target_receipt.digest
        and identity.target_attempt_id == lifecycle.attempt.attempt_id
        and identity.target_attempt_digest == lifecycle.attempt.attempt_digest
        and identity.target_container_id == lifecycle.coordinate.target_container_id
        and identity.target_network_id == lifecycle.coordinate.target_network_id
        and identity.worker_container_id == topology.worker_container_id
        and identity.proxy_container_id == topology.proxy_container_id
        and identity.internal_network_id == topology.internal_network_id
    )


@dataclass(frozen=True, slots=True)
class _ReopenedSource:
    public: AISourceMeasurementAuthority
    private: AIPrivateSourceMeasurementBinding
    verified: VerifiedAIAnalysisObservationSource
    identity: AIMeasurementExecutionIdentity
    accounting: AIMeasurementAccountingObservation


def _reopen_source(
    outcome: AISourceMeasurementOutcome,
    *,
    measured_cases: AIMeasuredCaseMapping,
    provider: AIFixtureDockerProvider,
) -> _ReopenedSource:
    try:
        public = load_ai_source_measurement_authority(
            outcome,
            measured_cases=measured_cases,
            provider=provider,
        )
        private = AIPrivateSourceMeasurementBinding.model_validate_json(
            outcome.mapping.private_binding.model_dump_json(by_alias=True)
        )
        source_tool = AIM03SourceChatProbeTool(
            challenge=private.measurement.challenge,
            expected_request=private.measurement.request,
        )
        verified = load_verified_ai_analysis_observation_source(
            outcome.execution.source_inputs,
            graph_store=outcome.execution.graph_store,
            source_tool=source_tool,
        )
        identity = _build_source_identity(verified, private.measurement)
        provider_registration = ai_source_provider_registration(
            private.measurement.lifecycle.coordinate
        )
        accounting = _build_accounting(
            operation_ordinal=1,
            source=verified,
            provider=provider_registration,
        )
    except (
        AttributeError,
        AISourceMeasurementError,
        ValidationError,
        ValueError,
    ) as exc:
        raise AIReplayEvaluationError("AI-002C source could not be contextfully reopened") from exc
    if (
        public != outcome.mapping.public_authority
        or private != outcome.mapping.private_binding
        or outcome.execution.lifecycle != private.measurement.lifecycle
        or not _identity_matches_source(identity, private.measurement)
    ):
        raise AIReplayEvaluationError(
            "AI-002C source artifact, private Evidence, or identity differs"
        )
    return _ReopenedSource(
        public=public,
        private=private,
        verified=verified,
        identity=identity,
        accounting=accounting,
    )


def _elapsed_microseconds(started_at: datetime, finished_at: datetime) -> int:
    if (
        started_at.tzinfo is None
        or started_at.utcoffset() is None
        or finished_at.tzinfo is None
        or finished_at.utcoffset() is None
    ):
        raise AIReplayEvaluationError("AI-002C Worker timestamps require UTC offsets")
    delta = finished_at - started_at
    microseconds = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    if microseconds < 0:
        raise AIReplayEvaluationError("AI-002C Worker completion precedes its start")
    return microseconds


def _require_threshold(
    requirement: AIBenchmarkMetricFloorRequirement,
    *,
    numerator: int,
    denominator: int,
) -> None:
    if (
        requirement.minimum_denominator is not None
        and denominator < requirement.minimum_denominator
    ):
        raise AIReplayEvaluationError("AI-002C metric denominator is below the registered floor")
    if requirement.comparison is AIMetricFloorComparison.MEASUREMENT_REQUIRED:
        return
    if requirement.threshold_numerator is None or requirement.threshold_denominator is None:
        raise AIReplayEvaluationError("AI-002C metric threshold is incomplete")
    left = numerator * requirement.threshold_denominator
    right = requirement.threshold_numerator * denominator
    if (requirement.comparison is AIMetricFloorComparison.AT_LEAST and left < right) or (
        requirement.comparison is AIMetricFloorComparison.AT_MOST and left > right
    ):
        raise AIReplayEvaluationError("AI-002C metric threshold is not satisfied")


def _metric_observations(
    floor: tuple[AIBenchmarkMetricFloorRequirement, ...],
    *,
    first_replay_result_microseconds: int,
) -> tuple[AIReplayMetricObservation, ...]:
    if tuple(item.metric.metric_id for item in floor) != _METRIC_IDS:
        raise AIReplayEvaluationError("AI-002C floor metric order differs")
    values = dict(_FIXED_RATIONALS)
    values["common.time-to-first-valid-result"] = (
        first_replay_result_microseconds,
        1_000_000,
    )
    observations: list[AIReplayMetricObservation] = []
    for requirement in floor:
        if requirement.applicability is DomainBenchmarkMetricApplicability.NOT_APPLICABLE:
            observation = AIReplayMetricObservation(
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
            observation = AIReplayMetricObservation(
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
    observations: tuple[AIReplayMetricObservation, ...],
) -> None:
    floor = registered_ai_validation_floor_policy()
    if tuple(item.metric.metric_id for item in observations) != _METRIC_IDS or len(
        {item.metric.metric_id for item in observations}
    ) != len(_METRIC_IDS):
        raise ValueError("AI-002C public metric order or membership differs")
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
            raise ValueError("AI-002C public metric contract differs")
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
            raise ValueError("AI-002C fixed metric rational differs")
    for metric_id, reason in _NOT_APPLICABLE_REASONS.items():
        item = by_id[metric_id]
        if item.not_applicable_reason is not reason:
            raise ValueError("AI-002C metric N/A reason differs")
    elapsed = by_id["common.time-to-first-valid-result"]
    if elapsed.numerator is None or elapsed.numerator < 0 or elapsed.denominator != 1_000_000:
        raise ValueError("AI-002C elapsed-time rational differs")


def _build_operation_lineages(
    *,
    source_private: AIPrivateSourceMeasurement,
    followups: tuple[AIPrivateFollowupOperationMeasurement, ...],
    identities: tuple[AIMeasurementExecutionIdentity, ...],
    accounting: tuple[AIMeasurementAccountingObservation, ...],
) -> tuple[AIReplayOperationLineage, ...]:
    operations = registered_ai_measurement_operations()
    private_digests = (
        source_private.measurement_digest,
        *(item.measurement_digest for item in followups),
    )
    states = cast(
        tuple[
            Literal[
                "known-positive-observed",
                "supporting-replay-observed",
                "baseline-control-observed",
                "negative-control-not-observed",
                "counterfactual-control-not-observed",
            ],
            ...,
        ],
        (
            "known-positive-observed",
            "supporting-replay-observed",
            "supporting-replay-observed",
            "baseline-control-observed",
            "negative-control-not-observed",
            "counterfactual-control-not-observed",
        ),
    )
    return tuple(
        AIReplayOperationLineage(
            operation=operation,
            registeredOperationDigest=_operation_digest(operation),
            executionIdentityDigest=identity.identity_digest,
            privateMeasurementDigest=private_digest,
            accountingDigest=accounting_item.accounting_digest,
            resultState=state,
        )
        for operation, identity, private_digest, accounting_item, state in zip(
            operations,
            identities,
            private_digests,
            accounting,
            states,
            strict=True,
        )
    )


def _build_mapping(
    *,
    measured_authority: AIMeasuredCaseAuthority,
    private_ground_truth: AIPrivateGroundTruthBinding,
    source: _ReopenedSource,
    followups: tuple[AIPrivateFollowupOperationMeasurement, ...],
    verified_followups: tuple[VerifiedAIAnalysisObservationSource, ...],
    images: AISourceImageBinding,
    action_authority_context_digest: str,
) -> AIReplayEvaluationMapping:
    operations = registered_ai_measurement_operations()
    if (
        private_ground_truth != registered_ai_private_ground_truth_binding()
        or source.public.measured_case_authority != measured_authority.reference()
        or source.public.measurement_protocol != measured_authority.measurement_protocol.reference()
        or source.public.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or source.public.images != images.reference()
        or source.private.images != images
        or source.public.action_authority_context_digest != action_authority_context_digest
        or tuple(item.operation for item in followups) != operations[1:]
        or len(verified_followups) != 5
        or len(source.public.denials) != 8
        or any(item.denied is not True for item in source.public.denials)
    ):
        raise AIReplayEvaluationError(
            "AI-002C source, operation, image, denial, or authority semantics differ"
        )
    followup_identities = tuple(
        _build_followup_identity(verified, private)
        for verified, private in zip(verified_followups, followups, strict=True)
    )
    if any(
        not _identity_matches_followup(identity, private)
        for identity, private in zip(followup_identities, followups, strict=True)
    ):
        raise AIReplayEvaluationError(
            "AI-002C follow-up execution identity differs from private Evidence"
        )
    identities = (source.identity, *followup_identities)
    _require_disjoint_identities(identities)
    accounting = (source.accounting, *(item.accounting for item in followups))
    if (
        tuple(item.operation_ordinal for item in accounting) != tuple(range(1, 7))
        or sum(int(item.request_unit_count) for item in accounting) != 6
        or sum(int(item.tool_call_count) for item in accounting) != 6
        or sum(item.model_provider_call_count for item in accounting) != 0
        or sum(item.model_provider_cost_micro_usd for item in accounting) != 0
    ):
        raise AIReplayEvaluationError("AI-002C measured accounting aggregate differs")
    observations = _metric_observations(
        measured_authority.validation_floor_policy.requirements,
        first_replay_result_microseconds=_elapsed_microseconds(
            followups[0].worker_result.started_at,
            followups[0].worker_result.finished_at,
        ),
    )
    public = AIReplayFloorEvaluation(
        measuredCaseAuthority=measured_authority.reference(),
        measurementProtocol=measured_authority.measurement_protocol.reference(),
        floorPolicy=measured_authority.validation_floor_policy.reference(),
        sourceMeasurement=source.public.reference(),
        images=images.reference(),
        actionAuthorityContextDigest=action_authority_context_digest,
        operations=_build_operation_lineages(
            source_private=source.private.measurement,
            followups=followups,
            identities=identities,
            accounting=accounting,
        ),
        observations=observations,
    )
    private = AIPrivateReplayEvaluationBinding(
        publicEvaluation=public.reference(),
        measuredCaseAuthority=measured_authority.reference(),
        sourceMeasurement=source.public.reference(),
        privateGroundTruth=private_ground_truth,
        images=images,
        sourcePrivateMeasurement=source.private.measurement,
        followupMeasurements=followups,
        executionIdentities=identities,
        accountingObservations=accounting,
    )
    mapping = AIReplayEvaluationMapping(
        public_evaluation=public,
        private_binding=private,
    )
    _validate_mapping(
        mapping,
        measured_authority=measured_authority,
        source=source,
    )
    return mapping


def _validate_mapping(
    mapping: AIReplayEvaluationMapping,
    *,
    measured_authority: AIMeasuredCaseAuthority,
    source: _ReopenedSource,
) -> None:
    if type(mapping) is not AIReplayEvaluationMapping:
        raise AIReplayEvaluationError("AI-002C mapping requires its exact type")
    public = mapping.public_evaluation
    private = mapping.private_binding
    if (
        public.measured_case_authority != measured_authority.reference()
        or public.measurement_protocol != measured_authority.measurement_protocol.reference()
        or public.floor_policy != measured_authority.validation_floor_policy.reference()
        or public.source_measurement != source.public.reference()
        or private.public_evaluation != public.reference()
        or private.measured_case_authority != public.measured_case_authority
        or private.source_measurement != public.source_measurement
        or private.images.reference() != public.images
        or tuple(item.private_measurement_digest for item in public.operations)
        != (
            private.source_private_measurement.measurement_digest,
            *(item.measurement_digest for item in private.followup_measurements),
        )
        or tuple(item.execution_identity_digest for item in public.operations)
        != tuple(item.identity_digest for item in private.execution_identities)
        or tuple(item.accounting_digest for item in public.operations)
        != tuple(item.accounting_digest for item in private.accounting_observations)
    ):
        raise AIReplayEvaluationError("AI-002C public/private mapping differs")
    _validate_public_observations(public.observations)


class AIReplayEvaluationRunner:
    """Execute five fresh follow-ups and evaluate source plus exact AI-002C floor."""

    def __init__(
        self,
        *,
        source: AISourceMeasurementOutcome,
        measured_cases: AIMeasuredCaseMapping,
        images: AISourceImageBinding,
        provider: AIFixtureDockerProvider,
        authorizer: AIMeasurementActionAuthorizer,
        operation_runs_root: Path,
        evaluation_runs_root: Path,
    ) -> None:
        if type(source) is not AISourceMeasurementOutcome:
            raise TypeError("AI-002C requires one exact AI-002B source outcome")
        if type(measured_cases) is not AIMeasuredCaseMapping:
            raise TypeError("AI-002C requires exact measured-case mapping")
        if type(images) is not AISourceImageBinding:
            raise TypeError("AI-002C requires exact observed image binding")
        if not isinstance(provider, AIFixtureDockerProvider):
            raise TypeError("AI-002C requires the exact Docker provider")
        if not callable(getattr(authorizer, "authorize", None)):
            raise TypeError("AI-002C requires a deployment action authorizer")
        try:
            measured_authority = load_ai_measured_case_authority(
                measured_cases.public_authority,
                private_ground_truth_binding=measured_cases.private_binding,
            )
            image_binding = load_ai_source_image_binding(images, inspector=provider)
            reopened_source = _reopen_source(
                source,
                measured_cases=measured_cases,
                provider=provider,
            )
            authority_context, authority_context_digest = _canonical_authority_context(authorizer)
        except (
            AIFixtureRuntimeError,
            AIReplayEvaluationError,
            AISourceMeasurementError,
            ValueError,
        ) as exc:
            raise AIReplayEvaluationError(
                "AI-002C source or execution authority could not be reopened"
            ) from exc
        if (
            reopened_source.public.images != image_binding.reference()
            or reopened_source.private.images != image_binding
            or reopened_source.public.action_authority_context_digest != authority_context_digest
        ):
            raise AIReplayEvaluationError("AI-002C source image or deployment authority differs")
        self._source = source
        self._measured_cases = measured_cases
        self._measured_authority = measured_authority
        self._private_ground_truth = measured_cases.private_binding.model_copy(deep=True)
        self._images = image_binding
        self._provider = provider
        self._authorizer = authorizer
        self._authority_context = authority_context
        self._authority_context_digest = authority_context_digest
        self._operation_runs_root = Path(operation_runs_root)
        self._evaluation_runs_root = Path(evaluation_runs_root)

    async def run(self) -> AIReplayEvaluationOutcome:
        if not self._provider.managed_resources_absent():
            raise AIReplayEvaluationError("AI-002C cannot start with managed Docker residue")
        current_context, current_digest = _canonical_authority_context(self._authorizer)
        if (
            current_context != self._authority_context
            or current_digest != self._authority_context_digest
        ):
            raise AIReplayEvaluationError("AI-002C deployment authority changed before execution")
        source = _reopen_source(
            self._source,
            measured_cases=self._measured_cases,
            provider=self._provider,
        )
        source_probe = AIChatProbeInput.model_validate(source.private.measurement.request.arguments)
        public_case = self._measured_authority.public_registry.cases[0].reference()
        followups: list[AIPrivateFollowupOperationMeasurement] = []
        verified_followups: list[VerifiedAIAnalysisObservationSource] = []
        contexts: list[AIMeasurementExecutionContext] = []
        for operation in registered_ai_measurement_operations()[1:]:
            live: AIFixtureLiveTarget | None = None
            target_finished = False
            nonce = uuid4().hex
            try:
                live = self._provider.start(case=public_case, images=self._images)
                inspector = self._provider.boundary_inspector(
                    coordinate=live.coordinate,
                    images=self._images,
                )
                worker_image = self._images.role(AIMeasurementImageRole.WORKER)
                proxy_image = self._images.role(AIMeasurementImageRole.PROXY)
                backend = DockerWorkerBackend(
                    allowed_images={"pajin-worker:dev"},
                    egress_proxy_image=proxy_image.observed_image_id,
                    external_network_routes={"ai-chat-probe": live.coordinate.target_network_name},
                    runtime_image_bindings={"pajin-worker:dev": worker_image.observed_image_id},
                    egress_lifecycle_observer=inspector,
                )
                probe = _materialize_operation_probe(
                    operation,
                    source_probe=source_probe,
                    nonce=nonce,
                )
                request_id = f"tool_ai002c_operation_{operation.ordinal:02d}_{uuid4().hex}"
                request = ToolRequest(
                    request_id=request_id,
                    agent_id="agent:ai002c-measurement",
                    tool_id=AIChatProbeTool.spec.tool_id,
                    target=live.coordinate.target_url,
                    method="POST",
                    arguments=probe.model_dump(mode="json"),
                )
                run_id = RunStore.new_run_id()
                plan = self._authorizer.authorize(
                    case=public_case.model_copy(deep=True),
                    operation=operation.model_copy(deep=True),
                    target=live.coordinate.model_copy(deep=True),
                    run_id=run_id,
                    request=ToolRequest.model_validate_json(request.model_dump_json()),
                )
                executed = await _execute_approved_operation(
                    plan,
                    expected_case=public_case,
                    operation=operation,
                    expected_request=request,
                    target=live.coordinate,
                    images=self._images,
                    authority_context=self._authority_context,
                    authority_context_digest=self._authority_context_digest,
                    backend=backend,
                    inspector=inspector,
                    source_runs_root=self._operation_runs_root,
                )
                topology = inspector.topology_observation(
                    executed.source.evidence.worker_result.execution_id
                )
                target_receipt = self._provider.measurement_target_receipt(live)
                lifecycle = self._provider.finish_measurement(
                    live,
                    topology=topology,
                    target_receipt=target_receipt,
                )
                target_finished = True
                private = _build_followup_measurement(
                    operation=operation,
                    nonce=nonce,
                    executed=executed,
                    trust_anchor=live.trust_anchor,
                    lifecycle=lifecycle,
                    provider=plan.provider_registration,
                )
                followups.append(private)
                verified_followups.append(executed.source)
                contexts.append(
                    AIMeasurementExecutionContext(
                        source_inputs=executed.source_inputs,
                        graph_store=executed.graph_store,
                        lifecycle=lifecycle,
                        challenge=executed.challenge,
                    )
                )
            except BaseException:
                if live is not None and not target_finished:
                    try:
                        self._provider.abort(live)
                    except Exception as cleanup_error:
                        raise AIReplayEvaluationError(
                            "AI-002C failure cleanup could not remove its Target"
                        ) from cleanup_error
                raise
            if not self._provider.managed_resources_absent():
                raise AIReplayEvaluationError(
                    "AI-002C managed Docker residue remains between operations"
                )
        stable_context, stable_digest = _canonical_authority_context(self._authorizer)
        if (
            stable_context != self._authority_context
            or stable_digest != self._authority_context_digest
            or not self._provider.managed_resources_absent()
        ):
            raise AIReplayEvaluationError("AI-002C authority changed or Target residue remains")
        mapping = _build_mapping(
            measured_authority=self._measured_authority,
            private_ground_truth=self._private_ground_truth,
            source=source,
            followups=tuple(followups),
            verified_followups=tuple(verified_followups),
            images=self._images,
            action_authority_context_digest=self._authority_context_digest,
        )
        store = RunStore.create(
            self._evaluation_runs_root,
            "ai-replay-evaluation",
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
            "ai.replay-floor-evaluation.sealed",
            {
                "evaluationDigest": mapping.public_evaluation.evaluation_digest,
                "privateBindingDigest": mapping.private_binding.binding_digest,
                "operationCount": 6,
                "metricCount": 14,
                "floorSatisfied": True,
            },
        )
        store.seal()
        return AIReplayEvaluationOutcome(
            run_id=store.run_id,
            run_path=store.path,
            evaluation_path=_PUBLIC_ARTIFACT,
            private_binding_path=_PRIVATE_ARTIFACT,
            mapping=mapping,
            source=self._source,
            executions=tuple(contexts),
        )


def load_ai_replay_floor_evaluation(
    outcome: AIReplayEvaluationOutcome,
    *,
    measured_cases: AIMeasuredCaseMapping,
    provider: AIFixtureDockerProvider,
) -> AIReplayFloorEvaluation:
    """Contextfully reopen all six executions and the sealed AI-002C authority."""

    if type(outcome) is not AIReplayEvaluationOutcome:
        raise TypeError("AI-002C reload requires its exact outcome")
    if type(measured_cases) is not AIMeasuredCaseMapping:
        raise TypeError("AI-002C reload requires exact measured-case mapping")
    if not isinstance(provider, AIFixtureDockerProvider):
        raise TypeError("AI-002C reload requires exact Docker provider")
    try:
        measured_authority = load_ai_measured_case_authority(
            measured_cases.public_authority,
            private_ground_truth_binding=measured_cases.private_binding,
        )
        source = _reopen_source(
            outcome.source,
            measured_cases=measured_cases,
            provider=provider,
        )
        public = AIReplayFloorEvaluation.model_validate_json(
            outcome.mapping.public_evaluation.model_dump_json(by_alias=True)
        )
        private = AIPrivateReplayEvaluationBinding.model_validate_json(
            outcome.mapping.private_binding.model_dump_json(by_alias=True)
        )
        image_binding = load_ai_source_image_binding(private.images, inspector=provider)
        if len(outcome.executions) != 5:
            raise AIReplayEvaluationError("AI-002C reload requires five exact follow-up contexts")
        verified_followups: list[VerifiedAIAnalysisObservationSource] = []
        rebuilt_followups: list[AIPrivateFollowupOperationMeasurement] = []
        operations = registered_ai_measurement_operations()[1:]
        for operation, context, stored in zip(
            operations,
            outcome.executions,
            private.followup_measurements,
            strict=True,
        ):
            if type(context) is not AIMeasurementExecutionContext:
                raise AIReplayEvaluationError("AI-002C reload requires exact execution contexts")
            measurement_tool = AIM03MeasurementChatProbeTool(
                challenge=stored.challenge,
                expected_request=stored.request,
            )
            verified = load_verified_ai_analysis_observation_source(
                context.source_inputs,
                graph_store=context.graph_store,
                measurement_tool=measurement_tool,
            )
            rebuilt = _build_followup_measurement(
                operation=operation,
                nonce=stored.materialization_nonce,
                executed=_ExecutedOperation(
                    source=verified,
                    source_inputs=context.source_inputs,
                    graph_store=context.graph_store,
                    approval_receipt=stored.approval_receipt,
                    permit=stored.approval_receipt.action_permit,
                    challenge=stored.challenge,
                    measurement_tool=measurement_tool,
                ),
                trust_anchor=stored.trust_anchor,
                lifecycle=context.lifecycle,
                provider=ai_source_provider_registration(stored.lifecycle.coordinate),
            )
            if (
                context.lifecycle != stored.lifecycle
                or context.challenge != stored.challenge
                or rebuilt != stored
            ):
                raise AIReplayEvaluationError(
                    "AI-002C execution context or rebuilt private Evidence differs"
                )
            verified_followups.append(verified)
            rebuilt_followups.append(rebuilt)
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                outcome.evaluation_path: _MAX_CANONICAL_BYTES,
                outcome.private_binding_path: _MAX_CANONICAL_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_public = AIReplayFloorEvaluation.model_validate_json(
            snapshot.artifact_bytes(outcome.evaluation_path)
        )
        sealed_private = AIPrivateReplayEvaluationBinding.model_validate_json(
            snapshot.artifact_bytes(outcome.private_binding_path)
        )
        rebuilt_mapping = _build_mapping(
            measured_authority=measured_authority,
            private_ground_truth=measured_cases.private_binding,
            source=source,
            followups=tuple(rebuilt_followups),
            verified_followups=tuple(verified_followups),
            images=image_binding,
            action_authority_context_digest=(public.action_authority_context_digest),
        )
    except (
        AttributeError,
        AIFixtureRuntimeError,
        AIReplayEvaluationError,
        AISourceMeasurementError,
        OSError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise AIReplayEvaluationError(
            "AI-002C sealed evaluation could not be contextfully reopened"
        ) from exc
    paths = {
        Path(outcome.source.run_path).resolve(),
        Path(outcome.run_path).resolve(),
        *(Path(item.source_inputs.run_path).resolve() for item in outcome.executions),
    }
    if (
        len(paths) != 7
        or sealed_public != public
        or sealed_private != private
        or public != outcome.mapping.public_evaluation
        or private != outcome.mapping.private_binding
        or rebuilt_mapping != outcome.mapping
        or not provider.managed_resources_absent()
    ):
        raise AIReplayEvaluationError(
            "AI-002C sealed artifacts, execution identities, or cleanup differ"
        )
    return public.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class AIReplayEvaluationReopenContext:
    """Host-owned context required to trust one sealed AI-002C result."""

    outcome: AIReplayEvaluationOutcome
    measured_cases: AIMeasuredCaseMapping
    provider: AIFixtureDockerProvider

    def reopen(self) -> AIReplayFloorEvaluation:
        if type(self) is not AIReplayEvaluationReopenContext:
            raise AIReplayEvaluationError("AI-002C reopen context requires its exact type")
        return load_ai_replay_floor_evaluation(
            self.outcome,
            measured_cases=self.measured_cases,
            provider=self.provider,
        )


__all__ = [
    "AI_PRIVATE_REPLAY_EVALUATION_BINDING_API_VERSION",
    "AI_REPLAY_FLOOR_EVALUATION_API_VERSION",
    "AI_REPLAY_REQUIRED_OPERATION_EVIDENCE_NAMES",
    "AIMeasurementAccountingObservation",
    "AIMeasurementActionAuthorizer",
    "AIMeasurementApprovedAction",
    "AIMeasurementExecutionContext",
    "AIMeasurementExecutionIdentity",
    "AIPrivateFollowupOperationMeasurement",
    "AIPrivateReplayEvaluationBinding",
    "AIReplayEvaluationError",
    "AIReplayEvaluationMapping",
    "AIReplayEvaluationOutcome",
    "AIReplayEvaluationReopenContext",
    "AIReplayEvaluationRunner",
    "AIReplayFloorEvaluation",
    "AIReplayFloorEvaluationRef",
    "AIReplayMetricObservation",
    "AIReplayOperationLineage",
    "load_ai_replay_floor_evaluation",
]
