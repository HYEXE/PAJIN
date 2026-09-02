"""AI-002B registry-governed disposable M03 source measurement."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self
from uuid import uuid4

from pydantic import (
    AnyHttpUrl,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.benchmark.models import benchmark_digest
from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    ExistingModeCapabilityActivation,
    capability_gateway_outcome_digest,
    capability_grant_digest,
)
from pajin.capabilities.ai_analysis import (
    AIReadOnlyAnalysisPreparation,
    prepare_ai_read_only_analysis,
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
from pajin.policy.engine import PolicyEngine
from pajin.policy.scope import InvalidScopeURL, normalize_scope_pattern
from pajin.providers.models import ProviderRegistration
from pajin.runtime.store import RunStore, load_verified_run_artifacts
from pajin.runtime.worker import DockerWorkerBackend, WorkerResult
from pajin.target_attestation import (
    AISourceTargetExecutionChallenge,
    AISourceTargetProxyBinding,
    TargetAttestationTrustAnchor,
    derive_ai_source_target_execution_challenge,
    verify_ai_source_target_execution_receipt,
)
from pajin.tools.ai import (
    AIChatProbeInput,
    AIChatProbeOutput,
    AIChatProbeTool,
    AIM03SourceChatProbeTool,
    ai_source_target_proxy_binding,
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
    AIFixtureTargetLifecycleEvidence,
    AISourceImageBinding,
    AISourceImageBindingRef,
    load_ai_source_image_binding,
)
from pajin.workflow.ai_measured_case_authority import (
    AIMeasuredCaseAuthority,
    AIMeasuredCaseAuthorityRef,
    AIMeasuredCaseMapping,
    AIMeasuredCaseRef,
    AIMeasurementImageRole,
    AIMeasurementProtocolRef,
    AIPrivateGroundTruthBinding,
    AIPrivateGroundTruthCase,
    load_ai_measured_case_authority,
    registered_ai_measured_case_authority,
    registered_ai_private_ground_truth_case,
)

AI_SOURCE_CASE_LINEAGE_API_VERSION: Literal["pajin.dev/ai-source-case-lineage/v1alpha1"] = (
    "pajin.dev/ai-source-case-lineage/v1alpha1"
)
AI_SOURCE_DENIAL_RECEIPT_API_VERSION: Literal["pajin.dev/ai-source-denial-receipt/v1alpha1"] = (
    "pajin.dev/ai-source-denial-receipt/v1alpha1"
)
AI_SOURCE_MEASUREMENT_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/ai-source-measurement-authority/v1alpha1"
] = "pajin.dev/ai-source-measurement-authority/v1alpha1"
AI_PRIVATE_SOURCE_MEASUREMENT_BINDING_API_VERSION: Literal[
    "pajin.dev/ai-private-source-measurement-binding/v1alpha1"
] = "pajin.dev/ai-private-source-measurement-binding/v1alpha1"

AI_SOURCE_PROVIDER_ID = "ai002b-local-target"
AI_SOURCE_MODEL_ID = "pajin-deterministic-lab-v1"
AI_SOURCE_SECRET_REF = "provider/ai002b/not-materialized"
_PUBLIC_AUTHORITY_ARTIFACT = "ai-source-measurement-authority.json"
_PRIVATE_AUTHORITY_ARTIFACT = "private/ai-source-measurement-binding.json"
_MAX_CANONICAL_BYTES = 16 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]


class AISourceMeasurementError(RuntimeError):
    """Raised when AI-002B authority, execution, or private custody drifts."""


class AISourceDenialControl(StrEnum):
    SCENARIO_SUBSTITUTION = "scenario-substitution"
    PROMPT_SUBSTITUTION = "prompt-substitution"
    CHECK_SUBSTITUTION = "check-substitution"
    MODE_SUBSTITUTION = "mode-substitution"
    IMAGE_SUBSTITUTION = "image-substitution"
    ROUTE_SUBSTITUTION = "route-substitution"
    SCOPE_SUBSTITUTION = "scope-substitution"
    AUTHORITY_SUBSTITUTION = "authority-substitution"


_DENIAL_ORDER = tuple(AISourceDenialControl)
_AUTHORITY_TRUE_FIELDS = (
    "source_measurement_observed",
    "exact_m03_case_verified",
    "approval_and_one_use_permit_verified",
    "ai001c_source_reopened",
    "target_receipt_verified",
    "proxy_only_topology_verified",
    "immutable_image_identity_verified",
    "target_cleanup_verified",
    "private_material_custody_verified",
    "pre_dispatch_denial_set_verified",
)
_AUTHORITY_FALSE_FIELDS = (
    "replay_authorized",
    "controls_authorized",
    "measurement_floor_evaluated",
    "validation_floor_satisfied",
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
    "rag_authorized",
    "mcp_authorized",
    "memory_mutation_authorized",
    "m06_authorized",
    "a04_authorized",
    "general_ai_scanner_authorized",
    "caller_configuration_authorized",
    "additional_application_write_authorized",
    "additional_execution_authorized",
)


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
    )


class AISourceCaseLineage(_FrozenStrictModel):
    """Public-safe M03 case identity and sealed private Evidence commitments."""

    api_version: Literal["pajin.dev/ai-source-case-lineage/v1alpha1"] = Field(
        default=AI_SOURCE_CASE_LINEAGE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AISourceCaseLineage"] = "AISourceCaseLineage"
    lineage_digest: str = Field(default="", alias="lineageDigest", max_length=64)
    case: AIMeasuredCaseRef
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    permit_digest: _Sha256 = Field(alias="permitDigest")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    target_lifecycle_evidence_digest: _Sha256 = Field(alias="targetLifecycleEvidenceDigest")
    target_receipt_digest: _Sha256 = Field(alias="targetReceiptDigest")
    private_measurement_digest: _Sha256 = Field(alias="privateMeasurementDigest")
    measurement_state: Literal["approved-proxy-only-m03-source-complete"] = Field(
        default="approved-proxy-only-m03-source-complete",
        alias="measurementState",
    )

    @model_validator(mode="after")
    def bind_lineage(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"lineage_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-source-case-lineage/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.lineage_digest and self.lineage_digest != digest:
            raise ValueError("AI source case lineage Digest differs")
        object.__setattr__(self, "lineage_digest", digest)
        return self


class AISourceDenialReceipt(_FrozenStrictModel):
    """Public-safe proof that one code-owned substitution never reached dispatch."""

    api_version: Literal["pajin.dev/ai-source-denial-receipt/v1alpha1"] = Field(
        default=AI_SOURCE_DENIAL_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AISourceDenialReceipt"] = "AISourceDenialReceipt"
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    control: AISourceDenialControl
    stage: Literal["pre-dispatch"] = "pre-dispatch"
    denied: Literal[True] = True
    dispatch_invocation_count: Literal[0] = Field(
        default=0,
        alias="dispatchInvocationCount",
    )
    denial_semantics: Literal["code-owned-substitution-rejected"] = Field(
        default="code-owned-substitution-rejected",
        alias="denialSemantics",
    )

    @field_validator("denied", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI source denial marker must be boolean true")
        return value

    @field_validator("dispatch_invocation_count", mode="before")
    @classmethod
    def require_zero_dispatch(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("AI source denial dispatch count must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-source-denial-receipt/v1",
            material,
            max_bytes=256 * 1024,
        )
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("AI source denial receipt Digest differs")
        object.__setattr__(self, "receipt_digest", digest)
        return self


class AISourceMeasurementAuthorityRef(_FrozenStrictModel):
    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^ai-source-measurement_[a-f0-9]{64}$",
    )
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.authority_id != f"ai-source-measurement_{self.authority_digest}":
            raise ValueError("AI Source Measurement Authority reference differs")
        return self


class AISourceMeasurementAuthority(_FrozenStrictModel):
    """Public-safe AI-002B completion authority without prompt or transcript."""

    api_version: Literal["pajin.dev/ai-source-measurement-authority/v1alpha1"] = Field(
        default=AI_SOURCE_MEASUREMENT_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AISourceMeasurementAuthority"] = "AISourceMeasurementAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=105)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    measured_case_authority: AIMeasuredCaseAuthorityRef = Field(alias="measuredCaseAuthority")
    measurement_protocol: AIMeasurementProtocolRef = Field(alias="measurementProtocol")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    images: AISourceImageBindingRef
    action_authority_context_digest: _Sha256 = Field(alias="actionAuthorityContextDigest")
    case: AISourceCaseLineage
    denials: tuple[AISourceDenialReceipt, ...] = Field(min_length=8, max_length=8)
    state: Literal["registry-governed-private-m03-source-complete"] = (
        "registry-governed-private-m03-source-complete"
    )
    source_measurement_observed: Literal[True] = Field(
        default=True,
        alias="sourceMeasurementObserved",
    )
    exact_m03_case_verified: Literal[True] = Field(
        default=True,
        alias="exactM03CaseVerified",
    )
    approval_and_one_use_permit_verified: Literal[True] = Field(
        default=True,
        alias="approvalAndOneUsePermitVerified",
    )
    ai001c_source_reopened: Literal[True] = Field(
        default=True,
        alias="ai001cSourceReopened",
    )
    target_receipt_verified: Literal[True] = Field(
        default=True,
        alias="targetReceiptVerified",
    )
    proxy_only_topology_verified: Literal[True] = Field(
        default=True,
        alias="proxyOnlyTopologyVerified",
    )
    immutable_image_identity_verified: Literal[True] = Field(
        default=True,
        alias="immutableImageIdentityVerified",
    )
    target_cleanup_verified: Literal[True] = Field(
        default=True,
        alias="targetCleanupVerified",
    )
    private_material_custody_verified: Literal[True] = Field(
        default=True,
        alias="privateMaterialCustodyVerified",
    )
    pre_dispatch_denial_set_verified: Literal[True] = Field(
        default=True,
        alias="preDispatchDenialSetVerified",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    controls_authorized: Literal[False] = Field(default=False, alias="controlsAuthorized")
    measurement_floor_evaluated: Literal[False] = Field(
        default=False,
        alias="measurementFloorEvaluated",
    )
    validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="validationFloorSatisfied",
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
    caller_configuration_authorized: Literal[False] = Field(
        default=False,
        alias="callerConfigurationAuthorized",
    )
    additional_application_write_authorized: Literal[False] = Field(
        default=False,
        alias="additionalApplicationWriteAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(*_AUTHORITY_TRUE_FIELDS, mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI-002B verification markers must be boolean true")
        return value

    @field_validator(*_AUTHORITY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI-002B authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        expected = registered_ai_measured_case_authority()
        if (
            self.measured_case_authority != expected.reference()
            or self.measurement_protocol != expected.measurement_protocol.reference()
            or self.case.case != expected.public_registry.cases[0].reference()
            or tuple(item.control for item in self.denials) != _DENIAL_ORDER
            or any(item.dispatch_invocation_count != 0 for item in self.denials)
        ):
            raise ValueError("AI source membership, protocol, or denial order differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-source-measurement-authority/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        authority_id = f"ai-source-measurement_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("AI Source Measurement Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("AI Source Measurement Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self

    def reference(self) -> AISourceMeasurementAuthorityRef:
        return AISourceMeasurementAuthorityRef(
            authorityId=self.authority_id,
            authorityDigest=self.authority_digest,
        )


class AIPrivateSourceMeasurement(_FrozenStrictModel):
    """Private prompt, transcript, runtime, approval, receipt, and cleanup custody."""

    measurement_digest: str = Field(
        default="",
        alias="measurementDigest",
        max_length=64,
    )
    ground_truth: AIPrivateGroundTruthCase = Field(alias="groundTruth")
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
    challenge: AISourceTargetExecutionChallenge
    trust_anchor: TargetAttestationTrustAnchor = Field(alias="trustAnchor")
    proxy_binding: AISourceTargetProxyBinding = Field(alias="proxyBinding")
    lifecycle: AIFixtureTargetLifecycleEvidence
    worker_result: WorkerResult = Field(alias="workerResult")
    tool_result: ToolResult = Field(alias="toolResult")
    output: AIChatProbeOutput
    request_unit_count: Literal[1] = Field(default=1, alias="requestUnitCount")
    tool_call_count: Literal[1] = Field(default=1, alias="toolCallCount")
    model_provider_cost_micro_usd: Literal[0] = Field(
        default=0,
        alias="modelProviderCostMicroUsd",
    )
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    finding_created: Literal[False] = Field(default=False, alias="findingCreated")

    @field_validator(
        "request_unit_count",
        "tool_call_count",
        "model_provider_cost_micro_usd",
        mode="before",
    )
    @classmethod
    def require_exact_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("AI private source counters must be exact integers")
        return value

    @field_validator("graph_admitted", "finding_created", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI private source escalation markers must be false")
        return value

    @model_validator(mode="after")
    def bind_private_measurement(self) -> Self:
        probe = AIChatProbeInput.model_validate(self.request.arguments)
        expected_ground_truth = registered_ai_private_ground_truth_case()
        if (
            self.ground_truth != expected_ground_truth
            or self.request.request_id != self.challenge.source_request_id
            or self.request.tool_id != AIChatProbeTool.spec.tool_id
            or self.request.method != "POST"
            or self.request.target != self.lifecycle.coordinate.target_url
            or probe.scenario_id != expected_ground_truth.scenario_id
            or probe.threat_class != expected_ground_truth.threat_class
            or len(probe.turns) != 1
            or len(probe.turns[0].messages) != 1
            or probe.turns[0].messages[0].content != expected_ground_truth.prompt_text
            or len(probe.checks) != 1
            or probe.checks[0].check_id != expected_ground_truth.check_id
            or probe.checks[0].kind.value != expected_ground_truth.check_kind
            or probe.checks[0].turn != expected_ground_truth.check_turn
            or probe.checks[0].value != expected_ground_truth.check_value
            or probe.checks[0].sensitive is not True
            or self.output.scenario_id != expected_ground_truth.scenario_id
            or self.output.threat_class != expected_ground_truth.threat_class
            or self.output.target != self.request.target
            or self.output.session_id != probe.session_id
            or self.output.vulnerable is not True
            or self.output.sensitive_exposure_count != 1
            or len(self.output.turns) != 1
            or len(self.output.checks) != 1
            or self.output.checks[0].matched is not True
            or self.tool_result.request_id != self.request.request_id
            or self.tool_result.tool_id != self.request.tool_id
            or self.tool_result.success is not True
            or self.lifecycle.attempt.case.case_id != self.ground_truth.case_id
            or self.lifecycle.target_receipt.digest != self.proxy_binding.target_receipt_sha256
            or self.challenge.digest != self.proxy_binding.challenge_sha256
            or self.approval_receipt.action_permit.permit_digest != self.challenge.permit_digest
            or self.approval_receipt.receipt_digest == ""
        ):
            raise ValueError("AI private source prompt, output, or authority differs")
        verify_ai_source_target_execution_receipt(
            self.lifecycle.target_receipt,
            trust_anchor=self.trust_anchor,
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"measurement_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-private-source-measurement/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.measurement_digest and self.measurement_digest != digest:
            raise ValueError("AI private source measurement Digest differs")
        object.__setattr__(self, "measurement_digest", digest)
        return self


class AIPrivateSourceMeasurementBinding(_FrozenStrictModel):
    """Separate private source authority; no raw material enters the public artifact."""

    api_version: Literal["pajin.dev/ai-private-source-measurement-binding/v1alpha1"] = Field(
        default=AI_PRIVATE_SOURCE_MEASUREMENT_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIPrivateSourceMeasurementBinding"] = "AIPrivateSourceMeasurementBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    public_authority: AISourceMeasurementAuthorityRef = Field(alias="publicAuthority")
    private_ground_truth_binding_id: _Identifier = Field(alias="privateGroundTruthBindingId")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    images: AISourceImageBinding
    measurement: AIPrivateSourceMeasurement

    @model_validator(mode="after")
    def bind_private_authority(self) -> Self:
        expected = registered_ai_measured_case_authority()
        if (
            self.private_ground_truth_binding_digest != expected.private_ground_truth_binding_digest
            or self.measurement.ground_truth.case_id != expected.public_registry.cases[0].case_id
            or self.measurement.lifecycle.attempt.images != self.images.reference()
        ):
            raise ValueError("AI private source authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-private-source-measurement-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"ai-private-source-measurement_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI private source binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("AI private source binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


@dataclass(frozen=True, slots=True)
class AISourceMeasurementMapping:
    public_authority: AISourceMeasurementAuthority
    private_binding: AIPrivateSourceMeasurementBinding


@dataclass(frozen=True, slots=True)
class AISourceApprovedAction:
    """Deployment-owned normal approval inputs compiled after Target inspection."""

    activation: ExistingModeCapabilityActivation
    campaign: CampaignManifest
    preparation: AIReadOnlyAnalysisPreparation
    job: CapabilityGraphCampaignJobInput
    mission_envelope: MissionEnvelope
    graph_store: SQLiteGraphStore
    approval_input_authority: ActionApprovalInputAuthority
    approval_issuer: ActionApprovalIssuerAuthorityBinding
    provider_registration: ProviderRegistration
    authority_context_digest: str


class AISourceActionAuthorizer(Protocol):
    """Deployment authority creating one fresh approval plan for the fixed Target."""

    def stable_authority_context(self) -> Mapping[str, object]: ...

    def authorize(
        self,
        *,
        case: AIMeasuredCaseRef,
        target: AIFixtureTargetCoordinate,
        run_id: str,
        request_id: str,
    ) -> AISourceApprovedAction: ...


class _AIActionAuthorityContext(Protocol):
    def stable_authority_context(self) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class AISourceExecutionContext:
    source_inputs: AIAnalysisObservationSourceInputs
    graph_store: SQLiteGraphStore
    lifecycle: AIFixtureTargetLifecycleEvidence
    challenge: AISourceTargetExecutionChallenge


@dataclass(frozen=True, slots=True)
class AISourceMeasurementOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    private_binding_path: str
    mapping: AISourceMeasurementMapping
    execution: AISourceExecutionContext


@dataclass(frozen=True, slots=True)
class _ExecutedAISource:
    source: VerifiedAIAnalysisObservationSource
    source_inputs: AIAnalysisObservationSourceInputs
    graph_store: SQLiteGraphStore
    approval_receipt: ActionApprovalConsumptionReceipt
    permit: ActionPermit
    challenge: AISourceTargetExecutionChallenge
    source_tool: AIM03SourceChatProbeTool


@dataclass(frozen=True, slots=True)
class _DispatchedAISource:
    outcome: GatewayOutcome
    challenge: AISourceTargetExecutionChallenge
    source_tool: AIM03SourceChatProbeTool


def ai_source_provider_registration(
    target: AIFixtureTargetCoordinate,
) -> ProviderRegistration:
    """Return the code-owned local registration; no credential lease is materialized."""

    return ProviderRegistration(
        provider_id=AI_SOURCE_PROVIDER_ID,
        endpoint=AnyHttpUrl(target.target_url),
        model=AI_SOURCE_MODEL_ID,
        secret_ref=AI_SOURCE_SECRET_REF,
        allow_streaming=False,
        allowed_function_tools=set(),
        lease_ttl_seconds=30,
        allow_private_networks=True,
        input_cost_per_million_usd=0,
        output_cost_per_million_usd=0,
    )


def _canonical_authority_context(
    authorizer: _AIActionAuthorityContext,
) -> tuple[dict[str, object], str]:
    try:
        raw = authorizer.stable_authority_context()
        encoded = json.dumps(
            raw,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        parsed = json.loads(encoded)
    except (AttributeError, OverflowError, TypeError, ValueError) as exc:
        raise AISourceMeasurementError(
            "AI source action authority context is not canonical JSON"
        ) from exc
    if type(parsed) is not dict or len(encoded) > 1024 * 1024:
        raise AISourceMeasurementError("AI source action authority context is not a bounded object")
    digest = benchmark_digest(
        "pajin.workflow.ai-source-action-authority-context/v1",
        parsed,
        max_bytes=1024 * 1024,
    )
    return parsed, digest


def _canonical_backend_context(backend: DockerWorkerBackend) -> dict[str, object]:
    if type(backend) is not DockerWorkerBackend:
        raise AISourceMeasurementError(
            "AI source execution requires the exact Docker Worker backend"
        )
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
        raise AISourceMeasurementError("AI source Docker backend context is invalid") from exc
    if type(parsed) is not dict or len(encoded) > 1024 * 1024:
        raise AISourceMeasurementError("AI source Docker backend context is not bounded")
    return parsed


def _validate_source_pre_dispatch(
    plan: AISourceApprovedAction,
    *,
    expected_case: AIMeasuredCaseRef,
    target: AIFixtureTargetCoordinate,
    images: AISourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    inspector: AIDockerBoundaryInspector,
    backend_context: Mapping[str, object] | None = None,
    expected_mode: str = "vulnerable",
    expected_route: str = "/v1/chat",
) -> None:
    """Fail closed on scenario, prompt, check, mode, image, route, Scope, or authority."""

    if type(plan) is not AISourceApprovedAction:
        raise AISourceMeasurementError("AI source action plan requires its exact deployment type")
    if (
        not isinstance(plan.activation, ExistingModeCapabilityActivation)
        or not isinstance(plan.graph_store, SQLiteGraphStore)
        or not callable(getattr(plan.approval_input_authority, "verify_action_approval", None))
    ):
        raise AISourceMeasurementError("AI source action authority inputs are invalid")
    try:
        case = AIMeasuredCaseRef.model_validate_json(expected_case.model_dump_json(by_alias=True))
        coordinate = AIFixtureTargetCoordinate.model_validate_json(
            target.model_dump_json(by_alias=True)
        )
        image_binding = AISourceImageBinding.model_validate_json(
            images.model_dump_json(by_alias=True)
        )
        campaign = CampaignManifest.model_validate_json(
            plan.campaign.model_dump_json(by_alias=True)
        )
        preparation = AIReadOnlyAnalysisPreparation.model_validate_json(
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
        raise AISourceMeasurementError("AI source action plan is not canonical") from exc
    approval = job.approval
    expected_issuer = authority_context.get("approvalIssuer")
    try:
        normalized_allow = tuple(
            normalize_scope_pattern(item) for item in campaign.spec.scope.allow
        )
        normalized_deny = tuple(normalize_scope_pattern(item) for item in campaign.spec.scope.deny)
        expected_scope = normalize_scope_pattern(coordinate.target_url)
    except InvalidScopeURL as exc:
        raise AISourceMeasurementError("AI source Campaign Scope is invalid") from exc
    rebuilt = prepare_ai_read_only_analysis(
        activation=plan.activation,
        release=preparation.release,
        binding=preparation.binding,
        request=job.request,
        provider_registration=provider,
    )
    expected_provider = ai_source_provider_registration(coordinate)
    probe = AIChatProbeInput.model_validate(job.request.arguments)
    ground_truth = registered_ai_private_ground_truth_case()
    expected_session = f"pajin:ai002b:{job.request.request_id[-32:]}"
    actual_backend_context = (
        dict(backend_context)
        if backend_context is not None
        else _canonical_backend_context(backend)
    )
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
        or job.request.request_id != preparation.prepared_action.request.request_id
        or not job.request.request_id.startswith("tool_ai002b_source_")
        or len(job.request.request_id) != len("tool_ai002b_source_") + 32
        or job.request.target != coordinate.target_url
        or job.request.method != "POST"
        or job.request.tool_id != AIChatProbeTool.spec.tool_id
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
        or probe.scenario_id != ground_truth.scenario_id
        or probe.threat_class != ground_truth.threat_class
        or probe.session_id != expected_session
        or len(probe.turns) != 1
        or len(probe.turns[0].messages) != 1
        or probe.turns[0].messages[0].content != ground_truth.prompt_text
        or len(probe.checks) != 1
        or probe.checks[0].check_id != ground_truth.check_id
        or probe.checks[0].kind.value != ground_truth.check_kind
        or probe.checks[0].turn != ground_truth.check_turn
        or probe.checks[0].value != ground_truth.check_value
        or probe.checks[0].sensitive is not True
        or coordinate.target_mode != expected_mode
        or coordinate.route_path != expected_route
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
        raise AISourceMeasurementError("AI source pre-dispatch authority differs")
    if any(
        permit.run_id == envelope.run_id
        or permit.request_id == preparation.prepared_action.request.request_id
        for permit in plan.graph_store.permit_store.permits()
    ):
        raise AISourceMeasurementError(
            "AI source Run, request, approval, or Permit authority was reused"
        )
    if (
        plan.graph_store.permit_store.approved_authorization(
            approval.approval_id,
            approval.expected_action_permit_id,
        )
        is not None
    ):
        raise AISourceMeasurementError("AI source approval authority was already consumed")


def _mutated_request_plan(
    plan: AISourceApprovedAction,
    *,
    control: AISourceDenialControl,
) -> AISourceApprovedAction:
    probe = AIChatProbeInput.model_validate(plan.job.request.arguments)
    payload = probe.model_dump(mode="json")
    if control is AISourceDenialControl.SCENARIO_SUBSTITUTION:
        payload["scenario_id"] = "kisa.model.jailbreak-policy-bypass"
    elif control is AISourceDenialControl.PROMPT_SUBSTITUTION:
        payload["turns"][0]["messages"][0]["content"] = "caller-selected prompt"
    elif control is AISourceDenialControl.CHECK_SUBSTITUTION:
        payload["checks"][0]["value"] = "caller-selected check"
    else:
        raise ValueError("AI source request mutation control is unsupported")
    request = plan.job.request.model_copy(update={"arguments": payload})
    job = plan.job.model_copy(update={"request": request})
    return replace(plan, job=job)


def _scope_substitution(plan: AISourceApprovedAction) -> AISourceApprovedAction:
    payload = plan.campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"]["allow"] = ["https://foreign.invalid/v1/chat"]
    campaign = CampaignManifest.model_validate(payload)
    return replace(plan, campaign=campaign)


def _foreign_image_binding(images: AISourceImageBinding) -> AISourceImageBinding:
    payload = images.model_dump(mode="python", by_alias=True)
    roles = list(images.roles)
    for index, role in enumerate(roles):
        if role.role is AIMeasurementImageRole.WORKER:
            current = role.observed_image_id
            foreign = "sha256:" + ("0" * 64)
            if current == foreign:
                foreign = "sha256:" + ("f" * 64)
            role_payload = role.model_dump(mode="python", by_alias=True)
            role_payload["observedImageId"] = foreign
            role_payload["bindingDigest"] = ""
            roles[index] = type(role).model_validate(role_payload)
    payload["bindingId"] = ""
    payload["bindingDigest"] = ""
    payload["roles"] = tuple(roles)
    return AISourceImageBinding.model_validate(payload)


def _evaluate_code_owned_denials(
    plan: AISourceApprovedAction,
    *,
    case: AIMeasuredCaseRef,
    target: AIFixtureTargetCoordinate,
    images: AISourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    inspector: AIDockerBoundaryInspector,
) -> tuple[AISourceDenialReceipt, ...]:
    valid_context = _canonical_backend_context(backend)
    foreign_route = dict(valid_context)
    foreign_route["externalNetworkRoutes"] = {
        "ai-chat-probe": f"{target.target_network_name}-foreign"
    }
    foreign_authority = "0" * 64
    if foreign_authority == authority_context_digest:
        foreign_authority = "f" * 64
    probes = (
        (
            AISourceDenialControl.SCENARIO_SUBSTITUTION,
            _mutated_request_plan(
                plan,
                control=AISourceDenialControl.SCENARIO_SUBSTITUTION,
            ),
            images,
            valid_context,
            "vulnerable",
            "/v1/chat",
            authority_context_digest,
        ),
        (
            AISourceDenialControl.PROMPT_SUBSTITUTION,
            _mutated_request_plan(
                plan,
                control=AISourceDenialControl.PROMPT_SUBSTITUTION,
            ),
            images,
            valid_context,
            "vulnerable",
            "/v1/chat",
            authority_context_digest,
        ),
        (
            AISourceDenialControl.CHECK_SUBSTITUTION,
            _mutated_request_plan(
                plan,
                control=AISourceDenialControl.CHECK_SUBSTITUTION,
            ),
            images,
            valid_context,
            "vulnerable",
            "/v1/chat",
            authority_context_digest,
        ),
        (
            AISourceDenialControl.MODE_SUBSTITUTION,
            plan,
            images,
            valid_context,
            "hardened",
            "/v1/chat",
            authority_context_digest,
        ),
        (
            AISourceDenialControl.IMAGE_SUBSTITUTION,
            plan,
            _foreign_image_binding(images),
            valid_context,
            "vulnerable",
            "/v1/chat",
            authority_context_digest,
        ),
        (
            AISourceDenialControl.ROUTE_SUBSTITUTION,
            plan,
            images,
            foreign_route,
            "vulnerable",
            "/v1/foreign",
            authority_context_digest,
        ),
        (
            AISourceDenialControl.SCOPE_SUBSTITUTION,
            _scope_substitution(plan),
            images,
            valid_context,
            "vulnerable",
            "/v1/chat",
            authority_context_digest,
        ),
        (
            AISourceDenialControl.AUTHORITY_SUBSTITUTION,
            plan,
            images,
            valid_context,
            "vulnerable",
            "/v1/chat",
            foreign_authority,
        ),
    )
    receipts: list[AISourceDenialReceipt] = []
    for control, candidate, candidate_images, context, mode, route, digest in probes:
        try:
            _validate_source_pre_dispatch(
                candidate,
                expected_case=case,
                target=target,
                images=candidate_images,
                authority_context=authority_context,
                authority_context_digest=digest,
                backend=backend,
                inspector=inspector,
                backend_context=context,
                expected_mode=mode,
                expected_route=route,
            )
        except (AIFixtureRuntimeError, AISourceMeasurementError, ValueError):
            receipts.append(AISourceDenialReceipt(control=control))
            continue
        raise AISourceMeasurementError(f"AI source {control} denial reached dispatch eligibility")
    return tuple(receipts)


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
        raise AISourceMeasurementError("AI source JSON is not canonical") from exc
    return sha256(encoded).hexdigest()


async def _execute_approved_source(
    plan: AISourceApprovedAction,
    *,
    expected_case: AIMeasuredCaseRef,
    target: AIFixtureTargetCoordinate,
    images: AISourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    inspector: AIDockerBoundaryInspector,
    source_runs_root: Path,
) -> _ExecutedAISource:
    _validate_source_pre_dispatch(
        plan,
        expected_case=expected_case,
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
        raise AISourceMeasurementError("AI source execution requires one explicit approval")
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
    ) -> _DispatchedAISource:
        issued_at = datetime.now(UTC)
        expires_at = min(issued_at + timedelta(seconds=60), permit.expires_at)
        if expires_at <= issued_at:
            raise AISourceMeasurementError("AI source Permit expires before its Target challenge")
        operation_digest = benchmark_digest(
            "pajin.workflow.ai-source-operation/v1",
            {
                "caseDigest": expected_case.case_digest,
                "attemptDigest": target.attempt_digest,
                "permitDigest": permit.permit_digest,
                "requestDigest": permit.request_digest,
            },
            max_bytes=256 * 1024,
        )
        challenge = derive_ai_source_target_execution_challenge(
            permit_digest=permit.permit_digest,
            source_request_id=job.request.request_id,
            source_operation_id=f"ai-source-operation_{operation_digest}",
            target=job.request.target,
            method=job.request.method,
            compiled_argument_digest=_canonical_json_sha256(job.request.arguments),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        source_tool = AIM03SourceChatProbeTool(
            challenge=challenge,
            expected_request=job.request,
        )
        tools = ToolRegistry()
        tools.register(source_tool)
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
        return _DispatchedAISource(
            outcome=outcome,
            challenge=challenge,
            source_tool=source_tool,
        )

    dispatched = await dispatcher.dispatch_once(
        plan.mission_envelope,
        job.proposal,
        job.decision,
        approval,
        dispatch,
    )
    if dispatched.dispatched is not True or dispatched.result is None:
        raise AISourceMeasurementError("AI source approval or Permit was reused before dispatch")
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
        source_tool=dispatched.result.source_tool,
    )
    return _ExecutedAISource(
        source=source,
        source_inputs=source_inputs,
        graph_store=plan.graph_store,
        approval_receipt=dispatched.authorization.receipt,
        permit=dispatched.authorization.action.permit,
        challenge=dispatched.result.challenge,
        source_tool=dispatched.result.source_tool,
    )


def _build_private_measurement(
    *,
    ground_truth: AIPrivateGroundTruthCase,
    executed: _ExecutedAISource,
    trust_anchor: TargetAttestationTrustAnchor,
    lifecycle: AIFixtureTargetLifecycleEvidence,
) -> AIPrivateSourceMeasurement:
    source = executed.source
    try:
        output = AIChatProbeOutput.model_validate(source.evidence.result.data)
    except (TypeError, ValidationError, ValueError) as exc:
        raise AISourceMeasurementError(
            "AI source Tool output is not the exact typed M03 transcript"
        ) from exc
    proxy_binding = ai_source_target_proxy_binding(
        source.job.request,
        source.evidence.worker_result,
        output,
        expected_challenge=executed.challenge,
        target_receipt=lifecycle.target_receipt,
        network_log_trusted=source.evidence.network_log_trusted,
    )
    if (
        verify_ai_source_target_execution_receipt(
            lifecycle.target_receipt,
            trust_anchor=trust_anchor,
        )
        != lifecycle.target_receipt.key_id
    ):
        raise AISourceMeasurementError("AI source Target receipt signer identity differs")
    return AIPrivateSourceMeasurement(
        groundTruth=ground_truth,
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
    )


def _build_public_lineage(
    private: AIPrivateSourceMeasurement,
) -> AISourceCaseLineage:
    return AISourceCaseLineage(
        case=private.lifecycle.attempt.case,
        sourceRunId=private.source_run_id,
        sourceRootDigest=private.source_root_digest,
        approvalReceiptDigest=private.approval_receipt.receipt_digest,
        permitDigest=private.approval_receipt.action_permit.permit_digest,
        executionEvidenceSha256=private.execution_evidence_sha256,
        targetLifecycleEvidenceDigest=private.lifecycle.evidence_digest,
        targetReceiptDigest=private.lifecycle.target_receipt_digest,
        privateMeasurementDigest=private.measurement_digest,
    )


class AISourceMeasurementRunner:
    """Execute exactly one fresh AI-002B M03 source and no later operation."""

    def __init__(
        self,
        *,
        measured_cases: AIMeasuredCaseMapping,
        images: AISourceImageBinding,
        provider: AIFixtureDockerProvider,
        authorizer: AISourceActionAuthorizer,
        source_runs_root: Path,
        authority_runs_root: Path,
    ) -> None:
        if type(measured_cases) is not AIMeasuredCaseMapping:
            raise TypeError("AI source runner requires exact measured-case mapping")
        if not isinstance(provider, AIFixtureDockerProvider):
            raise TypeError("AI source runner requires exact Docker provider")
        if not callable(getattr(authorizer, "authorize", None)):
            raise TypeError("AI source runner requires an action authorizer")
        try:
            authority = load_ai_measured_case_authority(
                measured_cases.public_authority,
                private_ground_truth_binding=measured_cases.private_binding,
            )
            image_binding = load_ai_source_image_binding(
                images,
                inspector=provider,
            )
        except (AIFixtureRuntimeError, ValueError) as exc:
            raise AISourceMeasurementError(
                "AI source runner authority could not be reopened"
            ) from exc
        context, context_digest = _canonical_authority_context(authorizer)
        self._measured_authority = authority
        self._private_ground_truth = measured_cases.private_binding.model_copy(deep=True)
        self._images = image_binding
        self._provider = provider
        self._authorizer = authorizer
        self._authority_context = context
        self._authority_context_digest = context_digest
        self._source_runs_root = Path(source_runs_root)
        self._authority_runs_root = Path(authority_runs_root)

    async def run(self) -> AISourceMeasurementOutcome:
        if not self._provider.managed_resources_absent():
            raise AISourceMeasurementError(
                "AI source managed Target residue exists before execution"
            )
        current_context, current_digest = _canonical_authority_context(self._authorizer)
        if (
            current_context != self._authority_context
            or current_digest != self._authority_context_digest
        ):
            raise AISourceMeasurementError(
                "AI source action authority context changed before execution"
            )
        public_case = self._measured_authority.public_registry.cases[0].reference()
        ground_truth = self._private_ground_truth.case
        if public_case.case_id != ground_truth.case_id:
            raise AISourceMeasurementError("AI source public and private M03 case differ")
        live: AIFixtureLiveTarget | None = None
        target_finished = False
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
            run_id = RunStore.new_run_id()
            request_id = f"tool_ai002b_source_{uuid4().hex}"
            plan = self._authorizer.authorize(
                case=public_case.model_copy(deep=True),
                target=live.coordinate.model_copy(deep=True),
                run_id=run_id,
                request_id=request_id,
            )
            denials = _evaluate_code_owned_denials(
                plan,
                case=public_case,
                target=live.coordinate,
                images=self._images,
                authority_context=self._authority_context,
                authority_context_digest=self._authority_context_digest,
                backend=backend,
                inspector=inspector,
            )
            executed = await _execute_approved_source(
                plan,
                expected_case=public_case,
                target=live.coordinate,
                images=self._images,
                authority_context=self._authority_context,
                authority_context_digest=self._authority_context_digest,
                backend=backend,
                inspector=inspector,
                source_runs_root=self._source_runs_root,
            )
            topology = inspector.topology_observation(
                executed.source.evidence.worker_result.execution_id
            )
            target_receipt = self._provider.source_target_receipt(live)
            lifecycle = self._provider.finish(
                live,
                topology=topology,
                target_receipt=target_receipt,
            )
            target_finished = True
            private_measurement = _build_private_measurement(
                ground_truth=ground_truth,
                executed=executed,
                trust_anchor=live.trust_anchor,
                lifecycle=lifecycle,
            )
            lineage = _build_public_lineage(private_measurement)
            stable_context, stable_digest = _canonical_authority_context(self._authorizer)
            if (
                stable_context != self._authority_context
                or stable_digest != self._authority_context_digest
                or not self._provider.managed_resources_absent()
            ):
                raise AISourceMeasurementError(
                    "AI source authority changed or Target residue remains"
                )
            public_authority = AISourceMeasurementAuthority(
                measuredCaseAuthority=self._measured_authority.reference(),
                measurementProtocol=self._measured_authority.measurement_protocol.reference(),
                privateGroundTruthBindingDigest=self._private_ground_truth.binding_digest,
                images=self._images.reference(),
                actionAuthorityContextDigest=self._authority_context_digest,
                case=lineage,
                denials=denials,
            )
            private_binding = AIPrivateSourceMeasurementBinding(
                publicAuthority=public_authority.reference(),
                privateGroundTruthBindingId=self._private_ground_truth.binding_id,
                privateGroundTruthBindingDigest=self._private_ground_truth.binding_digest,
                images=self._images,
                measurement=private_measurement,
            )
            mapping = AISourceMeasurementMapping(
                public_authority=public_authority,
                private_binding=private_binding,
            )
            _validate_mapping(
                mapping,
                measured_authority=self._measured_authority,
                private_ground_truth=self._private_ground_truth,
            )
            store = RunStore.create(
                self._authority_runs_root,
                "ai-source-measurement",
            )
            store.write_json_create_only(
                _PUBLIC_AUTHORITY_ARTIFACT,
                public_authority.model_dump(mode="json", by_alias=True),
            )
            store.write_json_create_only(
                _PRIVATE_AUTHORITY_ARTIFACT,
                private_binding.model_dump(mode="json", by_alias=True),
            )
            store.append_event(
                "ai.source-measurement.sealed",
                {
                    "authorityDigest": public_authority.authority_digest,
                    "privateBindingDigest": private_binding.binding_digest,
                    "caseCount": 1,
                    "denialCount": 8,
                },
            )
            store.seal()
            return AISourceMeasurementOutcome(
                run_id=store.run_id,
                run_path=store.path,
                authority_path=_PUBLIC_AUTHORITY_ARTIFACT,
                private_binding_path=_PRIVATE_AUTHORITY_ARTIFACT,
                mapping=mapping,
                execution=AISourceExecutionContext(
                    source_inputs=executed.source_inputs,
                    graph_store=executed.graph_store,
                    lifecycle=lifecycle,
                    challenge=executed.challenge,
                ),
            )
        except BaseException:
            if live is not None and not target_finished:
                try:
                    self._provider.abort(live)
                except Exception as cleanup_error:
                    raise AISourceMeasurementError(
                        "AI source failure cleanup could not remove its Target"
                    ) from cleanup_error
            raise


def _validate_mapping(
    mapping: AISourceMeasurementMapping,
    *,
    measured_authority: AIMeasuredCaseAuthority,
    private_ground_truth: AIPrivateGroundTruthBinding,
) -> None:
    if type(mapping) is not AISourceMeasurementMapping:
        raise AISourceMeasurementError("AI source mapping requires its exact separated type")
    try:
        public = AISourceMeasurementAuthority.model_validate_json(
            mapping.public_authority.model_dump_json(by_alias=True)
        )
        private = AIPrivateSourceMeasurementBinding.model_validate_json(
            mapping.private_binding.model_dump_json(by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise AISourceMeasurementError("AI source public/private mapping is invalid") from exc
    measurement = private.measurement
    public_wire = public.model_dump_json(by_alias=True)
    sensitive_values = (
        measurement.ground_truth.prompt_text,
        measurement.ground_truth.check_value,
        measurement.output.session_id,
        measurement.request.target,
        measurement.worker_result.stdout,
        measurement.worker_result.network_log,
    )
    if (
        public != mapping.public_authority
        or private != mapping.private_binding
        or public.measured_case_authority != measured_authority.reference()
        or public.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or private.public_authority != public.reference()
        or private.private_ground_truth_binding_id != private_ground_truth.binding_id
        or private.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or public.images != private.images.reference()
        or public.case.private_measurement_digest != measurement.measurement_digest
        or public.case.target_lifecycle_evidence_digest != measurement.lifecycle.evidence_digest
        or any(value and value in public_wire for value in sensitive_values)
    ):
        raise AISourceMeasurementError(
            "AI source public/private authority binding or custody differs"
        )


def load_ai_source_measurement_authority(
    outcome: AISourceMeasurementOutcome,
    *,
    measured_cases: AIMeasuredCaseMapping,
    provider: AIFixtureDockerProvider,
) -> AISourceMeasurementAuthority:
    """Reopen sealed public/private AI-002B artifacts and the AI-001C source."""

    if type(outcome) is not AISourceMeasurementOutcome:
        raise TypeError("AI source reload requires its exact outcome")
    if type(measured_cases) is not AIMeasuredCaseMapping:
        raise TypeError("AI source reload requires exact measured-case mapping")
    if not isinstance(provider, AIFixtureDockerProvider):
        raise TypeError("AI source reload requires exact Docker provider")
    try:
        measured_authority = load_ai_measured_case_authority(
            measured_cases.public_authority,
            private_ground_truth_binding=measured_cases.private_binding,
        )
        public = AISourceMeasurementAuthority.model_validate_json(
            outcome.mapping.public_authority.model_dump_json(by_alias=True)
        )
        private = AIPrivateSourceMeasurementBinding.model_validate_json(
            outcome.mapping.private_binding.model_dump_json(by_alias=True)
        )
        load_ai_source_image_binding(private.images, inspector=provider)
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                outcome.authority_path: _MAX_CANONICAL_BYTES,
                outcome.private_binding_path: _MAX_CANONICAL_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_public = AISourceMeasurementAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.authority_path)
        )
        sealed_private = AIPrivateSourceMeasurementBinding.model_validate_json(
            snapshot.artifact_bytes(outcome.private_binding_path)
        )
    except (
        AttributeError,
        AIFixtureRuntimeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise AISourceMeasurementError("AI source sealed authority could not be reopened") from exc
    if (
        sealed_public != public
        or sealed_private != private
        or public != outcome.mapping.public_authority
        or private != outcome.mapping.private_binding
        or outcome.execution.source_inputs.expected_run_id != private.measurement.source_run_id
        or outcome.execution.source_inputs.run_path == outcome.run_path
        or outcome.execution.lifecycle != private.measurement.lifecycle
        or outcome.execution.challenge != private.measurement.challenge
    ):
        raise AISourceMeasurementError("AI source sealed artifacts or Run identities differ")
    source_tool = AIM03SourceChatProbeTool(
        challenge=private.measurement.challenge,
        expected_request=private.measurement.request,
    )
    try:
        source = load_verified_ai_analysis_observation_source(
            outcome.execution.source_inputs,
            graph_store=outcome.execution.graph_store,
            source_tool=source_tool,
        )
        rebuilt = _build_private_measurement(
            ground_truth=measured_cases.private_binding.case,
            executed=_ExecutedAISource(
                source=source,
                source_inputs=outcome.execution.source_inputs,
                graph_store=outcome.execution.graph_store,
                approval_receipt=private.measurement.approval_receipt,
                permit=private.measurement.approval_receipt.action_permit,
                challenge=private.measurement.challenge,
                source_tool=source_tool,
            ),
            trust_anchor=private.measurement.trust_anchor,
            lifecycle=outcome.execution.lifecycle,
        )
    except Exception as exc:
        raise AISourceMeasurementError(
            "AI source execution could not be contextfully reopened"
        ) from exc
    if (
        rebuilt != private.measurement
        or _build_public_lineage(rebuilt) != public.case
        or not provider.managed_resources_absent()
    ):
        raise AISourceMeasurementError(
            "AI source private output, receipt, topology, or cleanup differs"
        )
    mapping = AISourceMeasurementMapping(
        public_authority=public,
        private_binding=private,
    )
    _validate_mapping(
        mapping,
        measured_authority=measured_authority,
        private_ground_truth=measured_cases.private_binding,
    )
    return public.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class AISourceMeasurementReopenContext:
    """Host-owned context required to trust one sealed AI-002B result."""

    outcome: AISourceMeasurementOutcome
    measured_cases: AIMeasuredCaseMapping
    provider: AIFixtureDockerProvider

    def reopen(self) -> AISourceMeasurementAuthority:
        if type(self) is not AISourceMeasurementReopenContext:
            raise AISourceMeasurementError("AI source reopen context requires its exact type")
        return load_ai_source_measurement_authority(
            self.outcome,
            measured_cases=self.measured_cases,
            provider=self.provider,
        )


__all__ = [
    "AI_PRIVATE_SOURCE_MEASUREMENT_BINDING_API_VERSION",
    "AI_SOURCE_CASE_LINEAGE_API_VERSION",
    "AI_SOURCE_DENIAL_RECEIPT_API_VERSION",
    "AI_SOURCE_MEASUREMENT_AUTHORITY_API_VERSION",
    "AIPrivateSourceMeasurement",
    "AIPrivateSourceMeasurementBinding",
    "AISourceActionAuthorizer",
    "AISourceApprovedAction",
    "AISourceCaseLineage",
    "AISourceDenialControl",
    "AISourceDenialReceipt",
    "AISourceExecutionContext",
    "AISourceMeasurementAuthority",
    "AISourceMeasurementAuthorityRef",
    "AISourceMeasurementError",
    "AISourceMeasurementMapping",
    "AISourceMeasurementOutcome",
    "AISourceMeasurementReopenContext",
    "AISourceMeasurementRunner",
    "ai_source_provider_registration",
    "load_ai_source_measurement_authority",
]
