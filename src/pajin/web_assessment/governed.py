"""End-to-end governed execution for the exact local OWASP Juice Shop adapter.

The coordinator in this module is intentionally narrow.  It accepts only the
installed ``juice-shop-local/v1`` adapter and the canonical numeric-loopback
origin, derives every route and payload from code, and joins the existing
Campaign, Capability, Graph, Gateway, Worker, validation, SARIF, and reporting
boundaries without turning caller input into execution authority.
"""

from __future__ import annotations

import inspect
import json
import os
import secrets as stdlib_secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from pajin.capabilities.activation import (
    PreparedCapabilityAction,
    capability_grant_digest,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity, capability_definition_digest
from pajin.capabilities.web_authenticated_assessment import (
    WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
    WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID,
    WebAuthenticatedAssessmentCapabilityActivation,
    WebAuthenticatedAssessmentParameters,
    WebAuthenticatedAssessmentTool,
    activate_web_authenticated_assessment_capability,
    web_authenticated_assessment_capability_bundle,
)
from pajin.domain.models import (
    Authorization,
    AutonomyLevel,
    Budgets,
    CampaignManifest,
    CampaignMetadata,
    CampaignMode,
    CampaignSpec,
    CapabilityGrant,
    RulesOfEngagement,
    Scope,
    StrictModel,
    Target,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalReleaseRef,
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionPermit,
    ActionProposal,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
    GraphDecision,
    GraphDecisionKind,
    GraphProjectionCoordinator,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    GraphSnapshotRef,
    MissionEnvelope,
    SQLiteGraphStore,
    action_permit_attempt_id,
    graph_snapshot_ref,
)
from pajin.policy.capability import CapabilityLedger
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.runtime.pinned_sqlite import PinnedSQLiteCheckpoint
from pajin.runtime.pinned_workspace import active_pinned_workspace_identity
from pajin.runtime.safe_files import (
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import (
    RunIntegrityVerification,
    RunStore,
    load_verified_run_artifacts,
    verify_run_integrity,
)
from pajin.runtime.worker import WorkerResult
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, RequestRateLimitLedger
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignResult,
    LocalWebAssessmentRunReference,
    local_web_assessment_run_reference,
    reconcile_local_web_assessment_runs,
)
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE as _PROFILE_JUICE_SHOP_ADAPTER_REF,
)
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ORIGIN as _PROFILE_JUICE_SHOP_ORIGIN,
)
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_WEB_CAMPAIGN_ID as _PROFILE_WEB_CAMPAIGN_ID,
)
from pajin.web_assessment.governed_adapter_profile import (
    GovernedWebAdapterProfileError,
    ResolvedGovernedWebAdapterProfile,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_campaign_evidence import (
    GovernedWebCampaignDatabaseEnrollment,
    GovernedWebCampaignHistoricalResult,
    GovernedWebCampaignParentWriter,
    GovernedWebCampaignPlannedRuns,
    GovernedWebCampaignStageIntent,
    GovernedWebCampaignStageObservation,
    GovernedWebCampaignTrustMaterial,
    GovernedWebCodeTrustBinding,
    GovernedWebCompletedCampaignEvidence,
    begin_governed_web_campaign_parent,
    load_verified_governed_web_completed_campaign_evidence,
)
from pajin.web_assessment.governed_gateway import (
    HostLoopbackWebAssessmentGateway,
    WebGatewayCompletedActionAuthority,
    WebGatewayCompletionReceipt,
)
from pajin.web_assessment.governed_models import (
    ProvisionedWebAccountReceipt,
    ProvisionedWebAccountReceiptRegistry,
    SignedProvisionedWebAccountReceipt,
    SignedWebActionApproval,
    SignedWebAssessmentAdapter,
    WebActionApprovalAuthoritySet,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRegistry,
    WebAssessmentCapabilityGrantConsumptionReceipt,
    WebAssessmentCapabilityGrantConsumptionStore,
    WebAssessmentDispatchAuthority,
    WebAssessmentDispatchBinding,
    WebAssessmentDispatchBindingRegistry,
    WebAssessmentSigningKeyState,
    WebAssessmentSigningRole,
    WebAssessmentVerificationKey,
    WebAuthenticatedAssessmentWorkerOutput,
    sign_provisioned_web_account_receipt,
    sign_web_action_approval,
    sign_web_assessment_adapter,
    web_action_approval_issuer_binding,
    web_assessment_public_key_base64url,
)
from pajin.web_assessment.governed_reporting import (
    GovernedWebExecutionEvidence,
    GovernedWebExportBundle,
    GovernedWebGraphAdmission,
    GovernedWebPromotion,
    GovernedWebValidationAuthority,
    RedactedGovernedWebPocManifest,
    admit_governed_web_graph,
    create_governed_web_execution_verifier_binding,
    create_governed_web_graph_authority,
    governed_web_execution_verifier_digest,
    promote_governed_web_findings,
    write_governed_web_validation_projection,
    write_redacted_governed_web_poc,
    write_verified_governed_web_exports,
)
from pajin.web_assessment.governed_worker import (
    WEB_WORKER_BACKEND_NAME,
    WEB_WORKER_IMPLEMENTATION_VERSION,
    WEB_WORKER_PROCESS_IMPLEMENTATION_VERSION,
    HostLoopbackBrowserWorkerBackend,
    HostLoopbackWebAssessmentJobCompiler,
    HostLoopbackWebAssessmentOutputVerifier,
    HostLoopbackWebDeploymentContext,
    SignedWebWorkerActionEvidence,
    WebIndependentWorkerEvidence,
    WebProvisionedAccountMaterial,
    WebWorkerAuthorityBinding,
    WebWorkerKeyState,
    WebWorkerRole,
    WebWorkerTrustRegistry,
    WebWorkerVerificationKey,
    canonical_web_worker_sha256,
    verify_independent_web_worker_evidence,
    web_target_fingerprint_digest,
    web_worker_private_key_base64url,
    web_worker_public_key_base64url,
)
from pajin.web_assessment.models import LocalWebAssessmentAuthorization, WebAssessmentPlan
from pajin.web_assessment.runner import (
    ProvisionedLocalWebAssessmentAccount,
    issue_local_web_assessment_authorization,
    provision_local_web_assessment_account,
)
from pajin.web_assessment.verification import (
    load_verified_local_web_assessment_source_integrity,
)

if TYPE_CHECKING:
    from pajin.web_assessment.governed_process import GovernedWebCampaignProcessReceipt

GOVERNED_JUICE_SHOP_ORIGIN: Final[Literal["http://127.0.0.1:3000"]] = _PROFILE_JUICE_SHOP_ORIGIN
GOVERNED_JUICE_SHOP_ADAPTER_REF: Final[Literal["juice-shop-local/v1"]] = (
    _PROFILE_JUICE_SHOP_ADAPTER_REF
)
GOVERNED_WEB_CAMPAIGN_ID: Final = _PROFILE_WEB_CAMPAIGN_ID

_COMPILER_ID = "pajin.web-assessment.governed-compiler"
_COMPILER_VERSION = "1.0.0"
_COMPILER_DIGEST = capability_definition_digest(
    "pajin.web-assessment.governed-compiler/v1",
    {
        "compilerId": _COMPILER_ID,
        "campaign": GOVERNED_WEB_CAMPAIGN_ID,
        "actions": ("source", "validation"),
        "adapterRef": GOVERNED_JUICE_SHOP_ADAPTER_REF,
    },
)
_PROFILE_ID = "web-governed-local"
_PROFILE_VERSION = "1.0.0"
_PROFILE_DIGEST = capability_definition_digest(
    "pajin.web-assessment.governed-profile/v1",
    {
        "profileId": _PROFILE_ID,
        "adapterRef": GOVERNED_JUICE_SHOP_ADAPTER_REF,
        "approvalRequired": True,
        "actions": 2,
    },
)
_WORKER_IMPLEMENTATION_ID = "pajin.worker.host-loopback-browser"
_WORKER_IMPLEMENTATION_DIGEST = capability_definition_digest(
    "pajin.web-assessment.host-loopback-browser-worker-implementation/v1",
    {
        "backendName": WEB_WORKER_BACKEND_NAME,
        "implementationVersion": WEB_WORKER_IMPLEMENTATION_VERSION,
        "processImplementationVersion": WEB_WORKER_PROCESS_IMPLEMENTATION_VERSION,
    },
)
_GATEWAY_IMPLEMENTATION_ID = "pajin.gateway.host-loopback-web"
_GATEWAY_IMPLEMENTATION_VERSION = "pajin.host-loopback-web-gateway/v1"
_GATEWAY_IMPLEMENTATION_DIGEST = capability_definition_digest(
    "pajin.web-assessment.host-loopback-web-gateway-implementation/v1",
    {
        "implementationVersion": _GATEWAY_IMPLEMENTATION_VERSION,
        "oneAction": True,
        "workerBackend": WEB_WORKER_BACKEND_NAME,
        "workerImplementationDigest": _WORKER_IMPLEMENTATION_DIGEST,
    },
)
_WORKER_OUTPUT_ROOT_REFERENCE = "web-governed-worker-runs"
_ACCOUNT_NAME_REF = "secret:web-governed-account-name"
_ACCOUNT_PROOF_REF = "secret:web-governed-account-proof"


class GovernedWebCampaignError(RuntimeError):
    """Raised when any link in the WEB-005 authority chain fails closed."""


def _governed_code_trust_bindings(
    profile: ResolvedGovernedWebAdapterProfile,
) -> tuple[GovernedWebCodeTrustBinding, ...]:
    profile.public_metadata()
    bindings = (
        GovernedWebCodeTrustBinding(
            role="adapter-implementation",
            implementationId=profile.implementation_id,
            implementationDigest=profile.implementation_digest,
        ),
        GovernedWebCodeTrustBinding(
            role="compiler",
            implementationId=_COMPILER_ID,
            implementationDigest=_COMPILER_DIGEST,
        ),
        GovernedWebCodeTrustBinding(
            role="profile",
            implementationId=_PROFILE_ID,
            implementationDigest=_PROFILE_DIGEST,
        ),
        GovernedWebCodeTrustBinding(
            role="worker",
            implementationId=_WORKER_IMPLEMENTATION_ID,
            implementationDigest=_WORKER_IMPLEMENTATION_DIGEST,
        ),
        GovernedWebCodeTrustBinding(
            role="gateway",
            implementationId=_GATEWAY_IMPLEMENTATION_ID,
            implementationDigest=_GATEWAY_IMPLEMENTATION_DIGEST,
        ),
    )
    return tuple(sorted(bindings, key=lambda item: item.role))


class GovernedWebCampaignResult(StrictModel):
    """Frozen, public-safe summary of one complete governed campaign."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/governed-web-campaign-result/v1alpha1"] = Field(
        default="pajin.dev/governed-web-campaign-result/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCampaignResult"] = "GovernedWebCampaignResult"
    adapter_ref: Literal["juice-shop-local/v1"] = Field(alias="adapterRef")
    origin: Literal["http://127.0.0.1:3000"]
    campaign_id: str = Field(alias="campaignId")
    campaign_digest: str = Field(alias="campaignDigest", pattern=r"^[a-f0-9]{64}$")
    deployment_trust_anchor_digest: str = Field(
        alias="deploymentTrustAnchorDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    activation_set_id: str = Field(alias="activationSetId")
    activation_set_digest: str = Field(
        alias="activationSetDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    source_request_id: str = Field(alias="sourceRequestId")
    validation_request_id: str = Field(alias="validationRequestId")
    source_approval_id: str = Field(alias="sourceApprovalId")
    validation_approval_id: str = Field(alias="validationApprovalId")
    source_permit_id: str = Field(alias="sourcePermitId")
    validation_permit_id: str = Field(alias="validationPermitId")
    source_run_id: str = Field(alias="sourceRunId")
    validation_run_id: str = Field(alias="validationRunId")
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=r"^[a-f0-9]{64}$")
    validation_root_digest: str = Field(
        alias="validationRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    source_gateway_run_id: str = Field(alias="sourceGatewayRunId")
    validation_gateway_run_id: str = Field(alias="validationGatewayRunId")
    source_gateway_root_digest: str = Field(
        alias="sourceGatewayRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    validation_gateway_root_digest: str = Field(
        alias="validationGatewayRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    source_observer_process_id: int = Field(alias="sourceObserverProcessId", ge=1)
    source_executor_process_id: int = Field(alias="sourceExecutorProcessId", ge=1)
    validation_observer_process_id: int = Field(alias="validationObserverProcessId", ge=1)
    validation_executor_process_id: int = Field(alias="validationExecutorProcessId", ge=1)
    source_observer_key_id: str = Field(alias="sourceObserverKeyId")
    source_executor_key_id: str = Field(alias="sourceExecutorKeyId")
    validation_observer_key_id: str = Field(alias="validationObserverKeyId")
    validation_executor_key_id: str = Field(alias="validationExecutorKeyId")
    source_observer_execution_id: str = Field(alias="sourceObserverExecutionId")
    source_executor_execution_id: str = Field(alias="sourceExecutorExecutionId")
    validation_observer_execution_id: str = Field(alias="validationObserverExecutionId")
    validation_executor_execution_id: str = Field(alias="validationExecutorExecutionId")
    graph_event_count: int = Field(alias="graphEventCount", ge=1)
    finding_count: int = Field(alias="findingCount", ge=0)
    attack_path_count: int = Field(alias="attackPathCount", ge=0)
    validation_projection_run_id: str = Field(alias="validationProjectionRunId")
    validation_projection_root_digest: str = Field(
        alias="validationProjectionRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    sarif_reference: Literal["findings.sarif"] = Field(
        default="findings.sarif",
        alias="sarifReference",
    )
    sarif_digest: str = Field(alias="sarifDigest", pattern=r"^[a-f0-9]{64}$")
    poc_manifest_reference: Literal["poc/manifest.json"] = Field(
        default="poc/manifest.json",
        alias="pocManifestReference",
    )
    poc_manifest_digest: str = Field(
        alias="pocManifestDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    delivery_readiness_reference: Literal["delivery-readiness.json"] = Field(
        default="delivery-readiness.json",
        alias="deliveryReadinessReference",
    )
    account_retained_in_local_lab: Literal[True] = Field(
        default=True,
        alias="accountRetainedInLocalLab",
    )
    credentials_persisted: Literal[False] = Field(
        default=False,
        alias="credentialsPersisted",
    )
    external_delivery_performed: Literal[False] = Field(
        default=False,
        alias="externalDeliveryPerformed",
    )


@dataclass(frozen=True, slots=True)
class GovernedWebActionArtifacts:
    """Public, secret-free authority and execution result for one action leg."""

    role: Literal["source", "validation"]
    prepared: PreparedCapabilityAction
    grant: CapabilityGrant
    envelope: MissionEnvelope
    decision: GraphDecision
    proposal: ActionProposal
    approval: ActionApprovalEnvelope
    signed_approval: SignedWebActionApproval
    permit: ActionPermit
    approval_receipt: ActionApprovalConsumptionReceipt
    grant_consumption_receipt: WebAssessmentCapabilityGrantConsumptionReceipt
    dispatch_binding: WebWorkerAuthorityBinding
    gateway_completion: WebGatewayCompletionReceipt
    gateway_completion_reference: str
    gateway_completion_authority_digest: str
    gateway_final_root_digest: str
    gateway_final_event_head_digest: str
    gateway_outcome: GatewayOutcome
    worker_output: WebAuthenticatedAssessmentWorkerOutput
    worker_evidence: SignedWebWorkerActionEvidence
    run_reference: LocalWebAssessmentRunReference
    run_path: Path


@dataclass(frozen=True, slots=True)
class GovernedWebCampaignArtifacts:
    """Typed output of one complete, locally retained governed campaign."""

    adapter_ref: str
    origin: str
    deployment_trust_anchor_digest: str
    campaign: CampaignManifest
    campaign_digest: str
    signed_adapter: SignedWebAssessmentAdapter
    signed_account_receipt: SignedProvisionedWebAccountReceipt
    release_bundle: CapabilityReleaseBundle
    activation: WebAuthenticatedAssessmentCapabilityActivation
    worker_trust_registry: WebWorkerTrustRegistry
    source: GovernedWebActionArtifacts
    validation: GovernedWebActionArtifacts
    independent_worker_evidence: WebIndependentWorkerEvidence
    reconciliation: LocalWebAssessmentCampaignResult
    execution_evidence: GovernedWebExecutionEvidence
    promotion: GovernedWebPromotion
    graph_admission: GovernedWebGraphAdmission
    validation_authority: GovernedWebValidationAuthority
    poc: RedactedGovernedWebPocManifest
    exports: GovernedWebExportBundle
    parent_run_path: Path
    parent_root_digest: str
    parent_integrity: RunIntegrityVerification
    graph_path: Path
    initial_graph_snapshot: GraphSnapshotRef
    final_graph_snapshot: GraphSnapshotRef
    validation_run_path: Path
    report_path: Path
    poc_bundle_path: Path
    sarif_path: Path
    delivery_readiness_path: Path

    @property
    def result(self) -> GovernedWebCampaignResult:
        source_record = self.source.worker_evidence.execution_attestation.statement
        source_target = self.source.worker_evidence.target_identity.statement
        validation_record = self.validation.worker_evidence.execution_attestation.statement
        validation_target = self.validation.worker_evidence.target_identity.statement
        return GovernedWebCampaignResult(
            adapterRef=cast(Literal["juice-shop-local/v1"], self.adapter_ref),
            origin=cast(Literal["http://127.0.0.1:3000"], self.origin),
            campaignId=self.campaign.metadata.name,
            campaignDigest=self.campaign_digest,
            deploymentTrustAnchorDigest=self.deployment_trust_anchor_digest,
            activationSetId=self.activation.activation_set.activation_set_id,
            activationSetDigest=self.activation.activation_set.activation_set_digest,
            sourceRequestId=self.source.prepared.request.request_id,
            validationRequestId=self.validation.prepared.request.request_id,
            sourceApprovalId=self.source.approval.approval_id,
            validationApprovalId=self.validation.approval.approval_id,
            sourcePermitId=self.source.permit.permit_id,
            validationPermitId=self.validation.permit.permit_id,
            sourceRunId=self.source.run_reference.run_id,
            validationRunId=self.validation.run_reference.run_id,
            sourceRootDigest=self.source.run_reference.root_digest,
            validationRootDigest=self.validation.run_reference.root_digest,
            sourceGatewayRunId=self.source.gateway_completion.gateway_audit_run_id,
            validationGatewayRunId=self.validation.gateway_completion.gateway_audit_run_id,
            sourceGatewayRootDigest=self.source.gateway_final_root_digest,
            validationGatewayRootDigest=self.validation.gateway_final_root_digest,
            sourceObserverProcessId=source_target.process_id,
            sourceExecutorProcessId=source_record.process_id,
            validationObserverProcessId=validation_target.process_id,
            validationExecutorProcessId=validation_record.process_id,
            sourceObserverKeyId=self.source.worker_evidence.target_identity.key_id,
            sourceExecutorKeyId=self.source.worker_evidence.execution_attestation.key_id,
            validationObserverKeyId=self.validation.worker_evidence.target_identity.key_id,
            validationExecutorKeyId=(self.validation.worker_evidence.execution_attestation.key_id),
            sourceObserverExecutionId=source_target.execution_id,
            sourceExecutorExecutionId=source_record.execution_id,
            validationObserverExecutionId=validation_target.execution_id,
            validationExecutorExecutionId=validation_record.execution_id,
            graphEventCount=self.final_graph_snapshot.revision,
            findingCount=len(self.promotion.findings),
            attackPathCount=len(self.promotion.attack_paths),
            validationProjectionRunId=self.validation_authority.run_id,
            validationProjectionRootDigest=self.validation_authority.final_root_digest,
            sarifDigest=self.exports.sarif.sarif_digest,
            pocManifestDigest=self.poc.manifest_digest,
        )


@dataclass(frozen=True, slots=True)
class _ActionIntent:
    role: Literal["source", "validation"]
    prepared: PreparedCapabilityAction
    grant: CapabilityGrant
    envelope: MissionEnvelope
    decision: GraphDecision
    proposal: ActionProposal
    approval: ActionApprovalEnvelope
    signed_approval: SignedWebActionApproval
    run_id: str
    worker_execution_id: str
    observer_execution_id: str
    worker_secret_ref: str
    observer_secret_ref: str


@dataclass(frozen=True, slots=True)
class _GovernedWebEphemeralTrust:
    account_private_key: bytes
    source_approval_private_key: bytes
    validation_approval_private_key: bytes
    lifecycle_publisher_private_key: bytes
    lifecycle_reviewer_private_key: bytes
    worker_private_keys: dict[WebWorkerRole, bytes]
    adapter_key: WebAssessmentVerificationKey
    account_key: WebAssessmentVerificationKey
    source_approval_key: WebAssessmentVerificationKey
    validation_approval_key: WebAssessmentVerificationKey
    lifecycle_publisher_key: CapabilityLifecycleTrustKey
    lifecycle_reviewer_key: CapabilityLifecycleTrustKey
    adapter: WebAssessmentAdapterManifest
    signed_adapter: SignedWebAssessmentAdapter
    worker_registry: WebWorkerTrustRegistry
    public_trust_material: GovernedWebCampaignTrustMaterial


_CampaignFailureStage = Literal[
    "provisioning",
    "source-gateway",
    "validation-gateway",
    "graph-admission",
    "poc-publication",
    "export-publication",
    "parent-evidence",
]
_CAMPAIGN_STAGE_ORDER: Final[tuple[_CampaignFailureStage, ...]] = (
    "provisioning",
    "source-gateway",
    "validation-gateway",
    "graph-admission",
    "poc-publication",
    "export-publication",
    "parent-evidence",
)

_CampaignProgressStage = Literal[
    "initial",
    "provisioning",
    "source-gateway",
    "validation-gateway",
    "graph-admission",
    "poc-publication",
    "export-publication",
    "parent-evidence",
]
_CampaignDatabaseCheckpointStage = Literal[
    "provisioning",
    "source-gateway",
    "validation-gateway",
    "graph-admission",
]
_CampaignDatabaseStoreKind = Literal["governed-web-graph", "governed-web-grant"]


@dataclass(frozen=True, slots=True)
class _GovernedWebCampaignSealedProgress:
    """Public-safe notice emitted only after one parent checkpoint is sealed."""

    parent_run_id: str
    campaign_plan_digest: str
    deployment_trust_anchor_digest: str
    previous_parent_root_digest: str | None
    parent_root_digest: str
    stage: _CampaignProgressStage
    status: Literal["prepared", "started", "completed", "database-checkpoint", "failed"]
    terminal: bool
    database_store_kind: _CampaignDatabaseStoreKind | None = None
    database_checkpoint_ordinal: int | None = None
    database_manifest_digest: str | None = None
    database_sha256: str | None = None
    database_checkpoint_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            self.stage
            not in {
                "initial",
                "provisioning",
                "source-gateway",
                "validation-gateway",
                "graph-admission",
                "poc-publication",
                "export-publication",
                "parent-evidence",
            }
            or self.status
            not in {"prepared", "started", "completed", "database-checkpoint", "failed"}
            or type(self.terminal) is not bool
        ):
            raise ValueError("governed WEB sealed progress state is invalid")
        digests = (
            self.campaign_plan_digest,
            self.deployment_trust_anchor_digest,
            self.parent_root_digest,
            *(
                value
                for value in (
                    self.database_manifest_digest,
                    self.database_sha256,
                    self.database_checkpoint_digest,
                )
                if value is not None
            ),
        )
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in digests
        ):
            raise ValueError("governed WEB sealed progress contains an invalid digest")
        previous = self.previous_parent_root_digest
        if previous is not None and (
            len(previous) != 64
            or any(character not in "0123456789abcdef" for character in previous)
            or previous == self.parent_root_digest
        ):
            raise ValueError("governed WEB sealed progress previous root is invalid")
        database_fields_present = (
            self.database_store_kind is not None,
            self.database_checkpoint_ordinal is not None,
            self.database_manifest_digest is not None,
            self.database_sha256 is not None,
            self.database_checkpoint_digest is not None,
        )
        if self.status == "database-checkpoint":
            valid = (
                self.stage
                in {
                    "provisioning",
                    "source-gateway",
                    "validation-gateway",
                    "graph-admission",
                }
                and previous is not None
                and not self.terminal
                and all(database_fields_present)
                and self.database_store_kind in {"governed-web-graph", "governed-web-grant"}
                and type(self.database_checkpoint_ordinal) is int
                and self.database_checkpoint_ordinal >= 1
            )
        elif any(database_fields_present):
            valid = False
        elif self.stage == "initial":
            valid = self.status == "prepared" and previous is None and not self.terminal
        elif self.status == "prepared":
            valid = False
        else:
            valid = previous is not None and self.terminal == (
                self.status == "failed"
                or (self.stage == "parent-evidence" and self.status == "completed")
            )
        if not valid:
            raise ValueError("governed WEB sealed progress state is invalid")


_CampaignProgressSink = Callable[[_GovernedWebCampaignSealedProgress], None]
_ACTIVE_CAMPAIGN_PROGRESS_SINK: ContextVar[_CampaignProgressSink | None] = ContextVar(
    "pajin_governed_web_campaign_progress_sink",
    default=None,
)
_CAMPAIGN_PROGRESS_EMITTING: ContextVar[bool] = ContextVar(
    "pajin_governed_web_campaign_progress_emitting",
    default=False,
)
_ACTIVE_CAMPAIGN_FAILURE_TYPE: ContextVar[str] = ContextVar(
    "pajin_governed_web_campaign_failure_type",
    default="governed-stage-failure",
)


@contextmanager
def _activate_governed_web_campaign_progress_sink(
    sink: _CampaignProgressSink,
) -> Iterator[None]:
    """Install one process-local coordinator sink without widening the public API."""

    if not callable(sink):
        raise TypeError("governed WEB campaign progress sink must be callable")
    if _ACTIVE_CAMPAIGN_PROGRESS_SINK.get() is not None:
        raise ValueError("governed WEB campaign progress sink is already active")
    token: Token[_CampaignProgressSink | None] = _ACTIVE_CAMPAIGN_PROGRESS_SINK.set(sink)
    try:
        yield
    finally:
        _ACTIVE_CAMPAIGN_PROGRESS_SINK.reset(token)


def _emit_governed_web_campaign_sealed_progress(
    writer: GovernedWebCampaignParentWriter,
    *,
    previous_parent_root_digest: str | None,
    stage: _CampaignProgressStage,
    status: Literal["prepared", "started", "completed", "database-checkpoint", "failed"],
    terminal: bool,
    database_store_kind: _CampaignDatabaseStoreKind | None = None,
    database_checkpoint_ordinal: int | None = None,
    database_manifest_digest: str | None = None,
    database_sha256: str | None = None,
    database_checkpoint_digest: str | None = None,
) -> None:
    sink = _ACTIVE_CAMPAIGN_PROGRESS_SINK.get()
    if sink is None:
        return
    if _CAMPAIGN_PROGRESS_EMITTING.get():
        raise RuntimeError("governed WEB campaign progress sink cannot re-enter emission")
    token = _CAMPAIGN_PROGRESS_EMITTING.set(True)
    try:
        result = sink(
            _GovernedWebCampaignSealedProgress(
                parent_run_id=writer.parent_run_id,
                campaign_plan_digest=writer.plan.campaign_plan_digest,
                deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
                previous_parent_root_digest=previous_parent_root_digest,
                parent_root_digest=writer.current_root_digest,
                stage=stage,
                status=status,
                terminal=terminal,
                database_store_kind=database_store_kind,
                database_checkpoint_ordinal=database_checkpoint_ordinal,
                database_manifest_digest=database_manifest_digest,
                database_sha256=database_sha256,
                database_checkpoint_digest=database_checkpoint_digest,
            )
        )
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise TypeError("governed WEB campaign progress sink must complete synchronously")
        if result is not None:
            raise TypeError("governed WEB campaign progress sink must return None")
        writer._acknowledge_external_progress(
            parent_root_digest=writer.current_root_digest,
        )
    finally:
        _CAMPAIGN_PROGRESS_EMITTING.reset(token)


def _record_governed_database_checkpoint(
    writer: GovernedWebCampaignParentWriter,
    *,
    stage: _CampaignDatabaseCheckpointStage,
    store_kind: _CampaignDatabaseStoreKind,
    checkpoint: PinnedSQLiteCheckpoint,
) -> None:
    """Seal and externally ACK one exact durable database checkpoint."""

    previous_root = writer.current_root_digest
    writer.record_database_checkpoint(
        stage=stage,
        store_kind=store_kind,
        checkpoint=checkpoint,
        occurred_at=_now_utc(),
    )
    persisted = writer.latest_database_checkpoint
    if (
        persisted is None
        or persisted.stage != stage
        or persisted.store_kind != store_kind
        or persisted.ordinal != checkpoint.ordinal
        or persisted.manifest_reference != checkpoint.manifest_reference
        or persisted.manifest_digest != checkpoint.manifest_digest
        or persisted.manifest_sha256 != checkpoint.manifest_sha256
        or persisted.manifest_size != checkpoint.manifest_size
        or persisted.database_reference != checkpoint.database_reference
        or persisted.database_sha256 != checkpoint.database_sha256
        or persisted.database_size != checkpoint.database_size
        or persisted.state_digest != checkpoint.state_digest
        or persisted.previous_parent_root_digest != previous_root
    ):
        raise GovernedWebCampaignError(
            "governed WEB database checkpoint changed during parent journaling"
        )
    _emit_governed_web_campaign_sealed_progress(
        writer,
        previous_parent_root_digest=previous_root,
        stage=stage,
        status="database-checkpoint",
        terminal=False,
        database_store_kind=store_kind,
        database_checkpoint_ordinal=checkpoint.ordinal,
        database_manifest_digest=checkpoint.manifest_digest,
        database_sha256=checkpoint.database_sha256,
        database_checkpoint_digest=persisted.checkpoint_digest,
    )


class _GovernedWebDatabaseCheckpointJournal:
    """Route each live SQLite commit into the currently active parent stage."""

    __slots__ = ("_stage", "_writer")

    def __init__(self, writer: GovernedWebCampaignParentWriter) -> None:
        self._writer = writer
        self._stage: _CampaignDatabaseCheckpointStage = "provisioning"

    def advance(self, stage: _CampaignDatabaseCheckpointStage) -> None:
        transitions = {
            "provisioning": "source-gateway",
            "source-gateway": "validation-gateway",
            "validation-gateway": "graph-admission",
        }
        if transitions.get(self._stage) != stage:
            raise GovernedWebCampaignError(
                "governed WEB database checkpoint stage transition is invalid"
            )
        self._stage = stage

    def graph_checkpoint(self, checkpoint: PinnedSQLiteCheckpoint) -> None:
        _record_governed_database_checkpoint(
            self._writer,
            stage=self._stage,
            store_kind="governed-web-graph",
            checkpoint=checkpoint,
        )

    def grant_checkpoint(self, checkpoint: PinnedSQLiteCheckpoint) -> None:
        _record_governed_database_checkpoint(
            self._writer,
            stage=self._stage,
            store_kind="governed-web-grant",
            checkpoint=checkpoint,
        )


class _GovernedWebDatabaseAuthorityCleanup:
    """Close live in-memory database authorities on every execution exit."""

    __slots__ = ("_closers",)

    def __init__(self) -> None:
        self._closers: list[Callable[[], None]] = []

    def register(self, closer: Callable[[], None]) -> None:
        if not callable(closer):
            raise TypeError("governed WEB database closer must be callable")
        self._closers.append(closer)

    def close(self) -> None:
        primary: BaseException | None = None
        while self._closers:
            closer = self._closers.pop()
            try:
                closer()
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    primary.add_note(
                        f"additional governed WEB database close failure: {type(exc).__name__}"
                    )
        if primary is not None:
            raise primary


@dataclass(frozen=True, slots=True)
class _GovernedWebCampaignRunPlan:
    parent_run_id: str
    source_run_id: str
    validation_run_id: str
    source_gateway_run_id: str
    validation_gateway_run_id: str
    validation_projection_run_id: str

    @classmethod
    def create(cls) -> _GovernedWebCampaignRunPlan:
        run_ids = tuple(RunStore.new_run_id() for _ in range(6))
        if len(set(run_ids)) != len(run_ids):
            raise GovernedWebCampaignError("governed Web planned Run IDs must be distinct")
        return cls(*run_ids)

    def evidence_plan(self) -> GovernedWebCampaignPlannedRuns:
        return GovernedWebCampaignPlannedRuns(
            parentRunId=self.parent_run_id,
            sourceBrowserRunId=self.source_run_id,
            validationBrowserRunId=self.validation_run_id,
            sourceGatewayRunId=self.source_gateway_run_id,
            validationGatewayRunId=self.validation_gateway_run_id,
            validationProjectionRunId=self.validation_projection_run_id,
        )


def _campaign_stage_boundary(
    _stage: _CampaignFailureStage,
    _status: Literal["started", "completed"],
) -> None:
    """Internal test seam after one durable campaign stage; production is a no-op."""


def _now_utc() -> datetime:
    value = datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise GovernedWebCampaignError("governed WEB clock requires an explicit UTC offset")
    return value.astimezone(UTC)


def _digest(domain: str, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(domain.encode("ascii") + b"\x00" + encoded).hexdigest()


def _public_model(value: BaseModel) -> dict[str, JsonValue]:
    return cast(
        dict[str, JsonValue],
        value.model_dump(mode="json", by_alias=True),
    )


def _bounded_file_sha256(path: Path, *, label: str) -> str:
    return sha256(
        read_bounded_regular_bytes(
            path,
            max_bytes=64 * 1024 * 1024,
            label=label,
            require_single_link=True,
        )
    ).hexdigest()


def _begin_campaign_stage(
    writer: GovernedWebCampaignParentWriter,
    stage: _CampaignFailureStage,
    bindings: dict[str, JsonValue],
) -> None:
    previous_root = writer.current_root_digest
    writer.begin_stage(
        stage,
        GovernedWebCampaignStageIntent(stage=stage, bindings=bindings),
        _now_utc(),
    )
    _emit_governed_web_campaign_sealed_progress(
        writer,
        previous_parent_root_digest=previous_root,
        stage=stage,
        status="started",
        terminal=False,
    )
    _campaign_stage_boundary(stage, "started")


def _complete_campaign_stage(
    writer: GovernedWebCampaignParentWriter,
    stage: _CampaignFailureStage,
    observed: dict[str, JsonValue],
) -> None:
    previous_root = writer.current_root_digest
    writer.complete_stage(
        stage,
        GovernedWebCampaignStageObservation(stage=stage, observed=observed),
        _now_utc(),
    )
    _emit_governed_web_campaign_sealed_progress(
        writer,
        previous_parent_root_digest=previous_root,
        stage=stage,
        status="completed",
        terminal=False,
    )
    _campaign_stage_boundary(stage, "completed")


def _private_key(label: str, issued: dict[str, bytes]) -> bytes:
    value = stdlib_secrets.token_bytes(32)
    if type(value) is not bytes or len(value) != 32:
        raise GovernedWebCampaignError("governed WEB Ed25519 seeds must contain 32 bytes")
    if value in issued.values():
        raise GovernedWebCampaignError("governed WEB signing roles require distinct keys")
    issued[label] = value
    return value


def _web_verification_key(
    *,
    label: str,
    role: WebAssessmentSigningRole,
    private_key: bytes,
    now: datetime,
) -> WebAssessmentVerificationKey:
    return WebAssessmentVerificationKey(
        keyId=f"web.{label}",
        principalId=f"principal.web.{label}",
        role=role,
        publicKeyBase64url=web_assessment_public_key_base64url(private_key),
        state=WebAssessmentSigningKeyState.ACTIVE,
        notBefore=now - timedelta(minutes=5),
        notAfter=now + timedelta(hours=1),
    )


def _lifecycle_key(
    *,
    label: str,
    principal: str,
    role: CapabilityLifecycleKeyRole,
    private_key: bytes,
    now: datetime,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"web.lifecycle.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(private_key),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=now - timedelta(hours=1),
        notAfter=now + timedelta(hours=1),
    )


def _worker_trust(
    *,
    keys: dict[WebWorkerRole, bytes],
    now: datetime,
) -> WebWorkerTrustRegistry:
    verification = tuple(
        sorted(
            (
                WebWorkerVerificationKey(
                    keyId=f"web.worker.{role.value}",
                    role=role,
                    publicKeyBase64url=web_worker_public_key_base64url(keys[role]),
                    state=WebWorkerKeyState.ACTIVE,
                    notBefore=now - timedelta(minutes=5),
                    notAfter=now + timedelta(hours=1),
                )
                for role in WebWorkerRole
            ),
            key=lambda item: (item.role.value, item.key_id),
        )
    )
    return WebWorkerTrustRegistry(
        trustDomain="pajin.web.local-governed",
        issuer="deployment:local-juice-shop",
        keys=verification,
    )


def _campaign(
    profile: ResolvedGovernedWebAdapterProfile,
    *,
    now: datetime,
) -> CampaignManifest:
    profile.public_metadata()
    plan = profile.plan
    return CampaignManifest(
        apiVersion="pajin.dev/v1alpha1",
        kind="Campaign",
        metadata=CampaignMetadata(
            name=profile.campaign_id,
            description=profile.description,
        ),
        spec=CampaignSpec(
            mode=CampaignMode.BUG_BOUNTY,
            autonomy=AutonomyLevel.SUPERVISED,
            authorization=Authorization(
                approvedBy="operator.local-lab",
                approvedAt=now - timedelta(seconds=5),
                expiresAt=now + timedelta(minutes=20),
                evidence="Explicit --authorized-local-lab assertion for the exact loopback target.",
            ),
            targets=[
                Target(
                    type=profile.target_type,
                    id=profile.target_id,
                    endpoint=profile.origin,
                )
            ],
            scope=Scope(
                allow=[profile.origin + "/**"],
                deny=[profile.origin + path + "*" for path in plan.deny_paths],
            ),
            accessProfile="authenticated-blackbox",
            objectives=[profile.objective],
            rulesOfEngagement=RulesOfEngagement(
                maxToolRiskTier=ToolRiskTier.T2,
                allowedMethods={"GET", "HEAD", "POST"},
                allowedToolCategories={"active-test", "browser", "bug-bounty", "web"},
                prohibit=set(),
                stopOn={"scope-boundary", "target-identity-drift"},
                allowPrivateNetworks=True,
                maxRequestsPerMinute=250,
            ),
            budgets=Budgets(
                durationSeconds=1_800,
                maxCostUsd=0,
                maxAgents=1,
                maxSpawnDepth=1,
                maxToolCalls=2,
                maxModelCalls=0,
                maxModelTokens=0,
            ),
            outputs=["markdown-report", "json-findings", "sarif", "redacted-poc"],
        ),
    )


def _installed_adapter(
    *,
    profile: ResolvedGovernedWebAdapterProfile,
    publisher_key: WebAssessmentVerificationKey,
    publisher_private_key: bytes,
    now: datetime,
) -> tuple[WebAssessmentAdapterManifest, SignedWebAssessmentAdapter]:
    manifest = WebAssessmentAdapterManifest.model_validate(
        profile.manifest_input(
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=30),
        )
    )
    signed = sign_web_assessment_adapter(
        manifest,
        key_id=publisher_key.key_id,
        private_key=publisher_private_key,
    )
    return manifest, signed


def _prepare_governed_web_ephemeral_trust(
    *,
    profile: ResolvedGovernedWebAdapterProfile,
    now: datetime,
) -> _GovernedWebEphemeralTrust:
    profile.public_metadata()
    issued_keys: dict[str, bytes] = {}
    adapter_private = _private_key("adapter-publisher", issued_keys)
    account_private = _private_key("account-issuer", issued_keys)
    source_approval_private = _private_key("source-action-approver", issued_keys)
    validation_approval_private = _private_key("validation-action-approver", issued_keys)
    lifecycle_publisher_private = _private_key("lifecycle-publisher", issued_keys)
    lifecycle_reviewer_private = _private_key("lifecycle-reviewer", issued_keys)
    worker_private = {
        role: _private_key(f"worker-{role.value}", issued_keys) for role in WebWorkerRole
    }
    adapter_key = _web_verification_key(
        label="adapter-publisher",
        role=WebAssessmentSigningRole.ADAPTER_PUBLISHER,
        private_key=adapter_private,
        now=now,
    )
    account_key = _web_verification_key(
        label="account-issuer",
        role=WebAssessmentSigningRole.ACCOUNT_ISSUER,
        private_key=account_private,
        now=now,
    )
    source_approval_key = _web_verification_key(
        label="source-action-approver",
        role=WebAssessmentSigningRole.ACTION_APPROVER,
        private_key=source_approval_private,
        now=now,
    )
    validation_approval_key = _web_verification_key(
        label="validation-action-approver",
        role=WebAssessmentSigningRole.ACTION_APPROVER,
        private_key=validation_approval_private,
        now=now,
    )
    lifecycle_publisher_key = _lifecycle_key(
        label="publisher",
        principal="principal.web.lifecycle.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
        private_key=lifecycle_publisher_private,
        now=now,
    )
    lifecycle_reviewer_key = _lifecycle_key(
        label="reviewer",
        principal="principal.web.lifecycle.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
        private_key=lifecycle_reviewer_private,
        now=now,
    )
    adapter, signed_adapter = _installed_adapter(
        profile=profile,
        publisher_key=adapter_key,
        publisher_private_key=adapter_private,
        now=now,
    )
    worker_registry = _worker_trust(keys=worker_private, now=now)
    trust_material = GovernedWebCampaignTrustMaterial(
        adapterKey=adapter_key,
        accountKey=account_key,
        sourceApprovalKey=source_approval_key,
        validationApprovalKey=validation_approval_key,
        lifecyclePublisherKey=lifecycle_publisher_key,
        lifecycleReviewerKey=lifecycle_reviewer_key,
        workerTrustDomain=worker_registry.trust_domain,
        workerIssuer=worker_registry.issuer,
        workerKeys=worker_registry.keys,
        codeBindings=_governed_code_trust_bindings(profile),
    )
    return _GovernedWebEphemeralTrust(
        account_private_key=account_private,
        source_approval_private_key=source_approval_private,
        validation_approval_private_key=validation_approval_private,
        lifecycle_publisher_private_key=lifecycle_publisher_private,
        lifecycle_reviewer_private_key=lifecycle_reviewer_private,
        worker_private_keys=worker_private,
        adapter_key=adapter_key,
        account_key=account_key,
        source_approval_key=source_approval_key,
        validation_approval_key=validation_approval_key,
        lifecycle_publisher_key=lifecycle_publisher_key,
        lifecycle_reviewer_key=lifecycle_reviewer_key,
        adapter=adapter,
        signed_adapter=signed_adapter,
        worker_registry=worker_registry,
        public_trust_material=trust_material,
    )


def _provisioning_fingerprint(
    provisioned: ProvisionedLocalWebAssessmentAccount,
    *,
    fingerprint_endpoint: str,
) -> tuple[str, int]:
    evidence = tuple(
        item
        for item in provisioned.request_evidence
        if item.phase == "target-fingerprint"
        and item.method == "GET"
        and item.path == fingerprint_endpoint
        and item.status == 200
    )
    if len(evidence) != 1:
        raise GovernedWebCampaignError(
            "account provisioning requires one exact successful target fingerprint"
        )
    return evidence[0].response_sha256, evidence[0].response_bytes


def _signed_account(
    *,
    adapter: WebAssessmentAdapterManifest,
    target_product: str,
    provisioned: ProvisionedLocalWebAssessmentAccount,
    authorization_ids: tuple[str, str],
    fingerprint_endpoint: str,
    issuer_key: WebAssessmentVerificationKey,
    issuer_private_key: bytes,
    now: datetime,
) -> tuple[ProvisionedWebAccountReceipt, SignedProvisionedWebAccountReceipt]:
    if provisioned.target_product != target_product:
        raise GovernedWebCampaignError(
            "provisioned Web target product differs from the selected deployment profile"
        )
    response_sha256, _response_bytes = _provisioning_fingerprint(
        provisioned,
        fingerprint_endpoint=fingerprint_endpoint,
    )
    ordered_authorizations = tuple(sorted(authorization_ids))
    receipt = ProvisionedWebAccountReceipt(
        adapter=adapter.reference(),
        origin=adapter.origin,
        accountReferenceDigest=_digest(
            "pajin.web-assessment.ephemeral-account-reference/v1",
            stdlib_secrets.token_hex(32),
        ),
        provisioningEvidenceDigest=_digest(
            "pajin.web-assessment.provisioning-evidence/v1",
            provisioned.receipt(),
        ),
        targetFingerprintResponseSha256=response_sha256,
        targetIdentityDigest=web_target_fingerprint_digest(
            origin=adapter.origin,
            product=target_product,
            version=provisioned.target_version,
            fingerprint_endpoint=fingerprint_endpoint,
            response_sha256=response_sha256,
            adapter_implementation_digest=adapter.implementation_digest,
            recipe_digest=adapter.recipe_digest,
        ),
        authorizationIds=(ordered_authorizations[0], ordered_authorizations[1]),
        identityMaterialRef=_ACCOUNT_NAME_REF,
        proofMaterialRef=_ACCOUNT_PROOF_REF,
        issuedAt=now,
        expiresAt=now + timedelta(minutes=20),
    )
    signed = sign_provisioned_web_account_receipt(
        receipt,
        key_id=issuer_key.key_id,
        private_key=issuer_private_key,
    )
    return receipt, signed


def _lifecycle_activation(
    *,
    adapter_ref: str,
    tools: ToolRegistry,
    publisher_key: CapabilityLifecycleTrustKey,
    reviewer_key: CapabilityLifecycleTrustKey,
    publisher_private_key: bytes,
    reviewer_private_key: bytes,
    now: datetime,
) -> tuple[CapabilityReleaseBundle, WebAuthenticatedAssessmentCapabilityActivation]:
    bundle = web_authenticated_assessment_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=publisher_private_key,
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=reviewer_private_key,
    )
    review = CapabilityReviewStatement(
        capability=bundle.capability.reference(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer_key.principal_id,
        checklistDigest=_digest(
            "pajin.web-assessment.lifecycle-review-checklist/v1",
            {"adapterRef": adapter_ref, "readOnly": True},
        ),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=now - timedelta(seconds=20),
        expiresAt=now + timedelta(minutes=20),
    )
    signed_review = reviewer.sign_review(review)
    release_statement = CapabilityReleaseStatement(
        capability=bundle.capability.reference(),
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher_key.principal_id,
        issuedAt=now - timedelta(seconds=10),
    )
    release = CapabilityReleaseBundle(
        release=publisher.sign_release(release_statement),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(release,),
        clock=_now_utc,
    )
    activation = activate_web_authenticated_assessment_capability(
        bundle=bundle,
        lifecycle=lifecycle,
        release=release.release.statement.reference(),
    )
    return release, activation


def _web_account_material(
    provisioned: ProvisionedLocalWebAssessmentAccount,
    *,
    authorization_id: str,
    account_receipt_digest: str,
) -> WebProvisionedAccountMaterial:
    return WebProvisionedAccountMaterial(
        accountReceiptDigest=account_receipt_digest,
        planDigest=provisioned.plan_digest,
        authorizationId=authorization_id,
        origin=provisioned.origin,
        targetVersion=provisioned.target_version,
        provisionedAt=provisioned.provisioned_at,
        requestEvidence=provisioned.request_evidence,
    )


def _action_intent(
    *,
    role: Literal["source", "validation"],
    campaign: CampaignManifest,
    campaign_digest: str,
    activation: WebAuthenticatedAssessmentCapabilityActivation,
    grant: CapabilityGrant,
    adapter: WebAssessmentAdapterManifest,
    account_receipt: ProvisionedWebAccountReceipt,
    snapshot: GraphSnapshotRef,
    run_id: str,
    approval_key: WebAssessmentVerificationKey,
    approval_private_key: bytes,
    now: datetime,
) -> _ActionIntent:
    request = ToolRequest(
        request_id=f"web_governed_{role}_{stdlib_secrets.token_hex(8)}",
        agent_id=grant.subject,
        tool_id=WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID,
        target=adapter.origin,
        method="POST",
        arguments=WebAuthenticatedAssessmentParameters(
            adapter=adapter.reference(),
            accountReceipt=account_receipt.reference(),
        ).model_dump(mode="json", by_alias=True),
    )
    prepared = activation.prepare_action(
        release=activation.activation_set.binding.release,
        request=request,
        parameters=request.arguments,
    )
    decision = GraphDecision(
        campaignId=campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=_digest(
            "pajin.web-assessment.governed-source-intent/v1",
            {
                "role": role,
                "requestId": prepared.request.request_id,
                "requestDigest": prepared.request_digest,
                "targetIdentityDigest": account_receipt.target_identity_digest,
            },
        ),
        snapshot=snapshot,
        actorId=f"pajin.web.{role}.planner",
        actorDigest=_digest(
            "pajin.web-assessment.governed-planner/v1",
            {"role": role, "compilerDigest": _COMPILER_DIGEST},
        ),
        createdAt=now,
    )
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=run_id,
        profileId=_PROFILE_ID,
        profileVersion=_PROFILE_VERSION,
        profileDigest=_PROFILE_DIGEST,
        compilerId=_COMPILER_ID,
        compilerVersion=_COMPILER_VERSION,
        compilerDigest=_COMPILER_DIGEST,
        sourceCampaignDigest=campaign_digest,
        allowedCapabilities=(prepared.capability,),
        allowedTargetDigests=(account_receipt.target_identity_digest,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(
            toolCallLimit=1,
            requestUnitLimit=WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
            costLimitMicrousd=0,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=campaign.spec.authorization.approved_at,
        notBefore=now,
        expiresAt=now + timedelta(minutes=10),
    )
    reservation = ActionBudgetReservation(
        requestUnits=WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
        costMicrousd=0,
    )
    proposal = ActionProposal(
        campaignId=campaign.metadata.name,
        runId=run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=snapshot,
        proposerId=f"pajin.web.{role}.planner",
        proposerDigest=decision.actor_digest,
        capability=prepared.capability,
        targetDigest=account_receipt.target_identity_digest,
        requestId=prepared.request.request_id,
        requestDigest=prepared.request_digest,
        normalizedParametersDigest=prepared.normalized_parameters_digest,
        riskTier=ToolRiskTier.T2,
        reservation=reservation,
        createdAt=now,
    )
    approval = ActionApprovalEnvelope(
        issuer=web_action_approval_issuer_binding(approval_key, role=role),
        requestedBy=f"principal.web.{role}.planner",
        approvedBy=approval_key.principal_id,
        campaignId=campaign.metadata.name,
        campaignDigest=campaign_digest,
        runId=run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=decision.decision_payload_digest,
        activationSetDigest=activation.activation_set.activation_set_digest,
        release=ActionApprovalReleaseRef(
            releaseId=prepared.release.release_id,
            releaseDigest=prepared.release.release_digest,
            capabilityId=prepared.capability.capability_id,
            capabilityVersion=prepared.capability.capability_version,
            capabilityDigest=prepared.capability.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        cleanupRequired=False,
        reservation=reservation,
        approvedAt=now,
        notBefore=now,
        expiresAt=now + timedelta(minutes=4),
    )
    signed = sign_web_action_approval(
        approval,
        role=role,
        key=approval_key,
        private_key=approval_private_key,
    )
    worker_secret_ref = f"secret:web-governed-{role}-executor-signing-key"
    observer_secret_ref = f"secret:web-governed-{role}-observer-signing-key"
    return _ActionIntent(
        role=role,
        prepared=prepared,
        grant=grant,
        envelope=envelope,
        decision=decision,
        proposal=proposal,
        approval=approval,
        signed_approval=signed,
        run_id=run_id,
        worker_execution_id=f"web-{role}-executor-{stdlib_secrets.token_hex(8)}",
        observer_execution_id=f"web-{role}-observer-{stdlib_secrets.token_hex(8)}",
        worker_secret_ref=worker_secret_ref,
        observer_secret_ref=observer_secret_ref,
    )


def _gateway_outcome(
    gateway: HostLoopbackWebAssessmentGateway,
    completion: WebGatewayCompletedActionAuthority,
) -> tuple[GatewayOutcome, WebAuthenticatedAssessmentWorkerOutput]:
    receipt = completion.receipt
    snapshot = load_verified_run_artifacts(
        gateway.store.path,
        requests={receipt.gateway_evidence_reference: 8_000_000},
        expected_run_id=receipt.gateway_audit_run_id,
    )
    evidence_bytes = snapshot.artifact_bytes(receipt.gateway_evidence_reference)
    if sha256(evidence_bytes).hexdigest() != receipt.gateway_evidence_digest:
        raise GovernedWebCampaignError("Gateway execution Evidence digest differs")
    raw = parse_strict_json_bytes(
        evidence_bytes,
        label="governed Web Gateway Evidence",
        max_bytes=8_000_000,
        max_depth=64,
        max_nodes=100_000,
    )
    if not isinstance(raw, dict) or type(raw.get("networkLogTrusted")) is not bool:
        raise GovernedWebCampaignError("Gateway execution Evidence is incomplete")
    try:
        decision = PolicyDecision.model_validate(raw["policyDecision"])
        result = ToolResult.model_validate(raw["result"])
        worker_result = WorkerResult.model_validate(raw["workerResult"])
        output = WebAuthenticatedAssessmentWorkerOutput.model_validate(result.data["workerOutput"])
    except (KeyError, TypeError, ValueError) as exc:
        raise GovernedWebCampaignError(
            "Gateway execution Evidence does not contain the verified Worker projection"
        ) from exc
    if result.evidence:
        raise GovernedWebCampaignError(
            "Gateway persisted Tool projection unexpectedly contains evidence references"
        )
    result = result.model_copy(
        update={"evidence": [receipt.gateway_evidence_reference]},
        deep=True,
    )
    outcome = GatewayOutcome(
        decision=decision,
        result=result,
        worker_result=worker_result,
        network_log_trusted=raw["networkLogTrusted"],
        result_identity_valid=True,
        executed=True,
    )
    if (
        canonical_web_worker_sha256(worker_result.model_dump(mode="json"))
        != receipt.worker_result_digest
        or canonical_web_worker_sha256(result.model_dump(mode="json")) != receipt.tool_result_digest
        or canonical_web_worker_sha256(decision.model_dump(mode="json"))
        != receipt.policy_decision_digest
        or canonical_web_worker_sha256(outcome.model_dump(mode="json"))
        != receipt.gateway_outcome_digest
    ):
        raise GovernedWebCampaignError("Gateway execution projections differ from its receipt")
    return outcome, output


async def _dispatch_intent(
    *,
    tool: WebAuthenticatedAssessmentTool,
    gateway: HostLoopbackWebAssessmentGateway,
    campaign: CampaignManifest,
    intent: _ActionIntent,
) -> tuple[
    ActionPermit,
    ActionApprovalConsumptionReceipt,
    WebAssessmentDispatchBinding,
    WebGatewayCompletedActionAuthority,
]:
    bindings: list[WebAssessmentDispatchBinding] = []
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set(f"{intent.role}-action-permit-dispatch-failure")

    async def execute(binding: WebAssessmentDispatchBinding) -> WebGatewayCompletedActionAuthority:
        _ACTIVE_CAMPAIGN_FAILURE_TYPE.set(f"{intent.role}-gateway-execution-failure")
        bindings.append(binding)
        return await gateway.execute_approved(
            campaign,
            intent.grant,
            intent.prepared.request,
            binding,
            used_calls=0,
        )

    try:
        dispatched = await tool.dispatch_approved_once(
            envelope=intent.envelope,
            proposal=intent.proposal,
            decision=intent.decision,
            approval=intent.approval,
            campaign=campaign,
            grant=intent.grant,
            request=intent.prepared.request,
            worker_execution_id=intent.worker_execution_id,
            target_observer_execution_id=intent.observer_execution_id,
            output_root_reference=_WORKER_OUTPUT_ROOT_REFERENCE,
            worker_signing_material_ref=intent.worker_secret_ref,
            target_observer_signing_material_ref=intent.observer_secret_ref,
            dispatch=execute,
        )
    except Exception as error:
        safe_code = {
            "Web dispatch Campaign or capability Grant binding differs": "grant-binding",
            "Web dispatch Campaign or capability Grant is not active": "grant-lifecycle",
            "Web dispatch approval or Permit Campaign binding differs": "campaign-binding",
            "Web dispatch Run lineage differs from deployment": "run-lineage",
            "Web dispatch Capability or request binding differs": "request-binding",
            "Web dispatch Target, adapter, or account binding differs": "target-binding",
            "Web dispatch ActionPermit is not active": "permit-lifecycle",
            "Web dispatch registry authority identity or implementation changed": (
                "registry-runtime"
            ),
            "Web dispatch production authority identity or implementation changed": (
                "authority-runtime"
            ),
            "Web dispatch SQLite Graph store identity or implementation changed": ("graph-runtime"),
            "Web dispatch Capability Ledger or durable grant authority changed": ("grant-runtime"),
            "Web dispatch inputs differ from durable approved authority": ("durable-approval"),
            "Web dispatch authority could not reload durable approved authority": (
                "approval-reload"
            ),
        }.get(str(error))
        if safe_code is None:
            safe_code = {
                "ActionApprovalError": "action-approval",
                "GovernedWebAssessmentModelError": "governed-binding",
                "ValueError": "value",
                "TypeError": "type",
            }.get(type(error).__name__)
        if safe_code is not None:
            _ACTIVE_CAMPAIGN_FAILURE_TYPE.set(f"{intent.role}-dispatch-{safe_code}-failure")
        raise
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set(f"{intent.role}-dispatch-result-failure")
    if not dispatched.dispatched or dispatched.result is None or len(bindings) != 1:
        raise GovernedWebCampaignError("fresh approved Web action was not dispatched exactly once")
    return (
        dispatched.authorization.action.permit,
        dispatched.authorization.receipt,
        bindings[0],
        dispatched.result,
    )


def _action_artifacts(
    *,
    intent: _ActionIntent,
    permit: ActionPermit,
    approval_receipt: ActionApprovalConsumptionReceipt,
    grant_receipt: WebAssessmentCapabilityGrantConsumptionReceipt,
    binding: WebAssessmentDispatchBinding,
    completion: WebGatewayCompletedActionAuthority,
    gateway: HostLoopbackWebAssessmentGateway,
    worker_output_root: Path,
    plan_name: str,
    authorization_id: str,
) -> GovernedWebActionArtifacts:
    outcome, worker_output = _gateway_outcome(gateway, completion)
    worker_evidence = completion.backend_completion.action_evidence
    run_path = worker_output_root / plan_name / worker_output.run_id
    verified = load_verified_local_web_assessment_source_integrity(
        run_path,
        expected_run_id=intent.run_id,
        expected_root_digest=worker_output.root_digest,
    )
    run_reference = local_web_assessment_run_reference(
        role=intent.role,
        verified_source=verified,
    )
    if (
        worker_output.run_id != intent.run_id
        or run_reference.authorization_id != authorization_id
        or worker_evidence.execution_attestation.statement.run_id != intent.run_id
    ):
        raise GovernedWebCampaignError("Worker Run differs from its approved action lineage")
    return GovernedWebActionArtifacts(
        role=intent.role,
        prepared=intent.prepared,
        grant=intent.grant,
        envelope=intent.envelope,
        decision=intent.decision,
        proposal=intent.proposal,
        approval=intent.approval,
        signed_approval=intent.signed_approval,
        permit=permit,
        approval_receipt=approval_receipt,
        grant_consumption_receipt=grant_receipt,
        dispatch_binding=worker_evidence.execution_attestation.statement.authority,
        gateway_completion=completion.receipt,
        gateway_completion_reference=completion.receipt_reference,
        gateway_completion_authority_digest=completion.authority_digest,
        gateway_final_root_digest=completion.final_root_digest,
        gateway_final_event_head_digest=completion.final_event_head,
        gateway_outcome=outcome,
        worker_output=worker_output,
        worker_evidence=worker_evidence,
        run_reference=run_reference,
        run_path=run_path,
    )


def _parent_action_evidence(
    *,
    authorization: LocalWebAssessmentAuthorization,
    action: GovernedWebActionArtifacts,
    run_plan: _GovernedWebCampaignRunPlan,
) -> dict[str, JsonValue]:
    paths = run_plan.evidence_plan().relative_paths()
    browser_role = "sourceBrowser" if action.role == "source" else "validationBrowser"
    gateway_role = "sourceGateway" if action.role == "source" else "validationGateway"
    browser_reference = {
        "path": paths[browser_role],
        "run": _public_model(action.run_reference),
    }
    gateway_reference = {
        "path": paths[gateway_role],
        "runId": action.gateway_completion.gateway_audit_run_id,
        "rootDigest": action.gateway_final_root_digest,
        "eventHeadDigest": action.gateway_final_event_head_digest,
        "completionReceiptReference": action.gateway_completion_reference,
        "completionAuthorityDigest": action.gateway_completion_authority_digest,
    }
    return {
        "localAuthorization": _public_model(authorization),
        "prepared": _public_model(action.prepared),
        "request": _public_model(action.prepared.request),
        "envelope": _public_model(action.envelope),
        "decision": _public_model(action.decision),
        "proposal": _public_model(action.proposal),
        "approval": _public_model(action.approval),
        "signedApproval": _public_model(action.signed_approval),
        "permit": _public_model(action.permit),
        "approvalConsumptionReceipt": _public_model(action.approval_receipt),
        "grantConsumptionReceipt": _public_model(action.grant_consumption_receipt),
        "workerAuthorityBinding": _public_model(action.dispatch_binding),
        "gatewayCompletionReceipt": _public_model(action.gateway_completion),
        "gatewayRunReference": cast(JsonValue, gateway_reference),
        "workerActionEvidence": _public_model(action.worker_evidence),
        "workerOutput": _public_model(action.worker_output),
        "browserRunReference": cast(JsonValue, browser_reference),
    }


def _historical_campaign_result(
    *,
    profile: ResolvedGovernedWebAdapterProfile,
    campaign_digest: str,
    deployment_trust_anchor_digest: str,
    activation: WebAuthenticatedAssessmentCapabilityActivation,
    source: GovernedWebActionArtifacts,
    validation: GovernedWebActionArtifacts,
    promotion: GovernedWebPromotion,
    final_graph_snapshot: GraphSnapshotRef,
    validation_authority: GovernedWebValidationAuthority,
    poc: RedactedGovernedWebPocManifest,
    exports: GovernedWebExportBundle,
) -> GovernedWebCampaignHistoricalResult:
    profile.public_metadata()
    source_execution = source.worker_evidence.execution_attestation
    source_target = source.worker_evidence.target_identity
    validation_execution = validation.worker_evidence.execution_attestation
    validation_target = validation.worker_evidence.target_identity
    return GovernedWebCampaignHistoricalResult(
        adapterRef=cast(Literal["juice-shop-local/v1"], profile.adapter_reference),
        origin=cast(Literal["http://127.0.0.1:3000"], profile.origin),
        campaignId=cast(Literal["juice-shop-governed-local"], profile.campaign_id),
        campaignDigest=campaign_digest,
        deploymentTrustAnchorDigest=deployment_trust_anchor_digest,
        activationSetId=activation.activation_set.activation_set_id,
        activationSetDigest=activation.activation_set.activation_set_digest,
        sourceRequestId=source.prepared.request.request_id,
        validationRequestId=validation.prepared.request.request_id,
        sourceApprovalId=source.approval.approval_id,
        validationApprovalId=validation.approval.approval_id,
        sourcePermitId=source.permit.permit_id,
        validationPermitId=validation.permit.permit_id,
        sourceRunId=source.run_reference.run_id,
        validationRunId=validation.run_reference.run_id,
        sourceRootDigest=source.run_reference.root_digest,
        validationRootDigest=validation.run_reference.root_digest,
        sourceGatewayRunId=source.gateway_completion.gateway_audit_run_id,
        validationGatewayRunId=validation.gateway_completion.gateway_audit_run_id,
        sourceGatewayRootDigest=source.gateway_final_root_digest,
        validationGatewayRootDigest=validation.gateway_final_root_digest,
        sourceObserverProcessId=source_target.statement.process_id,
        sourceExecutorProcessId=source_execution.statement.process_id,
        validationObserverProcessId=validation_target.statement.process_id,
        validationExecutorProcessId=validation_execution.statement.process_id,
        sourceObserverKeyId=source_target.key_id,
        sourceExecutorKeyId=source_execution.key_id,
        validationObserverKeyId=validation_target.key_id,
        validationExecutorKeyId=validation_execution.key_id,
        sourceObserverExecutionId=source_target.statement.execution_id,
        sourceExecutorExecutionId=source_execution.statement.execution_id,
        validationObserverExecutionId=validation_target.statement.execution_id,
        validationExecutorExecutionId=validation_execution.statement.execution_id,
        graphEventCount=final_graph_snapshot.revision,
        findingCount=len(promotion.findings),
        attackPathCount=len(promotion.attack_paths),
        validationProjectionRunId=validation_authority.run_id,
        validationProjectionRootDigest=validation_authority.final_root_digest,
        sarifReference="exports/findings.sarif",
        sarifDigest=exports.sarif.sarif_digest,
        reportReference=(
            "validation-runs/governed-web-validation/"
            f"{validation_authority.run_id}/validation/v1alpha1/report.md"
        ),
        pocManifestReference="poc-bundle/poc/manifest.json",
        pocManifestDigest=poc.manifest_digest,
        deliveryReadinessReference="exports/delivery-readiness.json",
    )


def _execution_evidence(
    *,
    profile: ResolvedGovernedWebAdapterProfile,
    campaign_digest: str,
    adapter: WebAssessmentAdapterManifest,
    account_receipt: ProvisionedWebAccountReceipt,
    worker_registry: WebWorkerTrustRegistry,
    source: GovernedWebActionArtifacts,
    validation: GovernedWebActionArtifacts,
) -> GovernedWebExecutionEvidence:
    profile.public_metadata()
    source_authority = source.worker_evidence.execution_attestation.statement.authority
    validation_authority = validation.worker_evidence.execution_attestation.statement.authority
    source_gateway = source.gateway_completion
    validation_gateway = validation.gateway_completion
    source_execution = source.worker_evidence.execution_attestation
    validation_execution = validation.worker_evidence.execution_attestation
    source_target = source.worker_evidence.target_identity
    validation_target = validation.worker_evidence.target_identity
    return GovernedWebExecutionEvidence(
        campaignId=profile.campaign_id,
        campaignManifestDigest=campaign_digest,
        sourceCapabilityGrantId=source.grant.grant_id,
        sourceCapabilityGrantDigest=capability_grant_digest(source.grant),
        sourceCapabilityGrantConsumptionReceiptId=(source.grant_consumption_receipt.receipt_id),
        sourceCapabilityGrantConsumptionReceiptDigest=(
            source.grant_consumption_receipt.receipt_digest
        ),
        validationCapabilityGrantId=validation.grant.grant_id,
        validationCapabilityGrantDigest=capability_grant_digest(validation.grant),
        validationCapabilityGrantConsumptionReceiptId=(
            validation.grant_consumption_receipt.receipt_id
        ),
        validationCapabilityGrantConsumptionReceiptDigest=(
            validation.grant_consumption_receipt.receipt_digest
        ),
        capabilityGrantAuthorityDigest=(source.grant_consumption_receipt.grant_authority_digest),
        capabilityId=source_authority.capability_id,
        capabilityVersion=source_authority.capability_version,
        capabilityDigest=source_authority.capability_digest,
        adapterRef=profile.adapter_reference,
        adapterDigest=adapter.adapter_digest,
        accountReceiptDigest=account_receipt.receipt_digest,
        workerTrustRegistryDigest=worker_registry.digest,
        executionVerifierDigest=governed_web_execution_verifier_digest(worker_registry),
        sourceActionPermitId=source.permit.permit_id,
        sourceActionPermitDigest=source.permit.permit_digest,
        validationActionPermitId=validation.permit.permit_id,
        validationActionPermitDigest=validation.permit.permit_digest,
        sourceApprovalId=source.approval.approval_id,
        sourceApprovalDigest=source.approval.approval_digest,
        validationApprovalId=validation.approval.approval_id,
        validationApprovalDigest=validation.approval.approval_digest,
        sourceApprovalReceiptId=source.approval_receipt.receipt_id,
        sourceApprovalReceiptDigest=source.approval_receipt.receipt_digest,
        validationApprovalReceiptId=validation.approval_receipt.receipt_id,
        validationApprovalReceiptDigest=validation.approval_receipt.receipt_digest,
        sourceGatewayRequestId=source_authority.request_id,
        sourceGatewayRequestDigest=source_authority.request_digest,
        validationGatewayRequestId=validation_authority.request_id,
        validationGatewayRequestDigest=validation_authority.request_digest,
        sourceGatewayAuditRunId=source_gateway.gateway_audit_run_id,
        validationGatewayAuditRunId=validation_gateway.gateway_audit_run_id,
        sourceGatewayAuditPreReceiptRootDigest=source_gateway.gateway_audit_root_digest,
        validationGatewayAuditPreReceiptRootDigest=(validation_gateway.gateway_audit_root_digest),
        sourceGatewayAuditPreReceiptEventHeadDigest=(source_gateway.gateway_event_head_digest),
        validationGatewayAuditPreReceiptEventHeadDigest=(
            validation_gateway.gateway_event_head_digest
        ),
        sourceGatewayAuditFinalRootDigest=source.gateway_final_root_digest,
        validationGatewayAuditFinalRootDigest=validation.gateway_final_root_digest,
        sourceGatewayAuditFinalEventHeadDigest=source.gateway_final_event_head_digest,
        validationGatewayAuditFinalEventHeadDigest=(validation.gateway_final_event_head_digest),
        sourceGatewayCompletionReceiptId=source_gateway.receipt_id,
        validationGatewayCompletionReceiptId=validation_gateway.receipt_id,
        sourceGatewayCompletionReceiptDigest=source_gateway.receipt_digest,
        validationGatewayCompletionReceiptDigest=validation_gateway.receipt_digest,
        sourceGatewayCompletionReceiptReference=source.gateway_completion_reference,
        validationGatewayCompletionReceiptReference=(validation.gateway_completion_reference),
        sourceGatewayCompletionAuthorityDigest=(source.gateway_completion_authority_digest),
        validationGatewayCompletionAuthorityDigest=(validation.gateway_completion_authority_digest),
        sourceGatewayLaunchId=source_gateway.gateway_launch_id,
        validationGatewayLaunchId=validation_gateway.gateway_launch_id,
        sourceGatewayEvidenceReference=source_gateway.gateway_evidence_reference,
        validationGatewayEvidenceReference=validation_gateway.gateway_evidence_reference,
        sourceGatewayEvidenceDigest=source_gateway.gateway_evidence_digest,
        validationGatewayEvidenceDigest=validation_gateway.gateway_evidence_digest,
        sourceGatewayRequestReservationReference=(
            source_gateway.gateway_request_reservation_reference
        ),
        validationGatewayRequestReservationReference=(
            validation_gateway.gateway_request_reservation_reference
        ),
        sourceGatewayRequestReservationDigest=(source_gateway.gateway_request_reservation_digest),
        validationGatewayRequestReservationDigest=(
            validation_gateway.gateway_request_reservation_digest
        ),
        sourceGatewayWorkerResultDigest=source_gateway.worker_result_digest,
        validationGatewayWorkerResultDigest=validation_gateway.worker_result_digest,
        sourceGatewayToolResultDigest=source_gateway.tool_result_digest,
        validationGatewayToolResultDigest=validation_gateway.tool_result_digest,
        sourceGatewayPolicyDecisionDigest=source_gateway.policy_decision_digest,
        validationGatewayPolicyDecisionDigest=validation_gateway.policy_decision_digest,
        sourceGatewayOutcomeDigest=source_gateway.gateway_outcome_digest,
        validationGatewayOutcomeDigest=validation_gateway.gateway_outcome_digest,
        targetOrigin=adapter.origin,
        targetIdentityDigest=account_receipt.target_identity_digest,
        sourceAuthorizationId=source.run_reference.authorization_id,
        validationAuthorizationId=validation.run_reference.authorization_id,
        sourceRunId=source.run_reference.run_id,
        sourceRootDigest=source.run_reference.root_digest,
        sourceResultDigest=source.run_reference.result_digest,
        validationRunId=validation.run_reference.run_id,
        validationRootDigest=validation.run_reference.root_digest,
        validationResultDigest=validation.run_reference.result_digest,
        sourceExecutorProcessId=source_execution.statement.process_id,
        validationExecutorProcessId=validation_execution.statement.process_id,
        sourceObserverProcessId=source_target.statement.process_id,
        validationObserverProcessId=validation_target.statement.process_id,
        sourceExecutorKeyId=source_execution.key_id,
        validationExecutorKeyId=validation_execution.key_id,
        sourceExecutorExecutionId=source_execution.statement.execution_id,
        validationExecutorExecutionId=validation_execution.statement.execution_id,
        sourceExecutionAttestationDigest=source_execution.digest,
        validationExecutionAttestationDigest=validation_execution.digest,
        sourceObserverKeyId=source_target.key_id,
        validationObserverKeyId=validation_target.key_id,
        sourceObserverExecutionId=source_target.statement.execution_id,
        validationObserverExecutionId=validation_target.statement.execution_id,
        sourceTargetAttestationDigest=source_target.digest,
        validationTargetAttestationDigest=validation_target.digest,
        sourceWorkerActionEvidenceDigest=source.worker_evidence.digest,
        validationWorkerActionEvidenceDigest=validation.worker_evidence.digest,
        sourceWorkerCompletionDigest=source_gateway.backend_completion_digest,
        validationWorkerCompletionDigest=validation_gateway.backend_completion_digest,
        sourceCompletedAt=source.run_reference.result.finished_at,
        validationCompletedAt=validation.run_reference.result.finished_at,
        sourceGatewayCompletedAt=source_gateway.completed_at,
        validationGatewayCompletedAt=validation_gateway.completed_at,
        completedAt=max(source_gateway.completed_at, validation_gateway.completed_at),
    )


def _validated_output_root(output_root: Path) -> Path:
    if type(output_root) is not type(Path()):
        raise TypeError("governed Web campaign output_root must be a Path")
    expanded = output_root.expanduser()
    if ".." in expanded.parts:
        raise GovernedWebCampaignError(
            "governed Web campaign output root cannot contain parent traversal"
        )
    requested = Path(os.path.abspath(os.fspath(expanded)))
    if requested.exists() or requested.is_symlink():
        raise FileExistsError("governed Web campaign output root already exists")
    cursor = requested.parent
    while not cursor.exists():
        if cursor.is_symlink():
            raise GovernedWebCampaignError(
                "governed Web output ancestry cannot contain a symbolic link"
            )
        if cursor.parent == cursor:
            raise GovernedWebCampaignError("governed Web output has no existing ancestor")
        cursor = cursor.parent
    while True:
        if cursor.is_symlink():
            raise GovernedWebCampaignError(
                "governed Web output ancestry cannot contain a symbolic link"
            )
        try:
            entries = {entry.name.casefold() for entry in cursor.iterdir()}
        except OSError as exc:
            raise GovernedWebCampaignError(
                "governed Web output ancestry cannot be inspected safely"
            ) from exc
        if (
            "events.jsonl" in entries
            or "run-integrity.jsonl" in entries
            or (cursor.name.startswith("run_") and "evidence" in entries)
        ):
            raise GovernedWebCampaignError(
                "governed Web output cannot be nested inside an existing Run"
            )
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    return requested


def _resolve_installed_profile(
    *,
    origin: str,
    adapter_ref: str | None,
) -> ResolvedGovernedWebAdapterProfile:
    if type(origin) is not str:
        raise GovernedWebCampaignError(
            "governed Web campaign origin must identify an exact installed profile"
        )
    selected_ref = GOVERNED_JUICE_SHOP_ADAPTER_REF if adapter_ref is None else adapter_ref
    if type(selected_ref) is not str:
        raise GovernedWebCampaignError(
            "governed Web campaign adapter reference must identify an exact installed profile"
        )
    try:
        return production_governed_web_adapter_profile_registry().resolve(
            adapter_reference=selected_ref,
            origin=origin,
        )
    except GovernedWebAdapterProfileError as exc:
        raise GovernedWebCampaignError(
            "governed Web campaign adapter is not installed for the exact origin"
        ) from exc


def _require_profile_execution_inputs(
    profile: ResolvedGovernedWebAdapterProfile,
    *,
    origin: str,
    adapter_ref: str,
    plan: WebAssessmentPlan,
    adapter: WebAssessmentAdapterManifest,
) -> None:
    profile.public_metadata()
    if (
        profile.origin != origin
        or profile.adapter_reference != adapter_ref
        or profile.plan != plan
        or profile.plan_digest != plan.plan_digest
        or adapter.adapter_id != profile.adapter_id
        or adapter.adapter_version != profile.adapter_version
        or adapter.origin != profile.origin
        or adapter.implementation_id != profile.implementation_id
        or adapter.implementation_digest != profile.implementation_digest
        or adapter.recipe_digest != profile.plan_digest
    ):
        raise GovernedWebCampaignError(
            "governed Web execution inputs differ from the resolved deployment profile"
        )


def _validate_public_inputs(
    *,
    origin: str,
    output_root: Path,
    authorized_local_lab: bool,
    adapter_ref: str | None,
    headless: bool,
) -> tuple[Path, ResolvedGovernedWebAdapterProfile]:
    if type(authorized_local_lab) is not bool or authorized_local_lab is not True:
        raise GovernedWebCampaignError("an explicit authorized-local-lab confirmation is required")
    profile = _resolve_installed_profile(origin=origin, adapter_ref=adapter_ref)
    if type(headless) is not bool:
        raise TypeError("governed Web campaign headless must be a literal boolean")
    return _validated_output_root(output_root), profile


async def run_governed_local_web_campaign(
    *,
    origin: str,
    output_root: Path,
    authorized_local_lab: bool,
    adapter_ref: str | None = None,
    headless: bool = True,
) -> GovernedWebCampaignProcessReceipt:
    """Run the fixed, fully governed Juice Shop local vertical slice once.

    No caller-provided clock, signing key, credential, route, payload, Worker,
    store, or delivery destination is accepted.  The disposable account remains
    in the explicitly approved local lab; its credentials and every private key
    remain only in process memory and one-use Secret Broker leases.
    """

    resolved_output, profile = _validate_public_inputs(
        origin=origin,
        output_root=output_root,
        authorized_local_lab=authorized_local_lab,
        adapter_ref=adapter_ref,
        headless=headless,
    )
    from pajin.web_assessment.governed_process import (
        _run_governed_local_web_campaign_process,
    )

    return await _run_governed_local_web_campaign_process(
        origin=profile.origin,
        output_root=resolved_output,
        authorized_local_lab=True,
        selected_adapter_ref=cast(
            Literal["juice-shop-local/v1"],
            profile.adapter_reference,
        ),
        headless=headless,
    )


async def _run_governed_local_web_campaign_in_pinned_workspace(
    *,
    origin: str,
    selected_adapter_ref: Literal["juice-shop-local/v1"],
    headless: bool,
) -> GovernedWebCampaignArtifacts:
    """Run below the coordinator process's already pinned current directory."""

    if active_pinned_workspace_identity() is None:
        raise GovernedWebCampaignError(
            "governed Web internal execution requires an active pinned workspace"
        )
    profile = _resolve_installed_profile(
        origin=origin,
        adapter_ref=selected_adapter_ref,
    )
    if type(headless) is not bool:
        raise TypeError("governed Web campaign headless must be a literal boolean")
    if _ACTIVE_CAMPAIGN_PROGRESS_SINK.get() is None:
        raise GovernedWebCampaignError(
            "governed Web internal execution requires an active supervised progress sink"
        )

    return await _run_governed_local_web_campaign_in_workspace(
        origin=cast(Literal["http://127.0.0.1:3000"], profile.origin),
        output_root=Path("."),
        selected_adapter_ref=cast(
            Literal["juice-shop-local/v1"],
            profile.adapter_reference,
        ),
        headless=headless,
    )


async def _run_governed_local_web_campaign_in_workspace(
    *,
    origin: Literal["http://127.0.0.1:3000"],
    output_root: Path,
    selected_adapter_ref: Literal["juice-shop-local/v1"],
    headless: bool,
) -> GovernedWebCampaignArtifacts:
    started_at = _now_utc()
    profile = _resolve_installed_profile(
        origin=origin,
        adapter_ref=selected_adapter_ref,
    )
    plan = profile.plan
    trust = _prepare_governed_web_ephemeral_trust(
        profile=profile,
        now=started_at,
    )
    run_plan = _GovernedWebCampaignRunPlan.create()
    parent_writer = begin_governed_web_campaign_parent(
        output_root,
        planned_runs=run_plan.evidence_plan(),
        trust_material=trust.public_trust_material,
        started_at=started_at,
        signer_not_after=started_at + timedelta(hours=1),
    )
    database_cleanup = _GovernedWebDatabaseAuthorityCleanup()
    primary_error: BaseException | None = None
    failure_type_token = _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("governed-stage-failure")
    try:
        _emit_governed_web_campaign_sealed_progress(
            parent_writer,
            previous_parent_root_digest=None,
            stage="initial",
            status="prepared",
            terminal=False,
        )
        return await _execute_governed_local_web_campaign(
            origin=origin,
            resolved_output=output_root,
            selected_adapter_ref=selected_adapter_ref,
            headless=headless,
            run_plan=run_plan,
            plan=plan,
            trust=trust,
            parent_writer=parent_writer,
            database_cleanup=database_cleanup,
            profile=profile,
        )
    except BaseException as error:
        primary_error = error
        try:
            previous_root = parent_writer.current_root_digest
            incomplete = parent_writer.fail(_ACTIVE_CAMPAIGN_FAILURE_TYPE.get(), _now_utc())
            _emit_governed_web_campaign_sealed_progress(
                parent_writer,
                previous_parent_root_digest=previous_root,
                stage=incomplete.failure_stage,
                status="failed",
                terminal=True,
            )
        except BaseException as journal_error:
            error.add_note(
                "governed WEB parent failure journal could not append: "
                f"{type(journal_error).__name__}"
            )
        raise
    finally:
        try:
            database_cleanup.close()
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            primary_error.add_note(
                f"governed WEB database authority cleanup failed: {type(cleanup_error).__name__}"
            )
        finally:
            _ACTIVE_CAMPAIGN_FAILURE_TYPE.reset(failure_type_token)


async def _execute_governed_local_web_campaign(
    *,
    origin: str,
    resolved_output: Path,
    selected_adapter_ref: Literal["juice-shop-local/v1"],
    headless: bool,
    run_plan: _GovernedWebCampaignRunPlan,
    plan: WebAssessmentPlan,
    trust: _GovernedWebEphemeralTrust,
    parent_writer: GovernedWebCampaignParentWriter,
    database_cleanup: _GovernedWebDatabaseAuthorityCleanup,
    profile: ResolvedGovernedWebAdapterProfile,
) -> GovernedWebCampaignArtifacts:
    _require_profile_execution_inputs(
        profile,
        origin=origin,
        adapter_ref=selected_adapter_ref,
        plan=plan,
        adapter=trust.adapter,
    )
    now = _now_utc()
    account_private = trust.account_private_key
    source_approval_private = trust.source_approval_private_key
    validation_approval_private = trust.validation_approval_private_key
    lifecycle_publisher_private = trust.lifecycle_publisher_private_key
    lifecycle_reviewer_private = trust.lifecycle_reviewer_private_key
    worker_private = trust.worker_private_keys
    adapter_key = trust.adapter_key
    account_key = trust.account_key
    source_approval_key = trust.source_approval_key
    validation_approval_key = trust.validation_approval_key
    lifecycle_publisher_key = trust.lifecycle_publisher_key
    lifecycle_reviewer_key = trust.lifecycle_reviewer_key
    adapter = trust.adapter
    signed_adapter = trust.signed_adapter
    adapter_registry = WebAssessmentAdapterRegistry(
        keys=(adapter_key,),
        adapters=(signed_adapter,),
    )
    installed_adapter = adapter_registry.resolve(adapter.reference())
    if installed_adapter != adapter:
        raise GovernedWebCampaignError("installed Web adapter changed during resolution")

    source_authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=now - timedelta(seconds=2),
    )
    validation_authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=now - timedelta(seconds=1),
    )
    if source_authorization.authorization_id == validation_authorization.authorization_id:
        raise GovernedWebCampaignError("source and validation authorizations must be distinct")
    _begin_campaign_stage(
        parent_writer,
        "provisioning",
        {
            "accountProvisioningState": "may-have-executed",
            "sourceAuthorizationId": source_authorization.authorization_id,
            "validationAuthorizationId": validation_authorization.authorization_id,
            "targetOrigin": origin,
            "adapterDigest": adapter.adapter_digest,
        },
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-account-failure")
    provisioned = await provision_local_web_assessment_account(
        plan=plan,
        authorization=source_authorization,
    )
    account_receipt, signed_account_receipt = _signed_account(
        adapter=adapter,
        target_product=profile.target_product,
        provisioned=provisioned,
        authorization_ids=(
            source_authorization.authorization_id,
            validation_authorization.authorization_id,
        ),
        fingerprint_endpoint=plan.fingerprint_endpoint,
        issuer_key=account_key,
        issuer_private_key=account_private,
        now=_now_utc(),
    )
    account_registry = ProvisionedWebAccountReceiptRegistry(
        keys=(account_key,),
        receipts=(signed_account_receipt,),
    )
    if account_registry.resolve(account_receipt.reference()) != account_receipt:
        raise GovernedWebCampaignError("signed provisioned account receipt changed")

    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-database-failure")
    authority_root = resolved_output / "authority"
    worker_output_root = resolved_output / "worker-runs"
    graph_path = authority_root / "governed-web.sqlite3"
    grant_path = authority_root / "capability-grant-consumptions.sqlite3"
    database_journal = _GovernedWebDatabaseCheckpointJournal(parent_writer)
    if active_pinned_workspace_identity() is not None:
        graph_fresh = parent_writer.issue_database_fresh_authority(
            graph_path,
            store_kind="governed-web-graph",
        )
        graph_store, graph_database_authority = SQLiteGraphStore.create_governed_in_memory(
            graph_path,
            campaign_id=profile.campaign_id,
            fresh_authority=graph_fresh,
            checkpoint_observer=database_journal.graph_checkpoint,
        )
        database_cleanup.register(graph_database_authority.close)

        grant_fresh = parent_writer.issue_database_fresh_authority(
            grant_path,
            store_kind="governed-web-grant",
        )
        (
            grant_store,
            grant_database_authority,
        ) = WebAssessmentCapabilityGrantConsumptionStore.create_governed_in_memory(
            grant_path,
            campaign_id=profile.campaign_id,
            fresh_authority=grant_fresh,
            checkpoint_observer=database_journal.grant_checkpoint,
        )
        database_cleanup.register(grant_database_authority.close)
    else:
        authority_root.mkdir(mode=0o700)
        graph_store = SQLiteGraphStore(
            graph_path,
            campaign_id=profile.campaign_id,
        )
        grant_store = WebAssessmentCapabilityGrantConsumptionStore(
            grant_path,
            campaign_id=profile.campaign_id,
        )
        graph_database_authority = None
        grant_database_authority = None

    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-grant-authority-failure")
    campaign = _campaign(profile, now=now)
    campaign_digest = campaign_manifest_digest(campaign)
    ledger = CapabilityLedger(max_depth=1)
    root_grant = ledger.issue_root(
        campaign,
        subject="agent:web-assessment-root",
        tools={WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
        targets={origin},
    )
    source_grant = ledger.delegate(
        root_grant.grant_id,
        subject="agent:web-assessment-source",
        tools={WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
        targets={origin},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=now + timedelta(minutes=10),
    )
    validation_grant = ledger.delegate(
        root_grant.grant_id,
        subject="agent:web-assessment-validation",
        tools={WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
        targets={origin},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=now + timedelta(minutes=10),
    )
    dispatch_authority = WebAssessmentDispatchAuthority.create(
        graph_store=graph_store,
        capability_ledger=ledger,
        grant_consumption_store=grant_store,
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    dispatch_registry = WebAssessmentDispatchBindingRegistry(
        authority=dispatch_authority,
    )

    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-worker-backend-failure")
    worker_registry = trust.worker_registry
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=worker_output_root,
        trust_registry=worker_registry,
    )
    source_account = _web_account_material(
        provisioned,
        authorization_id=source_authorization.authorization_id,
        account_receipt_digest=account_receipt.receipt_digest,
    )
    validation_account = _web_account_material(
        provisioned,
        authorization_id=validation_authorization.authorization_id,
        account_receipt_digest=account_receipt.receipt_digest,
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-worker-context-failure")
    context = HostLoopbackWebDeploymentContext(
        accountReceiptDigest=account_receipt.receipt_digest,
        adapter=adapter,
        plan=plan,
        sourceAuthorization=source_authorization,
        validationAuthorization=validation_authorization,
        sourceAccount=source_account,
        validationAccount=validation_account,
    )
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference=_WORKER_OUTPUT_ROOT_REFERENCE,
        contexts=(context,),
        implementation_id=adapter.implementation_id,
        implementation_digest=adapter.implementation_digest,
        headless=headless,
    )
    output_verifier = HostLoopbackWebAssessmentOutputVerifier(
        output_root=worker_output_root,
        output_root_reference=_WORKER_OUTPUT_ROOT_REFERENCE,
        trust_registry=worker_registry,
        contexts=(context,),
    )
    tool = WebAuthenticatedAssessmentTool(
        adapters=adapter_registry,
        account_receipts=account_registry,
        dispatch_bindings=dispatch_registry,
        job_compiler=compiler,
        output_verifier=output_verifier,
    )
    tools = ToolRegistry()
    tools.register(tool)
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-capability-lifecycle-failure")
    release, activation = _lifecycle_activation(
        adapter_ref=profile.adapter_reference,
        tools=tools,
        publisher_key=lifecycle_publisher_key,
        reviewer_key=lifecycle_reviewer_key,
        publisher_private_key=lifecycle_publisher_private,
        reviewer_private_key=lifecycle_reviewer_private,
        now=now,
    )

    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-graph-checkpoint-failure")
    graph_projection = GraphProjectionCoordinator(
        event_log=graph_store.event_log,
        projection_store=graph_store.projection_store,
    )
    graph_projection.refresh()
    graph_snapshot_authority = GraphSnapshotAuthority(
        creator_id="pajin.web.governed.snapshot-authority",
        creator_digest=_digest(
            "pajin.web-assessment.snapshot-authority/v1",
            {"campaignId": profile.campaign_id},
        ),
        projection_store=graph_store.projection_store,
        snapshot_store=graph_store.snapshot_store,
    )
    initial_graph_snapshot = graph_snapshot_ref(
        graph_snapshot_authority.capture(GraphSnapshotReason.CHECKPOINT)
    )
    source_run_id = run_plan.source_run_id
    validation_run_id = run_plan.validation_run_id
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("source-intent-failure")
    source_intent = _action_intent(
        role="source",
        campaign=campaign,
        campaign_digest=campaign_digest,
        activation=activation,
        grant=source_grant,
        adapter=adapter,
        account_receipt=account_receipt,
        snapshot=initial_graph_snapshot,
        run_id=source_run_id,
        approval_key=source_approval_key,
        approval_private_key=source_approval_private,
        now=_now_utc(),
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("validation-intent-failure")
    validation_intent = _action_intent(
        role="validation",
        campaign=campaign,
        campaign_digest=campaign_digest,
        activation=activation,
        grant=validation_grant,
        adapter=adapter,
        account_receipt=account_receipt,
        snapshot=initial_graph_snapshot,
        run_id=validation_run_id,
        approval_key=validation_approval_key,
        approval_private_key=validation_approval_private,
        now=_now_utc(),
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("action-approval-authority-failure")
    approval_authority = WebActionApprovalAuthoritySet(
        keys=(source_approval_key, validation_approval_key),
        approvals=(source_intent.signed_approval, validation_intent.signed_approval),
    )
    approval_policies = ActionApprovalCapabilityPolicyRegistry(
        (
            ActionApprovalCapabilityPolicy(
                capability=source_intent.prepared.capability,
                sideEffectClass="read-only",
                approvalRequired=True,
                cleanupRequired=False,
            ),
        )
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("action-permit-authority-failure")
    permit_authority = GraphApprovedActionPermitAuthority(
        campaign_id=profile.campaign_id,
        compiler_id=_COMPILER_ID,
        compiler_version=_COMPILER_VERSION,
        compiler_digest=_COMPILER_DIGEST,
        capabilities=activation.action_registry(),
        policies=approval_policies,
        permit_store=graph_store.permit_store,
        input_authority=approval_authority,
        permit_ttl=timedelta(seconds=30),
    )
    dispatch_registry.install_dispatcher(GraphApprovedActionPermitDispatcher(permit_authority))

    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("secret-broker-setup-failure")
    secret_broker = SecretBroker()
    secret_broker.register(_ACCOUNT_NAME_REF, provisioned.credentials.username)
    secret_broker.register(_ACCOUNT_PROOF_REF, provisioned.credentials.password)
    worker_role_by_leg = {
        "source": (WebWorkerRole.SOURCE_EXECUTOR, WebWorkerRole.SOURCE_TARGET_OBSERVER),
        "validation": (
            WebWorkerRole.VALIDATION_EXECUTOR,
            WebWorkerRole.VALIDATION_TARGET_OBSERVER,
        ),
    }
    for intent in (source_intent, validation_intent):
        executor_role, observer_role = worker_role_by_leg[intent.role]
        secret_broker.register(
            intent.worker_secret_ref,
            web_worker_private_key_base64url(worker_private[executor_role]),
        )
        secret_broker.register(
            intent.observer_secret_ref,
            web_worker_private_key_base64url(worker_private[observer_role]),
        )
    policy = PolicyEngine()
    rate_limits = RequestRateLimitLedger()
    gateway_root = resolved_output / "gateway-runs"
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("provisioning-completion-failure")
    _complete_campaign_stage(
        parent_writer,
        "provisioning",
        {
            "accountProvisioningState": "confirmed-retained",
            "accountReceiptId": account_receipt.receipt_id,
            "accountReceiptDigest": account_receipt.receipt_digest,
            "targetIdentityDigest": account_receipt.target_identity_digest,
            "targetFingerprintResponseSha256": (account_receipt.target_fingerprint_response_sha256),
            "initialGraphSnapshotId": initial_graph_snapshot.snapshot_id,
            "initialGraphSnapshotDigest": initial_graph_snapshot.snapshot_digest,
            "graphDatabaseCheckpointOrdinal": (
                graph_database_authority.latest_checkpoint().ordinal
                if graph_database_authority is not None
                else None
            ),
            "grantDatabaseCheckpointOrdinal": (
                grant_database_authority.latest_checkpoint().ordinal
                if grant_database_authority is not None
                else None
            ),
        },
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("source-gateway-start-failure")
    _begin_campaign_stage(
        parent_writer,
        "source-gateway",
        {
            "gatewayRunId": run_plan.source_gateway_run_id,
            "browserRunId": run_plan.source_run_id,
            "requestId": source_intent.prepared.request.request_id,
            "requestDigest": source_intent.prepared.request_digest,
            "capabilityGrantId": source_grant.grant_id,
            "capabilityGrantDigest": capability_grant_digest(source_grant),
            "approvalId": source_intent.approval.approval_id,
            "approvalDigest": source_intent.approval.approval_digest,
        },
    )
    database_journal.advance("source-gateway")
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("source-gateway-authority-failure")
    source_gateway = HostLoopbackWebAssessmentGateway.production(
        backend=backend,
        role="source",
        audit_output_root=gateway_root,
        policy=policy,
        tools=tools,
        secrets=secret_broker,
        rate_limits=rate_limits,
        audit_run_id=run_plan.source_gateway_run_id,
    )
    (
        source_permit,
        source_approval_receipt,
        source_binding,
        source_completion,
    ) = await _dispatch_intent(
        tool=tool,
        gateway=source_gateway,
        campaign=campaign,
        intent=source_intent,
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("source-grant-receipt-failure")
    source_grant_receipt = dispatch_registry.capability_grant_consumption_receipt(
        source_grant.grant_id
    )
    if source_grant_receipt is None:
        raise GovernedWebCampaignError("source capability Grant receipt is incomplete")
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("source-gateway-completion-failure")
    _complete_campaign_stage(
        parent_writer,
        "source-gateway",
        {
            "gatewayRunId": source_completion.receipt.gateway_audit_run_id,
            "gatewayRootDigest": source_completion.final_root_digest,
            "gatewayEventHeadDigest": source_completion.final_event_head,
            "gatewayCompletionReceiptId": source_completion.receipt.receipt_id,
            "gatewayCompletionReceiptDigest": source_completion.receipt.receipt_digest,
            "browserRunId": source_completion.receipt.authority.expected_run_id,
            "actionPermitId": source_permit.permit_id,
            "approvalReceiptId": source_approval_receipt.receipt_id,
            "grantConsumptionReceiptId": source_grant_receipt.receipt_id,
            "grantConsumptionReceiptDigest": source_grant_receipt.receipt_digest,
        },
    )

    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("validation-gateway-start-failure")
    _begin_campaign_stage(
        parent_writer,
        "validation-gateway",
        {
            "gatewayRunId": run_plan.validation_gateway_run_id,
            "browserRunId": run_plan.validation_run_id,
            "requestId": validation_intent.prepared.request.request_id,
            "requestDigest": validation_intent.prepared.request_digest,
            "capabilityGrantId": validation_grant.grant_id,
            "capabilityGrantDigest": capability_grant_digest(validation_grant),
            "approvalId": validation_intent.approval.approval_id,
            "approvalDigest": validation_intent.approval.approval_digest,
        },
    )
    database_journal.advance("validation-gateway")
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("validation-gateway-authority-failure")
    validation_gateway = HostLoopbackWebAssessmentGateway.production(
        backend=backend,
        role="validation",
        audit_output_root=gateway_root,
        policy=policy,
        tools=tools,
        secrets=secret_broker,
        rate_limits=rate_limits,
        audit_run_id=run_plan.validation_gateway_run_id,
    )
    (
        validation_permit,
        validation_approval_receipt,
        validation_binding,
        validation_completion,
    ) = await _dispatch_intent(
        tool=tool,
        gateway=validation_gateway,
        campaign=campaign,
        intent=validation_intent,
    )
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("validation-grant-receipt-failure")
    validation_grant_receipt = dispatch_registry.capability_grant_consumption_receipt(
        validation_grant.grant_id
    )
    if validation_grant_receipt is None:
        raise GovernedWebCampaignError("validation capability Grant receipt is incomplete")
    _ACTIVE_CAMPAIGN_FAILURE_TYPE.set("validation-gateway-completion-failure")
    _complete_campaign_stage(
        parent_writer,
        "validation-gateway",
        {
            "gatewayRunId": validation_completion.receipt.gateway_audit_run_id,
            "gatewayRootDigest": validation_completion.final_root_digest,
            "gatewayEventHeadDigest": validation_completion.final_event_head,
            "gatewayCompletionReceiptId": validation_completion.receipt.receipt_id,
            "gatewayCompletionReceiptDigest": validation_completion.receipt.receipt_digest,
            "browserRunId": validation_completion.receipt.authority.expected_run_id,
            "actionPermitId": validation_permit.permit_id,
            "approvalReceiptId": validation_approval_receipt.receipt_id,
            "grantConsumptionReceiptId": validation_grant_receipt.receipt_id,
            "grantConsumptionReceiptDigest": validation_grant_receipt.receipt_digest,
        },
    )

    source_artifacts = _action_artifacts(
        intent=source_intent,
        permit=source_permit,
        approval_receipt=source_approval_receipt,
        grant_receipt=source_grant_receipt,
        binding=source_binding,
        completion=source_completion,
        gateway=source_gateway,
        worker_output_root=worker_output_root,
        plan_name=plan.name,
        authorization_id=source_authorization.authorization_id,
    )
    validation_artifacts = _action_artifacts(
        intent=validation_intent,
        permit=validation_permit,
        approval_receipt=validation_approval_receipt,
        grant_receipt=validation_grant_receipt,
        binding=validation_binding,
        completion=validation_completion,
        gateway=validation_gateway,
        worker_output_root=worker_output_root,
        plan_name=plan.name,
        authorization_id=validation_authorization.authorization_id,
    )
    independent = verify_independent_web_worker_evidence(
        source_target=source_artifacts.worker_evidence.target_identity,
        source=source_artifacts.worker_evidence.execution_attestation,
        validation_target=validation_artifacts.worker_evidence.target_identity,
        validation=validation_artifacts.worker_evidence.execution_attestation,
        registry=worker_registry,
        verification_time=_now_utc(),
    )
    reconciliation = reconcile_local_web_assessment_runs(
        plan=plan,
        source=source_artifacts.run_reference,
        validation=validation_artifacts.run_reference,
        reconciled_at=_now_utc(),
    )
    execution_evidence = _execution_evidence(
        profile=profile,
        campaign_digest=campaign_digest,
        adapter=adapter,
        account_receipt=account_receipt,
        worker_registry=worker_registry,
        source=source_artifacts,
        validation=validation_artifacts,
    )
    _begin_campaign_stage(
        parent_writer,
        "graph-admission",
        {
            "sourceRunId": source_artifacts.run_reference.run_id,
            "sourceRootDigest": source_artifacts.run_reference.root_digest,
            "validationRunId": validation_artifacts.run_reference.run_id,
            "validationRootDigest": validation_artifacts.run_reference.root_digest,
            "executionEvidenceDigest": execution_evidence.evidence_digest,
            "validationProjectionRunId": run_plan.validation_projection_run_id,
        },
    )
    database_journal.advance("graph-admission")
    verifier = create_governed_web_execution_verifier_binding(
        worker_backend=backend,
        grant_consumption_store=grant_store,
        source_gateway_completion=source_completion,
        validation_gateway_completion=validation_completion,
    )
    promotion_authority = promote_governed_web_findings(
        reconciliation=reconciliation,
        execution_evidence=execution_evidence,
        verifier=verifier,
        source_run_path=source_artifacts.run_path,
        validation_run_path=validation_artifacts.run_path,
        promoted_at=_now_utc(),
    )
    graph_authority = create_governed_web_graph_authority(
        promotion=promotion_authority,
        graph_store=graph_store,
        grant_consumption_store=grant_store,
        graph_database_authority=graph_database_authority,
    )
    graph_admission_authority = admit_governed_web_graph(
        promotion=promotion_authority,
        graph_authority=graph_authority,
    )
    graph_projection.refresh()
    final_graph_snapshot = graph_snapshot_ref(
        graph_snapshot_authority.capture(GraphSnapshotReason.HANDOFF)
    )
    validation_store = RunStore.create(
        resolved_output / "validation-runs",
        "governed-web-validation",
        run_id=run_plan.validation_projection_run_id,
    )
    validation_authority = write_governed_web_validation_projection(
        validation_store,
        promotion_authority,
        graph_admission_authority,
        decided_at=_now_utc(),
    )
    if graph_database_authority is not None and grant_database_authority is not None:
        graph_enrollment_publication = graph_database_authority.enrollment_publication()
        grant_enrollment_publication = grant_database_authority.enrollment_publication()
        graph_publication = graph_authority.freeze_and_bind_database()
        grant_publication = grant_database_authority.freeze_and_publish()
        if (
            graph_publication.reference != "authority/governed-web.sqlite3"
            or graph_publication.sha256
            != _bounded_file_sha256(
                graph_path,
                label="governed Web frozen Graph database",
            )
            or grant_publication.reference != "authority/capability-grant-consumptions.sqlite3"
            or grant_publication.sha256
            != _bounded_file_sha256(
                grant_path,
                label="governed Web frozen Grant database",
            )
        ):
            raise GovernedWebCampaignError(
                "governed WEB frozen database publication differs from its exact file"
            )
    elif graph_database_authority is not None or grant_database_authority is not None:
        raise GovernedWebCampaignError(
            "governed WEB database authorities must be created and frozen as a pair"
        )
    else:
        graph_publication = None
        grant_publication = None
        graph_enrollment_publication = None
        grant_enrollment_publication = None
    _complete_campaign_stage(
        parent_writer,
        "graph-admission",
        {
            "promotionDigest": promotion_authority.promotion_digest,
            "graphAdmissionDigest": graph_admission_authority.admission.admission_digest,
            "finalGraphSnapshotId": final_graph_snapshot.snapshot_id,
            "finalGraphSnapshotDigest": final_graph_snapshot.snapshot_digest,
            "validationProjectionRunId": validation_authority.run_id,
            "validationProjectionRootDigest": validation_authority.final_root_digest,
            "graphDatabaseSha256": (
                graph_publication.sha256 if graph_publication is not None else None
            ),
            "grantDatabaseSha256": (
                grant_publication.sha256 if grant_publication is not None else None
            ),
        },
    )

    _begin_campaign_stage(
        parent_writer,
        "poc-publication",
        {
            "outputReference": "poc-bundle/poc/manifest.json",
            "validationProjectionRunId": validation_authority.run_id,
            "validationProjectionRootDigest": validation_authority.final_root_digest,
        },
    )
    poc_bundle_path = resolved_output / "poc-bundle"
    poc = write_redacted_governed_web_poc(
        validation=validation_authority,
        output_directory=poc_bundle_path,
        origin=profile.origin,
        adapter_ref=profile.adapter_reference,
    )
    _complete_campaign_stage(
        parent_writer,
        "poc-publication",
        {
            "manifestReference": "poc-bundle/poc/manifest.json",
            "manifestDigest": poc.manifest_digest,
        },
    )

    _begin_campaign_stage(
        parent_writer,
        "export-publication",
        {
            "sarifReference": "exports/findings.sarif",
            "deliveryReadinessReference": "exports/delivery-readiness.json",
            "externalDeliveryPerformed": False,
        },
    )
    export_root = resolved_output / "exports"
    exports = write_verified_governed_web_exports(
        validation=validation_authority,
        output_directory=export_root,
        prepared_at=_now_utc(),
    )
    _complete_campaign_stage(
        parent_writer,
        "export-publication",
        {
            "sarifDigest": exports.sarif.sarif_digest,
            "deliveryManifestDigest": exports.delivery_manifest.manifest_digest,
            "externalDeliveryPerformed": False,
        },
    )
    report_path = validation_store.path / "validation/v1alpha1/report.md"
    poc_manifest_path = poc_bundle_path / "poc/manifest.json"
    if (
        not report_path.is_file()
        or report_path.is_symlink()
        or not poc_manifest_path.is_file()
        or poc_manifest_path.is_symlink()
    ):
        raise GovernedWebCampaignError(
            "governed Web report or redacted PoC manifest is not exactly retained"
        )

    historical_result = _historical_campaign_result(
        profile=profile,
        campaign_digest=campaign_digest,
        deployment_trust_anchor_digest=parent_writer.deployment_trust_anchor_digest,
        activation=activation,
        source=source_artifacts,
        validation=validation_artifacts,
        promotion=promotion_authority.promotion,
        final_graph_snapshot=final_graph_snapshot,
        validation_authority=validation_authority,
        poc=poc,
        exports=exports,
    )
    if graph_enrollment_publication is None or grant_enrollment_publication is None:
        raise GovernedWebCampaignError(
            "completed governed WEB campaign requires pinned database enrollments"
        )
    completed_evidence = GovernedWebCompletedCampaignEvidence(
        campaignDigest=campaign_digest,
        trustBundle=parent_writer.plan.trust_bundle,
        campaign=_public_model(campaign),
        signedAdapter=_public_model(signed_adapter),
        signedAccountReceipt=_public_model(signed_account_receipt),
        lifecycle={
            "releaseBundle": _public_model(release),
            "activation": _public_model(activation.activation_set),
        },
        grants={
            "root": _public_model(root_grant),
            "source": _public_model(source_grant),
            "validation": _public_model(validation_grant),
        },
        sourceAction=_parent_action_evidence(
            authorization=source_authorization,
            action=source_artifacts,
            run_plan=run_plan,
        ),
        validationAction=_parent_action_evidence(
            authorization=validation_authorization,
            action=validation_artifacts,
            run_plan=run_plan,
        ),
        independentWorkerEvidence=_public_model(independent),
        reconciliation=_public_model(reconciliation),
        executionVerification=_public_model(promotion_authority.promotion.execution_verification),
        executionEvidence=_public_model(execution_evidence),
        promotion=_public_model(promotion_authority.promotion),
        graphAdmission=_public_model(graph_admission_authority.admission),
        initialGraphSnapshot=initial_graph_snapshot,
        finalGraphSnapshot=final_graph_snapshot,
        graphDatabaseEnrollment=GovernedWebCampaignDatabaseEnrollment(
            storeKind="governed-web-graph",
            reference=graph_enrollment_publication.reference,
            sha256=graph_enrollment_publication.sha256,
            size=graph_enrollment_publication.size,
        ),
        grantDatabaseEnrollment=GovernedWebCampaignDatabaseEnrollment(
            storeKind="governed-web-grant",
            reference=grant_enrollment_publication.reference,
            sha256=grant_enrollment_publication.sha256,
            size=grant_enrollment_publication.size,
        ),
        graphDatabaseSha256=_bounded_file_sha256(
            graph_path,
            label="governed Web Graph database",
        ),
        grantDatabaseSha256=_bounded_file_sha256(
            grant_path,
            label="governed Web Grant consumption database",
        ),
        sourceGatewayEventHeadDigest=source_artifacts.gateway_final_event_head_digest,
        validationGatewayEventHeadDigest=(validation_artifacts.gateway_final_event_head_digest),
        validationRootDigest=validation_authority.final_root_digest,
        validationReportSha256=_bounded_file_sha256(
            report_path,
            label="governed Web validation report",
        ),
        pocManifestDigest=poc.manifest_digest,
        sarifDigest=exports.sarif.sarif_digest,
        deliveryManifestDigest=exports.delivery_manifest.manifest_digest,
    )
    _begin_campaign_stage(
        parent_writer,
        "parent-evidence",
        {
            "campaignDigest": campaign_digest,
            "evidenceDigest": completed_evidence.evidence_digest,
            "finalGraphSnapshotId": final_graph_snapshot.snapshot_id,
            "finalGraphSnapshotDigest": final_graph_snapshot.snapshot_digest,
            "deploymentTrustAnchorDigest": (parent_writer.deployment_trust_anchor_digest),
        },
    )
    previous_parent_root = parent_writer.current_root_digest
    parent_writer.complete(completed_evidence, historical_result, _now_utc())
    parent_integrity = verify_run_integrity(parent_writer.parent_run_path)
    if (
        not parent_integrity.valid
        or parent_integrity.root_digest != parent_writer.current_root_digest
    ):
        raise GovernedWebCampaignError("parent governed campaign Run failed integrity verification")
    reloaded_parent = load_verified_governed_web_completed_campaign_evidence(
        parent_writer.parent_run_path,
        expected_parent_run_id=parent_writer.parent_run_id,
        expected_parent_root_digest=parent_integrity.root_digest,
        expected_campaign_plan_digest=parent_writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(parent_writer.deployment_trust_anchor_digest),
    )
    if (
        reloaded_parent.evidence != completed_evidence
        or reloaded_parent.result != historical_result
        or reloaded_parent.parent_root_digest != parent_integrity.root_digest
    ):
        raise GovernedWebCampaignError(
            "reloaded governed campaign evidence differs from live completion"
        )
    _emit_governed_web_campaign_sealed_progress(
        parent_writer,
        previous_parent_root_digest=previous_parent_root,
        stage="parent-evidence",
        status="completed",
        terminal=True,
    )

    return GovernedWebCampaignArtifacts(
        adapter_ref=profile.adapter_reference,
        origin=profile.origin,
        deployment_trust_anchor_digest=parent_writer.deployment_trust_anchor_digest,
        campaign=campaign,
        campaign_digest=campaign_digest,
        signed_adapter=signed_adapter,
        signed_account_receipt=signed_account_receipt,
        release_bundle=release,
        activation=activation,
        worker_trust_registry=worker_registry,
        source=source_artifacts,
        validation=validation_artifacts,
        independent_worker_evidence=independent,
        reconciliation=reconciliation,
        execution_evidence=execution_evidence,
        promotion=promotion_authority.promotion,
        graph_admission=graph_admission_authority.admission,
        validation_authority=validation_authority,
        poc=poc,
        exports=exports,
        parent_run_path=parent_writer.parent_run_path,
        parent_root_digest=parent_integrity.root_digest,
        parent_integrity=parent_integrity,
        graph_path=graph_path,
        initial_graph_snapshot=initial_graph_snapshot,
        final_graph_snapshot=final_graph_snapshot,
        validation_run_path=validation_store.path,
        report_path=report_path,
        poc_bundle_path=poc_bundle_path,
        sarif_path=exports.sarif_path,
        delivery_readiness_path=exports.delivery_manifest_path,
    )
