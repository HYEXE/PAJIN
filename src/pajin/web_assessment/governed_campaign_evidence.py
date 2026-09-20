"""Restart-safe, public evidence journal for governed WEB-005 campaigns.

The objects returned by this module are historical evidence only.  They never
recreate the in-memory Gateway, Promotion, Graph, validation, PoC, export, or
delivery authorities that produced a completed campaign.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import stat
import threading
import unicodedata
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Final, Literal, Self, cast, final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.capabilities.activation import (
    PreparedCapabilityAction,
    capability_grant_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.lifecycle import (
    _RELEASE_SIGNATURE_DOMAIN,
    _REVIEW_SIGNATURE_DOMAIN,
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReviewDecision,
    _canonical_release,
    _canonical_review,
)
from pajin.capabilities.models import capability_definition_digest
from pajin.capabilities.web_authenticated_assessment import (
    WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID,
    WebAuthenticatedAssessmentCapabilityActivationSet,
    WebAuthenticatedAssessmentTool,
    _release_bundle_digest,
)
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolResult,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionPermit,
    ActionProposal,
    GraphDecision,
    GraphSnapshotReason,
    GraphSnapshotRef,
    MissionEnvelope,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import (
    _MAX_GRAPH_BYTES,
    _events_from_connection,
    _require_exact_node_index,
    _validate_schema,
    _verified_projections,
    _verified_snapshots,
)
from pajin.graph.sqlite_store import (
    _SCHEMA_DIGEST as _GRAPH_SCHEMA_DIGEST,
)
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.reporting.sarif import SarifExportProjection, load_verified_sarif_export
from pajin.runtime.pinned_sqlite import (
    PinnedSQLiteCheckpoint,
    VerifiedPinnedSQLiteDatabase,
    _issue_pinned_sqlite_fresh_authority,
    load_verified_pinned_sqlite_database,
)
from pajin.runtime.pinned_workspace import pinned_workspace_relative_path
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes
from pajin.runtime.secrets import SecretLease, SecretLeaseStatus
from pajin.runtime.store import (
    ArtifactProvenance,
    AuditEvent,
    RunIntegrityError,
    RunIntegritySeal,
    RunStore,
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    locked_run_snapshot,
    validate_run_artifact_path,
    verify_run_integrity,
)
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.gateway import GatewayOutcome, canonical_tool_request_digest
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignResult,
    LocalWebAssessmentRunReference,
    local_web_assessment_run_reference,
)
from pajin.web_assessment.governed_gateway import WebGatewayCompletionReceipt
from pajin.web_assessment.governed_models import (
    _WEB_GRANT_CONSUMPTION_MAX_BYTES,
    _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    ProvisionedWebAccountReceiptRegistry,
    SignedProvisionedWebAccountReceipt,
    SignedWebActionApproval,
    SignedWebAssessmentAdapter,
    WebActionApprovalInputAuthority,
    WebAssessmentAdapterRegistry,
    WebAssessmentCapabilityGrantConsumptionReceipt,
    WebAssessmentCapabilityGrantReservation,
    WebAssessmentSigningKeyState,
    WebAssessmentSigningRole,
    WebAssessmentVerificationKey,
    WebAuthenticatedAssessmentWorkerOutput,
    _verify_web_grant_consumption_schema,
)
from pajin.web_assessment.governed_reporting import (
    GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
    GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
    GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
    GOVERNED_WEB_GRAPH_PRODUCER_ID,
    GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
    GovernedWebExecutionEvidence,
    GovernedWebExecutionVerification,
    GovernedWebGraphAdmission,
    GovernedWebPromotion,
    RedactedGovernedWebPocManifest,
    _delivery_manifest,
    _render_validation_report,
    governed_web_execution_verifier_digest,
    load_verified_governed_web_delivery_manifest,
    load_verified_redacted_governed_web_poc_manifest,
)
from pajin.web_assessment.governed_worker import (
    WEB_ACCOUNT_NAME_BINDING,
    WEB_ACCOUNT_PROOF_BINDING,
    WEB_ASSESSMENT_EXECUTOR_COMMAND,
    WEB_HOST_WORKER_IMAGE,
    WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
    WEB_WORKER_BACKEND_NAME,
    WEB_WORKER_IMPLEMENTATION_VERSION,
    WEB_WORKER_PROCESS_IMPLEMENTATION_VERSION,
    WEB_WORKER_SIGNING_KEY_BINDING,
    SignedWebWorkerActionEvidence,
    WebIndependentWorkerEvidence,
    WebWorkerAuthorityBinding,
    WebWorkerCompletedActionRecord,
    WebWorkerKeyState,
    WebWorkerRole,
    WebWorkerTrustRegistry,
    WebWorkerVerificationKey,
    canonical_web_worker_sha256,
    verify_independent_web_worker_evidence,
)
from pajin.web_assessment.models import IssueCheck, LocalWebAssessmentAuthorization
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.verification import (
    load_verified_local_web_assessment_source_integrity,
)
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    ValidationSnapshotSemantics,
    load_validation_snapshot,
)

GOVERNED_WEB_CAMPAIGN_EVIDENCE_API_VERSION: Final = (
    "pajin.dev/governed-web-completed-campaign-evidence/v1alpha2"
)
GOVERNED_WEB_CAMPAIGN_INDEX_API_VERSION: Final = (
    "pajin.dev/governed-web-campaign-index/v1alpha1"
)
GOVERNED_WEB_CAMPAIGN_PLAN_API_VERSION: Final = (
    "pajin.dev/governed-web-campaign-plan/v1alpha1"
)
GOVERNED_WEB_CAMPAIGN_TRUST_API_VERSION: Final = (
    "pajin.dev/governed-web-campaign-trust-bundle/v1alpha1"
)
GOVERNED_WEB_CAMPAIGN_ID: Final = "juice-shop-governed-local"
GOVERNED_WEB_ORIGIN: Final = "http://127.0.0.1:3000"
GOVERNED_WEB_ADAPTER_REF: Final = "juice-shop-local/v1"

_COMPILER_ID: Final = "pajin.web-assessment.governed-compiler"
_COMPILER_VERSION: Final = "1.0.0"
_COMPILER_DIGEST: Final = capability_definition_digest(
    "pajin.web-assessment.governed-compiler/v1",
    {
        "compilerId": _COMPILER_ID,
        "campaign": GOVERNED_WEB_CAMPAIGN_ID,
        "actions": ("source", "validation"),
        "adapterRef": GOVERNED_WEB_ADAPTER_REF,
    },
)
_PROFILE_ID: Final = "web-governed-local"
_PROFILE_VERSION: Final = "1.0.0"
_PROFILE_DIGEST: Final = capability_definition_digest(
    "pajin.web-assessment.governed-profile/v1",
    {
        "profileId": _PROFILE_ID,
        "adapterRef": GOVERNED_WEB_ADAPTER_REF,
        "approvalRequired": True,
        "actions": 2,
    },
)
_WORKER_IMPLEMENTATION_ID: Final = "pajin.worker.host-loopback-browser"
_WORKER_IMPLEMENTATION_DIGEST: Final = capability_definition_digest(
    "pajin.web-assessment.host-loopback-browser-worker-implementation/v1",
    {
        "backendName": WEB_WORKER_BACKEND_NAME,
        "implementationVersion": WEB_WORKER_IMPLEMENTATION_VERSION,
        "processImplementationVersion": WEB_WORKER_PROCESS_IMPLEMENTATION_VERSION,
    },
)
_GATEWAY_IMPLEMENTATION_ID: Final = "pajin.gateway.host-loopback-web"
_GATEWAY_IMPLEMENTATION_DIGEST: Final = capability_definition_digest(
    "pajin.web-assessment.host-loopback-web-gateway-implementation/v1",
    {
        "implementationVersion": "pajin.host-loopback-web-gateway/v1",
        "oneAction": True,
        "workerBackend": WEB_WORKER_BACKEND_NAME,
        "workerImplementationDigest": _WORKER_IMPLEMENTATION_DIGEST,
    },
)

_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_BASE64URL_PUBLIC_KEY_PATTERN = r"^[A-Za-z0-9_-]{43}$"
_BASE64URL_SIGNATURE_PATTERN = r"^[A-Za-z0-9_-]{86}$"
_CAMPAIGN_PLAN_PATH: Final[Literal["campaign-plan.json"]] = "campaign-plan.json"
_CAMPAIGN_EVIDENCE_PATH: Final[Literal["campaign-evidence.json"]] = (
    "campaign-evidence.json"
)
_CAMPAIGN_RESULT_PATH: Final[Literal["campaign-result.json"]] = "campaign-result.json"
_CAMPAIGN_INDEX_PATH = "campaign-index.json"
_INCOMPLETE_PATH = "incomplete.json"
_MAX_PLAN_BYTES = 512 * 1024
_MAX_CHECKPOINT_BYTES = 2 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
_MAX_RESULT_BYTES = 2 * 1024 * 1024
_MAX_INDEX_BYTES = 2 * 1024 * 1024
_MAX_INCOMPLETE_BYTES = 2 * 1024 * 1024
_MAX_EVENT_LOG_BYTES = 64 * 1024 * 1024
_MAX_INTEGRITY_LOG_BYTES = 64 * 1024 * 1024
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_RECORDS = 1_000_000

GovernedWebCampaignStage = Literal[
    "provisioning",
    "source-gateway",
    "validation-gateway",
    "graph-admission",
    "poc-publication",
    "export-publication",
    "parent-evidence",
]
_CampaignCheckpointStatus = Literal["started", "completed"]
_CampaignIndexArtifactPath = Literal[
    "campaign-plan.json",
    "campaign-evidence.json",
    "campaign-result.json",
]
_CAMPAIGN_CHECKPOINT_STATUSES: Final[tuple[_CampaignCheckpointStatus, ...]] = (
    "started",
    "completed",
)
GovernedWebCampaignDatabaseStoreKind = Literal[
    "governed-web-graph",
    "governed-web-grant",
]
_DATABASE_STORE_KINDS: Final[tuple[GovernedWebCampaignDatabaseStoreKind, ...]] = (
    "governed-web-graph",
    "governed-web-grant",
)
GOVERNED_WEB_CAMPAIGN_STAGE_ORDER: Final[tuple[GovernedWebCampaignStage, ...]] = (
    "provisioning",
    "source-gateway",
    "validation-gateway",
    "graph-admission",
    "poc-publication",
    "export-publication",
    "parent-evidence",
)

_TRUST_CODE_ROLES: Final = frozenset(
    {
        "adapter-implementation",
        "compiler",
        "profile",
        "worker",
        "gateway",
    }
)
_WORKER_ROLES: Final = frozenset(
    {
        WebWorkerRole.SOURCE_TARGET_OBSERVER,
        WebWorkerRole.SOURCE_EXECUTOR,
        WebWorkerRole.VALIDATION_TARGET_OBSERVER,
        WebWorkerRole.VALIDATION_EXECUTOR,
    }
)


class GovernedWebCampaignEvidenceError(ValueError):
    """Raised when the parent evidence journal does not verify exactly."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires an explicit UTC offset")
    return value.astimezone(UTC)


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError("governed WEB parent evidence is not canonical JSON") from exc


def _digest(domain: str, value: object) -> str:
    return sha256(domain.encode("utf-8") + b"\0" + _canonical_bytes(value)).hexdigest()


def _decode_base64url(value: str, *, size: int, label: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{label} is not valid base64url") from exc
    if len(decoded) != size or _encode_base64url(decoded) != value:
        raise ValueError(f"{label} has the wrong byte length")
    return decoded


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _require_public_safe(value: JsonValue, *, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z]", "", key.casefold())
            public_recipe_descriptor = normalized in {
                "passwordfield",
                "passwordselector",
                "repeatpasswordfield",
            }
            if not public_recipe_descriptor and any(
                marker in normalized
                for marker in (
                    "password",
                    "privatekey",
                    "credentialvalue",
                    "accesskey",
                    "refreshtoken",
                )
            ):
                raise ValueError(f"{label} contains forbidden private material")
            _require_public_safe(child, label=label)
    elif isinstance(value, list):
        for child in value:
            _require_public_safe(child, label=label)


class GovernedWebCampaignPlannedRuns(_FrozenStrictModel):
    parent_run_id: str = Field(alias="parentRunId", pattern=_RUN_ID_PATTERN)
    source_browser_run_id: str = Field(alias="sourceBrowserRunId", pattern=_RUN_ID_PATTERN)
    validation_browser_run_id: str = Field(
        alias="validationBrowserRunId", pattern=_RUN_ID_PATTERN
    )
    source_gateway_run_id: str = Field(alias="sourceGatewayRunId", pattern=_RUN_ID_PATTERN)
    validation_gateway_run_id: str = Field(
        alias="validationGatewayRunId", pattern=_RUN_ID_PATTERN
    )
    validation_projection_run_id: str = Field(
        alias="validationProjectionRunId", pattern=_RUN_ID_PATTERN
    )

    @model_validator(mode="after")
    def require_distinct_runs(self) -> Self:
        values = tuple(self.model_dump().values())
        if len(values) != len(set(values)):
            raise ValueError("governed WEB planned Run IDs must be distinct")
        return self

    def relative_paths(self) -> Mapping[str, str]:
        return MappingProxyType(
            {
                "parent": (
                    f"campaign-runs/{GOVERNED_WEB_CAMPAIGN_ID}/{self.parent_run_id}"
                ),
                "sourceBrowser": (
                    "worker-runs/juice-shop-web-assessment/"
                    f"{self.source_browser_run_id}"
                ),
                "validationBrowser": (
                    "worker-runs/juice-shop-web-assessment/"
                    f"{self.validation_browser_run_id}"
                ),
                "sourceGateway": (
                    f"gateway-runs/web-source-gateway/{self.source_gateway_run_id}"
                ),
                "validationGateway": (
                    "gateway-runs/web-validation-gateway/"
                    f"{self.validation_gateway_run_id}"
                ),
                "validationProjection": (
                    "validation-runs/governed-web-validation/"
                    f"{self.validation_projection_run_id}"
                ),
            }
        )


class GovernedWebCodeTrustBinding(_FrozenStrictModel):
    role: Literal[
        "adapter-implementation",
        "compiler",
        "profile",
        "worker",
        "gateway",
    ]
    implementation_id: str = Field(alias="implementationId", pattern=_SAFE_ID_PATTERN)
    implementation_digest: str = Field(
        alias="implementationDigest", pattern=_SHA256_PATTERN
    )


class GovernedWebCampaignTrustMaterial(_FrozenStrictModel):
    adapter_key: WebAssessmentVerificationKey = Field(alias="adapterKey")
    account_key: WebAssessmentVerificationKey = Field(alias="accountKey")
    source_approval_key: WebAssessmentVerificationKey = Field(alias="sourceApprovalKey")
    validation_approval_key: WebAssessmentVerificationKey = Field(
        alias="validationApprovalKey"
    )
    lifecycle_publisher_key: CapabilityLifecycleTrustKey = Field(
        alias="lifecyclePublisherKey"
    )
    lifecycle_reviewer_key: CapabilityLifecycleTrustKey = Field(alias="lifecycleReviewerKey")
    worker_trust_domain: str = Field(alias="workerTrustDomain", pattern=_SAFE_ID_PATTERN)
    worker_issuer: str = Field(alias="workerIssuer", pattern=_SAFE_ID_PATTERN)
    worker_keys: tuple[WebWorkerVerificationKey, ...] = Field(
        alias="workerKeys", min_length=4, max_length=4
    )
    code_bindings: tuple[GovernedWebCodeTrustBinding, ...] = Field(
        alias="codeBindings", min_length=5, max_length=5
    )

    @model_validator(mode="after")
    def require_exact_inventory(self) -> Self:
        if (
            self.adapter_key.role is not WebAssessmentSigningRole.ADAPTER_PUBLISHER
            or self.account_key.role is not WebAssessmentSigningRole.ACCOUNT_ISSUER
            or self.source_approval_key.role is not WebAssessmentSigningRole.ACTION_APPROVER
            or self.validation_approval_key.role is not WebAssessmentSigningRole.ACTION_APPROVER
            or any(
                key.state is not WebAssessmentSigningKeyState.ACTIVE
                for key in (
                    self.adapter_key,
                    self.account_key,
                    self.source_approval_key,
                    self.validation_approval_key,
                )
            )
            or self.lifecycle_publisher_key.role is not CapabilityLifecycleKeyRole.PUBLISHER
            or self.lifecycle_reviewer_key.role is not CapabilityLifecycleKeyRole.REVIEWER
            or self.lifecycle_publisher_key.state is not CapabilityLifecycleKeyState.ACTIVE
            or self.lifecycle_reviewer_key.state is not CapabilityLifecycleKeyState.ACTIVE
        ):
            raise ValueError("governed WEB trust key role or state inventory differs")
        if {key.role for key in self.worker_keys} != _WORKER_ROLES:
            raise ValueError("governed WEB trust material requires all four Worker roles")
        if (
            len({key.key_id for key in self.worker_keys}) != 4
            or any(key.state is not WebWorkerKeyState.ACTIVE for key in self.worker_keys)
        ):
            raise ValueError("governed WEB Worker trust keys must be distinct")
        if {binding.role for binding in self.code_bindings} != _TRUST_CODE_ROLES:
            raise ValueError("governed WEB code trust binding inventory differs")
        if len({binding.implementation_id for binding in self.code_bindings}) != 5:
            raise ValueError("governed WEB code trust identities must be distinct")
        return self


class GovernedWebCampaignIndexSigningKey(_FrozenStrictModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(alias="keyId", pattern=_SAFE_ID_PATTERN)
    principal_id: Literal["principal.web.campaign-evidence-index"] = Field(
        default="principal.web.campaign-evidence-index",
        alias="principalId",
    )
    role: Literal["campaign-evidence-index-signer"] = (
        "campaign-evidence-index-signer"
    )
    trust_domain: Literal["pajin.web.local-governed.campaign-evidence"] = Field(
        default="pajin.web.local-governed.campaign-evidence",
        alias="trustDomain",
    )
    state: Literal["active"] = "active"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url", pattern=_BASE64URL_PUBLIC_KEY_PATTERN
    )
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime = Field(alias="notAfter")

    @field_validator("not_before", "not_after")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _utc(value, label="campaign evidence signing key time")

    @model_validator(mode="after")
    def require_window(self) -> Self:
        if self.not_after <= self.not_before:
            raise ValueError("campaign evidence signing key validity window is empty")
        _decode_base64url(
            self.public_key_base64url,
            size=32,
            label="campaign evidence public key",
        )
        return self


class GovernedWebCampaignTrustBundle(_FrozenStrictModel):
    api_version: Literal["pajin.dev/governed-web-campaign-trust-bundle/v1alpha1"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_TRUST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCampaignTrustBundle"] = "GovernedWebCampaignTrustBundle"
    trust_material: GovernedWebCampaignTrustMaterial = Field(alias="trustMaterial")
    index_signing_key: GovernedWebCampaignIndexSigningKey = Field(alias="indexSigningKey")
    deployment_trust_anchor_digest: str = Field(
        default="", alias="deploymentTrustAnchorDigest", max_length=64
    )

    @model_validator(mode="after")
    def bind_anchor(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"deployment_trust_anchor_digest"},
        )
        expected = _digest("pajin.web.governed-campaign-trust-anchor/v1", material)
        if self.deployment_trust_anchor_digest and (
            self.deployment_trust_anchor_digest != expected
        ):
            raise ValueError("governed WEB deployment trust anchor digest differs")
        object.__setattr__(self, "deployment_trust_anchor_digest", expected)
        return self


class GovernedWebCampaignPlan(_FrozenStrictModel):
    api_version: Literal["pajin.dev/governed-web-campaign-plan/v1alpha1"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCampaignPlan"] = "GovernedWebCampaignPlan"
    campaign_id: Literal["juice-shop-governed-local"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_ID, alias="campaignId"
    )
    origin: Literal["http://127.0.0.1:3000"] = GOVERNED_WEB_ORIGIN
    adapter_ref: Literal["juice-shop-local/v1"] = Field(
        default=GOVERNED_WEB_ADAPTER_REF, alias="adapterRef"
    )
    planned_runs: GovernedWebCampaignPlannedRuns = Field(alias="plannedRuns")
    trust_bundle: GovernedWebCampaignTrustBundle = Field(alias="trustBundle")
    deployment_trust_anchor_digest: str = Field(
        alias="deploymentTrustAnchorDigest", pattern=_SHA256_PATTERN
    )
    signer_key_id: str = Field(alias="signerKeyId", pattern=_SAFE_ID_PATTERN)
    signed_at: datetime = Field(alias="signedAt")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=_BASE64URL_SIGNATURE_PATTERN,
    )
    campaign_plan_digest: str = Field(default="", alias="campaignPlanDigest", max_length=64)
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    external_delivery_performed: Literal[False] = Field(
        default=False, alias="externalDeliveryPerformed"
    )

    @field_validator("signed_at")
    @classmethod
    def normalize_signed_at(cls, value: datetime) -> datetime:
        return _utc(value, label="governed WEB campaign Plan signature time")

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        if (
            self.deployment_trust_anchor_digest
            != self.trust_bundle.deployment_trust_anchor_digest
            or self.signer_key_id != self.trust_bundle.index_signing_key.key_id
            or not self.trust_bundle.index_signing_key.not_before
            <= self.signed_at
            < self.trust_bundle.index_signing_key.not_after
        ):
            raise ValueError("governed WEB Plan signing authority differs")
        _decode_base64url(
            self.signature_base64url,
            size=64,
            label="governed WEB campaign Plan signature",
        )
        _require_distinct_trust_identities(self.trust_bundle)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"campaign_plan_digest", "signature_base64url"},
        )
        expected = _digest("pajin.web.governed-campaign-plan/v1", material)
        if self.campaign_plan_digest and self.campaign_plan_digest != expected:
            raise ValueError("governed WEB campaign Plan Digest differs")
        object.__setattr__(self, "campaign_plan_digest", expected)
        return self

    def signed_bytes(self) -> bytes:
        return (
            b"pajin.web.governed-campaign-plan-signature/v1\0"
            + bytes.fromhex(self.campaign_plan_digest)
        )


class GovernedWebCampaignStageIntent(_FrozenStrictModel):
    stage: GovernedWebCampaignStage
    bindings: dict[str, JsonValue] = Field(default_factory=dict, max_length=200)
    intent_digest: str = Field(default="", alias="intentDigest", max_length=64)
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    external_delivery_performed: Literal[False] = Field(
        default=False, alias="externalDeliveryPerformed"
    )

    @model_validator(mode="after")
    def bind_intent(self) -> Self:
        _require_public_safe(cast(JsonValue, self.bindings), label="campaign stage intent")
        material = self.model_dump(mode="json", by_alias=True, exclude={"intent_digest"})
        expected = _digest("pajin.web.governed-campaign-stage-intent/v1", material)
        if self.intent_digest and self.intent_digest != expected:
            raise ValueError("governed WEB campaign stage intent digest differs")
        object.__setattr__(self, "intent_digest", expected)
        return self


class GovernedWebCampaignStageObservation(_FrozenStrictModel):
    stage: GovernedWebCampaignStage
    observed: dict[str, JsonValue] = Field(default_factory=dict, max_length=500)
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    external_delivery_performed: Literal[False] = Field(
        default=False, alias="externalDeliveryPerformed"
    )

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        _require_public_safe(
            cast(JsonValue, self.observed),
            label="campaign stage observation",
        )
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"observation_digest"}
        )
        expected = _digest("pajin.web.governed-campaign-stage-observation/v1", material)
        if self.observation_digest and self.observation_digest != expected:
            raise ValueError("governed WEB campaign stage observation digest differs")
        object.__setattr__(self, "observation_digest", expected)
        return self


class GovernedWebCampaignCheckpoint(_FrozenStrictModel):
    api_version: Literal["pajin.dev/governed-web-campaign-checkpoint/v1alpha1"] = Field(
        default="pajin.dev/governed-web-campaign-checkpoint/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCampaignCheckpoint"] = "GovernedWebCampaignCheckpoint"
    campaign_id: Literal["juice-shop-governed-local"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_ID, alias="campaignId"
    )
    campaign_plan_digest: str = Field(alias="campaignPlanDigest", pattern=_SHA256_PATTERN)
    stage: GovernedWebCampaignStage
    status: Literal["started", "completed"]
    ordinal: int = Field(ge=1, le=len(GOVERNED_WEB_CAMPAIGN_STAGE_ORDER))
    completed_stages: tuple[GovernedWebCampaignStage, ...] = Field(alias="completedStages")
    started_checkpoint_digest: str | None = Field(
        default=None, alias="startedCheckpointDigest", pattern=_SHA256_PATTERN
    )
    intent: GovernedWebCampaignStageIntent | None = None
    observation: GovernedWebCampaignStageObservation | None = None
    may_have_executed: bool = Field(alias="mayHaveExecuted")
    checkpoint_digest: str = Field(default="", alias="checkpointDigest", max_length=64)

    @field_validator("may_have_executed", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("campaign checkpoint mayHaveExecuted must be a boolean")
        return value

    @model_validator(mode="after")
    def bind_checkpoint(self) -> Self:
        completed_count = self.ordinal if self.status == "completed" else self.ordinal - 1
        expected_prefix = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[:completed_count]
        if self.completed_stages != expected_prefix:
            raise ValueError("campaign checkpoint completed-stage prefix differs")
        if self.stage != GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[self.ordinal - 1]:
            raise ValueError("campaign checkpoint stage ordinal differs")
        if self.status == "started":
            valid = (
                self.intent is not None
                and self.intent.stage == self.stage
                and self.observation is None
                and self.started_checkpoint_digest is None
                and self.may_have_executed
            )
        else:
            valid = (
                self.intent is None
                and self.observation is not None
                and self.observation.stage == self.stage
                and self.started_checkpoint_digest is not None
                and not self.may_have_executed
            )
        if not valid:
            raise ValueError("campaign checkpoint payload differs from its status")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"checkpoint_digest"}
        )
        expected = _digest("pajin.web.governed-campaign-checkpoint/v1", material)
        if self.checkpoint_digest and self.checkpoint_digest != expected:
            raise ValueError("governed WEB campaign checkpoint digest differs")
        object.__setattr__(self, "checkpoint_digest", expected)
        return self


class GovernedWebCampaignDatabaseCheckpoint(_FrozenStrictModel):
    """One signer-bound ACK for an exact durable SQLite commit checkpoint."""

    api_version: Literal[
        "pajin.dev/governed-web-campaign-database-checkpoint/v1alpha1"
    ] = Field(
        default="pajin.dev/governed-web-campaign-database-checkpoint/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCampaignDatabaseCheckpoint"] = (
        "GovernedWebCampaignDatabaseCheckpoint"
    )
    campaign_id: Literal["juice-shop-governed-local"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_ID,
        alias="campaignId",
    )
    campaign_plan_digest: str = Field(alias="campaignPlanDigest", pattern=_SHA256_PATTERN)
    stage: Literal[
        "provisioning",
        "source-gateway",
        "validation-gateway",
        "graph-admission",
    ]
    store_kind: GovernedWebCampaignDatabaseStoreKind = Field(alias="storeKind")
    ordinal: int = Field(ge=1, le=1_000_000)
    manifest_reference: str = Field(alias="manifestReference", min_length=1, max_length=500)
    manifest_digest: str = Field(alias="manifestDigest", pattern=_SHA256_PATTERN)
    manifest_sha256: str = Field(alias="manifestSha256", pattern=_SHA256_PATTERN)
    manifest_size: int = Field(alias="manifestSize", ge=1, le=64 * 1024 * 1024)
    previous_manifest_digest: str | None = Field(
        default=None,
        alias="previousManifestDigest",
        pattern=_SHA256_PATTERN,
    )
    database_reference: str = Field(alias="databaseReference", min_length=1, max_length=500)
    database_sha256: str = Field(alias="databaseSha256", pattern=_SHA256_PATTERN)
    database_size: int = Field(alias="databaseSize", ge=1, le=512 * 1024 * 1024)
    state_digest: str = Field(alias="stateDigest", pattern=_SHA256_PATTERN)
    previous_parent_root_digest: str = Field(
        alias="previousParentRootDigest",
        pattern=_SHA256_PATTERN,
    )
    recorded_at: datetime = Field(alias="recordedAt")
    signer_key_id: str = Field(alias="signerKeyId", pattern=_SAFE_ID_PATTERN)
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=_BASE64URL_SIGNATURE_PATTERN,
    )
    checkpoint_digest: str = Field(default="", alias="checkpointDigest", max_length=64)
    credentials_persisted: Literal[False] = Field(
        default=False,
        alias="credentialsPersisted",
    )
    external_delivery_performed: Literal[False] = Field(
        default=False,
        alias="externalDeliveryPerformed",
    )

    @field_validator("recorded_at")
    @classmethod
    def normalize_recorded_at(cls, value: datetime) -> datetime:
        return _utc(value, label="governed WEB database checkpoint time")

    @model_validator(mode="after")
    def bind_database_checkpoint(self) -> Self:
        leaf = (
            "governed-web.sqlite3"
            if self.store_kind == "governed-web-graph"
            else "capability-grant-consumptions.sqlite3"
        )
        prefix = f".{leaf}.checkpoint-{self.ordinal:08d}-"
        manifest_path = PurePosixPath(self.manifest_reference)
        database_path = PurePosixPath(self.database_reference)
        manifest_name = manifest_path.name
        database_name = database_path.name
        if (
            manifest_path.parts != ("authority", manifest_name)
            or database_path.parts != ("authority", database_name)
            or not manifest_name.startswith(prefix)
            or not manifest_name.endswith(f"-{self.manifest_digest}.json")
            or not database_name.startswith(prefix)
            or not database_name.endswith(f"-{self.database_sha256}.sqlite3")
            or (self.ordinal == 1) is not (self.previous_manifest_digest is None)
        ):
            raise ValueError("governed WEB database checkpoint reference differs")
        _decode_base64url(
            self.signature_base64url,
            size=64,
            label="governed WEB database checkpoint signature",
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"checkpoint_digest", "signature_base64url"},
        )
        expected = _digest("pajin.web.governed-campaign-database-checkpoint/v1", material)
        if self.checkpoint_digest and self.checkpoint_digest != expected:
            raise ValueError("governed WEB database checkpoint Digest differs")
        object.__setattr__(self, "checkpoint_digest", expected)
        return self

    def signed_bytes(self) -> bytes:
        return (
            b"pajin.web.governed-campaign-database-checkpoint-signature/v1\0"
            + bytes.fromhex(self.checkpoint_digest)
        )


class _HistoricalBrowserRunReference(_FrozenStrictModel):
    path: str = Field(min_length=1, max_length=500)
    run: LocalWebAssessmentRunReference


class _HistoricalGatewayRunReference(_FrozenStrictModel):
    path: str = Field(min_length=1, max_length=500)
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    root_digest: str = Field(alias="rootDigest", pattern=_SHA256_PATTERN)
    event_head_digest: str = Field(alias="eventHeadDigest", pattern=_SHA256_PATTERN)
    completion_receipt_reference: str = Field(
        alias="completionReceiptReference",
        min_length=1,
        max_length=500,
    )
    completion_authority_digest: str = Field(
        alias="completionAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )


class _HistoricalGovernedWebAction(_FrozenStrictModel):
    local_authorization: LocalWebAssessmentAuthorization = Field(
        alias="localAuthorization"
    )
    prepared: PreparedCapabilityAction
    request: ToolRequest
    envelope: MissionEnvelope
    decision: GraphDecision
    proposal: ActionProposal
    approval: ActionApprovalEnvelope
    signed_approval: SignedWebActionApproval = Field(alias="signedApproval")
    permit: ActionPermit
    approval_consumption_receipt: ActionApprovalConsumptionReceipt = Field(
        alias="approvalConsumptionReceipt"
    )
    grant_consumption_receipt: WebAssessmentCapabilityGrantConsumptionReceipt = Field(
        alias="grantConsumptionReceipt"
    )
    worker_authority_binding: WebWorkerAuthorityBinding = Field(
        alias="workerAuthorityBinding"
    )
    gateway_completion_receipt: WebGatewayCompletionReceipt = Field(
        alias="gatewayCompletionReceipt"
    )
    gateway_run_reference: _HistoricalGatewayRunReference = Field(
        alias="gatewayRunReference"
    )
    worker_action_evidence: SignedWebWorkerActionEvidence = Field(
        alias="workerActionEvidence"
    )
    worker_output: WebAuthenticatedAssessmentWorkerOutput = Field(alias="workerOutput")
    browser_run_reference: _HistoricalBrowserRunReference = Field(
        alias="browserRunReference"
    )


class _HistoricalLifecycle(_FrozenStrictModel):
    release_bundle: CapabilityReleaseBundle = Field(alias="releaseBundle")
    activation: WebAuthenticatedAssessmentCapabilityActivationSet


class _HistoricalGrants(_FrozenStrictModel):
    root: CapabilityGrant
    source: CapabilityGrant
    validation: CapabilityGrant


class GovernedWebCampaignDatabaseEnrollment(_FrozenStrictModel):
    """Parent-signed identity of one exact governed SQLite enrollment marker."""

    store_kind: GovernedWebCampaignDatabaseStoreKind = Field(alias="storeKind")
    reference: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=1, le=16 * 1024)

    @model_validator(mode="after")
    def bind_enrollment_reference(self) -> Self:
        expected = re.compile(
            rf"^\.pajin-governed-sqlite-enrollment-v1-{self.store_kind}-"
            rf"[a-f0-9]{{64}}-[a-f0-9]{{64}}\.json$"
        )
        if expected.fullmatch(self.reference) is None:
            raise ValueError("governed WEB SQLite enrollment reference differs")
        return self


@dataclass(frozen=True, slots=True)
class _CompletedCampaignModels:
    campaign: CampaignManifest
    signed_adapter: SignedWebAssessmentAdapter
    signed_account_receipt: SignedProvisionedWebAccountReceipt
    lifecycle: _HistoricalLifecycle
    grants: _HistoricalGrants
    source: _HistoricalGovernedWebAction
    validation: _HistoricalGovernedWebAction
    independent_worker_evidence: WebIndependentWorkerEvidence
    reconciliation: LocalWebAssessmentCampaignResult
    execution_verification: GovernedWebExecutionVerification
    execution_evidence: GovernedWebExecutionEvidence
    promotion: GovernedWebPromotion
    graph_admission: GovernedWebGraphAdmission


class GovernedWebCompletedCampaignEvidence(_FrozenStrictModel):
    """Canonical, secret-free complete WEB-005 authority and evidence chain."""

    api_version: Literal[
        "pajin.dev/governed-web-completed-campaign-evidence/v1alpha2"
    ] = Field(
        default=GOVERNED_WEB_CAMPAIGN_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCompletedCampaignEvidence"] = (
        "GovernedWebCompletedCampaignEvidence"
    )
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    campaign_id: Literal["juice-shop-governed-local"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_ID, alias="campaignId"
    )
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    trust_bundle: GovernedWebCampaignTrustBundle = Field(alias="trustBundle")
    campaign: dict[str, JsonValue]
    signed_adapter: dict[str, JsonValue] = Field(alias="signedAdapter")
    signed_account_receipt: dict[str, JsonValue] = Field(alias="signedAccountReceipt")
    lifecycle: dict[str, JsonValue]
    grants: dict[str, JsonValue]
    source_action: dict[str, JsonValue] = Field(alias="sourceAction")
    validation_action: dict[str, JsonValue] = Field(alias="validationAction")
    independent_worker_evidence: dict[str, JsonValue] = Field(
        alias="independentWorkerEvidence"
    )
    reconciliation: dict[str, JsonValue]
    execution_verification: dict[str, JsonValue] = Field(alias="executionVerification")
    execution_evidence: dict[str, JsonValue] = Field(alias="executionEvidence")
    promotion: dict[str, JsonValue]
    graph_admission: dict[str, JsonValue] = Field(alias="graphAdmission")
    initial_graph_snapshot: GraphSnapshotRef = Field(alias="initialGraphSnapshot")
    final_graph_snapshot: GraphSnapshotRef = Field(alias="finalGraphSnapshot")
    graph_database_sha256: str = Field(alias="graphDatabaseSha256", pattern=_SHA256_PATTERN)
    grant_database_sha256: str = Field(alias="grantDatabaseSha256", pattern=_SHA256_PATTERN)
    graph_database_enrollment: GovernedWebCampaignDatabaseEnrollment = Field(
        alias="graphDatabaseEnrollment"
    )
    grant_database_enrollment: GovernedWebCampaignDatabaseEnrollment = Field(
        alias="grantDatabaseEnrollment"
    )
    source_gateway_event_head_digest: str = Field(
        alias="sourceGatewayEventHeadDigest", pattern=_SHA256_PATTERN
    )
    validation_gateway_event_head_digest: str = Field(
        alias="validationGatewayEventHeadDigest", pattern=_SHA256_PATTERN
    )
    validation_root_digest: str = Field(
        alias="validationRootDigest", pattern=_SHA256_PATTERN
    )
    validation_report_sha256: str = Field(
        alias="validationReportSha256", pattern=_SHA256_PATTERN
    )
    poc_manifest_digest: str = Field(alias="pocManifestDigest", pattern=_SHA256_PATTERN)
    sarif_digest: str = Field(alias="sarifDigest", pattern=_SHA256_PATTERN)
    delivery_manifest_digest: str = Field(
        alias="deliveryManifestDigest", pattern=_SHA256_PATTERN
    )
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    private_keys_persisted: Literal[False] = Field(default=False, alias="privateKeysPersisted")
    external_delivery_performed: Literal[False] = Field(
        default=False, alias="externalDeliveryPerformed"
    )

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        if set(self.lifecycle) != {"releaseBundle", "activation"}:
            raise ValueError("governed WEB lifecycle evidence inventory differs")
        if set(self.grants) != {"root", "source", "validation"}:
            raise ValueError("governed WEB Grant evidence inventory differs")
        required_action = {
            "localAuthorization",
            "prepared",
            "request",
            "envelope",
            "decision",
            "proposal",
            "approval",
            "signedApproval",
            "permit",
            "approvalConsumptionReceipt",
            "grantConsumptionReceipt",
            "workerAuthorityBinding",
            "gatewayCompletionReceipt",
            "gatewayRunReference",
            "workerActionEvidence",
            "workerOutput",
            "browserRunReference",
        }
        if set(self.source_action) != required_action or set(self.validation_action) != (
            required_action
        ):
            raise ValueError("governed WEB action evidence inventory differs")
        if (
            self.initial_graph_snapshot.campaign_id != self.campaign_id
            or self.final_graph_snapshot.campaign_id != self.campaign_id
            or self.initial_graph_snapshot.revision > self.final_graph_snapshot.revision
            or self.graph_database_enrollment.store_kind != "governed-web-graph"
            or self.grant_database_enrollment.store_kind != "governed-web-grant"
        ):
            raise ValueError("governed WEB Graph Snapshot lineage differs")
        for label, value in (
            ("campaign", self.campaign),
            ("signed adapter", self.signed_adapter),
            ("signed account receipt", self.signed_account_receipt),
            ("lifecycle", self.lifecycle),
            ("Grants", self.grants),
            ("source action", self.source_action),
            ("validation action", self.validation_action),
            ("independent Worker evidence", self.independent_worker_evidence),
            ("reconciliation", self.reconciliation),
            ("execution verification", self.execution_verification),
            ("execution evidence", self.execution_evidence),
            ("Promotion", self.promotion),
            ("Graph admission", self.graph_admission),
        ):
            _require_public_safe(cast(JsonValue, value), label=label)
        material = self.model_dump(mode="json", by_alias=True, exclude={"evidence_digest"})
        expected = _digest("pajin.web.governed-completed-campaign-evidence/v1", material)
        if self.evidence_digest and self.evidence_digest != expected:
            raise ValueError("governed WEB completed Evidence Digest differs")
        object.__setattr__(self, "evidence_digest", expected)
        return self


class GovernedWebCampaignHistoricalResult(_FrozenStrictModel):
    """Scalar completion receipt sufficient for restart-safe CLI reporting."""

    api_version: Literal["pajin.dev/governed-web-campaign-result/v1alpha1"] = Field(
        default="pajin.dev/governed-web-campaign-result/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCampaignResult"] = "GovernedWebCampaignResult"
    adapter_ref: Literal["juice-shop-local/v1"] = Field(alias="adapterRef")
    origin: Literal["http://127.0.0.1:3000"]
    campaign_id: Literal["juice-shop-governed-local"] = Field(alias="campaignId")
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    deployment_trust_anchor_digest: str = Field(
        alias="deploymentTrustAnchorDigest", pattern=_SHA256_PATTERN
    )
    activation_set_id: str = Field(alias="activationSetId", pattern=_SAFE_ID_PATTERN)
    activation_set_digest: str = Field(alias="activationSetDigest", pattern=_SHA256_PATTERN)
    source_request_id: str = Field(alias="sourceRequestId", pattern=_SAFE_ID_PATTERN)
    validation_request_id: str = Field(alias="validationRequestId", pattern=_SAFE_ID_PATTERN)
    source_approval_id: str = Field(alias="sourceApprovalId", pattern=_SAFE_ID_PATTERN)
    validation_approval_id: str = Field(alias="validationApprovalId", pattern=_SAFE_ID_PATTERN)
    source_permit_id: str = Field(alias="sourcePermitId", pattern=_SAFE_ID_PATTERN)
    validation_permit_id: str = Field(alias="validationPermitId", pattern=_SAFE_ID_PATTERN)
    source_run_id: str = Field(alias="sourceRunId", pattern=_RUN_ID_PATTERN)
    validation_run_id: str = Field(alias="validationRunId", pattern=_RUN_ID_PATTERN)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_SHA256_PATTERN)
    validation_root_digest: str = Field(alias="validationRootDigest", pattern=_SHA256_PATTERN)
    source_gateway_run_id: str = Field(alias="sourceGatewayRunId", pattern=_RUN_ID_PATTERN)
    validation_gateway_run_id: str = Field(
        alias="validationGatewayRunId", pattern=_RUN_ID_PATTERN
    )
    source_gateway_root_digest: str = Field(
        alias="sourceGatewayRootDigest", pattern=_SHA256_PATTERN
    )
    validation_gateway_root_digest: str = Field(
        alias="validationGatewayRootDigest", pattern=_SHA256_PATTERN
    )
    source_observer_process_id: int = Field(alias="sourceObserverProcessId", ge=1)
    source_executor_process_id: int = Field(alias="sourceExecutorProcessId", ge=1)
    validation_observer_process_id: int = Field(alias="validationObserverProcessId", ge=1)
    validation_executor_process_id: int = Field(alias="validationExecutorProcessId", ge=1)
    source_observer_key_id: str = Field(alias="sourceObserverKeyId", pattern=_SAFE_ID_PATTERN)
    source_executor_key_id: str = Field(alias="sourceExecutorKeyId", pattern=_SAFE_ID_PATTERN)
    validation_observer_key_id: str = Field(
        alias="validationObserverKeyId", pattern=_SAFE_ID_PATTERN
    )
    validation_executor_key_id: str = Field(
        alias="validationExecutorKeyId", pattern=_SAFE_ID_PATTERN
    )
    source_observer_execution_id: str = Field(
        alias="sourceObserverExecutionId", pattern=_SAFE_ID_PATTERN
    )
    source_executor_execution_id: str = Field(
        alias="sourceExecutorExecutionId", pattern=_SAFE_ID_PATTERN
    )
    validation_observer_execution_id: str = Field(
        alias="validationObserverExecutionId", pattern=_SAFE_ID_PATTERN
    )
    validation_executor_execution_id: str = Field(
        alias="validationExecutorExecutionId", pattern=_SAFE_ID_PATTERN
    )
    graph_event_count: int = Field(alias="graphEventCount", ge=1)
    finding_count: int = Field(alias="findingCount", ge=0)
    attack_path_count: int = Field(alias="attackPathCount", ge=0)
    validation_projection_run_id: str = Field(
        alias="validationProjectionRunId", pattern=_RUN_ID_PATTERN
    )
    validation_projection_root_digest: str = Field(
        alias="validationProjectionRootDigest", pattern=_SHA256_PATTERN
    )
    sarif_reference: Literal["exports/findings.sarif"] = Field(alias="sarifReference")
    sarif_digest: str = Field(alias="sarifDigest", pattern=_SHA256_PATTERN)
    report_reference: str = Field(alias="reportReference", min_length=1, max_length=500)
    poc_manifest_reference: Literal["poc-bundle/poc/manifest.json"] = Field(
        alias="pocManifestReference"
    )
    poc_manifest_digest: str = Field(alias="pocManifestDigest", pattern=_SHA256_PATTERN)
    delivery_readiness_reference: Literal["exports/delivery-readiness.json"] = Field(
        alias="deliveryReadinessReference"
    )
    account_retained_in_local_lab: Literal[True] = Field(
        default=True, alias="accountRetainedInLocalLab"
    )
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    external_delivery_performed: Literal[False] = Field(
        default=False, alias="externalDeliveryPerformed"
    )

    @model_validator(mode="after")
    def bind_result(self) -> Self:
        four_processes = {
            self.source_observer_process_id,
            self.source_executor_process_id,
            self.validation_observer_process_id,
            self.validation_executor_process_id,
        }
        four_keys = {
            self.source_observer_key_id,
            self.source_executor_key_id,
            self.validation_observer_key_id,
            self.validation_executor_key_id,
        }
        four_executions = {
            self.source_observer_execution_id,
            self.source_executor_execution_id,
            self.validation_observer_execution_id,
            self.validation_executor_execution_id,
        }
        if len(four_processes) != 4 or len(four_keys) != 4 or len(four_executions) != 4:
            raise ValueError("governed WEB historical result loses four-way independence")
        expected_report = (
            "validation-runs/governed-web-validation/"
            f"{self.validation_projection_run_id}/validation/v1alpha1/report.md"
        )
        if self.report_reference != expected_report:
            raise ValueError("governed WEB historical report reference is not deterministic")
        return self


class GovernedWebCampaignIndexArtifact(_FrozenStrictModel):
    path: _CampaignIndexArtifactPath
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size_bytes: int = Field(alias="sizeBytes", ge=1)


class GovernedWebCampaignIndex(_FrozenStrictModel):
    api_version: Literal["pajin.dev/governed-web-campaign-index/v1alpha1"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_INDEX_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GovernedWebCampaignIndex"] = "GovernedWebCampaignIndex"
    index_digest: str = Field(default="", alias="indexDigest", max_length=64)
    parent_run_id: str = Field(alias="parentRunId", pattern=_RUN_ID_PATTERN)
    campaign_plan_digest: str = Field(alias="campaignPlanDigest", pattern=_SHA256_PATTERN)
    evidence_digest: str = Field(alias="evidenceDigest", pattern=_SHA256_PATTERN)
    deployment_trust_anchor_digest: str = Field(
        alias="deploymentTrustAnchorDigest", pattern=_SHA256_PATTERN
    )
    final_graph_snapshot_id: str = Field(alias="finalGraphSnapshotId", min_length=1)
    final_graph_snapshot_digest: str = Field(
        alias="finalGraphSnapshotDigest", pattern=_SHA256_PATTERN
    )
    artifacts: tuple[GovernedWebCampaignIndexArtifact, ...] = Field(
        min_length=3, max_length=3
    )
    signed_at: datetime = Field(alias="signedAt")
    signer_key_id: str = Field(alias="signerKeyId", pattern=_SAFE_ID_PATTERN)
    signature_base64url: str = Field(
        alias="signatureBase64url", pattern=_BASE64URL_SIGNATURE_PATTERN
    )

    @field_validator("signed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _utc(value, label="campaign evidence index signature time")

    @model_validator(mode="after")
    def bind_index(self) -> Self:
        expected_paths = {
            _CAMPAIGN_PLAN_PATH,
            _CAMPAIGN_EVIDENCE_PATH,
            _CAMPAIGN_RESULT_PATH,
        }
        if {artifact.path for artifact in self.artifacts} != expected_paths:
            raise ValueError("governed WEB campaign index artifact inventory differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"index_digest", "signature_base64url"},
        )
        expected = _digest("pajin.web.governed-campaign-index/v1", material)
        if self.index_digest and self.index_digest != expected:
            raise ValueError("governed WEB campaign Index Digest differs")
        object.__setattr__(self, "index_digest", expected)
        _decode_base64url(
            self.signature_base64url,
            size=64,
            label="campaign evidence index signature",
        )
        return self

    def signed_bytes(self) -> bytes:
        return (
            b"pajin.web.governed-campaign-index-signature/v1\0"
            + bytes.fromhex(self.index_digest)
        )


class GovernedWebIncompleteCampaignEvidence(_FrozenStrictModel):
    api_version: Literal["pajin.dev/incomplete-governed-web-campaign/v1alpha1"] = Field(
        default="pajin.dev/incomplete-governed-web-campaign/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["IncompleteGovernedWebCampaignEvidence"] = (
        "IncompleteGovernedWebCampaignEvidence"
    )
    incomplete_digest: str = Field(default="", alias="incompleteDigest", max_length=64)
    campaign_id: Literal["juice-shop-governed-local"] = Field(
        default=GOVERNED_WEB_CAMPAIGN_ID, alias="campaignId"
    )
    failure_stage: GovernedWebCampaignStage = Field(alias="failureStage")
    failure_type: str = Field(alias="failureType", pattern=r"^[a-z][a-z0-9-]{2,79}$")
    completed_stages: tuple[GovernedWebCampaignStage, ...] = Field(alias="completedStages")
    active_stage: GovernedWebCampaignStage | None = Field(alias="activeStage")
    may_have_executed: bool = Field(alias="mayHaveExecuted")
    account_provisioning_state: Literal[
        "not-started", "may-have-executed", "confirmed-retained"
    ] = Field(alias="accountProvisioningState")
    previous_journal_root_digest: str = Field(
        alias="previousJournalRootDigest", pattern=_SHA256_PATTERN
    )
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    external_delivery_performed: Literal[False] = Field(
        default=False, alias="externalDeliveryPerformed"
    )

    @field_validator("may_have_executed", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("incomplete campaign mayHaveExecuted must be a boolean")
        return value

    @model_validator(mode="after")
    def bind_incomplete(self) -> Self:
        if self.completed_stages != GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[
            : len(self.completed_stages)
        ]:
            raise ValueError("incomplete campaign completed-stage prefix differs")
        expected_stage = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[len(self.completed_stages)]
        if self.failure_stage != expected_stage:
            raise ValueError("incomplete campaign failure stage differs from progression")
        if self.may_have_executed is not (self.active_stage == self.failure_stage):
            raise ValueError("incomplete campaign execution uncertainty differs")
        expected_account_state = (
            "confirmed-retained"
            if "provisioning" in self.completed_stages
            else "may-have-executed"
            if self.active_stage == "provisioning"
            else "not-started"
        )
        if self.account_provisioning_state != expected_account_state:
            raise ValueError("incomplete campaign account provisioning state differs")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"incomplete_digest"}
        )
        expected = _digest("pajin.web.incomplete-governed-campaign/v1", material)
        if self.incomplete_digest and self.incomplete_digest != expected:
            raise ValueError("incomplete governed WEB Campaign Digest differs")
        object.__setattr__(self, "incomplete_digest", expected)
        return self


_INDEX_SIGNER_FACTORY_TOKEN = object()
_PARENT_WRITER_FACTORY_TOKEN = object()


class _ImmutableOpaque:
    __slots__ = ("__sealed",)

    def _seal_opaque(self) -> None:
        object.__setattr__(self, "_ImmutableOpaque__sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_ImmutableOpaque__sealed", False):
            raise AttributeError("governed WEB campaign evidence authority is immutable")
        object.__setattr__(self, name, value)

    def __copy__(self) -> Self:
        raise TypeError("governed WEB campaign evidence authority cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> Self:
        raise TypeError("governed WEB campaign evidence authority cannot be copied")

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("governed WEB campaign evidence authority cannot be serialized")


@final
class GovernedWebCampaignIndexSignerAuthority(_ImmutableOpaque):
    """Ephemeral signer; only its public trust bundle can be serialized."""

    __slots__ = ("__private_key", "__trust_bundle")

    def __init__(
        self,
        *,
        factory_token: object,
        private_key: Ed25519PrivateKey,
        trust_bundle: GovernedWebCampaignTrustBundle,
    ) -> None:
        if factory_token is not _INDEX_SIGNER_FACTORY_TOKEN:
            raise TypeError("campaign evidence index signer is generated only by its factory")
        self.__private_key = private_key
        self.__trust_bundle = trust_bundle
        self._seal_opaque()

    @property
    def trust_bundle(self) -> GovernedWebCampaignTrustBundle:
        return self.__trust_bundle.model_copy(deep=True)

    def _sign(self, index_digest: str, *, signed_at: datetime) -> str:
        key = self.__trust_bundle.index_signing_key
        at = _utc(signed_at, label="campaign evidence index signature time")
        if not key.not_before <= at < key.not_after:
            raise ValueError("campaign evidence index signer is inactive at signature time")
        return _encode_base64url(
            self.__private_key.sign(
                b"pajin.web.governed-campaign-index-signature/v1\0"
                + bytes.fromhex(index_digest)
            )
        )

    def _sign_plan(self, plan_digest: str, *, signed_at: datetime) -> str:
        key = self.__trust_bundle.index_signing_key
        at = _utc(signed_at, label="campaign evidence Plan signature time")
        if not key.not_before <= at < key.not_after:
            raise ValueError("campaign evidence signer is inactive at Plan signature time")
        return _encode_base64url(
            self.__private_key.sign(
                b"pajin.web.governed-campaign-plan-signature/v1\0"
                + bytes.fromhex(plan_digest)
            )
        )

    def _sign_database_checkpoint(
        self,
        checkpoint_digest: str,
        *,
        signed_at: datetime,
    ) -> str:
        key = self.__trust_bundle.index_signing_key
        at = _utc(signed_at, label="campaign database checkpoint signature time")
        if not key.not_before <= at < key.not_after:
            raise ValueError(
                "campaign evidence signer is inactive at database checkpoint time"
            )
        return _encode_base64url(
            self.__private_key.sign(
                b"pajin.web.governed-campaign-database-checkpoint-signature/v1\0"
                + bytes.fromhex(checkpoint_digest)
            )
        )


def generate_governed_web_campaign_evidence_signer(
    *,
    trust_material: GovernedWebCampaignTrustMaterial,
    not_before: datetime,
    not_after: datetime,
) -> GovernedWebCampaignIndexSignerAuthority:
    """Generate a process-local Ed25519 signer and public deployment trust bundle."""

    canonical_trust = GovernedWebCampaignTrustMaterial.model_validate(
        trust_material.model_dump(mode="json", by_alias=True)
    )
    before = _utc(not_before, label="campaign evidence signer not-before time")
    after = _utc(not_after, label="campaign evidence signer not-after time")
    if after <= before:
        raise ValueError("campaign evidence signer validity window is empty")
    private_key = Ed25519PrivateKey.generate()
    public = _encode_base64url(private_key.public_key().public_bytes_raw())
    key_digest = _digest(
        "pajin.web.governed-campaign-index-key/v1",
        {"publicKeyBase64url": public, "notBefore": before.isoformat()},
    )
    signing_key = GovernedWebCampaignIndexSigningKey(
        keyId=f"web.campaign-evidence.{key_digest[:24]}",
        publicKeyBase64url=public,
        notBefore=before,
        notAfter=after,
    )
    trust_bundle = GovernedWebCampaignTrustBundle(
        trustMaterial=canonical_trust,
        indexSigningKey=signing_key,
    )
    _require_distinct_trust_identities(trust_bundle)
    return GovernedWebCampaignIndexSignerAuthority(
        factory_token=_INDEX_SIGNER_FACTORY_TOKEN,
        private_key=private_key,
        trust_bundle=trust_bundle,
    )


def build_governed_web_campaign_trust_bundle(
    signer: GovernedWebCampaignIndexSignerAuthority,
) -> GovernedWebCampaignTrustBundle:
    """Return only the public half of one factory-generated index signer."""

    if type(signer) is not GovernedWebCampaignIndexSignerAuthority:
        raise TypeError("campaign trust bundle requires its generated index signer")
    bundle = signer.trust_bundle
    _require_distinct_trust_identities(bundle)
    return bundle


def _require_distinct_trust_identities(bundle: GovernedWebCampaignTrustBundle) -> None:
    trust = bundle.trust_material
    web_keys = (
        trust.adapter_key,
        trust.account_key,
        trust.source_approval_key,
        trust.validation_approval_key,
    )
    lifecycle_keys = (trust.lifecycle_publisher_key, trust.lifecycle_reviewer_key)
    public_keys = [
        _decode_base64url(
            key.public_key_base64url,
            size=32,
            label="governed WEB verification public key",
        )
        for key in web_keys
    ]
    public_keys.extend(
        _decode_base64url(
            key.public_key_base64url,
            size=32,
            label="governed WEB lifecycle public key",
        )
        for key in lifecycle_keys
    )
    public_keys.extend(
        _decode_base64url(
            key.public_key_base64url,
            size=32,
            label="governed WEB Worker public key",
        )
        for key in trust.worker_keys
    )
    public_keys.append(
        _decode_base64url(
            bundle.index_signing_key.public_key_base64url,
            size=32,
            label="governed WEB campaign evidence public key",
        )
    )
    key_ids = [key.key_id for key in web_keys]
    key_ids.extend(key.key_id for key in lifecycle_keys)
    key_ids.extend(key.key_id for key in trust.worker_keys)
    key_ids.append(bundle.index_signing_key.key_id)
    principals = [key.principal_id for key in web_keys]
    principals.extend(key.principal_id for key in lifecycle_keys)
    principals.extend(f"{trust.worker_issuer}/{key.role.value}" for key in trust.worker_keys)
    principals.append(bundle.index_signing_key.principal_id)
    if (
        len(public_keys) != len(set(public_keys))
        or len(key_ids) != len(set(key_ids))
        or len(principals) != len(set(principals))
    ):
        raise ValueError("governed WEB signing roles require distinct trust identities")


def _campaign_checkpoint_path(
    stage: GovernedWebCampaignStage,
    status: Literal["started", "completed"],
) -> str:
    ordinal = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER.index(stage) + 1
    return f"checkpoints/{ordinal:02d}-{stage}-{status}.json"


def _campaign_database_checkpoint_path(
    *,
    stage: GovernedWebCampaignStage,
    store_kind: GovernedWebCampaignDatabaseStoreKind,
    ordinal: int,
) -> str:
    stage_ordinal = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER.index(stage) + 1
    store = "graph" if store_kind == "governed-web-graph" else "grant"
    return (
        f"checkpoints/database/{stage_ordinal:02d}-{stage}-{store}-"
        f"{ordinal:08d}.json"
    )


def _campaign_parent_checkpoint_fault(
    _point: Literal["artifact-created", "event-appended", "seal-appended"],
    _artifact_path: str,
) -> None:
    """Test seam around one append-only parent checkpoint."""


@final
class GovernedWebCampaignParentWriter(_ImmutableOpaque):
    """One process-local append-only writer for a preallocated parent Run."""

    __slots__ = (
        "__active_checkpoint",
        "__active_intent",
        "__completed_stages",
        "__current_root_digest",
        "__database_checkpoint_ack_roots",
        "__database_checkpoint_parent_roots",
        "__database_checkpoints",
        "__database_fresh_bindings",
        "__externally_acked_parent_root_digest",
        "__factory_token",
        "__latest_database_checkpoint",
        "__lock",
        "__plan",
        "__signer",
        "__store",
        "__terminal",
    )

    def __init__(
        self,
        *,
        factory_token: object,
        store: RunStore,
        plan: GovernedWebCampaignPlan,
        signer: GovernedWebCampaignIndexSignerAuthority,
        current_root_digest: str,
    ) -> None:
        if factory_token is not _PARENT_WRITER_FACTORY_TOKEN:
            raise TypeError("governed WEB parent writer is created only by its factory")
        self.__factory_token = factory_token
        self.__store = store
        self.__plan = plan
        self.__signer = signer
        self.__current_root_digest = current_root_digest
        self.__completed_stages: tuple[GovernedWebCampaignStage, ...] = ()
        self.__database_checkpoints: tuple[
            GovernedWebCampaignDatabaseCheckpoint, ...
        ] = ()
        self.__database_checkpoint_ack_roots: dict[
            tuple[str, GovernedWebCampaignDatabaseStoreKind, int, str, str, str],
            str,
        ] = {}
        self.__database_checkpoint_parent_roots: dict[
            tuple[str, GovernedWebCampaignDatabaseStoreKind, int, str, str, str],
            str,
        ] = {}
        self.__database_fresh_bindings: dict[
            tuple[str, GovernedWebCampaignDatabaseStoreKind],
            tuple[str, str, bool],
        ] = {}
        self.__externally_acked_parent_root_digest: str | None = None
        self.__latest_database_checkpoint: (
            GovernedWebCampaignDatabaseCheckpoint | None
        ) = None
        self.__active_intent: GovernedWebCampaignStageIntent | None = None
        self.__active_checkpoint: GovernedWebCampaignCheckpoint | None = None
        self.__terminal = False
        self.__lock = threading.RLock()
        self._seal_opaque()

    @property
    def parent_run_id(self) -> str:
        return self.__store.run_id

    @property
    def parent_run_path(self) -> Path:
        return self.__store.path

    @property
    def current_root_digest(self) -> str:
        return self.__current_root_digest

    @property
    def deployment_trust_anchor_digest(self) -> str:
        return self.__plan.deployment_trust_anchor_digest

    @property
    def plan(self) -> GovernedWebCampaignPlan:
        return self.__plan.model_copy(deep=True)

    @property
    def latest_database_checkpoint(
        self,
    ) -> GovernedWebCampaignDatabaseCheckpoint | None:
        checkpoint = self.__latest_database_checkpoint
        return checkpoint.model_copy(deep=True) if checkpoint is not None else None

    def _acknowledge_external_progress(self, *, parent_root_digest: str) -> None:
        """Record a synchronous out-of-process ACK for the exact current seal."""

        with self.__lock:
            if self.__factory_token is not _PARENT_WRITER_FACTORY_TOKEN:
                raise ValueError("governed WEB parent writer differs from its factory")
            try:
                integrity = verify_run_integrity(self.__store.path)
            except (OSError, RunIntegrityError, ValueError) as exc:
                raise ValueError(
                    "governed WEB parent progress ACK cannot reload its seal"
                ) from exc
            if (
                re.fullmatch(_SHA256_PATTERN, parent_root_digest) is None
                or parent_root_digest != self.__current_root_digest
                or integrity.root_digest != parent_root_digest
            ):
                raise ValueError(
                    "governed WEB parent progress ACK differs from its current seal"
                )
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__externally_acked_parent_root_digest",
                parent_root_digest,
            )
            for key, checkpoint_root in self.__database_checkpoint_parent_roots.items():
                if checkpoint_root == parent_root_digest:
                    self.__database_checkpoint_ack_roots[key] = parent_root_digest

    def issue_database_fresh_authority(
        self,
        path: Path,
        *,
        store_kind: GovernedWebCampaignDatabaseStoreKind,
    ) -> object:
        """Mint one first-creation token from the externally ACKed parent seal."""

        with self.__lock:
            self._require_live()
            if not isinstance(path, Path) or store_kind not in _DATABASE_STORE_KINDS:
                raise TypeError("governed WEB database fresh authority input is invalid")
            relative = pinned_workspace_relative_path(
                path,
                label="governed WEB database fresh authority path",
            )
            expected_leaf = (
                "governed-web.sqlite3"
                if store_kind == "governed-web-graph"
                else "capability-grant-consumptions.sqlite3"
            )
            if relative is None or relative.parts != ("authority", expected_leaf):
                raise ValueError(
                    "governed WEB database fresh authority path differs from its store kind"
                )
            acknowledged = self.__externally_acked_parent_root_digest
            key = (relative.as_posix(), store_kind)
            if (
                acknowledged is None
                or acknowledged != self.__current_root_digest
                or key in self.__database_fresh_bindings
            ):
                raise ValueError(
                    "governed WEB database fresh authority lacks a current external ACK"
                )
            authority = _issue_pinned_sqlite_fresh_authority(
                path,
                store_kind=store_kind,
                campaign_id=self.__plan.campaign_id,
                witness_root_digest=acknowledged,
                parent_writer=self,
            )
            self.__database_fresh_bindings[key] = (
                acknowledged,
                self.__plan.campaign_plan_digest,
                False,
            )
            return authority

    def _consume_database_fresh_authority_binding(
        self,
        *,
        path: str,
        store_kind: str,
        campaign_id: str,
        witness_root_digest: str,
    ) -> None:
        """Consume the writer half of a runtime first-creation authority."""

        with self.__lock:
            self._require_live()
            try:
                typed_kind = cast(
                    GovernedWebCampaignDatabaseStoreKind,
                    store_kind,
                )
                binding = self.__database_fresh_bindings[(path, typed_kind)]
            except (KeyError, TypeError) as exc:
                raise ValueError(
                    "governed WEB database fresh authority was not issued"
                ) from exc
            expected_leaf = (
                "governed-web.sqlite3"
                if typed_kind == "governed-web-graph"
                else "capability-grant-consumptions.sqlite3"
            )
            acknowledged = self.__externally_acked_parent_root_digest
            try:
                integrity = verify_run_integrity(self.__store.path)
            except (OSError, RunIntegrityError, ValueError) as exc:
                raise ValueError(
                    "governed WEB database fresh authority lost its parent seal"
                ) from exc
            if (
                store_kind not in _DATABASE_STORE_KINDS
                or path != f"authority/{expected_leaf}"
                or campaign_id != self.__plan.campaign_id
                or binding
                != (
                    witness_root_digest,
                    self.__plan.campaign_plan_digest,
                    False,
                )
                or acknowledged != witness_root_digest
                or self.__current_root_digest != witness_root_digest
                or integrity.root_digest != witness_root_digest
            ):
                raise ValueError(
                    "governed WEB database fresh authority binding is no longer current"
                )
            self.__database_fresh_bindings[(path, typed_kind)] = (
                witness_root_digest,
                self.__plan.campaign_plan_digest,
                True,
            )

    def _require_database_checkpoint_external_ack(
        self,
        *,
        path: str,
        store_kind: str,
        checkpoint: PinnedSQLiteCheckpoint,
    ) -> None:
        """Require the latest runtime commit to have an externally ACKed parent seal."""

        with self.__lock:
            self._require_live()
            if type(checkpoint) is not PinnedSQLiteCheckpoint:
                raise TypeError(
                    "governed WEB database checkpoint ACK requires its exact runtime record"
                )
            if store_kind not in _DATABASE_STORE_KINDS:
                raise ValueError("governed WEB database checkpoint ACK store kind is invalid")
            typed_kind: GovernedWebCampaignDatabaseStoreKind = store_kind
            expected_leaf = (
                "governed-web.sqlite3"
                if typed_kind == "governed-web-graph"
                else "capability-grant-consumptions.sqlite3"
            )
            matches = tuple(
                item
                for item in self.__database_checkpoints
                if item.store_kind == typed_kind
                and item.ordinal == checkpoint.ordinal
                and item.manifest_digest == checkpoint.manifest_digest
                and item.database_sha256 == checkpoint.database_sha256
                and item.state_digest == checkpoint.state_digest
            )
            latest = matches[0] if len(matches) == 1 else None
            acknowledged = self.__externally_acked_parent_root_digest
            key = (
                path,
                typed_kind,
                checkpoint.ordinal,
                checkpoint.manifest_digest,
                checkpoint.database_sha256,
                checkpoint.state_digest,
            )
            checkpoint_parent_root = self.__database_checkpoint_parent_roots.get(key)
            if (
                path != f"authority/{expected_leaf}"
                or latest is None
                or latest.store_kind != typed_kind
                or latest.ordinal != checkpoint.ordinal
                or latest.manifest_reference != checkpoint.manifest_reference
                or latest.manifest_digest != checkpoint.manifest_digest
                or latest.manifest_sha256 != checkpoint.manifest_sha256
                or latest.manifest_size != checkpoint.manifest_size
                or latest.previous_manifest_digest
                != checkpoint.previous_manifest_digest
                or latest.database_reference != checkpoint.database_reference
                or latest.database_sha256 != checkpoint.database_sha256
                or latest.database_size != checkpoint.database_size
                or latest.state_digest != checkpoint.state_digest
                or checkpoint_parent_root is None
                or self.__database_checkpoint_ack_roots.get(key)
                != checkpoint_parent_root
                or acknowledged is None
                or acknowledged != self.__current_root_digest
            ):
                raise ValueError(
                    "governed WEB database checkpoint lacks its exact external ACK"
                )
            artifact_path = _campaign_database_checkpoint_path(
                stage=latest.stage,
                store_kind=typed_kind,
                ordinal=latest.ordinal,
            )
            try:
                stored = GovernedWebCampaignDatabaseCheckpoint.model_validate(
                    parse_strict_json_bytes(
                        read_bounded_regular_bytes(
                            self.__store.path / artifact_path,
                            max_bytes=_MAX_CHECKPOINT_BYTES,
                            label="governed WEB database checkpoint ACK artifact",
                            require_single_link=True,
                        ),
                        label="governed WEB database checkpoint ACK artifact",
                        max_bytes=_MAX_CHECKPOINT_BYTES,
                    )
                )
                integrity = verify_run_integrity(self.__store.path)
            except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
                raise ValueError(
                    "governed WEB database checkpoint ACK cannot reload its parent proof"
                ) from exc
            signing_key = self.__signer.trust_bundle.index_signing_key
            if (
                stored != latest
                or stored.signer_key_id != signing_key.key_id
                or not signing_key.not_before <= stored.recorded_at < signing_key.not_after
                or integrity.root_digest != acknowledged
            ):
                raise ValueError(
                    "governed WEB database checkpoint ACK differs from its parent proof"
                )
            try:
                _verify_ed25519_statement(
                    public_key_base64url=signing_key.public_key_base64url,
                    signature_base64url=stored.signature_base64url,
                    payload=stored.signed_bytes(),
                    label="governed WEB database checkpoint ACK",
                )
            except ValueError as exc:
                raise ValueError(
                    "governed WEB database checkpoint ACK signature is invalid"
                ) from exc

    def begin_stage(
        self,
        stage: GovernedWebCampaignStage,
        intent: GovernedWebCampaignStageIntent,
        occurred_at: datetime,
    ) -> str:
        with self.__lock:
            self._require_live()
            expected = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[len(self.__completed_stages)]
            canonical = GovernedWebCampaignStageIntent.model_validate(
                intent.model_dump(mode="json", by_alias=True)
            )
            if stage != expected or canonical.stage != stage or self.__active_intent is not None:
                raise ValueError("governed WEB parent stage start is out of order")
            checkpoint = GovernedWebCampaignCheckpoint(
                campaignPlanDigest=self.__plan.campaign_plan_digest,
                stage=stage,
                status="started",
                ordinal=len(self.__completed_stages) + 1,
                completedStages=self.__completed_stages,
                intent=canonical,
                mayHaveExecuted=True,
            )
            path = _campaign_checkpoint_path(stage, "started")
            self._append_checkpoint(path, checkpoint, occurred_at=occurred_at)
            object.__setattr__(self, "_GovernedWebCampaignParentWriter__active_intent", canonical)
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__active_checkpoint",
                checkpoint,
            )
            return self.__current_root_digest

    def complete_stage(
        self,
        stage: GovernedWebCampaignStage,
        observed: GovernedWebCampaignStageObservation,
        occurred_at: datetime,
    ) -> str:
        with self.__lock:
            self._require_live()
            if stage == "parent-evidence":
                raise ValueError(
                    "parent-evidence completes atomically with the terminal evidence group"
                )
            canonical = GovernedWebCampaignStageObservation.model_validate(
                observed.model_dump(mode="json", by_alias=True)
            )
            started = self.__active_checkpoint
            if (
                self.__active_intent is None
                or started is None
                or stage != started.stage
                or canonical.stage != stage
            ):
                raise ValueError("governed WEB parent stage completion has no matching start")
            completed = (*self.__completed_stages, stage)
            checkpoint = GovernedWebCampaignCheckpoint(
                campaignPlanDigest=self.__plan.campaign_plan_digest,
                stage=stage,
                status="completed",
                ordinal=len(completed),
                completedStages=completed,
                startedCheckpointDigest=started.checkpoint_digest,
                observation=canonical,
                mayHaveExecuted=False,
            )
            path = _campaign_checkpoint_path(stage, "completed")
            self._append_checkpoint(path, checkpoint, occurred_at=occurred_at)
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__completed_stages",
                completed,
            )
            object.__setattr__(self, "_GovernedWebCampaignParentWriter__active_intent", None)
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__active_checkpoint",
                None,
            )
            return self.__current_root_digest

    def record_database_checkpoint(
        self,
        *,
        stage: GovernedWebCampaignStage,
        store_kind: GovernedWebCampaignDatabaseStoreKind,
        checkpoint: PinnedSQLiteCheckpoint,
        occurred_at: datetime,
    ) -> str:
        """Seal and ACK one exact pinned SQLite commit inside an active stage."""

        with self.__lock:
            self._require_live()
            active = self.__active_checkpoint
            if (
                active is None
                or self.__active_intent is None
                or active.stage != stage
                or stage
                not in {
                    "provisioning",
                    "source-gateway",
                    "validation-gateway",
                    "graph-admission",
                }
                or store_kind not in _DATABASE_STORE_KINDS
                or type(checkpoint) is not PinnedSQLiteCheckpoint
            ):
                raise ValueError(
                    "governed WEB database checkpoint requires its active action stage"
                )
            try:
                raw_state = parse_strict_json_bytes(
                    checkpoint.state_json,
                    label="governed WEB database checkpoint state",
                    max_bytes=2 * 1024 * 1024,
                    max_depth=32,
                    max_nodes=20_000,
                )
            except ValueError as exc:
                raise ValueError(
                    "governed WEB database checkpoint state is invalid"
                ) from exc
            if (
                not isinstance(raw_state, dict)
                or _canonical_bytes(raw_state) != checkpoint.state_json
            ):
                raise ValueError(
                    "governed WEB database checkpoint state is not canonical"
                )
            _require_public_safe(
                cast(JsonValue, raw_state),
                label="governed WEB database checkpoint state",
            )
            previous = next(
                (
                    item
                    for item in reversed(self.__database_checkpoints)
                    if item.store_kind == store_kind
                ),
                None,
            )
            if (
                checkpoint.ordinal != (1 if previous is None else previous.ordinal + 1)
                or checkpoint.previous_manifest_digest
                != (None if previous is None else previous.manifest_digest)
            ):
                raise ValueError(
                    "governed WEB database checkpoint lineage is not contiguous"
                )
            occurred_at = _utc(
                occurred_at,
                label="governed WEB database checkpoint event time",
            )
            provisional = GovernedWebCampaignDatabaseCheckpoint(
                campaignPlanDigest=self.__plan.campaign_plan_digest,
                stage=cast(
                    Literal[
                        "provisioning",
                        "source-gateway",
                        "validation-gateway",
                        "graph-admission",
                    ],
                    stage,
                ),
                storeKind=store_kind,
                ordinal=checkpoint.ordinal,
                manifestReference=checkpoint.manifest_reference,
                manifestDigest=checkpoint.manifest_digest,
                manifestSha256=checkpoint.manifest_sha256,
                manifestSize=checkpoint.manifest_size,
                previousManifestDigest=checkpoint.previous_manifest_digest,
                databaseReference=checkpoint.database_reference,
                databaseSha256=checkpoint.database_sha256,
                databaseSize=checkpoint.database_size,
                stateDigest=checkpoint.state_digest,
                previousParentRootDigest=self.__current_root_digest,
                recordedAt=occurred_at,
                signerKeyId=self.__signer.trust_bundle.index_signing_key.key_id,
                signatureBase64url=_encode_base64url(bytes(64)),
            )
            signed = GovernedWebCampaignDatabaseCheckpoint.model_validate(
                provisional.model_copy(
                    update={
                        "signature_base64url": self.__signer._sign_database_checkpoint(
                            provisional.checkpoint_digest,
                            signed_at=occurred_at,
                        )
                    }
                ).model_dump(mode="json", by_alias=True)
            )
            path = _campaign_database_checkpoint_path(
                stage=stage,
                store_kind=store_kind,
                ordinal=checkpoint.ordinal,
            )
            self.__store.write_json_create_only(
                path,
                signed.model_dump(mode="json", by_alias=True),
            )
            _campaign_parent_checkpoint_fault("artifact-created", path)
            self.__store.append_event(
                "web.governed.database-checkpoint",
                {
                    "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
                    "stage": stage,
                    "storeKind": store_kind,
                    "ordinal": checkpoint.ordinal,
                    "checkpointPath": path,
                    "checkpointDigest": signed.checkpoint_digest,
                    "manifestReference": signed.manifest_reference,
                    "manifestDigest": signed.manifest_digest,
                    "manifestSha256": signed.manifest_sha256,
                    "manifestSize": signed.manifest_size,
                    "databaseReference": signed.database_reference,
                    "databaseSha256": signed.database_sha256,
                    "databaseSize": signed.database_size,
                    "stateDigest": signed.state_digest,
                    "previousParentRootDigest": signed.previous_parent_root_digest,
                },
                occurred_at=occurred_at,
            )
            _campaign_parent_checkpoint_fault("event-appended", path)
            self._seal(path)
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__database_checkpoints",
                (*self.__database_checkpoints, signed),
            )
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__latest_database_checkpoint",
                signed,
            )
            expected_leaf = (
                "governed-web.sqlite3"
                if store_kind == "governed-web-graph"
                else "capability-grant-consumptions.sqlite3"
            )
            key = (
                f"authority/{expected_leaf}",
                store_kind,
                checkpoint.ordinal,
                checkpoint.manifest_digest,
                checkpoint.database_sha256,
                checkpoint.state_digest,
            )
            self.__database_checkpoint_parent_roots[key] = self.__current_root_digest
            return self.__current_root_digest

    def complete(
        self,
        evidence: GovernedWebCompletedCampaignEvidence,
        result: GovernedWebCampaignHistoricalResult,
        completed_at: datetime,
    ) -> GovernedWebCampaignIndex:
        with self.__lock:
            self._require_live()
            active = self.__active_checkpoint
            if (
                self.__completed_stages != GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[:-1]
                or self.__active_intent is None
                or active is None
                or active.stage != "parent-evidence"
            ):
                raise ValueError(
                    "governed WEB parent completion requires an active parent-evidence stage"
                )
            canonical_evidence = GovernedWebCompletedCampaignEvidence.model_validate(
                evidence.model_dump(mode="json", by_alias=True)
            )
            canonical_result = GovernedWebCampaignHistoricalResult.model_validate(
                result.model_dump(mode="json", by_alias=True)
            )
            self._require_completion_links(canonical_evidence, canonical_result)
            _verify_completed_external_chain(
                self.parent_run_path,
                self.__plan,
                canonical_evidence,
                canonical_result,
                database_checkpoints=self.__database_checkpoints,
            )
            completed_at = _utc(completed_at, label="governed WEB campaign completion time")
            completed_checkpoint = GovernedWebCampaignCheckpoint(
                campaignPlanDigest=self.__plan.campaign_plan_digest,
                stage="parent-evidence",
                status="completed",
                ordinal=len(GOVERNED_WEB_CAMPAIGN_STAGE_ORDER),
                completedStages=GOVERNED_WEB_CAMPAIGN_STAGE_ORDER,
                startedCheckpointDigest=active.checkpoint_digest,
                observation=GovernedWebCampaignStageObservation(
                    stage="parent-evidence",
                    observed={
                        "evidenceDigest": canonical_evidence.evidence_digest,
                        "campaignDigest": canonical_result.campaign_digest,
                        "finalGraphSnapshotDigest": (
                            canonical_evidence.final_graph_snapshot.snapshot_digest
                        ),
                    },
                ),
                mayHaveExecuted=False,
            )
            completed_checkpoint_path = _campaign_checkpoint_path(
                "parent-evidence",
                "completed",
            )
            self.__store.write_json_create_only(
                completed_checkpoint_path,
                completed_checkpoint.model_dump(mode="json", by_alias=True),
            )
            self.__store.write_json_create_only(
                _CAMPAIGN_EVIDENCE_PATH,
                canonical_evidence.model_dump(mode="json", by_alias=True),
            )
            self.__store.write_json_create_only(
                _CAMPAIGN_RESULT_PATH,
                canonical_result.model_dump(mode="json", by_alias=True),
            )
            artifacts = tuple(
                self._index_artifact(path)
                for path in (
                    _CAMPAIGN_PLAN_PATH,
                    _CAMPAIGN_EVIDENCE_PATH,
                    _CAMPAIGN_RESULT_PATH,
                )
            )
            provisional_signature = _encode_base64url(bytes(64))
            provisional = GovernedWebCampaignIndex(
                parentRunId=self.parent_run_id,
                campaignPlanDigest=self.__plan.campaign_plan_digest,
                evidenceDigest=canonical_evidence.evidence_digest,
                deploymentTrustAnchorDigest=self.deployment_trust_anchor_digest,
                finalGraphSnapshotId=canonical_evidence.final_graph_snapshot.snapshot_id,
                finalGraphSnapshotDigest=canonical_evidence.final_graph_snapshot.snapshot_digest,
                artifacts=artifacts,
                signedAt=completed_at,
                signerKeyId=self.__signer.trust_bundle.index_signing_key.key_id,
                signatureBase64url=provisional_signature,
            )
            index = provisional.model_copy(
                update={
                    "signature_base64url": self.__signer._sign(
                        provisional.index_digest,
                        signed_at=completed_at,
                    )
                }
            )
            index = GovernedWebCampaignIndex.model_validate(
                index.model_dump(mode="json", by_alias=True)
            )
            self.__store.write_json_create_only(
                _CAMPAIGN_INDEX_PATH,
                index.model_dump(mode="json", by_alias=True),
            )
            _campaign_parent_checkpoint_fault(
                "artifact-created",
                completed_checkpoint_path,
            )
            self.__store.append_event(
                "web.governed.stage.completed",
                {
                    "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
                    "stage": "parent-evidence",
                    "checkpointPath": completed_checkpoint_path,
                    "checkpointDigest": completed_checkpoint.checkpoint_digest,
                    "mayHaveExecuted": False,
                },
                occurred_at=completed_at,
            )
            self.__store.append_event(
                "campaign.completed",
                {
                    "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
                    "campaignPlanDigest": self.__plan.campaign_plan_digest,
                    "evidenceDigest": canonical_evidence.evidence_digest,
                    "indexDigest": index.index_digest,
                    "deploymentTrustAnchorDigest": self.deployment_trust_anchor_digest,
                    "externalDeliveryPerformed": False,
                },
                occurred_at=completed_at,
            )
            _campaign_parent_checkpoint_fault(
                "event-appended",
                completed_checkpoint_path,
            )
            self._seal("campaign-completion")
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__completed_stages",
                GOVERNED_WEB_CAMPAIGN_STAGE_ORDER,
            )
            object.__setattr__(self, "_GovernedWebCampaignParentWriter__active_intent", None)
            object.__setattr__(
                self,
                "_GovernedWebCampaignParentWriter__active_checkpoint",
                None,
            )
            object.__setattr__(self, "_GovernedWebCampaignParentWriter__terminal", True)
            return index.model_copy(deep=True)

    def fail(self, failure_type: str, failed_at: datetime) -> GovernedWebIncompleteCampaignEvidence:
        with self.__lock:
            self._require_live()
            prefix = _load_parent_sealed_prefix(
                self.__store.path,
                expected_parent_run_id=self.__store.run_id,
                expected_parent_root_digest=self.__current_root_digest,
            )
            if prefix.root_digest != self.__current_root_digest:
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB parent root differs before failure sealing"
                )
            completed_stages, active = _failure_progression_for_writer(self.__store)
            if len(completed_stages) >= len(GOVERNED_WEB_CAMPAIGN_STAGE_ORDER):
                raise ValueError("governed WEB completed stages cannot be failed")
            stage = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[len(completed_stages)]
            incomplete = GovernedWebIncompleteCampaignEvidence(
                failureStage=stage,
                failureType=failure_type,
                completedStages=completed_stages,
                activeStage=active,
                mayHaveExecuted=active == stage,
                accountProvisioningState=(
                    "confirmed-retained"
                    if "provisioning" in completed_stages
                    else "may-have-executed"
                    if active == "provisioning"
                    else "not-started"
                ),
                previousJournalRootDigest=self.__current_root_digest,
            )
            failed_at = _utc(failed_at, label="governed WEB campaign failure time")
            self.__store.write_json_create_only(
                _INCOMPLETE_PATH,
                incomplete.model_dump(mode="json", by_alias=True),
            )
            self.__store.append_event(
                "campaign.failed",
                {
                    "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
                    "failureStage": stage,
                    "failureType": failure_type,
                    "incompleteDigest": incomplete.incomplete_digest,
                    "mayHaveExecuted": incomplete.may_have_executed,
                    "externalDeliveryPerformed": False,
                },
                occurred_at=failed_at,
            )
            self._seal("campaign-failure")
            object.__setattr__(self, "_GovernedWebCampaignParentWriter__terminal", True)
            return incomplete.model_copy(deep=True)

    def _append_checkpoint(
        self,
        path: str,
        checkpoint: GovernedWebCampaignCheckpoint,
        *,
        occurred_at: datetime,
    ) -> None:
        occurred_at = _utc(occurred_at, label="governed WEB campaign checkpoint time")
        self.__store.write_json_create_only(
            path,
            checkpoint.model_dump(mode="json", by_alias=True),
        )
        _campaign_parent_checkpoint_fault("artifact-created", path)
        self.__store.append_event(
            f"web.governed.stage.{checkpoint.status}",
            {
                "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
                "stage": checkpoint.stage,
                "checkpointPath": path,
                "checkpointDigest": checkpoint.checkpoint_digest,
                "mayHaveExecuted": checkpoint.may_have_executed,
            },
            occurred_at=occurred_at,
        )
        _campaign_parent_checkpoint_fault("event-appended", path)
        self._seal(path)

    def _seal(self, artifact_path: str) -> None:
        seal = self.__store.seal()
        object.__setattr__(
            self,
            "_GovernedWebCampaignParentWriter__externally_acked_parent_root_digest",
            None,
        )
        object.__setattr__(
            self,
            "_GovernedWebCampaignParentWriter__current_root_digest",
            seal.root_digest,
        )
        _campaign_parent_checkpoint_fault("seal-appended", artifact_path)
        integrity = verify_run_integrity(self.__store.path)
        if integrity.root_digest != seal.root_digest or not integrity.valid:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent journal failed post-seal verification"
            )

    def _index_artifact(self, path: str) -> GovernedWebCampaignIndexArtifact:
        content = read_bounded_regular_bytes(
            self.__store.path / path,
            max_bytes=_MAX_EVIDENCE_BYTES,
            label=f"governed WEB parent artifact {path}",
            require_single_link=True,
        )
        return GovernedWebCampaignIndexArtifact(
            path=cast(_CampaignIndexArtifactPath, path),
            sha256=sha256(content).hexdigest(),
            sizeBytes=len(content),
        )

    def _require_completion_links(
        self,
        evidence: GovernedWebCompletedCampaignEvidence,
        result: GovernedWebCampaignHistoricalResult,
    ) -> None:
        planned = self.__plan.planned_runs
        if (
            evidence.trust_bundle != self.__signer.trust_bundle
            or evidence.campaign_id != result.campaign_id
            or evidence.campaign_digest != result.campaign_digest
            or result.deployment_trust_anchor_digest != self.deployment_trust_anchor_digest
            or result.source_run_id != planned.source_browser_run_id
            or result.validation_run_id != planned.validation_browser_run_id
            or result.source_gateway_run_id != planned.source_gateway_run_id
            or result.validation_gateway_run_id != planned.validation_gateway_run_id
            or result.validation_projection_run_id != planned.validation_projection_run_id
            or result.validation_projection_root_digest != evidence.validation_root_digest
            or result.sarif_digest != evidence.sarif_digest
            or result.poc_manifest_digest != evidence.poc_manifest_digest
            or result.graph_event_count != evidence.final_graph_snapshot.revision
        ):
            raise ValueError("governed WEB completion evidence differs from its Plan or result")

    def _require_live(self) -> None:
        if self.__factory_token is not _PARENT_WRITER_FACTORY_TOKEN or self.__terminal:
            raise ValueError("governed WEB parent writer is no longer active")


def begin_governed_web_campaign_parent(
    output_root: Path,
    *,
    planned_runs: GovernedWebCampaignPlannedRuns,
    trust_material: GovernedWebCampaignTrustMaterial,
    started_at: datetime,
    signer_not_after: datetime,
) -> GovernedWebCampaignParentWriter:
    """Create and seal the plan/start checkpoint before any irreversible stage."""

    if not isinstance(output_root, Path):
        raise TypeError("governed WEB campaign output root must be a Path")
    canonical_runs = GovernedWebCampaignPlannedRuns.model_validate(
        planned_runs.model_dump(mode="json", by_alias=True)
    )
    canonical_trust = GovernedWebCampaignTrustMaterial.model_validate(
        trust_material.model_dump(mode="json", by_alias=True)
    )
    started_at = _utc(started_at, label="governed WEB campaign start time")
    signer = generate_governed_web_campaign_evidence_signer(
        trust_material=canonical_trust,
        not_before=started_at,
        not_after=signer_not_after,
    )
    bundle = signer.trust_bundle
    provisional_plan = GovernedWebCampaignPlan(
        plannedRuns=canonical_runs,
        trustBundle=bundle,
        deploymentTrustAnchorDigest=bundle.deployment_trust_anchor_digest,
        signerKeyId=bundle.index_signing_key.key_id,
        signedAt=started_at,
        signatureBase64url=_encode_base64url(bytes(64)),
    )
    plan = GovernedWebCampaignPlan.model_validate(
        provisional_plan.model_copy(
            update={
                "signature_base64url": signer._sign_plan(
                    provisional_plan.campaign_plan_digest,
                    signed_at=started_at,
                )
            }
        ).model_dump(mode="json", by_alias=True)
    )
    store = RunStore.create(
        output_root / "campaign-runs",
        GOVERNED_WEB_CAMPAIGN_ID,
        run_id=canonical_runs.parent_run_id,
    )
    store.write_json_create_only(
        _CAMPAIGN_PLAN_PATH,
        plan.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "campaign.started",
        {
            "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
            "origin": GOVERNED_WEB_ORIGIN,
            "adapterRef": GOVERNED_WEB_ADAPTER_REF,
            "campaignPlanDigest": plan.campaign_plan_digest,
            "deploymentTrustAnchorDigest": bundle.deployment_trust_anchor_digest,
            "credentialsPersisted": False,
            "externalDeliveryPerformed": False,
        },
        occurred_at=started_at,
    )
    seal = store.seal()
    integrity = verify_run_integrity(store.path)
    if integrity.seal_count != 1 or integrity.root_digest != seal.root_digest:
        raise GovernedWebCampaignEvidenceError("initial governed WEB parent seal differs")
    return GovernedWebCampaignParentWriter(
        factory_token=_PARENT_WRITER_FACTORY_TOKEN,
        store=store,
        plan=plan,
        signer=signer,
        current_root_digest=seal.root_digest,
    )


@dataclass(frozen=True, slots=True)
class VerifiedGovernedWebCompletedCampaign:
    """A fully reloaded historical receipt; it grants no runtime authority."""

    parent_run_path: Path
    parent_run_id: str
    parent_root_digest: str
    deployment_trust_anchor_digest: str
    plan: GovernedWebCampaignPlan
    evidence: GovernedWebCompletedCampaignEvidence
    result: GovernedWebCampaignHistoricalResult
    index: GovernedWebCampaignIndex
    events: tuple[AuditEvent, ...]
    seals: tuple[RunIntegritySeal, ...]
    relative_references: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class VerifiedGovernedWebIncompleteCampaign:
    """The latest valid historical prefix of a failed or interrupted campaign."""

    parent_run_path: Path
    parent_run_id: str
    parent_root_digest: str
    deployment_trust_anchor_digest: str
    plan: GovernedWebCampaignPlan
    incomplete: GovernedWebIncompleteCampaignEvidence
    terminal: Literal["failed", "interrupted"]
    completed_stages: tuple[GovernedWebCampaignStage, ...]
    active_stage: GovernedWebCampaignStage | None
    active_intent: GovernedWebCampaignStageIntent | None
    observations: tuple[GovernedWebCampaignStageObservation, ...]
    events: tuple[AuditEvent, ...]
    seals: tuple[RunIntegritySeal, ...]
    has_unsealed_tail: bool
    relative_references: Mapping[str, str]


VerifiedGovernedWebCampaign = (
    VerifiedGovernedWebCompletedCampaign | VerifiedGovernedWebIncompleteCampaign
)


@dataclass(frozen=True, slots=True)
class _ParentSealedPrefix:
    run_path: Path
    run_id: str
    root_digest: str
    events: tuple[AuditEvent, ...]
    seals: tuple[RunIntegritySeal, ...]
    artifacts: Mapping[str, bytes]
    has_unsealed_tail: bool


@dataclass(frozen=True, slots=True)
class _CampaignProgression:
    completed: tuple[GovernedWebCampaignStage, ...]
    active_checkpoint: GovernedWebCampaignCheckpoint | None
    intents: tuple[GovernedWebCampaignStageIntent, ...]
    observations: tuple[GovernedWebCampaignStageObservation, ...]
    database_checkpoints: tuple[GovernedWebCampaignDatabaseCheckpoint, ...]
    terminal_event: AuditEvent | None


_KNOWN_PARENT_ARTIFACTS: Final = frozenset(
    {
        _CAMPAIGN_PLAN_PATH,
        _CAMPAIGN_EVIDENCE_PATH,
        _CAMPAIGN_RESULT_PATH,
        _CAMPAIGN_INDEX_PATH,
        _INCOMPLETE_PATH,
        *(
            _campaign_checkpoint_path(stage, status)
            for stage in GOVERNED_WEB_CAMPAIGN_STAGE_ORDER
            for status in _CAMPAIGN_CHECKPOINT_STATUSES
        ),
    }
)
_DATABASE_CHECKPOINT_ARTIFACT_PATTERN: Final = re.compile(
    r"^checkpoints/database/(?:01-provisioning|02-source-gateway|03-validation-gateway|"
    r"04-graph-admission)-(?:graph|grant)-[0-9]{8}\.json$"
)
_PARENT_MEDIA_TYPES: Final = MappingProxyType(
    {
        ".json": "application/json",
        ".jsonl": "application/x-ndjson",
        ".md": "text/markdown",
        ".txt": "text/plain",
        ".yaml": "application/yaml",
        ".yml": "application/yaml",
    }
)


def _is_known_parent_artifact(path: str) -> bool:
    return path in _KNOWN_PARENT_ARTIFACTS or (
        _DATABASE_CHECKPOINT_ARTIFACT_PATTERN.fullmatch(path) is not None
    )


def _normalized_parent_run_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("governed WEB parent Run path must be a Path")
    pinned = pinned_workspace_relative_path(path, label="governed WEB parent Run path")
    try:
        return pinned if pinned is not None else path.resolve(strict=True)
    except OSError as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent Run path is unavailable"
        ) from exc


def _complete_jsonl_records(
    content: bytes,
    *,
    label: str,
    max_record_bytes: int,
    max_records: int,
) -> tuple[tuple[bytes, ...], bool]:
    if not content:
        raise GovernedWebCampaignEvidenceError(f"{label} is empty")
    pieces = content.split(b"\n")
    trailing = pieces.pop()
    has_partial_tail = bool(trailing)
    if len(pieces) > max_records:
        raise GovernedWebCampaignEvidenceError(f"{label} has too many records")
    records: list[bytes] = []
    for raw in pieces:
        if not raw:
            raise GovernedWebCampaignEvidenceError(f"{label} contains a blank record")
        if len(raw) > max_record_bytes:
            raise GovernedWebCampaignEvidenceError(f"{label} record is too large")
        records.append(raw)
    if not records:
        raise GovernedWebCampaignEvidenceError(f"{label} has no complete record")
    return tuple(records), has_partial_tail


def _parse_parent_events(
    content: bytes,
    *,
    expected_run_id: str,
    stop_after: int | None = None,
) -> tuple[tuple[AuditEvent, ...], bool]:
    records, partial_tail = _complete_jsonl_records(
        content,
        label="governed WEB parent event stream",
        max_record_bytes=_MAX_RECORD_BYTES,
        max_records=_MAX_RECORDS,
    )
    if stop_after is not None:
        if stop_after < 1 or len(records) < stop_after:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent event stream is shorter than its seal"
            )
        selected_records = records[:stop_after]
        partial_tail = partial_tail or len(records) > stop_after
    else:
        selected_records = records
    events: list[AuditEvent] = []
    previous_hash: str | None = None
    previous_time: datetime | None = None
    for sequence, record in enumerate(selected_records, start=1):
        try:
            raw = parse_strict_json_bytes(
                record,
                label=f"governed WEB parent event {sequence}",
                max_bytes=_MAX_RECORD_BYTES,
            )
            event = AuditEvent.model_validate(raw)
        except ValueError as exc:
            raise GovernedWebCampaignEvidenceError(
                f"governed WEB parent event {sequence} is invalid"
            ) from exc
        occurred_at = _utc(event.occurred_at, label="governed WEB parent event time")
        if (
            event.run_id != expected_run_id
            or event.sequence != sequence
            or event.previous_hash != previous_hash
            or event.event_hash != event.computed_hash()
        ):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent event chain differs"
            )
        if previous_time is not None and occurred_at < previous_time:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent event time moved backwards"
            )
        events.append(event)
        previous_hash = event.event_hash
        previous_time = occurred_at
    return tuple(events), partial_tail


def _failure_progression_for_writer(
    store: RunStore,
) -> tuple[tuple[GovernedWebCampaignStage, ...], GovernedWebCampaignStage | None]:
    """Recover writer-authored state, including a well-formed unsealed tail."""

    try:
        content = read_bounded_regular_bytes(
            store.events_path,
            max_bytes=_MAX_EVENT_LOG_BYTES,
            label="governed WEB parent event stream before failure",
            require_single_link=True,
        )
    except (OSError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent event stream cannot be recovered for failure"
        ) from exc
    events, partial_tail = _parse_parent_events(content, expected_run_id=store.run_id)
    if partial_tail:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent has a malformed partial event tail"
        )
    completed: list[GovernedWebCampaignStage] = []
    active: GovernedWebCampaignStage | None = None
    for event in events[1:]:
        if event.event_type in {"campaign.completed", "campaign.failed"}:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent already has a terminal event"
            )
        if len(completed) >= len(GOVERNED_WEB_CAMPAIGN_STAGE_ORDER):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent stage tail extends past its inventory"
            )
        expected = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[len(completed)]
        if event.event_type == "web.governed.stage.started" and active is None:
            if event.payload.get("stage") != expected:
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB parent unsealed stage start is out of order"
                )
            active = expected
        elif event.event_type == "web.governed.database-checkpoint" and active == expected:
            payload = event.payload
            if (
                payload.get("campaignId") != GOVERNED_WEB_CAMPAIGN_ID
                or payload.get("stage") != expected
                or payload.get("storeKind") not in _DATABASE_STORE_KINDS
                or type(payload.get("ordinal")) is not int
                or cast(int, payload["ordinal"]) < 1
            ):
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB parent database checkpoint progression is invalid"
                )
        elif event.event_type == "web.governed.stage.completed" and active == expected:
            completed.append(expected)
            active = None
        else:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent unsealed stage progression is invalid"
            )
    return tuple(completed), active


def _parse_parent_seals(
    content: bytes,
    *,
    expected_run_id: str,
) -> tuple[tuple[RunIntegritySeal, ...], bool]:
    records, partial_tail = _complete_jsonl_records(
        content,
        label="governed WEB parent integrity stream",
        max_record_bytes=_MAX_RECORD_BYTES,
        max_records=_MAX_RECORDS,
    )
    seals: list[RunIntegritySeal] = []
    previous_root: str | None = None
    previous_event_count = 0
    for sequence, record in enumerate(records, start=1):
        try:
            raw = parse_strict_json_bytes(
                record,
                label=f"governed WEB parent seal {sequence}",
                max_bytes=_MAX_RECORD_BYTES,
            )
            seal = RunIntegritySeal.model_validate(raw)
        except ValueError as exc:
            raise GovernedWebCampaignEvidenceError(
                f"governed WEB parent seal {sequence} is invalid"
            ) from exc
        if (
            seal.api_version != "pajin.dev/run-integrity/v1"
            or seal.run_id != expected_run_id
            or seal.sequence != sequence
            or seal.previous_root_digest != previous_root
            or seal.event_count < previous_event_count
            or seal.artifacts != sorted(seal.artifacts, key=lambda item: item.path)
            or seal.artifact_root_digest != seal.computed_artifact_root_digest()
            or seal.root_digest != seal.computed_root_digest()
        ):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent seal chain differs"
            )
        seals.append(seal)
        previous_root = seal.root_digest
        previous_event_count = seal.event_count
    return tuple(seals), partial_tail


def _parse_selected_parent_seals(
    content: bytes,
    *,
    expected_run_id: str,
    expected_root_digest: str | None,
) -> tuple[tuple[RunIntegritySeal, ...], bool]:
    """Verify only the caller-pinned seal prefix; later bytes are untrusted tail."""

    if not content:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent integrity stream is empty"
        )
    seals: list[RunIntegritySeal] = []
    previous_root: str | None = None
    previous_event_count = 0
    offset = 0
    for sequence in range(1, _MAX_RECORDS + 1):
        newline = content.find(b"\n", offset)
        if newline < 0:
            break
        record = content[offset:newline]
        offset = newline + 1
        if not record or len(record) > _MAX_RECORD_BYTES:
            raise GovernedWebCampaignEvidenceError(
                f"governed WEB parent seal {sequence} is invalid"
            )
        try:
            raw = parse_strict_json_bytes(
                record,
                label=f"governed WEB parent seal {sequence}",
                max_bytes=_MAX_RECORD_BYTES,
            )
            seal = RunIntegritySeal.model_validate(raw)
        except ValueError as exc:
            raise GovernedWebCampaignEvidenceError(
                f"governed WEB parent seal {sequence} is invalid"
            ) from exc
        if (
            seal.api_version != "pajin.dev/run-integrity/v1"
            or seal.run_id != expected_run_id
            or seal.sequence != sequence
            or seal.previous_root_digest != previous_root
            or seal.event_count < previous_event_count
            or seal.artifacts != sorted(seal.artifacts, key=lambda item: item.path)
            or seal.artifact_root_digest != seal.computed_artifact_root_digest()
            or seal.root_digest != seal.computed_root_digest()
        ):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent seal chain differs"
            )
        seals.append(seal)
        previous_root = seal.root_digest
        previous_event_count = seal.event_count
        selected = (
            sequence == 1
            if expected_root_digest is None
            else seal.root_digest == expected_root_digest
        )
        if selected:
            return tuple(seals), offset < len(content)
    raise GovernedWebCampaignEvidenceError(
        "governed WEB parent root digest is absent from the verified seal chain"
    )


def _parse_selected_parent_events(
    content: bytes,
    *,
    expected_run_id: str,
    event_count: int,
) -> tuple[tuple[AuditEvent, ...], bool]:
    """Verify exactly the event prefix named by one already-selected seal."""

    if not content or event_count < 1 or event_count > _MAX_RECORDS:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent event checkpoint is invalid"
        )
    events: list[AuditEvent] = []
    previous_hash: str | None = None
    previous_time: datetime | None = None
    offset = 0
    for sequence in range(1, event_count + 1):
        newline = content.find(b"\n", offset)
        if newline < 0:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent event stream is shorter than its seal"
            )
        record = content[offset:newline]
        offset = newline + 1
        if not record or len(record) > _MAX_RECORD_BYTES:
            raise GovernedWebCampaignEvidenceError(
                f"governed WEB parent event {sequence} is invalid"
            )
        try:
            raw = parse_strict_json_bytes(
                record,
                label=f"governed WEB parent event {sequence}",
                max_bytes=_MAX_RECORD_BYTES,
            )
            event = AuditEvent.model_validate(raw)
        except ValueError as exc:
            raise GovernedWebCampaignEvidenceError(
                f"governed WEB parent event {sequence} is invalid"
            ) from exc
        occurred_at = _utc(event.occurred_at, label="governed WEB parent event time")
        if (
            event.run_id != expected_run_id
            or event.sequence != sequence
            or event.previous_hash != previous_hash
            or event.event_hash != event.computed_hash()
        ):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent event chain differs"
            )
        if previous_time is not None and occurred_at < previous_time:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent event time moved backwards"
            )
        events.append(event)
        previous_hash = event.event_hash
        previous_time = occurred_at
    return tuple(events), offset < len(content)


def _event_scalar_references(event: AuditEvent, expected: str) -> bool:
    stack: list[object] = [event.payload]
    while stack:
        value = stack.pop()
        if value == expected:
            return True
        if isinstance(value, dict):
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return False


def _expected_parent_artifact_provenance(
    path: str,
    events: tuple[AuditEvent, ...],
) -> ArtifactProvenance | None:
    event_ids = [event.event_id for event in events if _event_scalar_references(event, path)]
    if not event_ids:
        return None
    return ArtifactProvenance(event_ids=event_ids)


def _read_exact_parent_artifact(
    root: Path,
    artifact: SealedArtifact,
    *,
    events: tuple[AuditEvent, ...],
) -> bytes:
    try:
        relative = validate_run_artifact_path(artifact.path)
    except ValueError as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent seal has a non-portable artifact path"
        ) from exc
    if relative != artifact.path or not _is_known_parent_artifact(relative):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent sealed artifact inventory differs"
        )
    current = root
    for component in PurePosixPath(relative).parts[:-1]:
        current = current / component
        try:
            observed = current.lstat()
        except OSError as exc:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent artifact ancestor is unavailable"
            ) from exc
        if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent artifact ancestor is not a real directory"
            )
    destination = root / relative
    try:
        content = read_bounded_regular_bytes(
            destination,
            max_bytes=_MAX_EVIDENCE_BYTES,
            label=f"governed WEB parent artifact {relative}",
            require_single_link=True,
        )
    except (OSError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB parent artifact {relative} cannot be read safely"
        ) from exc
    expected_media = _PARENT_MEDIA_TYPES.get(
        PurePosixPath(relative).suffix.casefold(),
        "application/octet-stream",
    )
    if (
        artifact.sha256 != sha256(content).hexdigest()
        or artifact.size_bytes != len(content)
        or artifact.media_type != expected_media
        or artifact.provenance != _expected_parent_artifact_provenance(relative, events)
    ):
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB parent artifact {relative} differs from its seal"
        )
    return content


def _root_identity(path: Path) -> tuple[int, int, int, int]:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent Run cannot be inspected"
        ) from exc
    if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent Run must be a real directory"
        )
    return (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid)


def _has_known_unsealed_artifact(root: Path, sealed_paths: set[str]) -> bool:
    inspected = 0
    allowed_empty_directories = {"evidence", "checkpoints", "checkpoints/database"}
    for directory, child_directories, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in tuple(child_directories):
            inspected += 1
            if inspected > 10_000:
                return True
            child = directory_path / name
            try:
                observed = child.lstat()
            except OSError:
                return True
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                return True
            relative_directory = child.relative_to(root).as_posix()
            if relative_directory not in allowed_empty_directories:
                return True
        for name in files:
            inspected += 1
            if inspected > 10_000:
                return True
            candidate = directory_path / name
            relative = candidate.relative_to(root).as_posix()
            if relative in {
                "events.jsonl",
                "run-integrity.jsonl",
                ".pajin-run.lock",
            }:
                continue
            if relative not in sealed_paths:
                return True
    return False


def _load_parent_sealed_prefix(
    parent_run_path: Path,
    *,
    expected_parent_run_id: str,
    expected_parent_root_digest: str | None,
) -> _ParentSealedPrefix:
    if re.fullmatch(_RUN_ID_PATTERN, expected_parent_run_id) is None:
        raise ValueError("expected governed WEB parent Run ID is invalid")
    if expected_parent_root_digest is not None and (
        re.fullmatch(_SHA256_PATTERN, expected_parent_root_digest) is None
    ):
        raise ValueError("expected governed WEB parent root digest is invalid")
    normalized = _normalized_parent_run_path(parent_run_path)
    with locked_run_snapshot(normalized) as root:
        initial_identity = _root_identity(root)
        try:
            event_content = read_bounded_regular_bytes(
                root / "events.jsonl",
                max_bytes=_MAX_EVENT_LOG_BYTES,
                label="governed WEB parent event stream",
                require_single_link=True,
            )
            seal_content = read_bounded_regular_bytes(
                root / "run-integrity.jsonl",
                max_bytes=_MAX_INTEGRITY_LOG_BYTES,
                label="governed WEB parent integrity stream",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent journal cannot be read safely"
            ) from exc
        seals, seal_partial_tail = _parse_selected_parent_seals(
            seal_content,
            expected_run_id=expected_parent_run_id,
            expected_root_digest=expected_parent_root_digest,
        )
        last = seals[-1]
        events, event_partial_tail = _parse_selected_parent_events(
            event_content,
            expected_run_id=expected_parent_run_id,
            event_count=last.event_count,
        )
        if not 1 <= last.event_count <= len(events):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent seal event checkpoint is invalid"
            )
        sealed_paths: set[str] = set()
        sealed_path_keys: set[str] = set()
        artifacts: dict[str, bytes] = {}
        for seal in seals:
            if seal.event_count > len(events):
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB parent seal exceeds the event stream"
                )
            if events[seal.event_count - 1].event_hash != seal.event_head_hash:
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB parent seal event head differs"
                )
            prefix_events = events[: seal.event_count]
            for artifact in seal.artifacts:
                key = unicodedata.normalize("NFC", artifact.path).casefold()
                if artifact.path in sealed_paths or key in sealed_path_keys:
                    raise GovernedWebCampaignEvidenceError(
                        "governed WEB parent artifact was sealed more than once"
                    )
                artifacts[artifact.path] = _read_exact_parent_artifact(
                    root,
                    artifact,
                    events=prefix_events,
                )
                sealed_paths.add(artifact.path)
                sealed_path_keys.add(key)
        if _CAMPAIGN_PLAN_PATH not in artifacts:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent Plan is absent from the sealed prefix"
            )
        if _root_identity(root) != initial_identity:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent Run changed while loading its prefix"
            )
        has_unsealed_tail = (
            event_partial_tail
            or seal_partial_tail
            or last.event_count != len(events)
            or _has_known_unsealed_artifact(root, sealed_paths)
        )
        return _ParentSealedPrefix(
            run_path=root,
            run_id=expected_parent_run_id,
            root_digest=last.root_digest,
            events=tuple(event.model_copy(deep=True) for event in events[: last.event_count]),
            seals=tuple(seal.model_copy(deep=True) for seal in seals),
            artifacts=MappingProxyType(dict(artifacts)),
            has_unsealed_tail=has_unsealed_tail,
        )


def _load_parent_model(
    prefix: _ParentSealedPrefix,
    path: str,
    model_type: type[_FrozenStrictModel],
    *,
    max_bytes: int,
) -> _FrozenStrictModel:
    try:
        content = prefix.artifacts[path]
    except KeyError as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB parent artifact is missing: {path}"
        ) from exc
    try:
        raw = parse_strict_json_bytes(
            content,
            label=f"governed WEB parent artifact {path}",
            max_bytes=max_bytes,
        )
        return model_type.model_validate(raw)
    except ValueError as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB parent artifact is invalid: {path}"
        ) from exc


def _expected_started_event_payload(
    plan: GovernedWebCampaignPlan,
) -> dict[str, JsonValue]:
    return {
        "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
        "origin": GOVERNED_WEB_ORIGIN,
        "adapterRef": GOVERNED_WEB_ADAPTER_REF,
        "campaignPlanDigest": plan.campaign_plan_digest,
        "deploymentTrustAnchorDigest": plan.deployment_trust_anchor_digest,
        "credentialsPersisted": False,
        "externalDeliveryPerformed": False,
    }


def _checkpoint_for_event(
    prefix: _ParentSealedPrefix,
    event: AuditEvent,
    *,
    expected_stage: GovernedWebCampaignStage,
    expected_status: Literal["started", "completed"],
) -> GovernedWebCampaignCheckpoint:
    path = _campaign_checkpoint_path(expected_stage, expected_status)
    expected_payload: dict[str, JsonValue]
    try:
        raw = parse_strict_json_bytes(
            prefix.artifacts[path],
            label=f"governed WEB checkpoint {path}",
            max_bytes=_MAX_CHECKPOINT_BYTES,
        )
        checkpoint = GovernedWebCampaignCheckpoint.model_validate(raw)
    except (KeyError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB checkpoint is missing or invalid: {path}"
        ) from exc
    expected_payload = {
        "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
        "stage": expected_stage,
        "checkpointPath": path,
        "checkpointDigest": checkpoint.checkpoint_digest,
        "mayHaveExecuted": expected_status == "started",
    }
    if (
        event.event_type != f"web.governed.stage.{expected_status}"
        or event.payload != expected_payload
        or checkpoint.stage != expected_stage
        or checkpoint.status != expected_status
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB checkpoint event differs from its artifact"
        )
    return checkpoint


def _database_checkpoint_for_event(
    prefix: _ParentSealedPrefix,
    event: AuditEvent,
    *,
    plan: GovernedWebCampaignPlan,
    active_stage: GovernedWebCampaignStage,
    previous: tuple[GovernedWebCampaignDatabaseCheckpoint, ...],
) -> GovernedWebCampaignDatabaseCheckpoint:
    payload = event.payload
    store_kind = payload.get("storeKind")
    ordinal = payload.get("ordinal")
    if (
        event.event_type != "web.governed.database-checkpoint"
        or store_kind not in _DATABASE_STORE_KINDS
        or type(ordinal) is not int
        or active_stage
        not in {
            "provisioning",
            "source-gateway",
            "validation-gateway",
            "graph-admission",
        }
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB database checkpoint event is out of order"
        )
    canonical_kind = cast(GovernedWebCampaignDatabaseStoreKind, store_kind)
    path = _campaign_database_checkpoint_path(
        stage=active_stage,
        store_kind=canonical_kind,
        ordinal=ordinal,
    )
    try:
        raw = parse_strict_json_bytes(
            prefix.artifacts[path],
            label=f"governed WEB database checkpoint {path}",
            max_bytes=_MAX_CHECKPOINT_BYTES,
        )
        checkpoint = GovernedWebCampaignDatabaseCheckpoint.model_validate(raw)
    except (KeyError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB database checkpoint is missing or invalid: {path}"
        ) from exc
    expected_payload: dict[str, JsonValue] = {
        "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
        "stage": active_stage,
        "storeKind": canonical_kind,
        "ordinal": ordinal,
        "checkpointPath": path,
        "checkpointDigest": checkpoint.checkpoint_digest,
        "manifestReference": checkpoint.manifest_reference,
        "manifestDigest": checkpoint.manifest_digest,
        "manifestSha256": checkpoint.manifest_sha256,
        "manifestSize": checkpoint.manifest_size,
        "databaseReference": checkpoint.database_reference,
        "databaseSha256": checkpoint.database_sha256,
        "databaseSize": checkpoint.database_size,
        "stateDigest": checkpoint.state_digest,
        "previousParentRootDigest": checkpoint.previous_parent_root_digest,
    }
    matching_seals = tuple(
        seal for seal in prefix.seals if seal.event_count == event.sequence
    )
    prior = next(
        (
            item
            for item in reversed(previous)
            if item.store_kind == canonical_kind
        ),
        None,
    )
    key = plan.trust_bundle.index_signing_key
    if (
        event.payload != expected_payload
        or checkpoint.campaign_plan_digest != plan.campaign_plan_digest
        or checkpoint.stage != active_stage
        or checkpoint.store_kind != canonical_kind
        or checkpoint.ordinal != ordinal
        or checkpoint.recorded_at != event.occurred_at
        or checkpoint.signer_key_id != key.key_id
        or not key.not_before <= checkpoint.recorded_at < key.not_after
        or checkpoint.ordinal != (1 if prior is None else prior.ordinal + 1)
        or checkpoint.previous_manifest_digest
        != (None if prior is None else prior.manifest_digest)
        or len(matching_seals) != 1
        or matching_seals[0].previous_root_digest
        != checkpoint.previous_parent_root_digest
        or {artifact.path for artifact in matching_seals[0].artifacts} != {path}
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB database checkpoint chain differs"
        )
    _verify_ed25519_statement(
        public_key_base64url=key.public_key_base64url,
        signature_base64url=checkpoint.signature_base64url,
        payload=checkpoint.signed_bytes(),
        label="governed WEB database checkpoint",
    )
    return checkpoint


def _load_campaign_progression(
    prefix: _ParentSealedPrefix,
    plan: GovernedWebCampaignPlan,
) -> _CampaignProgression:
    if not prefix.events or (
        prefix.events[0].event_type != "campaign.started"
        or prefix.events[0].payload != _expected_started_event_payload(plan)
        or prefix.events[0].occurred_at != plan.signed_at
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent journal does not start with its exact Plan event"
        )
    if (
        prefix.seals[0].event_count != 1
        or {artifact.path for artifact in prefix.seals[0].artifacts}
        != {_CAMPAIGN_PLAN_PATH}
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB initial Plan checkpoint differs"
        )
    completed: list[GovernedWebCampaignStage] = []
    intents: list[GovernedWebCampaignStageIntent] = []
    observations: list[GovernedWebCampaignStageObservation] = []
    database_checkpoints: list[GovernedWebCampaignDatabaseCheckpoint] = []
    active: GovernedWebCampaignCheckpoint | None = None
    terminal: AuditEvent | None = None
    for event in prefix.events[1:]:
        if event.event_type in {"campaign.completed", "campaign.failed"}:
            if terminal is not None:
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB parent journal has multiple terminal events"
                )
            terminal = event
            continue
        if terminal is not None:
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent terminal event is not last"
            )
        if len(completed) >= len(GOVERNED_WEB_CAMPAIGN_STAGE_ORDER):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB parent journal extends past its stage inventory"
            )
        expected_stage = GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[len(completed)]
        if event.event_type == "web.governed.database-checkpoint":
            if active is None:
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB database checkpoint has no active stage"
                )
            database_checkpoints.append(
                _database_checkpoint_for_event(
                    prefix,
                    event,
                    plan=plan,
                    active_stage=active.stage,
                    previous=tuple(database_checkpoints),
                )
            )
            continue
        if active is None:
            checkpoint = _checkpoint_for_event(
                prefix,
                event,
                expected_stage=expected_stage,
                expected_status="started",
            )
            if checkpoint.campaign_plan_digest != plan.campaign_plan_digest:
                raise GovernedWebCampaignEvidenceError(
                    "governed WEB started checkpoint belongs to another Plan"
                )
            assert checkpoint.intent is not None
            intents.append(checkpoint.intent)
            active = checkpoint
            continue
        checkpoint = _checkpoint_for_event(
            prefix,
            event,
            expected_stage=expected_stage,
            expected_status="completed",
        )
        if (
            checkpoint.campaign_plan_digest != plan.campaign_plan_digest
            or checkpoint.started_checkpoint_digest != active.checkpoint_digest
        ):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB completed checkpoint loses its started checkpoint"
            )
        assert checkpoint.observation is not None
        observations.append(checkpoint.observation)
        completed.append(expected_stage)
        active = None
    if terminal is not None and terminal is not prefix.events[-1]:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent terminal event is not last"
        )
    return _CampaignProgression(
        completed=tuple(completed),
        active_checkpoint=active,
        intents=tuple(intents),
        observations=tuple(observations),
        database_checkpoints=tuple(database_checkpoints),
        terminal_event=terminal,
    )


def _parse_completed_campaign_models(
    evidence: GovernedWebCompletedCampaignEvidence,
) -> _CompletedCampaignModels:
    try:
        return _CompletedCampaignModels(
            campaign=CampaignManifest.model_validate(evidence.campaign),
            signed_adapter=SignedWebAssessmentAdapter.model_validate(
                evidence.signed_adapter
            ),
            signed_account_receipt=SignedProvisionedWebAccountReceipt.model_validate(
                evidence.signed_account_receipt
            ),
            lifecycle=_HistoricalLifecycle.model_validate(evidence.lifecycle),
            grants=_HistoricalGrants.model_validate(evidence.grants),
            source=_HistoricalGovernedWebAction.model_validate(evidence.source_action),
            validation=_HistoricalGovernedWebAction.model_validate(
                evidence.validation_action
            ),
            independent_worker_evidence=WebIndependentWorkerEvidence.model_validate(
                evidence.independent_worker_evidence
            ),
            reconciliation=LocalWebAssessmentCampaignResult.model_validate(
                evidence.reconciliation
            ),
            execution_verification=GovernedWebExecutionVerification.model_validate(
                evidence.execution_verification
            ),
            execution_evidence=GovernedWebExecutionEvidence.model_validate(
                evidence.execution_evidence
            ),
            promotion=GovernedWebPromotion.model_validate(evidence.promotion),
            graph_admission=GovernedWebGraphAdmission.model_validate(
                evidence.graph_admission
            ),
        )
    except (TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB evidence contains a non-canonical typed record"
        ) from exc


def _completed_output_root(
    parent_run_path: Path,
    plan: GovernedWebCampaignPlan,
) -> Path:
    expected = Path(plan.planned_runs.relative_paths()["parent"])
    candidate = _normalized_parent_run_path(parent_run_path)
    root = candidate
    for _component in expected.parts:
        root = root.parent
    if candidate != root / expected:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent Run is outside its deterministic output layout"
        )
    return root


def _exact_external_path(
    output_root: Path,
    relative_reference: str,
    *,
    label: str,
    directory: bool,
) -> Path:
    reference = PurePosixPath(relative_reference)
    if (
        reference.is_absolute()
        or not reference.parts
        or any(part in {"", ".", ".."} for part in reference.parts)
    ):
        raise GovernedWebCampaignEvidenceError(f"{label} reference is not canonical")
    candidate = output_root.joinpath(*reference.parts)
    cursor = output_root
    for index, component in enumerate(reference.parts):
        try:
            names = os.listdir(cursor)
        except OSError as exc:
            raise GovernedWebCampaignEvidenceError(f"{label} ancestry is unavailable") from exc
        folded = unicodedata.normalize("NFC", component).casefold()
        matches = [
            name
            for name in names
            if unicodedata.normalize("NFC", name).casefold() == folded
        ]
        if matches != [component]:
            raise GovernedWebCampaignEvidenceError(f"{label} path identity differs")
        cursor = cursor / component
        try:
            observed = cursor.lstat()
        except OSError as exc:
            raise GovernedWebCampaignEvidenceError(f"{label} is unavailable") from exc
        if cursor.is_symlink() or cursor.is_junction():
            raise GovernedWebCampaignEvidenceError(f"{label} cannot contain a link")
        is_leaf = index == len(reference.parts) - 1
        if (not is_leaf or directory) and not stat.S_ISDIR(observed.st_mode):
            raise GovernedWebCampaignEvidenceError(f"{label} is not a directory")
        if is_leaf and not directory and (
            not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1
        ):
            raise GovernedWebCampaignEvidenceError(
                f"{label} is not a private regular file"
            )
    return candidate


def _verify_ed25519_statement(
    *,
    public_key_base64url: str,
    signature_base64url: str,
    payload: bytes,
    label: str,
) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(
                public_key_base64url,
                size=32,
                label=f"{label} public key",
            )
        ).verify(
            _decode_base64url(
                signature_base64url,
                size=64,
                label=f"{label} signature",
            ),
            payload,
        )
    except InvalidSignature as exc:
        raise GovernedWebCampaignEvidenceError(f"{label} signature is invalid") from exc


def _require_code_trust_bindings(bundle: GovernedWebCampaignTrustBundle) -> None:
    expected = {
        "adapter-implementation": (
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        ),
        "compiler": (_COMPILER_ID, _COMPILER_DIGEST),
        "profile": (_PROFILE_ID, _PROFILE_DIGEST),
        "worker": (_WORKER_IMPLEMENTATION_ID, _WORKER_IMPLEMENTATION_DIGEST),
        "gateway": (_GATEWAY_IMPLEMENTATION_ID, _GATEWAY_IMPLEMENTATION_DIGEST),
    }
    observed = {
        item.role: (item.implementation_id, item.implementation_digest)
        for item in bundle.trust_material.code_bindings
    }
    if observed != expected:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB code trust bindings differ from this implementation"
        )


def _verify_completed_signatures(
    models: _CompletedCampaignModels,
    bundle: GovernedWebCampaignTrustBundle,
) -> WebWorkerTrustRegistry:
    trust = bundle.trust_material
    adapter = models.signed_adapter
    account = models.signed_account_receipt
    execution_use_time = max(
        models.source.permit.consumed_at,
        models.validation.permit.consumed_at,
    )
    try:
        installed = WebAssessmentAdapterRegistry(
            keys=(trust.adapter_key,),
            adapters=(adapter,),
            clock=lambda: execution_use_time,
        ).resolve(adapter.manifest.reference())
        retained = ProvisionedWebAccountReceiptRegistry(
            keys=(trust.account_key,),
            receipts=(account,),
            clock=lambda: execution_use_time,
        ).resolve(account.receipt.reference())
    except ValueError as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB adapter or account signature is invalid"
        ) from exc
    if installed != adapter.manifest or retained != account.receipt:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB signed deployment input changed during verification"
        )

    release = models.lifecycle.release_bundle.release
    release_key = trust.lifecycle_publisher_key
    if (
        release.key_id != release_key.key_id
        or release.statement.publisher_principal_id != release_key.principal_id
        or release_key.state is not CapabilityLifecycleKeyState.ACTIVE
        or release_key.not_after is None
        or not release_key.not_before <= release.statement.issued_at < release_key.not_after
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB Capability release authority differs"
        )
    _verify_ed25519_statement(
        public_key_base64url=release_key.public_key_base64url,
        signature_base64url=release.signature_base64url,
        payload=_RELEASE_SIGNATURE_DOMAIN + _canonical_release(release.statement),
        label="governed WEB Capability release",
    )
    policy = CapabilityLifecyclePolicy.reference_policy()
    if release.statement.policy_digest != policy.digest:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB Capability release policy differs"
        )
    if len(models.lifecycle.release_bundle.reviews) != policy.approvals_for(
        release.statement.maturity
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB Capability release review quorum differs"
        )
    review_key = trust.lifecycle_reviewer_key
    for signed_review in models.lifecycle.release_bundle.reviews:
        review = signed_review.statement
        if (
            signed_review.key_id != review_key.key_id
            or review.reviewer_principal_id != review_key.principal_id
            or review_key.state is not CapabilityLifecycleKeyState.ACTIVE
            or review_key.not_after is None
            or not review_key.not_before <= review.issued_at < review_key.not_after
            or review.expires_at <= release.statement.issued_at
            or review.decision is not CapabilityReviewDecision.APPROVED
            or review.policy_digest != policy.digest
            or review.capability != release.statement.capability
            or review.target_maturity is not release.statement.maturity
        ):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB Capability review authority differs"
            )
        _verify_ed25519_statement(
            public_key_base64url=review_key.public_key_base64url,
            signature_base64url=signed_review.signature_base64url,
            payload=_REVIEW_SIGNATURE_DOMAIN + _canonical_review(review),
            label="governed WEB Capability review",
        )

    activation = models.lifecycle.activation
    if (
        activation.binding.release != release.statement.reference()
        or activation.binding.release_bundle_digest
        != _release_bundle_digest(models.lifecycle.release_bundle)
        or activation.binding.capability != release.statement.capability
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB Capability activation differs from its signed release"
        )

    worker_registry = WebWorkerTrustRegistry(
        trustDomain=trust.worker_trust_domain,
        issuer=trust.worker_issuer,
        keys=trust.worker_keys,
    )
    try:
        verified = verify_independent_web_worker_evidence(
            source_target=models.source.worker_action_evidence.target_identity,
            source=models.source.worker_action_evidence.execution_attestation,
            validation_target=models.validation.worker_action_evidence.target_identity,
            validation=models.validation.worker_action_evidence.execution_attestation,
            registry=worker_registry,
            verification_time=models.execution_verification.verified_at,
        )
    except ValueError as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB independent Worker signatures are invalid"
        ) from exc
    if verified != models.independent_worker_evidence:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB independent Worker evidence differs after verification"
        )
    return worker_registry


def _require_action_links(
    *,
    role: Literal["source", "validation"],
    action: _HistoricalGovernedWebAction,
    grant: CapabilityGrant,
    models: _CompletedCampaignModels,
    plan: GovernedWebCampaignPlan,
) -> None:
    trust = plan.trust_bundle.trust_material
    approval_key = (
        trust.source_approval_key
        if role == "source"
        else trust.validation_approval_key
    )
    try:
        WebActionApprovalInputAuthority(
            role=role,
            key=approval_key,
            signed=action.signed_approval,
            clock=lambda: action.permit.consumed_at,
        ).verify_action_approval(
            action.envelope,
            action.proposal,
            action.decision,
            action.approval,
        )
    except ValueError as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} approval signature is invalid"
        ) from exc

    browser_key = "sourceBrowser" if role == "source" else "validationBrowser"
    gateway_key = "sourceGateway" if role == "source" else "validationGateway"
    expected_browser_run = (
        plan.planned_runs.source_browser_run_id
        if role == "source"
        else plan.planned_runs.validation_browser_run_id
    )
    expected_gateway_run = (
        plan.planned_runs.source_gateway_run_id
        if role == "source"
        else plan.planned_runs.validation_gateway_run_id
    )
    worker = action.worker_authority_binding
    receipt = action.gateway_completion_receipt
    run = action.browser_run_reference.run
    output = action.worker_output
    signed_worker = action.worker_action_evidence
    execution = signed_worker.execution_attestation
    target = signed_worker.target_identity
    expected_prepared = models.lifecycle.activation
    account = models.signed_account_receipt.receipt
    adapter = models.signed_adapter.manifest
    gateway_final_root = (
        models.execution_evidence.source_gateway_audit_final_root_digest
        if role == "source"
        else models.execution_evidence.validation_gateway_audit_final_root_digest
    )
    gateway_final_head = (
        models.execution_evidence.source_gateway_audit_final_event_head_digest
        if role == "source"
        else models.execution_evidence.validation_gateway_audit_final_event_head_digest
    )
    if (
        action.browser_run_reference.path
        != plan.planned_runs.relative_paths()[browser_key]
        or action.gateway_run_reference.path
        != plan.planned_runs.relative_paths()[gateway_key]
        or action.browser_run_reference.run.role != role
        or run.run_id != expected_browser_run
        or action.gateway_run_reference.run_id != expected_gateway_run
        or action.prepared.request != action.request
        or action.prepared.request_digest != capability_tool_request_digest(action.request)
        or action.prepared.activation_set_digest
        != expected_prepared.activation_set_digest
        or action.prepared.release != expected_prepared.binding.release
        or action.local_authorization != run.authorization
        or action.signed_approval.approval != action.approval
        or action.approval.mission_envelope != action.envelope
        or action.approval.proposal != action.proposal
        or action.approval.graph_decision != action.decision
        or action.approval_consumption_receipt.approval != action.approval
        or action.approval_consumption_receipt.action_permit != action.permit
        or action.permit.run_id != expected_browser_run
        or action.permit.request_id != action.request.request_id
        or action.permit.request_digest != action.prepared.request_digest
        or action.permit.proposal_id != action.proposal.proposal_id
        or action.permit.proposal_digest != action.proposal.proposal_digest
        or action.grant_consumption_receipt.campaign_id != models.campaign.metadata.name
        or action.grant_consumption_receipt.capability_grant_id != grant.grant_id
        or action.grant_consumption_receipt.capability_grant_digest
        != capability_grant_digest(grant)
        or action.grant_consumption_receipt.request_id != action.request.request_id
        or action.grant_consumption_receipt.request_digest
        != action.prepared.request_digest
        or action.grant_consumption_receipt.permit_id != action.permit.permit_id
        or action.grant_consumption_receipt.permit_digest
        != action.permit.permit_digest
        or action.grant_consumption_receipt.approval_receipt_id
        != action.approval_consumption_receipt.receipt_id
        or action.grant_consumption_receipt.approval_receipt_digest
        != action.approval_consumption_receipt.receipt_digest
        or execution.statement.authority != worker
        or target.statement.authority != worker
        or worker.expected_run_id != expected_browser_run
        or worker.campaign_id != models.campaign.metadata.name
        or worker.campaign_digest != campaign_manifest_digest(models.campaign)
        or worker.capability_grant_id != grant.grant_id
        or worker.capability_grant_digest != capability_grant_digest(grant)
        or worker.capability_grant_consumption_receipt_id
        != action.grant_consumption_receipt.receipt_id
        or worker.capability_grant_consumption_receipt_digest
        != action.grant_consumption_receipt.receipt_digest
        or worker.adapter_digest != adapter.adapter_digest
        or worker.account_receipt_digest != account.receipt_digest
        or worker.request_id != action.request.request_id
        or worker.request_digest != action.prepared.request_digest
        or worker.action_permit_id != action.permit.permit_id
        or worker.action_permit_digest != action.permit.permit_digest
        or worker.approval_id != action.approval.approval_id
        or worker.approval_digest != action.approval.approval_digest
        or worker.approval_receipt_id != action.approval_consumption_receipt.receipt_id
        or worker.approval_receipt_digest
        != action.approval_consumption_receipt.receipt_digest
        or receipt.role != role
        or receipt.authority != worker
        or receipt.dispatch_binding_digest != worker.dispatch_binding_digest
        or receipt.request_id != worker.request_id
        or receipt.worker_execution_id != execution.statement.execution_id
        or receipt.gateway_audit_run_id != expected_gateway_run
        or action.gateway_run_reference.root_digest != gateway_final_root
        or action.gateway_run_reference.event_head_digest != gateway_final_head
        or action.gateway_run_reference.completion_receipt_reference
        != (
            models.execution_evidence.source_gateway_completion_receipt_reference
            if role == "source"
            else models.execution_evidence.validation_gateway_completion_receipt_reference
        )
        or output.adapter != adapter.reference()
        or output.account_receipt != account.reference()
        or output.dispatch_binding_digest != worker.dispatch_binding_digest
        or output.worker_execution_id != execution.statement.execution_id
        or output.origin != adapter.origin
        or output.run_id != run.run_id
        or output.root_digest != run.root_digest
        or output.result_digest != run.result_digest
        or output.attestation_digest != signed_worker.digest
    ):
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} action authority chain differs"
        )


def _require_execution_links(
    *,
    models: _CompletedCampaignModels,
    evidence: GovernedWebCompletedCampaignEvidence,
    result: GovernedWebCampaignHistoricalResult,
    worker_registry: WebWorkerTrustRegistry,
) -> None:
    campaign = models.campaign
    adapter = models.signed_adapter.manifest
    account = models.signed_account_receipt.receipt
    source = models.source
    validation = models.validation
    source_worker = source.worker_action_evidence.execution_attestation
    validation_worker = validation.worker_action_evidence.execution_attestation
    source_target = source.worker_action_evidence.target_identity
    validation_target = validation.worker_action_evidence.target_identity
    execution = models.execution_evidence
    verification = models.execution_verification
    source_grant_digest = capability_grant_digest(models.grants.source)
    validation_grant_digest = capability_grant_digest(models.grants.validation)
    if (
        evidence.campaign_digest != campaign_manifest_digest(campaign)
        or campaign.metadata.name != GOVERNED_WEB_CAMPAIGN_ID
        or execution.campaign_id != campaign.metadata.name
        or execution.campaign_manifest_digest != evidence.campaign_digest
        or adapter.origin != GOVERNED_WEB_ORIGIN
        or execution.adapter_ref != GOVERNED_WEB_ADAPTER_REF
        or execution.adapter_digest != adapter.adapter_digest
        or account.adapter != adapter.reference()
        or account.origin != adapter.origin
        or execution.account_receipt_digest != account.receipt_digest
        or execution.target_identity_digest != account.target_identity_digest
        or execution.worker_trust_registry_digest != worker_registry.digest
        or execution.execution_verifier_digest
        != governed_web_execution_verifier_digest(worker_registry)
        or verification.verifier_digest != execution.execution_verifier_digest
        or verification.evidence_digest != execution.evidence_digest
        or models.promotion.execution_evidence != execution
        or models.promotion.execution_verification != verification
        or models.promotion.reconciliation_result_digest
        != models.reconciliation.result_digest
        or models.graph_admission.campaign_id != campaign.metadata.name
        or models.graph_admission.promotion_digest != models.promotion.promotion_digest
        or models.graph_admission.execution_evidence_digest != execution.evidence_digest
        or execution.source_capability_grant_id != models.grants.source.grant_id
        or execution.source_capability_grant_digest != source_grant_digest
        or execution.validation_capability_grant_id != models.grants.validation.grant_id
        or execution.validation_capability_grant_digest != validation_grant_digest
        or execution.source_capability_grant_consumption_receipt_id
        != source.grant_consumption_receipt.receipt_id
        or execution.source_capability_grant_consumption_receipt_digest
        != source.grant_consumption_receipt.receipt_digest
        or execution.validation_capability_grant_consumption_receipt_id
        != validation.grant_consumption_receipt.receipt_id
        or execution.validation_capability_grant_consumption_receipt_digest
        != validation.grant_consumption_receipt.receipt_digest
        or execution.source_action_permit_id != source.permit.permit_id
        or execution.source_action_permit_digest != source.permit.permit_digest
        or execution.validation_action_permit_id != validation.permit.permit_id
        or execution.validation_action_permit_digest != validation.permit.permit_digest
        or execution.source_approval_id != source.approval.approval_id
        or execution.source_approval_digest != source.approval.approval_digest
        or execution.validation_approval_id != validation.approval.approval_id
        or execution.validation_approval_digest != validation.approval.approval_digest
        or execution.source_approval_receipt_id
        != source.approval_consumption_receipt.receipt_id
        or execution.source_approval_receipt_digest
        != source.approval_consumption_receipt.receipt_digest
        or execution.validation_approval_receipt_id
        != validation.approval_consumption_receipt.receipt_id
        or execution.validation_approval_receipt_digest
        != validation.approval_consumption_receipt.receipt_digest
        or execution.source_gateway_audit_run_id
        != source.gateway_completion_receipt.gateway_audit_run_id
        or execution.validation_gateway_audit_run_id
        != validation.gateway_completion_receipt.gateway_audit_run_id
        or execution.source_gateway_completion_receipt_id
        != source.gateway_completion_receipt.receipt_id
        or execution.source_gateway_completion_receipt_digest
        != source.gateway_completion_receipt.receipt_digest
        or execution.validation_gateway_completion_receipt_id
        != validation.gateway_completion_receipt.receipt_id
        or execution.validation_gateway_completion_receipt_digest
        != validation.gateway_completion_receipt.receipt_digest
        or execution.source_run_id != source.browser_run_reference.run.run_id
        or execution.source_root_digest != source.browser_run_reference.run.root_digest
        or execution.source_result_digest != source.browser_run_reference.run.result_digest
        or execution.validation_run_id != validation.browser_run_reference.run.run_id
        or execution.validation_root_digest
        != validation.browser_run_reference.run.root_digest
        or execution.validation_result_digest
        != validation.browser_run_reference.run.result_digest
        or execution.source_authorization_id
        != source.browser_run_reference.run.authorization_id
        or execution.validation_authorization_id
        != validation.browser_run_reference.run.authorization_id
        or execution.source_executor_process_id != source_worker.statement.process_id
        or execution.validation_executor_process_id
        != validation_worker.statement.process_id
        or execution.source_observer_process_id != source_target.statement.process_id
        or execution.validation_observer_process_id
        != validation_target.statement.process_id
        or execution.source_executor_key_id != source_worker.key_id
        or execution.validation_executor_key_id != validation_worker.key_id
        or execution.source_observer_key_id != source_target.key_id
        or execution.validation_observer_key_id != validation_target.key_id
        or execution.source_executor_execution_id
        != source_worker.statement.execution_id
        or execution.validation_executor_execution_id
        != validation_worker.statement.execution_id
        or execution.source_observer_execution_id != source_target.statement.execution_id
        or execution.validation_observer_execution_id
        != validation_target.statement.execution_id
        or execution.source_execution_attestation_digest != source_worker.digest
        or execution.validation_execution_attestation_digest != validation_worker.digest
        or execution.source_target_attestation_digest != source_target.digest
        or execution.validation_target_attestation_digest != validation_target.digest
        or execution.source_worker_action_evidence_digest
        != source.worker_action_evidence.digest
        or execution.validation_worker_action_evidence_digest
        != validation.worker_action_evidence.digest
        or result.campaign_digest != evidence.campaign_digest
        or result.activation_set_id != models.lifecycle.activation.activation_set_id
        or result.activation_set_digest
        != models.lifecycle.activation.activation_set_digest
        or result.source_request_id != source.request.request_id
        or result.validation_request_id != validation.request.request_id
        or result.source_approval_id != source.approval.approval_id
        or result.validation_approval_id != validation.approval.approval_id
        or result.source_permit_id != source.permit.permit_id
        or result.validation_permit_id != validation.permit.permit_id
        or result.source_run_id != execution.source_run_id
        or result.validation_run_id != execution.validation_run_id
        or result.source_root_digest != execution.source_root_digest
        or result.validation_root_digest != execution.validation_root_digest
        or result.source_gateway_run_id != execution.source_gateway_audit_run_id
        or result.validation_gateway_run_id != execution.validation_gateway_audit_run_id
        or result.source_gateway_root_digest
        != execution.source_gateway_audit_final_root_digest
        or result.validation_gateway_root_digest
        != execution.validation_gateway_audit_final_root_digest
        or result.finding_count != len(models.promotion.findings)
        or result.attack_path_count != len(models.promotion.attack_paths)
        or result.sarif_digest != evidence.sarif_digest
        or result.poc_manifest_digest != evidence.poc_manifest_digest
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB execution or result links differ"
        )


def _verify_browser_run(
    *,
    output_root: Path,
    role: Literal["source", "validation"],
    action: _HistoricalGovernedWebAction,
) -> None:
    path = _exact_external_path(
        output_root,
        action.browser_run_reference.path,
        label=f"governed WEB {role} Browser Run",
        directory=True,
    )
    embedded = action.browser_run_reference.run
    try:
        verified = load_verified_local_web_assessment_source_integrity(
            path,
            expected_run_id=embedded.run_id,
            expected_root_digest=embedded.root_digest,
        )
        reprojected = local_web_assessment_run_reference(
            role=role,
            verified_source=verified,
        )
    except (OSError, RunIntegrityError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} Browser Run failed strict reload"
        ) from exc
    if reprojected != embedded:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} Browser Run reference differs"
        )


def _verify_gateway_run(
    *,
    output_root: Path,
    role: Literal["source", "validation"],
    action: _HistoricalGovernedWebAction,
    campaign: CampaignManifest,
    grant: CapabilityGrant,
    worker_registry: WebWorkerTrustRegistry,
) -> None:
    reference = action.gateway_run_reference
    receipt = action.gateway_completion_receipt
    request_id = action.request.request_id
    evidence_reference = f"evidence/{request_id}.json"
    reservation_reference = f"requests/{request_id}.json"
    receipt_reference = f"gateway-completions/{receipt.receipt_digest}.json"
    if (
        receipt.gateway_evidence_reference != evidence_reference
        or receipt.gateway_request_reservation_reference != reservation_reference
        or reference.completion_receipt_reference != receipt_reference
    ):
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} Gateway artifact references differ"
        )
    path = _exact_external_path(
        output_root,
        reference.path,
        label=f"governed WEB {role} Gateway Run",
        directory=True,
    )
    requests = {
        evidence_reference: 64 * 1024 * 1024,
        reservation_reference: 64 * 1024 * 1024,
        receipt_reference: 64 * 1024 * 1024,
    }
    try:
        snapshot = load_verified_run_artifacts(
            path,
            requests=requests,
            expected_run_id=receipt.gateway_audit_run_id,
        )
        decoded_receipt = WebGatewayCompletionReceipt.model_validate(
            parse_strict_json_bytes(
                snapshot.artifact_bytes(receipt_reference),
                label=f"governed WEB {role} Gateway completion receipt",
                max_bytes=64 * 1024 * 1024,
                max_depth=32,
                max_nodes=20_000,
            )
        )
        reservation = parse_strict_json_bytes(
            snapshot.artifact_bytes(reservation_reference),
            label=f"governed WEB {role} Gateway reservation",
            max_bytes=64 * 1024 * 1024,
            max_depth=16,
            max_nodes=1_000,
        )
        raw_evidence = parse_strict_json_bytes(
            snapshot.artifact_bytes(evidence_reference),
            label=f"governed WEB {role} Gateway evidence",
            max_bytes=64 * 1024 * 1024,
            max_depth=64,
            max_nodes=200_000,
        )
        if not isinstance(raw_evidence, dict) or set(raw_evidence) != {
            "request",
            "policyDecision",
            "result",
            "networkLogTrusted",
            "workerJob",
            "workerResult",
            "secretLeases",
        }:
            raise ValueError("Gateway evidence is not an object")
        request = ToolRequest.model_validate(raw_evidence["request"])
        decision = PolicyDecision.model_validate(raw_evidence["policyDecision"])
        stored_result = ToolResult.model_validate(raw_evidence["result"])
        worker_result = WorkerResult.model_validate(raw_evidence["workerResult"])
        worker_job = raw_evidence["workerJob"]
        raw_leases = raw_evidence["secretLeases"]
        if not isinstance(worker_job, dict) or not isinstance(raw_leases, list):
            raise ValueError("Gateway Worker audit material is not structured")
        leases = tuple(SecretLease.model_validate(item) for item in raw_leases)
        stdout_evidence = SignedWebWorkerActionEvidence.model_validate(
            parse_strict_json_bytes(
                worker_result.stdout.encode("utf-8"),
                label=f"governed WEB {role} Gateway Worker stdout",
                max_bytes=1_000_000,
                max_depth=64,
                max_nodes=200_000,
            )
        )
    except (KeyError, OSError, RunIntegrityError, TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} Gateway Run failed strict reload"
        ) from exc

    expected_event_types = (
        "tool.request_reserved",
        "tool.policy_evaluated",
        *("secret.lease.issued",) * 4,
        "worker.dispatched",
        *("secret.lease.revoked",) * 4,
        "worker.completed",
        "tool.completed",
        "web.gateway_completion.recorded",
    )
    sealed_paths = {artifact.path for seal in snapshot.seals for artifact in seal.artifacts}
    expected_reservation: dict[str, JsonValue] = {
        "apiVersion": "pajin.dev/tool-request-reservation/v1",
        "kind": "ToolRequestReservation",
        "requestId": request.request_id,
        "requestSha256": canonical_tool_request_digest(request),
    }
    network_log_trusted = raw_evidence.get("networkLogTrusted")
    if (
        network_log_trusted is not False
        or stored_result.evidence
        or stored_result.finished_at < stored_result.started_at
        or not stored_result.success
        or stored_result.error is not None
        or stored_result.started_at != worker_result.started_at
        or stored_result.finished_at != worker_result.finished_at
    ):
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} Gateway persisted evidence authority differs"
        )
    enriched_result = stored_result.model_copy(
        update={
            "evidence": [
                *stored_result.evidence,
                evidence_reference,
            ]
        },
        deep=True,
    )
    outcome = GatewayOutcome(
        decision=decision,
        result=enriched_result,
        worker_result=worker_result,
        network_log_trusted=network_log_trusted,
        result_identity_valid=True,
        executed=True,
    )
    signed = action.worker_action_evidence
    target = signed.target_identity
    execution = signed.execution_attestation
    expected_decision = PolicyEngine().evaluate_tool_request(
        campaign,
        grant,
        request,
        WebAuthenticatedAssessmentTool.spec,
        used_calls=0,
        now=snapshot.events[1].occurred_at,
    )
    expected_bindings = (
        WEB_ACCOUNT_NAME_BINDING,
        WEB_ACCOUNT_PROOF_BINDING,
        WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
        WEB_WORKER_SIGNING_KEY_BINDING,
    )
    expected_job_keys = {
        "requestId",
        "executionId",
        "image",
        "command",
        "network",
        "egressPolicy",
        "limits",
        "stdinBytes",
        "stdinSha256",
        "secretRequests",
        "secretLeaseIds",
    }
    try:
        secret_requests = worker_job["secretRequests"]
        stdin_bytes = worker_job["stdinBytes"]
        stdin_sha256 = worker_job["stdinSha256"]
        if not isinstance(secret_requests, list):
            raise TypeError("Gateway secret requests are not a list")
        lease_material = tuple(lease.model_dump(mode="json") for lease in leases)
        expected_secret_requests: list[dict[str, object]] = [
            {
                "binding": lease.binding,
                "secretRefFingerprint": lease.secret_ref_fingerprint,
                "ttlSeconds": 300,
            }
            for lease in leases
        ]
        expected_issued_payloads: tuple[dict[str, object], ...] = tuple(
            {
                "leaseId": lease.lease_id,
                "scope": lease.scope,
                "binding": lease.binding,
                "secretRefFingerprint": lease.secret_ref_fingerprint,
                "expiresAt": material["expires_at"],
            }
            for lease, material in zip(leases, lease_material, strict=True)
        )
        expected_revoked_payloads: tuple[dict[str, object], ...] = tuple(
            {
                "leaseId": lease.lease_id,
                "scope": lease.scope,
                "binding": lease.binding,
                "reason": "Worker execution finished",
            }
            for lease in leases
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} Gateway Worker metadata differs"
        ) from exc
    expected_recipe = juice_shop_plan(GOVERNED_WEB_ORIGIN)
    expected_egress_policy: dict[str, object] = {
        "allow": list(campaign.spec.scope.allow),
        "deny": list(campaign.spec.scope.deny),
        "allowed_methods": sorted(campaign.spec.rules_of_engagement.allowed_methods),
        "allow_private_networks": campaign.spec.rules_of_engagement.allow_private_networks,
        "max_response_bytes": expected_recipe.max_response_bytes,
        "max_requests": 100,
    }
    expected_limits: dict[str, JsonValue] = {
        "timeout_seconds": float(min(3_600, expected_recipe.duration_seconds + 120)),
        "memory_mb": 1_024,
        "cpus": 2.0,
        "pids": 128,
        "workspace_mb": 512,
        "stdout_bytes": 1_000_000,
        "stderr_bytes": 64_000,
    }
    lease_ids = [lease.lease_id for lease in leases]
    dispatched_job = dict(worker_job)
    dispatched_job["secretLeaseIds"] = lease_ids
    expected_payloads: tuple[dict[str, object], ...] = (
        {
            "requestId": request.request_id,
            "requestSha256": canonical_tool_request_digest(request),
            "reservation": reservation_reference,
        },
        {
            "requestId": request.request_id,
            "toolId": request.tool_id,
            "allowed": expected_decision.allowed,
            "policy": expected_decision.policy,
            "reason": expected_decision.reason,
        },
        *expected_issued_payloads,
        dispatched_job,
        *expected_revoked_payloads,
        {
            "requestId": request.request_id,
            "executionId": worker_result.execution_id,
            "backend": worker_result.backend,
            "status": worker_result.status.value,
            "exitCode": worker_result.exit_code,
            "stdoutTruncated": worker_result.stdout_truncated,
            "stderrTruncated": worker_result.stderr_truncated,
        },
        {
            "requestId": request.request_id,
            "toolId": request.tool_id,
            "success": True,
            "evidence": evidence_reference,
        },
    )
    completion = WebWorkerCompletedActionRecord(
        workerTrustRegistryDigest=worker_registry.digest,
        role=execution.statement.role,
        authority=action.worker_authority_binding,
        gatewayLaunchId=receipt.gateway_launch_id,
        gatewayAuditRunId=receipt.gateway_audit_run_id,
        gatewayExecutionId=execution.statement.execution_id,
        workerExecutionId=execution.statement.execution_id,
        observerExecutionId=target.statement.execution_id,
        observerProcessId=target.statement.process_id,
        executorProcessId=execution.statement.process_id,
        observerKeyId=target.key_id,
        executorKeyId=execution.key_id,
        targetIdentityAttestationDigest=target.digest,
        executionAttestationDigest=execution.digest,
        workerActionEvidenceDigest=signed.digest,
        targetIdentityDigest=action.worker_authority_binding.expected_target_fingerprint_digest,
        runId=execution.statement.run_id,
        runRootDigest=execution.statement.run_root_digest,
        resultDigest=execution.statement.result_digest,
        workerResultDigest=canonical_web_worker_sha256(worker_result.model_dump(mode="json")),
        completedAt=worker_result.finished_at,
    )
    authority_digest = canonical_web_worker_sha256(
        {
            "domain": "pajin.web-gateway.completed-action-authority/v1",
            "receiptDigest": receipt.receipt_digest,
            "receiptReference": receipt_reference,
            "backendCompletionDigest": completion.completion_digest,
            "finalRootDigest": reference.root_digest,
            "finalEventHead": reference.event_head_digest,
        }
    )
    completion_event = snapshot.events[-1]
    expected_completion_payload: dict[str, JsonValue] = {
        "requestId": request.request_id,
        "executionId": execution.statement.execution_id,
        "receiptId": receipt.receipt_id,
        "receiptDigest": receipt.receipt_digest,
        "receiptReference": receipt_reference,
        "backendCompletionDigest": completion.completion_digest,
    }
    event_times = tuple(event.occurred_at for event in snapshot.events)
    revoked_event_times = event_times[7:11]
    first_provenance = {
        artifact.path: artifact.provenance for artifact in snapshot.seals[0].artifacts
    }
    final_provenance = {
        artifact.path: artifact.provenance for artifact in snapshot.seals[1].artifacts
    }
    evidence_provenance = first_provenance.get(evidence_reference)
    reservation_provenance = first_provenance.get(reservation_reference)
    receipt_provenance = final_provenance.get(receipt_reference)
    expected_evidence_event_ids = [
        snapshot.events[index].event_id for index in (0, 1, 6, 11, 12)
    ]
    if (
        snapshot.verification.root_digest != reference.root_digest
        or snapshot.verification.seal_count != 2
        or snapshot.verification.artifact_count != 3
        or snapshot.verification.event_count != 14
        or tuple(event.event_type for event in snapshot.events) != expected_event_types
        or len(snapshot.seals) != 2
        or snapshot.seals[0].event_count != 13
        or snapshot.seals[1].event_count != 14
        or snapshot.seals[0].root_digest != receipt.gateway_audit_root_digest
        or snapshot.seals[0].event_head_hash != receipt.gateway_event_head_digest
        or snapshot.seals[1].previous_root_digest != receipt.gateway_audit_root_digest
        or snapshot.seals[1].event_head_hash != reference.event_head_digest
        or sealed_paths != set(requests)
        or decoded_receipt != receipt
        or reservation != expected_reservation
        or request != action.request
        or request.tool_id != WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID
        or decision != expected_decision
        or expected_decision
        != PolicyDecision(
            allowed=True,
            reason="all policy checks passed",
            policy="allow",
        )
        or set(worker_job) != expected_job_keys
        or worker_job.get("requestId") != request.request_id
        or worker_job.get("executionId") != execution.statement.execution_id
        or worker_job.get("image") != WEB_HOST_WORKER_IMAGE
        or worker_job.get("command") != list(WEB_ASSESSMENT_EXECUTOR_COMMAND)
        or worker_job.get("network") != "egress-proxy"
        or worker_job.get("egressPolicy") != expected_egress_policy
        or worker_job.get("limits") != expected_limits
        or type(stdin_bytes) is not int
        or not 1 <= stdin_bytes <= 1_000_000
        or not isinstance(stdin_sha256, str)
        or re.fullmatch(_SHA256_PATTERN, stdin_sha256) is None
        or worker_job.get("secretLeaseIds") != []
        or secret_requests != expected_secret_requests
        or len(leases) != 4
        or tuple(lease.binding for lease in leases) != expected_bindings
        or len(set(lease_ids)) != 4
        or any(
            lease.scope != receipt.gateway_audit_run_id
            or lease.audience != f"{request.agent_id}:{execution.statement.execution_id}"
            or re.fullmatch(r"^[a-f0-9]{16}$", lease.secret_ref_fingerprint) is None
            or lease.status is not SecretLeaseStatus.REVOKED
            or lease.max_uses != 1
            or lease.remaining_uses != 0
            or lease.revoked_reason != "Worker execution finished"
            or lease.expires_at != lease.issued_at + timedelta(seconds=300)
            for lease in leases
        )
        or tuple(event.payload for event in snapshot.events[:13]) != expected_payloads
        or event_times != tuple(sorted(event_times))
        or any(
            lease.issued_at > issued_event.occurred_at
            for lease, issued_event in zip(leases, snapshot.events[2:6], strict=True)
        )
        or event_times[6] > worker_result.started_at
        or execution.statement.started_at < worker_result.started_at
        or execution.statement.finished_at > worker_result.finished_at
        or any(worker_result.finished_at > at for at in revoked_event_times)
        or snapshot.seals[0].sealed_at < event_times[12]
        or receipt.completed_at < snapshot.seals[0].sealed_at
        or receipt.completed_at != completion_event.occurred_at
        or snapshot.seals[1].sealed_at < completion_event.occurred_at
        or not enriched_result.success
        or stored_result.error is not None
        or enriched_result.request_id != request.request_id
        or enriched_result.tool_id != request.tool_id
        or enriched_result.data
        != {"workerOutput": action.worker_output.model_dump(mode="json", by_alias=True)}
        or worker_result.status is not WorkerStatus.SUCCEEDED
        or worker_result.backend != WEB_WORKER_BACKEND_NAME
        or worker_result.execution_id != execution.statement.execution_id
        or worker_result.failure_code is not None
        or worker_result.exit_code != 0
        or worker_result.stderr != ""
        or worker_result.network_log != ""
        or worker_result.stdout_truncated
        or worker_result.stderr_truncated
        or stdout_evidence != signed
        or action.worker_output.worker_attestation
        != signed.model_dump(mode="json", by_alias=True)
        or receipt.worker_result_digest
        != canonical_web_worker_sha256(worker_result.model_dump(mode="json"))
        or receipt.tool_result_digest
        != canonical_web_worker_sha256(enriched_result.model_dump(mode="json"))
        or receipt.policy_decision_digest
        != canonical_web_worker_sha256(decision.model_dump(mode="json"))
        or receipt.gateway_outcome_digest
        != canonical_web_worker_sha256(outcome.model_dump(mode="json"))
        or sha256(snapshot.artifact_bytes(evidence_reference)).hexdigest()
        != receipt.gateway_evidence_digest
        or sha256(snapshot.artifact_bytes(reservation_reference)).hexdigest()
        != receipt.gateway_request_reservation_digest
        or receipt.backend_completion_digest != completion.completion_digest
        or reference.completion_authority_digest != authority_digest
        or completion_event.payload != expected_completion_payload
        or evidence_provenance is None
        or evidence_provenance.request_id != request.request_id
        or evidence_provenance.tool_id != request.tool_id
        or evidence_provenance.execution_id != execution.statement.execution_id
        or evidence_provenance.event_ids != expected_evidence_event_ids
        or reservation_provenance is None
        or reservation_provenance.request_id is not None
        or reservation_provenance.tool_id is not None
        or reservation_provenance.execution_id is not None
        or reservation_provenance.event_ids != [snapshot.events[0].event_id]
        or receipt_provenance is None
        or receipt_provenance.request_id is not None
        or receipt_provenance.tool_id is not None
        or receipt_provenance.execution_id is not None
        or receipt_provenance.event_ids != [completion_event.event_id]
    ):
        raise GovernedWebCampaignEvidenceError(
            f"governed WEB {role} Gateway completion chain differs"
        )


def _verified_database_checkpoint_chain(
    *,
    output_root: Path,
    store_kind: GovernedWebCampaignDatabaseStoreKind,
    final_reference: str,
    final_sha256: str,
    schema_digest: str,
    max_bytes: int,
    enrollment: GovernedWebCampaignDatabaseEnrollment,
    database_checkpoints: tuple[GovernedWebCampaignDatabaseCheckpoint, ...],
) -> VerifiedPinnedSQLiteDatabase:
    parent_checkpoints = tuple(
        checkpoint
        for checkpoint in database_checkpoints
        if checkpoint.store_kind == store_kind
    )
    if not parent_checkpoints:
        raise GovernedWebCampaignEvidenceError(
            f"completed governed WEB {store_kind} database has no parent checkpoint"
        )
    latest = parent_checkpoints[-1]
    try:
        verified = load_verified_pinned_sqlite_database(
            output_root,
            final_database_reference=final_reference,
            expected_store_kind=store_kind,
            expected_campaign_id=GOVERNED_WEB_CAMPAIGN_ID,
            expected_schema_digest=schema_digest,
            expected_latest_manifest_reference=latest.manifest_reference,
            expected_latest_manifest_digest=latest.manifest_digest,
            expected_latest_ordinal=latest.ordinal,
            expected_final_database_sha256=final_sha256,
            expected_enrollment_reference=enrollment.reference,
            expected_enrollment_sha256=enrollment.sha256,
            expected_enrollment_size=enrollment.size,
            max_database_bytes=max_bytes,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            f"completed governed WEB {store_kind} database failed strict reload"
        ) from exc
    expected = tuple(
        (
            checkpoint.ordinal,
            checkpoint.database_reference,
            checkpoint.database_sha256,
            checkpoint.database_size,
            checkpoint.manifest_reference,
            checkpoint.manifest_digest,
            checkpoint.manifest_sha256,
            checkpoint.manifest_size,
            checkpoint.previous_manifest_digest,
            checkpoint.state_digest,
        )
        for checkpoint in parent_checkpoints
    )
    observed = tuple(
        (
            checkpoint.ordinal,
            checkpoint.database_reference,
            checkpoint.database_sha256,
            checkpoint.database_size,
            checkpoint.manifest_reference,
            checkpoint.manifest_digest,
            checkpoint.manifest_sha256,
            checkpoint.manifest_size,
            checkpoint.previous_manifest_digest,
            checkpoint.state_digest,
        )
        for checkpoint in verified.checkpoints
    )
    if (
        observed != expected
        or verified.final_publication.reference != final_reference
        or verified.final_publication.sha256 != final_sha256
        or verified.final_publication.size != verified.checkpoints[-1].database_size
        or verified.checkpoints[-1].database_sha256 != final_sha256
        or verified.enrollment_publication.reference != enrollment.reference
        or verified.enrollment_publication.sha256 != enrollment.sha256
        or verified.enrollment_publication.size != enrollment.size
    ):
        raise GovernedWebCampaignEvidenceError(
            f"completed governed WEB {store_kind} checkpoint lineage differs"
        )
    return verified


def _verify_grant_database(
    *,
    output_root: Path,
    models: _CompletedCampaignModels,
    evidence: GovernedWebCompletedCampaignEvidence,
    database_checkpoints: tuple[GovernedWebCampaignDatabaseCheckpoint, ...],
) -> None:
    final_reference = "authority/capability-grant-consumptions.sqlite3"
    verified = _verified_database_checkpoint_chain(
        output_root=output_root,
        store_kind="governed-web-grant",
        final_reference=final_reference,
        final_sha256=evidence.grant_database_sha256,
        schema_digest=_WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST,
        max_bytes=_WEB_GRANT_CONSUMPTION_MAX_BYTES,
        enrollment=evidence.grant_database_enrollment,
        database_checkpoints=database_checkpoints,
    )
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        with closing(connection):
            connection.deserialize(verified.database_bytes)
            _verify_web_grant_consumption_schema(connection, GOVERNED_WEB_CAMPAIGN_ID)
            reservation_rows = connection.execute(
                """
                SELECT reservation_id, reservation_digest, campaign_id,
                       capability_grant_id, request_id, permit_id,
                       approval_receipt_id, reservation_json
                FROM web_capability_grant_reservations
                ORDER BY capability_grant_id
                """
            ).fetchall()
            receipt_rows = connection.execute(
                """
                SELECT receipt_id, receipt_digest, reservation_id, campaign_id,
                       capability_grant_id, request_id, permit_id,
                       approval_receipt_id, receipt_json
                FROM web_capability_grant_consumptions
                ORDER BY capability_grant_id
                """
            ).fetchall()
            expected_checkpoint_state = {
                "reservations": [
                    {
                        "reservationId": str(row[0]),
                        "reservationDigest": str(row[1]),
                        "capabilityGrantId": str(row[3]),
                        "requestId": str(row[4]),
                        "permitId": str(row[5]),
                        "approvalReceiptId": str(row[6]),
                    }
                    for row in sorted(reservation_rows, key=lambda item: str(item[0]))
                ],
                "consumptions": [
                    {
                        "receiptId": str(row[0]),
                        "receiptDigest": str(row[1]),
                        "reservationId": str(row[2]),
                        "capabilityGrantId": str(row[4]),
                        "requestId": str(row[5]),
                        "permitId": str(row[6]),
                        "approvalReceiptId": str(row[7]),
                    }
                    for row in sorted(receipt_rows, key=lambda item: str(item[0]))
                ],
            }
    except (OSError, sqlite3.DatabaseError, TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Grant database failed typed reload"
        ) from exc
    if len(reservation_rows) != 2 or len(receipt_rows) != 2:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Grant database inventory differs"
        )
    try:
        reservations = {
            WebAssessmentCapabilityGrantReservation.model_validate_json(row[7]).capability_grant_id:
            WebAssessmentCapabilityGrantReservation.model_validate_json(row[7])
            for row in reservation_rows
        }
        receipts = {
            WebAssessmentCapabilityGrantConsumptionReceipt.model_validate_json(row[8]).capability_grant_id:
            WebAssessmentCapabilityGrantConsumptionReceipt.model_validate_json(row[8])
            for row in receipt_rows
        }
    except (TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Grant database record is invalid"
        ) from exc
    expected_actions = (models.source, models.validation)
    expected_grant_ids = {
        action.grant_consumption_receipt.capability_grant_id
        for action in expected_actions
    }
    if set(reservations) != expected_grant_ids:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Grant reservation identity differs"
        )
    for action in expected_actions:
        expected_receipt = action.grant_consumption_receipt
        reservation = reservations.get(expected_receipt.capability_grant_id)
        receipt = receipts.get(expected_receipt.capability_grant_id)
        if reservation is None or receipt is None:
            raise GovernedWebCampaignEvidenceError(
                "completed governed WEB Grant receipt is absent"
            )
        reservation_row = next(
            row for row in reservation_rows if row[3] == reservation.capability_grant_id
        )
        receipt_row = next(
            row for row in receipt_rows if row[4] == receipt.capability_grant_id
        )
        if (
            receipt != expected_receipt
            or receipt.reservation_id != reservation.reservation_id
            or receipt.reservation_digest != reservation.reservation_digest
            or receipt.campaign_id != reservation.campaign_id
            or receipt.grant_authority_digest != reservation.grant_authority_digest
            or receipt.capability_grant_id != reservation.capability_grant_id
            or receipt.capability_grant_digest != reservation.capability_grant_digest
            or receipt.request_id != reservation.request_id
            or receipt.request_digest != reservation.request_digest
            or receipt.permit_id != reservation.permit_id
            or receipt.permit_digest != reservation.permit_digest
            or receipt.approval_receipt_id != reservation.approval_receipt_id
            or receipt.approval_receipt_digest != reservation.approval_receipt_digest
            or receipt.consumed_at < reservation.reserved_at
            or reservation_row[:7]
            != (
                reservation.reservation_id,
                reservation.reservation_digest,
                reservation.campaign_id,
                reservation.capability_grant_id,
                reservation.request_id,
                reservation.permit_id,
                reservation.approval_receipt_id,
            )
            or receipt_row[:8]
            != (
                receipt.receipt_id,
                receipt.receipt_digest,
                receipt.reservation_id,
                receipt.campaign_id,
                receipt.capability_grant_id,
                receipt.request_id,
                receipt.permit_id,
                receipt.approval_receipt_id,
            )
        ):
            raise GovernedWebCampaignEvidenceError(
                "completed governed WEB Grant reservation or receipt differs"
            )
    try:
        latest_state = parse_strict_json_bytes(
            verified.checkpoints[-1].state_json,
            label="governed WEB Grant checkpoint state",
            max_bytes=1_000_000,
            max_depth=16,
            max_nodes=10_000,
        )
    except ValueError as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Grant checkpoint state is invalid"
        ) from exc
    if latest_state != expected_checkpoint_state:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Grant checkpoint state differs"
        )


def _verify_graph_database(
    *,
    output_root: Path,
    models: _CompletedCampaignModels,
    evidence: GovernedWebCompletedCampaignEvidence,
    result: GovernedWebCampaignHistoricalResult,
    database_checkpoints: tuple[GovernedWebCampaignDatabaseCheckpoint, ...],
) -> None:
    final_reference = "authority/governed-web.sqlite3"
    verified = _verified_database_checkpoint_chain(
        output_root=output_root,
        store_kind="governed-web-graph",
        final_reference=final_reference,
        final_sha256=evidence.graph_database_sha256,
        schema_digest=_GRAPH_SCHEMA_DIGEST,
        max_bytes=_MAX_GRAPH_BYTES,
        enrollment=evidence.graph_database_enrollment,
        database_checkpoints=database_checkpoints,
    )
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        with closing(connection):
            connection.deserialize(verified.database_bytes)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            _validate_schema(connection, campaign_id=GOVERNED_WEB_CAMPAIGN_ID)
            events = _events_from_connection(
                connection,
                campaign_id=GOVERNED_WEB_CAMPAIGN_ID,
            )
            _require_exact_node_index(
                connection,
                campaign_id=GOVERNED_WEB_CAMPAIGN_ID,
                events=events,
            )
            projections = _verified_projections(
                connection,
                campaign_id=GOVERNED_WEB_CAMPAIGN_ID,
                events=events,
            )
            snapshots, snapshot_head = _verified_snapshots(
                connection,
                campaign_id=GOVERNED_WEB_CAMPAIGN_ID,
                projections=projections,
            )
            snapshot = snapshots.get(evidence.final_graph_snapshot.snapshot_id)
            history = tuple(snapshots.values())
            current_projection = projections[max(projections)]
            if snapshot is not None and (
                snapshot_head != snapshot.snapshot_digest
                or snapshot.projection != current_projection
            ):
                raise ValueError("governed WEB final Graph Snapshot is not current")
    except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Graph database failed strict reload"
        ) from exc
    if snapshot is None:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB final Graph Snapshot is absent"
        )
    initial_ref = evidence.initial_graph_snapshot
    final_ref = evidence.final_graph_snapshot
    initial_index = next(
        (
            index
            for index, item in enumerate(history)
            if item.snapshot_id == initial_ref.snapshot_id
        ),
        None,
    )
    final_index = next(
        (index for index, item in enumerate(history) if item.snapshot_id == final_ref.snapshot_id),
        None,
    )
    admission = models.graph_admission
    first_sequence = admission.events[0].sequence
    last_sequence = admission.events[-1].sequence
    expected_event_refs = tuple(
        (
            event.sequence,
            event.event_id,
            event.event_digest,
            event.proposal_id,
            event.proposal_digest,
        )
        for event in admission.events
    )
    observed_suffix = tuple(
        (
            event.sequence,
            event.event_id,
            event.event_digest,
            event.proposal_id,
            event.proposal_digest,
        )
        for event in events[first_sequence - 1 : last_sequence]
    )
    admitted_suffix = events[first_sequence - 1 : last_sequence]
    expected_proposal_kinds = (
        "SurfaceProposal",
        "HypothesisProposal",
        "HypothesisProposal",
        "HypothesisProposal",
        "ObservationProposal",
        "ObservationProposal",
        *("CampaignFactProposal" for _finding in models.promotion.findings),
    )
    expected_snapshot_creator_digest = _digest(
        "pajin.web-assessment.snapshot-authority/v1",
        {"campaignId": GOVERNED_WEB_CAMPAIGN_ID},
    )
    initial_snapshot = history[initial_index] if initial_index is not None else None
    final_snapshot = history[final_index] if final_index is not None else None
    surface_event = admitted_suffix[0] if admitted_suffix else None
    hypothesis_events = admitted_suffix[1:4]
    observation_events = admitted_suffix[4:6]
    fact_events = admitted_suffix[6:]
    hypothesis_checks: tuple[IssueCheck, IssueCheck, IssueCheck] = (
        "sql-login",
        "object-access",
        "dom-xss",
    )
    expected_hypothesis_ids = tuple(
        admission.hypothesis_node_ids.get(check)
        for check in hypothesis_checks
    )
    observed_hypothesis_ids = tuple(
        event.admitted_nodes[0].node_id
        if len(event.admitted_nodes) == 1
        and event.admitted_nodes[0].kind == "Hypothesis"
        else None
        for event in hypothesis_events
    )
    expected_finding_ids = tuple(finding.finding_id for finding in models.promotion.findings)
    observed_fact_ids = tuple(
        event.admitted_nodes[0].node_id
        if len(event.admitted_nodes) == 1
        and event.admitted_nodes[0].kind == "CampaignFact"
        else None
        for event in fact_events
    )
    if (
        graph_snapshot_ref(snapshot) != final_ref
        or initial_index is None
        or final_index is None
        or final_index != initial_index + 1
        or final_index != len(history) - 1
        or graph_snapshot_ref(history[initial_index]) != initial_ref
        or graph_snapshot_ref(history[final_index]) != final_ref
        or history[final_index].previous_snapshot_digest
        != history[initial_index].snapshot_digest
        or first_sequence != initial_ref.revision + 1
        or last_sequence != final_ref.revision
        or final_ref.revision != initial_ref.revision + len(admission.events)
        or len(events) != final_ref.revision
        or observed_suffix != expected_event_refs
        or len(admitted_suffix) != len(expected_proposal_kinds)
        or tuple(event.proposal_kind.value for event in admitted_suffix)
        != expected_proposal_kinds
        or any(
            event.decision.value != "admitted"
            or event.reason.value != "admitted"
            or event.campaign_id != GOVERNED_WEB_CAMPAIGN_ID
            or event.proposal_campaign_id != GOVERNED_WEB_CAMPAIGN_ID
            or event.authority_id != GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID
            or event.authority_digest != GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST
            or event.producer_id != GOVERNED_WEB_GRAPH_PRODUCER_ID
            or event.producer_version != GOVERNED_WEB_GRAPH_PRODUCER_VERSION
            or event.producer_digest != GOVERNED_WEB_GRAPH_PRODUCER_DIGEST
            for event in admitted_suffix
        )
        or surface_event is None
        or len(surface_event.admitted_nodes) != 1
        or surface_event.admitted_nodes[0].kind != "Surface"
        or admission.surface_node_id != surface_event.admitted_nodes[0].node_id
        or set(admission.hypothesis_node_ids)
        != {"sql-login", "object-access", "dom-xss"}
        or expected_hypothesis_ids != observed_hypothesis_ids
        or tuple(admission.finding_fact_node_ids) != expected_finding_ids
        or tuple(admission.finding_fact_node_ids[item] for item in expected_finding_ids)
        != observed_fact_ids
        or any(
            {node.kind for node in event.admitted_nodes}
            != {"Action", "Observation", "Evidence"}
            or len(event.admitted_nodes) != 3
            for event in observation_events
        )
        or initial_snapshot is None
        or final_snapshot is None
        or initial_snapshot.creator_id != "pajin.web.governed.snapshot-authority"
        or final_snapshot.creator_id != "pajin.web.governed.snapshot-authority"
        or initial_snapshot.creator_digest != expected_snapshot_creator_digest
        or final_snapshot.creator_digest != expected_snapshot_creator_digest
        or initial_snapshot.reason is not GraphSnapshotReason.CHECKPOINT
        or final_snapshot.reason is not GraphSnapshotReason.HANDOFF
        or initial_snapshot.created_at > admitted_suffix[0].occurred_at
        or admitted_suffix[-1].occurred_at > final_snapshot.created_at
        or final_ref.event_log_head_digest != events[-1].event_digest
        or result.graph_event_count != final_ref.revision
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Graph Snapshot or admission suffix differs"
        )
    try:
        latest_state = parse_strict_json_bytes(
            verified.checkpoints[-1].state_json,
            label="governed WEB Graph checkpoint state",
            max_bytes=2_000_000,
            max_depth=32,
            max_nodes=50_000,
        )
    except ValueError as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Graph checkpoint state is invalid"
        ) from exc
    if (
        not isinstance(latest_state, dict)
        or latest_state.get("eventRevision") != final_ref.revision
        or latest_state.get("eventHeadDigest") != final_ref.event_log_head_digest
        or latest_state.get("projectionRevision") != final_ref.revision
        or latest_state.get("projectionDigest") != final_ref.projection_digest
        or latest_state.get("snapshotHeadDigest") != final_ref.snapshot_digest
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Graph checkpoint state differs"
        )


def _verify_validation_run(
    *,
    output_root: Path,
    plan: GovernedWebCampaignPlan,
    models: _CompletedCampaignModels,
    evidence: GovernedWebCompletedCampaignEvidence,
    result: GovernedWebCampaignHistoricalResult,
) -> tuple[Path, VerifiedRunSnapshot]:
    relative = plan.planned_runs.relative_paths()["validationProjection"]
    path = _exact_external_path(
        output_root,
        relative,
        label="governed WEB validation Run",
        directory=True,
    )
    artifact_paths = {
        "governed-web-promotion.json",
        "governed-web-graph-admission.json",
        "candidate-findings.json",
        "validation-decisions.json",
        "validation-index.json",
        "findings.json",
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VERSIONED_VALIDATION_INDEX_PATH,
        VERSIONED_VALIDATION_REPORT_PATH,
    }
    try:
        snapshot = load_verified_run_artifacts(
            path,
            requests={item: 64 * 1024 * 1024 for item in artifact_paths},
            expected_run_id=plan.planned_runs.validation_projection_run_id,
        )
        loaded = load_validation_snapshot(
            path,
            expected_run_id=plan.planned_runs.validation_projection_run_id,
            expected_root_digest=evidence.validation_root_digest,
        )
        stored_promotion = GovernedWebPromotion.model_validate(
            parse_strict_json_bytes(
                snapshot.artifact_bytes("governed-web-promotion.json"),
                label="governed WEB stored Promotion",
                max_bytes=64 * 1024 * 1024,
                max_depth=64,
                max_nodes=200_000,
            )
        )
        stored_admission = GovernedWebGraphAdmission.model_validate(
            parse_strict_json_bytes(
                snapshot.artifact_bytes("governed-web-graph-admission.json"),
                label="governed WEB stored Graph admission",
                max_bytes=64 * 1024 * 1024,
                max_depth=64,
                max_nodes=200_000,
            )
        )
    except (OSError, RunIntegrityError, TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB validation Run failed strict reload"
        ) from exc
    first_event_payload: dict[str, JsonValue] = {
        "candidateCount": len(models.promotion.findings),
        "promotionDigest": models.promotion.promotion_digest,
        "graphAdmissionDigest": models.graph_admission.admission_digest,
        "graphEventCount": len(models.graph_admission.events),
    }
    second_event_payload: dict[str, JsonValue] = {
        "candidateSourceRootDigest": snapshot.seals[0].root_digest,
        "confirmedCount": len(models.promotion.findings),
        "confirmationSemantics": "verified-independent-replay",
    }
    report = snapshot.artifact_bytes(VERSIONED_VALIDATION_REPORT_PATH)
    expected_report_reference = (
        f"{relative}/{VERSIONED_VALIDATION_REPORT_PATH}"
    )
    sealed_paths = {
        artifact.path for seal in snapshot.seals for artifact in seal.artifacts
    }
    if (
        snapshot.verification.root_digest != evidence.validation_root_digest
        or snapshot.verification.root_digest
        != result.validation_projection_root_digest
        or snapshot.verification.seal_count != 2
        or snapshot.verification.event_count != 2
        or snapshot.verification.artifact_count != len(artifact_paths)
        or len(snapshot.seals) != 2
        or snapshot.seals[0].event_count != 1
        or snapshot.seals[1].event_count != 2
        or snapshot.seals[1].previous_root_digest != snapshot.seals[0].root_digest
        or sealed_paths != artifact_paths
        or tuple(event.event_type for event in snapshot.events)
        != (
            "web-governed.validation-source-created",
            "web-governed.validation-confirmed",
        )
        or snapshot.events[0].payload != first_event_payload
        or snapshot.events[1].payload != second_event_payload
        or snapshot.events[0].occurred_at != snapshot.events[1].occurred_at
        or stored_promotion != models.promotion
        or stored_admission != models.graph_admission
        or loaded.semantics is not ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY
        or loaded.index is None
        or loaded.index.source_run_id != plan.planned_runs.validation_projection_run_id
        or loaded.index.candidate_source_root_digest != snapshot.seals[0].root_digest
        or loaded.product_confirmed_findings != list(models.promotion.findings)
        or report != _render_validation_report(models.promotion).encode("utf-8")
        or sha256(report).hexdigest() != evidence.validation_report_sha256
        or result.validation_projection_run_id
        != plan.planned_runs.validation_projection_run_id
        or result.report_reference != expected_report_reference
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB validation projection differs"
        )
    return path, snapshot


def _verify_poc_bundle(
    *,
    output_root: Path,
    models: _CompletedCampaignModels,
    evidence: GovernedWebCompletedCampaignEvidence,
    result: GovernedWebCampaignHistoricalResult,
    sarif_finding_set_digest: str,
) -> RedactedGovernedWebPocManifest:
    bundle_root = _exact_external_path(
        output_root,
        "poc-bundle",
        label="governed WEB PoC bundle",
        directory=True,
    )
    manifest_path = _exact_external_path(
        output_root,
        result.poc_manifest_reference,
        label="governed WEB PoC manifest",
        directory=False,
    )
    try:
        manifest = RedactedGovernedWebPocManifest.model_validate(
            parse_strict_json_bytes(
                read_bounded_regular_bytes(
                    manifest_path,
                    max_bytes=2 * 1024 * 1024,
                    label="governed WEB PoC manifest",
                    require_single_link=True,
                ),
                label="governed WEB PoC manifest",
                max_bytes=2 * 1024 * 1024,
                max_depth=16,
                max_nodes=1_000,
            )
        )
        reloaded = load_verified_redacted_governed_web_poc_manifest(
            manifest_path,
            expected=manifest,
            bundle_root=bundle_root,
        )
    except (OSError, TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB PoC bundle failed strict reload"
        ) from exc
    execution = models.execution_evidence
    if (
        reloaded.manifest_digest != evidence.poc_manifest_digest
        or reloaded.manifest_digest != result.poc_manifest_digest
        or reloaded.campaign_id != models.campaign.metadata.name
        or reloaded.campaign_manifest_digest != evidence.campaign_digest
        or reloaded.origin != GOVERNED_WEB_ORIGIN
        or reloaded.adapter_ref != GOVERNED_WEB_ADAPTER_REF
        or reloaded.adapter_digest != execution.adapter_digest
        or reloaded.target_identity_digest != execution.target_identity_digest
        or reloaded.source_assessment_run_id != execution.source_run_id
        or reloaded.source_assessment_root_digest != execution.source_root_digest
        or reloaded.validation_assessment_run_id != execution.validation_run_id
        or reloaded.validation_assessment_root_digest != execution.validation_root_digest
        or reloaded.promotion_digest != models.promotion.promotion_digest
        or reloaded.graph_admission_digest != models.graph_admission.admission_digest
        or reloaded.validation_run_id != result.validation_projection_run_id
        or reloaded.validation_root_digest != evidence.validation_root_digest
        or reloaded.finding_set_digest != sarif_finding_set_digest
        or reloaded.finding_count != len(models.promotion.findings)
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB PoC lineage differs"
        )
    return reloaded


def _verify_export_bundle(
    *,
    output_root: Path,
    validation_path: Path,
    validation_snapshot: VerifiedRunSnapshot,
    models: _CompletedCampaignModels,
    evidence: GovernedWebCompletedCampaignEvidence,
    result: GovernedWebCampaignHistoricalResult,
) -> SarifExportProjection:
    exports_root = _exact_external_path(
        output_root,
        "exports",
        label="governed WEB export bundle",
        directory=True,
    )
    sarif_path = _exact_external_path(
        output_root,
        result.sarif_reference,
        label="governed WEB SARIF export",
        directory=False,
    )
    delivery_path = _exact_external_path(
        output_root,
        result.delivery_readiness_reference,
        label="governed WEB delivery-readiness manifest",
        directory=False,
    )
    try:
        authority = load_verified_sarif_export(
            validation_path,
            expected_run_id=result.validation_projection_run_id,
            expected_root_digest=evidence.validation_root_digest,
        )
        projection = authority.projection
        sarif_bytes = read_bounded_regular_bytes(
            sarif_path,
            max_bytes=64 * 1024 * 1024,
            label="governed WEB SARIF export",
            require_single_link=True,
        )
        delivery = load_verified_governed_web_delivery_manifest(
            delivery_path,
            expected_source_run_id=projection.source_run_id,
            expected_source_root_digest=projection.source_root_digest,
            expected_finding_set_digest=projection.finding_set_digest,
            expected_sarif_digest=projection.sarif_digest,
            expected_finding_count=projection.finding_count,
        )
        expected_delivery = _delivery_manifest(
            authority,
            prepared_at=delivery.prepared_at,
        )
    except (OSError, RunIntegrityError, TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB export bundle failed strict reload"
        ) from exc
    if (
        set(os.listdir(exports_root))
        != {Path(result.sarif_reference).name, Path(result.delivery_readiness_reference).name}
        or sarif_bytes != projection.content.encode("utf-8")
        or sha256(sarif_bytes).hexdigest() != projection.sarif_digest
        or projection.sarif_digest != evidence.sarif_digest
        or projection.sarif_digest != result.sarif_digest
        or projection.source_run_id != result.validation_projection_run_id
        or projection.source_root_digest != evidence.validation_root_digest
        or projection.finding_count != len(models.promotion.findings)
        or delivery != expected_delivery
        or delivery.prepared_at < validation_snapshot.seals[-1].sealed_at
        or delivery.manifest_digest != evidence.delivery_manifest_digest
        or delivery.external_delivery_performed is not False
        or delivery.delivery_receipt_authority is not False
        or delivery.delivery_authorization_present is not False
        or delivery.distinct_coordinator_record_supplied is not False
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB SARIF or delivery lineage differs"
        )
    return projection


def _verify_completed_external_chain(
    parent_run_path: Path,
    plan: GovernedWebCampaignPlan,
    evidence: GovernedWebCompletedCampaignEvidence,
    result: GovernedWebCampaignHistoricalResult,
    *,
    database_checkpoints: tuple[GovernedWebCampaignDatabaseCheckpoint, ...],
) -> _CompletedCampaignModels:
    """Re-derive historical evidence from every immutable child before completion."""

    _require_code_trust_bindings(plan.trust_bundle)
    models = _parse_completed_campaign_models(evidence)
    if models.campaign != CampaignManifest.model_validate(evidence.campaign):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Campaign changed during typed verification"
        )
    worker_registry = _verify_completed_signatures(models, plan.trust_bundle)
    if (
        models.grants.source.parent_grant_id != models.grants.root.grant_id
        or models.grants.validation.parent_grant_id != models.grants.root.grant_id
        or models.grants.source.grant_id == models.grants.validation.grant_id
        or models.grants.source.campaign != models.campaign.metadata.name
        or models.grants.validation.campaign != models.campaign.metadata.name
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB Capability Grant lineage differs"
        )
    _require_action_links(
        role="source",
        action=models.source,
        grant=models.grants.source,
        models=models,
        plan=plan,
    )
    _require_action_links(
        role="validation",
        action=models.validation,
        grant=models.grants.validation,
        models=models,
        plan=plan,
    )
    _require_execution_links(
        models=models,
        evidence=evidence,
        result=result,
        worker_registry=worker_registry,
    )
    output_root = _completed_output_root(parent_run_path, plan)
    _verify_browser_run(output_root=output_root, role="source", action=models.source)
    _verify_browser_run(
        output_root=output_root,
        role="validation",
        action=models.validation,
    )
    _verify_gateway_run(
        output_root=output_root,
        role="source",
        action=models.source,
        campaign=models.campaign,
        grant=models.grants.source,
        worker_registry=worker_registry,
    )
    _verify_gateway_run(
        output_root=output_root,
        role="validation",
        action=models.validation,
        campaign=models.campaign,
        grant=models.grants.validation,
        worker_registry=worker_registry,
    )
    _verify_grant_database(
        output_root=output_root,
        models=models,
        evidence=evidence,
        database_checkpoints=database_checkpoints,
    )
    _verify_graph_database(
        output_root=output_root,
        models=models,
        evidence=evidence,
        result=result,
        database_checkpoints=database_checkpoints,
    )
    validation_path, validation_snapshot = _verify_validation_run(
        output_root=output_root,
        plan=plan,
        models=models,
        evidence=evidence,
        result=result,
    )
    sarif_projection = _verify_export_bundle(
        output_root=output_root,
        validation_path=validation_path,
        validation_snapshot=validation_snapshot,
        models=models,
        evidence=evidence,
        result=result,
    )
    _verify_poc_bundle(
        output_root=output_root,
        models=models,
        evidence=evidence,
        result=result,
        sarif_finding_set_digest=sarif_projection.finding_set_digest,
    )
    return models


def _relative_campaign_references(
    plan: GovernedWebCampaignPlan,
    result: GovernedWebCampaignHistoricalResult | None = None,
) -> Mapping[str, str]:
    references = dict(plan.planned_runs.relative_paths())
    references.update(
        {
            "graphDatabase": "authority/governed-web.sqlite3",
            "grantDatabase": "authority/capability-grant-consumptions.sqlite3",
            "pocManifest": "poc-bundle/poc/manifest.json",
            "sarif": "exports/findings.sarif",
            "deliveryReadiness": "exports/delivery-readiness.json",
        }
    )
    if result is not None:
        references["report"] = result.report_reference
    return MappingProxyType(references)


def _require_expected_anchor(
    plan: GovernedWebCampaignPlan,
    expected_deployment_trust_anchor_digest: str,
) -> None:
    if re.fullmatch(_SHA256_PATTERN, expected_deployment_trust_anchor_digest) is None:
        raise ValueError("expected deployment trust anchor digest is invalid")
    _require_distinct_trust_identities(plan.trust_bundle)
    if (
        plan.deployment_trust_anchor_digest
        != expected_deployment_trust_anchor_digest
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB deployment trust anchor differs from the pinned anchor"
        )


def _verified_parent_plan(
    prefix: _ParentSealedPrefix,
    *,
    expected_campaign_plan_digest: str,
    expected_deployment_trust_anchor_digest: str,
) -> GovernedWebCampaignPlan:
    plan = cast(
        GovernedWebCampaignPlan,
        _load_parent_model(
            prefix,
            _CAMPAIGN_PLAN_PATH,
            GovernedWebCampaignPlan,
            max_bytes=_MAX_PLAN_BYTES,
        ),
    )
    if re.fullmatch(_SHA256_PATTERN, expected_campaign_plan_digest) is None:
        raise ValueError("expected governed WEB campaign Plan Digest is invalid")
    if (
        plan.planned_runs.parent_run_id != prefix.run_id
        or plan.campaign_plan_digest != expected_campaign_plan_digest
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent Run or Plan differs from its pinned Plan"
        )
    _require_expected_anchor(plan, expected_deployment_trust_anchor_digest)
    key = plan.trust_bundle.index_signing_key
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(
                key.public_key_base64url,
                size=32,
                label="campaign evidence Plan public key",
            )
        ).verify(
            _decode_base64url(
                plan.signature_base64url,
                size=64,
                label="campaign evidence Plan signature",
            ),
            plan.signed_bytes(),
        )
    except InvalidSignature as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB campaign Plan signature is invalid"
        ) from exc
    return plan


def _initial_plan_only_prefix(prefix: _ParentSealedPrefix) -> _ParentSealedPrefix:
    """Discard unpinned, unkeyed progression while retaining the anchored Plan."""

    first = prefix.seals[0]
    if (
        first.event_count != 1
        or len(prefix.events) < 1
        or {artifact.path for artifact in first.artifacts} != {_CAMPAIGN_PLAN_PATH}
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB initial Plan checkpoint differs"
        )
    return _ParentSealedPrefix(
        run_path=prefix.run_path,
        run_id=prefix.run_id,
        root_digest=first.root_digest,
        events=(prefix.events[0].model_copy(deep=True),),
        seals=(first.model_copy(deep=True),),
        artifacts=MappingProxyType(
            {_CAMPAIGN_PLAN_PATH: prefix.artifacts[_CAMPAIGN_PLAN_PATH]}
        ),
        has_unsealed_tail=(
            prefix.has_unsealed_tail
            or len(prefix.seals) > 1
            or len(prefix.events) > 1
            or len(prefix.artifacts) > 1
        ),
    )


def _require_completed_group(
    prefix: _ParentSealedPrefix,
    plan: GovernedWebCampaignPlan,
    progression: _CampaignProgression,
) -> tuple[
    GovernedWebCompletedCampaignEvidence,
    GovernedWebCampaignHistoricalResult,
    GovernedWebCampaignIndex,
]:
    terminal = progression.terminal_event
    if (
        terminal is None
        or terminal.event_type != "campaign.completed"
        or progression.completed != GOVERNED_WEB_CAMPAIGN_STAGE_ORDER
        or progression.active_checkpoint is not None
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent journal is not a completed campaign"
        )
    evidence = cast(
        GovernedWebCompletedCampaignEvidence,
        _load_parent_model(
            prefix,
            _CAMPAIGN_EVIDENCE_PATH,
            GovernedWebCompletedCampaignEvidence,
            max_bytes=_MAX_EVIDENCE_BYTES,
        ),
    )
    result = cast(
        GovernedWebCampaignHistoricalResult,
        _load_parent_model(
            prefix,
            _CAMPAIGN_RESULT_PATH,
            GovernedWebCampaignHistoricalResult,
            max_bytes=_MAX_RESULT_BYTES,
        ),
    )
    index = cast(
        GovernedWebCampaignIndex,
        _load_parent_model(
            prefix,
            _CAMPAIGN_INDEX_PATH,
            GovernedWebCampaignIndex,
            max_bytes=_MAX_INDEX_BYTES,
        ),
    )
    expected_artifacts = {
        _CAMPAIGN_PLAN_PATH,
        *(
            _campaign_checkpoint_path(stage, status)
            for stage in GOVERNED_WEB_CAMPAIGN_STAGE_ORDER
            for status in _CAMPAIGN_CHECKPOINT_STATUSES
        ),
        *(
            _campaign_database_checkpoint_path(
                stage=checkpoint.stage,
                store_kind=checkpoint.store_kind,
                ordinal=checkpoint.ordinal,
            )
            for checkpoint in progression.database_checkpoints
        ),
        _CAMPAIGN_EVIDENCE_PATH,
        _CAMPAIGN_RESULT_PATH,
        _CAMPAIGN_INDEX_PATH,
    }
    if set(prefix.artifacts) != expected_artifacts:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB parent artifact inventory differs"
        )
    key = plan.trust_bundle.index_signing_key
    if (
        evidence.trust_bundle != plan.trust_bundle
        or evidence.campaign_id != result.campaign_id
        or evidence.campaign_digest != result.campaign_digest
        or result.deployment_trust_anchor_digest
        != plan.deployment_trust_anchor_digest
        or index.parent_run_id != prefix.run_id
        or index.campaign_plan_digest != plan.campaign_plan_digest
        or index.evidence_digest != evidence.evidence_digest
        or index.deployment_trust_anchor_digest
        != plan.deployment_trust_anchor_digest
        or index.final_graph_snapshot_id != evidence.final_graph_snapshot.snapshot_id
        or index.final_graph_snapshot_digest
        != evidence.final_graph_snapshot.snapshot_digest
        or index.signer_key_id != key.key_id
        or terminal.occurred_at != index.signed_at
        or not key.not_before <= index.signed_at < key.not_after
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB completed evidence links differ"
        )
    indexed_artifacts = {artifact.path: artifact for artifact in index.artifacts}
    indexed_paths: tuple[_CampaignIndexArtifactPath, ...] = (
        _CAMPAIGN_PLAN_PATH,
        _CAMPAIGN_EVIDENCE_PATH,
        _CAMPAIGN_RESULT_PATH,
    )
    for path in indexed_paths:
        content = prefix.artifacts[path]
        record = indexed_artifacts[path]
        if record.sha256 != sha256(content).hexdigest() or record.size_bytes != len(content):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB campaign index artifact digest differs"
            )
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(
                key.public_key_base64url,
                size=32,
                label="campaign evidence index public key",
            )
        ).verify(
            _decode_base64url(
                index.signature_base64url,
                size=64,
                label="campaign evidence index signature",
            ),
            index.signed_bytes(),
        )
    except InvalidSignature as exc:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB campaign index signature is invalid"
        ) from exc
    expected_terminal_payload: dict[str, JsonValue] = {
        "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
        "campaignPlanDigest": plan.campaign_plan_digest,
        "evidenceDigest": evidence.evidence_digest,
        "indexDigest": index.index_digest,
        "deploymentTrustAnchorDigest": plan.deployment_trust_anchor_digest,
        "externalDeliveryPerformed": False,
    }
    if terminal.payload != expected_terminal_payload:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB completion event differs from its signed index"
        )
    planned = plan.planned_runs
    if (
        result.source_run_id != planned.source_browser_run_id
        or result.validation_run_id != planned.validation_browser_run_id
        or result.source_gateway_run_id != planned.source_gateway_run_id
        or result.validation_gateway_run_id != planned.validation_gateway_run_id
        or result.validation_projection_run_id != planned.validation_projection_run_id
        or result.validation_projection_root_digest != evidence.validation_root_digest
        or result.sarif_digest != evidence.sarif_digest
        or result.poc_manifest_digest != evidence.poc_manifest_digest
        or result.graph_event_count != evidence.final_graph_snapshot.revision
    ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB historical result differs from completed evidence"
        )
    _verify_completed_external_chain(
        prefix.run_path,
        plan,
        evidence,
        result,
        database_checkpoints=progression.database_checkpoints,
    )
    return evidence, result, index


def _require_failed_group(
    prefix: _ParentSealedPrefix,
    progression: _CampaignProgression,
) -> GovernedWebIncompleteCampaignEvidence:
    terminal = progression.terminal_event
    if terminal is None or terminal.event_type != "campaign.failed":
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent journal is not a failed campaign"
        )
    incomplete = cast(
        GovernedWebIncompleteCampaignEvidence,
        _load_parent_model(
            prefix,
            _INCOMPLETE_PATH,
            GovernedWebIncompleteCampaignEvidence,
            max_bytes=_MAX_INCOMPLETE_BYTES,
        ),
    )
    active_stage = (
        progression.active_checkpoint.stage
        if progression.active_checkpoint is not None
        else None
    )
    if (
        incomplete.completed_stages != progression.completed
        or incomplete.active_stage != active_stage
        or incomplete.may_have_executed != (active_stage is not None)
    ):
        raise GovernedWebCampaignEvidenceError(
            "incomplete governed WEB evidence differs from sealed progression"
        )
    failure_seal = prefix.seals[-1]
    expected_payload: dict[str, JsonValue] = {
        "campaignId": GOVERNED_WEB_CAMPAIGN_ID,
        "failureStage": incomplete.failure_stage,
        "failureType": incomplete.failure_type,
        "incompleteDigest": incomplete.incomplete_digest,
        "mayHaveExecuted": incomplete.may_have_executed,
        "externalDeliveryPerformed": False,
    }
    if (
        terminal.payload != expected_payload
        or incomplete.previous_journal_root_digest
        != failure_seal.previous_root_digest
            or _INCOMPLETE_PATH not in {
                artifact.path for artifact in failure_seal.artifacts
            }
            or any(not _is_known_parent_artifact(path) for path in prefix.artifacts)
        ):
        raise GovernedWebCampaignEvidenceError(
            "governed WEB failure terminal differs from its sealed evidence"
        )
    return incomplete


def load_verified_governed_web_campaign_terminal(
    parent_run_path: Path,
    *,
    expected_parent_run_id: str,
    expected_parent_root_digest: str | None,
    expected_campaign_plan_digest: str,
    expected_deployment_trust_anchor_digest: str,
) -> VerifiedGovernedWebCampaign:
    """Load one verified terminal or latest sealed crash prefix as evidence only."""

    prefix = _load_parent_sealed_prefix(
        parent_run_path,
        expected_parent_run_id=expected_parent_run_id,
        expected_parent_root_digest=expected_parent_root_digest,
    )
    if expected_parent_root_digest is None:
        prefix = _initial_plan_only_prefix(prefix)
    plan = _verified_parent_plan(
        prefix,
        expected_campaign_plan_digest=expected_campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(
            expected_deployment_trust_anchor_digest
        ),
    )
    progression = _load_campaign_progression(prefix, plan)
    terminal = progression.terminal_event
    if terminal is not None and terminal.event_type == "campaign.completed":
        if prefix.has_unsealed_tail:
            raise GovernedWebCampaignEvidenceError(
                "completed governed WEB parent has an unsealed extension"
            )
        evidence, result, index = _require_completed_group(prefix, plan, progression)
        return VerifiedGovernedWebCompletedCampaign(
            parent_run_path=prefix.run_path,
            parent_run_id=prefix.run_id,
            parent_root_digest=prefix.root_digest,
            deployment_trust_anchor_digest=plan.deployment_trust_anchor_digest,
            plan=plan.model_copy(deep=True),
            evidence=evidence.model_copy(deep=True),
            result=result.model_copy(deep=True),
            index=index.model_copy(deep=True),
            events=prefix.events,
            seals=prefix.seals,
            relative_references=_relative_campaign_references(plan, result),
        )
    if terminal is not None and terminal.event_type == "campaign.failed":
        incomplete = _require_failed_group(prefix, progression)
        terminal_state: Literal["failed", "interrupted"] = "failed"
    elif terminal is None:
        if len(progression.completed) >= len(GOVERNED_WEB_CAMPAIGN_STAGE_ORDER):
            raise GovernedWebCampaignEvidenceError(
                "governed WEB completed stage inventory lacks its terminal"
            )
        active_stage = (
            progression.active_checkpoint.stage
            if progression.active_checkpoint is not None
            else None
        )
        incomplete = GovernedWebIncompleteCampaignEvidence(
            failureStage=GOVERNED_WEB_CAMPAIGN_STAGE_ORDER[len(progression.completed)],
            failureType="hard-crash-prefix",
            completedStages=progression.completed,
            activeStage=active_stage,
            mayHaveExecuted=active_stage is not None,
            accountProvisioningState=(
                "confirmed-retained"
                if "provisioning" in progression.completed
                else "may-have-executed"
                if active_stage == "provisioning"
                else "not-started"
            ),
            previousJournalRootDigest=prefix.root_digest,
        )
        terminal_state = "interrupted"
    else:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent has an unsupported terminal event"
        )
    active_intent = (
        progression.active_checkpoint.intent
        if progression.active_checkpoint is not None
        else None
    )
    return VerifiedGovernedWebIncompleteCampaign(
        parent_run_path=prefix.run_path,
        parent_run_id=prefix.run_id,
        parent_root_digest=prefix.root_digest,
        deployment_trust_anchor_digest=plan.deployment_trust_anchor_digest,
        plan=plan.model_copy(deep=True),
        incomplete=incomplete.model_copy(deep=True),
        terminal=terminal_state,
        completed_stages=progression.completed,
        active_stage=(
            progression.active_checkpoint.stage
            if progression.active_checkpoint is not None
            else None
        ),
        active_intent=(active_intent.model_copy(deep=True) if active_intent else None),
        observations=tuple(item.model_copy(deep=True) for item in progression.observations),
        events=prefix.events,
        seals=prefix.seals,
        has_unsealed_tail=prefix.has_unsealed_tail,
        relative_references=_relative_campaign_references(plan),
    )


def load_verified_governed_web_completed_campaign_evidence(
    parent_run_path: Path,
    *,
    expected_parent_run_id: str,
    expected_parent_root_digest: str,
    expected_campaign_plan_digest: str,
    expected_deployment_trust_anchor_digest: str,
) -> VerifiedGovernedWebCompletedCampaign:
    """Strictly reload a current completed parent Run; never mint authorities."""

    loaded = load_verified_governed_web_campaign_terminal(
        parent_run_path,
        expected_parent_run_id=expected_parent_run_id,
        expected_parent_root_digest=expected_parent_root_digest,
        expected_campaign_plan_digest=expected_campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(
            expected_deployment_trust_anchor_digest
        ),
    )
    if type(loaded) is not VerifiedGovernedWebCompletedCampaign:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent is not a completed campaign"
        )
    try:
        current = verify_run_integrity(parent_run_path)
    except RunIntegrityError as exc:
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB parent is not fully sealed"
        ) from exc
    if (
        current.run_id != expected_parent_run_id
        or current.root_digest != expected_parent_root_digest
    ):
        raise GovernedWebCampaignEvidenceError(
            "completed governed WEB parent changed after strict reload"
        )
    return loaded


def load_verified_governed_web_incomplete_campaign_evidence(
    parent_run_path: Path,
    *,
    expected_parent_run_id: str,
    expected_campaign_plan_digest: str,
    expected_deployment_trust_anchor_digest: str,
    expected_parent_root_digest: str | None = None,
) -> VerifiedGovernedWebIncompleteCampaign:
    """Load a failed terminal or last fully sealed hard-crash prefix."""

    loaded = load_verified_governed_web_campaign_terminal(
        parent_run_path,
        expected_parent_run_id=expected_parent_run_id,
        expected_parent_root_digest=expected_parent_root_digest,
        expected_campaign_plan_digest=expected_campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(
            expected_deployment_trust_anchor_digest
        ),
    )
    if type(loaded) is not VerifiedGovernedWebIncompleteCampaign:
        raise GovernedWebCampaignEvidenceError(
            "governed WEB parent is complete, not incomplete"
        )
    return loaded


__all__ = [
    "GOVERNED_WEB_ADAPTER_REF",
    "GOVERNED_WEB_CAMPAIGN_EVIDENCE_API_VERSION",
    "GOVERNED_WEB_CAMPAIGN_ID",
    "GOVERNED_WEB_CAMPAIGN_INDEX_API_VERSION",
    "GOVERNED_WEB_CAMPAIGN_PLAN_API_VERSION",
    "GOVERNED_WEB_CAMPAIGN_STAGE_ORDER",
    "GOVERNED_WEB_CAMPAIGN_TRUST_API_VERSION",
    "GOVERNED_WEB_ORIGIN",
    "GovernedWebCampaignCheckpoint",
    "GovernedWebCampaignDatabaseEnrollment",
    "GovernedWebCampaignEvidenceError",
    "GovernedWebCampaignHistoricalResult",
    "GovernedWebCampaignIndex",
    "GovernedWebCampaignIndexArtifact",
    "GovernedWebCampaignIndexSignerAuthority",
    "GovernedWebCampaignParentWriter",
    "GovernedWebCampaignPlan",
    "GovernedWebCampaignPlannedRuns",
    "GovernedWebCampaignStageIntent",
    "GovernedWebCampaignStageObservation",
    "GovernedWebCampaignTrustBundle",
    "GovernedWebCampaignTrustMaterial",
    "GovernedWebCodeTrustBinding",
    "GovernedWebCompletedCampaignEvidence",
    "GovernedWebIncompleteCampaignEvidence",
    "VerifiedGovernedWebCampaign",
    "VerifiedGovernedWebCompletedCampaign",
    "VerifiedGovernedWebIncompleteCampaign",
    "begin_governed_web_campaign_parent",
    "build_governed_web_campaign_trust_bundle",
    "generate_governed_web_campaign_evidence_signer",
    "load_verified_governed_web_campaign_terminal",
    "load_verified_governed_web_completed_campaign_evidence",
    "load_verified_governed_web_incomplete_campaign_evidence",
]
